"""POST /v1/chat/completions（非流式 JSON + 流式 SSE 透传）。

安全入口顺序：鉴权（401）→ 请求体解析（400）→ 模型白名单（403）→ 限流（429）→ 路由。
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app import audit, auth, routing
from app.ratelimit import RateLimiter
from app.security import policy as policy_mod

router = APIRouter(tags=["chat"])


def _error(status_code: int, message: str, type_: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=routing.openai_error(message, type_=type_),
        headers={"X-GW-Request-Id": request_id},
    )


async def _security_gate(request: Request, body: dict[str, Any], request_id: str) -> JSONResponse | None:
    """鉴权 + 模型白名单 + 限流；放行返回 None，否则返回错误响应（事件已落库）。"""
    session_factory = getattr(request.app.state, "session_factory", None)
    result = await auth.authenticate(request, session_factory)
    if not result.ok:
        return _error(401, result.error or "鉴权失败", "authentication_error", request_id)
    if result.key is None:
        return None  # 鉴权关闭（本机模式）

    request.state.key_name = result.key.name  # 供请求日志归属（execute_chat 落库）

    model = str(body.get("model") or "")
    if not auth.key_allows_model(result.key, model):
        await audit.emit_event(
            session_factory,
            event_type=audit.EVENT_MODEL_DENIED,
            severity="high",
            action="deny",
            key=result.key,
            source_ip=audit.client_ip(request),
            request_id=request_id,
            resource=model,
        )
        return _error(403, f"该 API Key 无权访问模型 '{model}'", "permission_error", request_id)

    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        limiter = RateLimiter()
        request.app.state.rate_limiter = limiter
    if not limiter.check(result.key.key_hash, result.key.rpm_limit, result.key.burst):
        await audit.emit_event(
            session_factory,
            event_type=audit.EVENT_RATE_LIMIT,
            severity="medium",
            action="deny",
            key=result.key,
            source_ip=audit.client_ip(request),
            request_id=request_id,
            resource=model,
            metadata={"rpm_limit": result.key.rpm_limit, "burst": result.key.burst},
        )
        return _error(429, "请求频率超出该 API Key 的限额", "rate_limit_error", request_id)
    return None


def _gw_headers(
    attempts: int, provider: str | None, resolved: str | None, request_id: str
) -> dict[str, str]:
    headers = {"X-GW-Attempts": str(attempts), "X-GW-Request-Id": request_id}
    if provider:
        headers["X-GW-Provider"] = provider
    if resolved:
        headers["X-GW-Resolved-Model"] = resolved
    return headers


# ------------------------------------------------------------ 内容安全护栏（M2）


def _engine(request: Request):
    engine = getattr(request.app.state, "security_engine", None)
    if engine is None or not engine.policy.enabled:
        return None
    return engine


async def _emit_findings(
    request: Request, findings, applied_action: str, request_id: str
) -> None:
    """每条命中落一个安全事件；pii/secret 不记原文（preview 恒 None）。"""
    session_factory = getattr(request.app.state, "session_factory", None)
    for f in findings:
        metadata: dict[str, Any] = {
            "detector": f.detector,
            "rule_action": f.action,
        }
        if f.owasp:
            metadata["owasp"] = f.owasp
        if f.preview is not None:
            metadata["preview"] = f.preview
        if f.message_index is not None:
            metadata["message_index"] = f.message_index
        if f.span is not None:
            metadata["span"] = list(f.span)
        await audit.emit_event(
            session_factory,
            event_type=policy_mod.event_type_of(f.rule_id),
            severity=f.severity,
            action=applied_action,
            source_ip=audit.client_ip(request),
            rule_id=f.rule_id,
            request_id=request_id,
            metadata=metadata,
        )


async def _request_guard(request: Request, body: dict[str, Any], request_id: str):
    """请求护栏：block 返回错误响应；redact 返回重写后的 body；其余返回原 body。"""
    engine = _engine(request)
    if engine is None or not engine.policy.request_guard.enabled:
        return body, None
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body, None
    verdict, sanitized = engine.guard_messages(messages)
    if not verdict.findings:
        return body, None
    await _emit_findings(request, verdict.findings, verdict.action, request_id)
    if verdict.action == "block":
        rules = sorted({f.rule_id for f in verdict.findings if f.action == "block"})
        resp = _error(
            400,
            f"请求被安全策略拦截（命中规则: {', '.join(rules)}）",
            "content_policy_error",
            request_id,
        )
        resp.headers["X-GW-Security-Action"] = "block"
        return body, resp
    if verdict.action == "redact":
        body = {**body, "messages": sanitized}
    return body, None


def _response_contents(payload: dict[str, Any]) -> list[str]:
    texts = []
    for choice in payload.get("choices") or []:
        message = choice.get("message") or {}
        if isinstance(message.get("content"), str):
            texts.append(message["content"])
    return texts


async def _response_guard(request: Request, result, request_id: str):
    """非流式响应护栏：block 替换为错误响应；redact 改写 choices 内容。"""
    engine = _engine(request)
    if (
        engine is None
        or not engine.policy.response_guard.enabled
        or result.http_status != 200
        or not isinstance(result.body, dict)
    ):
        return None
    all_findings = []
    for text in _response_contents(result.body):
        all_findings.extend(engine.scan_text(text))
    if not all_findings:
        return None
    verdict = engine.verdict_of(all_findings)
    await _emit_findings(request, verdict.findings, verdict.action, request_id)
    if verdict.action == "block":
        rules = sorted({f.rule_id for f in verdict.findings if f.action == "block"})
        resp = _error(
            502,
            f"响应被安全策略拦截（命中规则: {', '.join(rules)}）",
            "content_policy_error",
            request_id,
        )
        resp.headers["X-GW-Security-Action"] = "block"
        return resp
    if verdict.action == "redact":
        for choice in result.body.get("choices") or []:
            message = choice.get("message") or {}
            if isinstance(message.get("content"), str):
                findings = engine.scan_text(message["content"])
                message["content"] = engine.apply_redactions(message["content"], findings)
    return None


def _sse_delta_text(line: bytes) -> str:
    payload = routing._sse_data_payload(line)
    if not payload:
        return ""
    parts = []
    for choice in payload.get("choices") or []:
        delta = choice.get("delta") or {}
        if isinstance(delta.get("content"), str):
            parts.append(delta["content"])
    return "".join(parts)


def _wrap_stream_audit(request: Request, stream, request_id: str):
    """流式响应护栏（audit-only）：滑窗增量扫描，命中只落事件、流量逐字节不变。"""
    engine = _engine(request)
    scanner = engine.make_stream_scanner()

    async def _wrapped():
        async for chunk in stream:
            text = _sse_delta_text(chunk)
            if text:
                scanner.feed(text)
                for finding in scanner.drain():
                    await _emit_findings(request, [finding], "audit", request_id)
            yield chunk

    return _wrapped()


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    request_id = uuid.uuid4().hex
    try:
        body: Any = await request.json()
    except ValueError:
        return _error(400, "请求体不是合法 JSON", "invalid_request_error", request_id)
    if not isinstance(body, dict):
        return _error(400, "请求体必须是 JSON 对象", "invalid_request_error", request_id)
    if not body.get("model"):
        return _error(400, "缺少 model 字段", "invalid_request_error", request_id)

    denied = await _security_gate(request, body, request_id)
    if denied is not None:
        return denied

    body, blocked = await _request_guard(request, body, request_id)
    if blocked is not None:
        return blocked

    config = request.app.state.config
    registry = request.app.state.registry
    transport = getattr(request.app.state, "http_transport", None)
    session_factory = getattr(request.app.state, "session_factory", None)
    tag = request.headers.get("x-gw-tag")
    key_name = getattr(request.state, "key_name", None)  # _security_gate 鉴权时挂上

    if body.get("stream"):
        stream_result = await routing.execute_chat_stream(
            config,
            registry,
            body,
            tag,
            transport=transport,
            session_factory=session_factory,
            key_name=key_name,
        )
        headers = _gw_headers(
            stream_result.attempts, stream_result.provider, stream_result.resolved_model, request_id
        )
        if not stream_result.ok:
            return JSONResponse(
                status_code=stream_result.http_status,
                content=stream_result.body,
                headers=headers,
            )
        if stream_result.ttft_ms is not None:
            headers["X-GW-TTFT-Ms"] = f"{stream_result.ttft_ms:.2f}"
        stream = stream_result.stream
        engine = _engine(request)
        if (
            engine is not None
            and engine.policy.response_guard.enabled
            and engine.policy.response_guard.stream_mode == "audit"
        ):
            stream = _wrap_stream_audit(request, stream, request_id)
        return StreamingResponse(
            stream, media_type="text/event-stream", headers=headers
        )

    result = await routing.execute_chat(
        config,
        registry,
        body,
        tag,
        transport=transport,
        session_factory=session_factory,
        key_name=key_name,
    )
    blocked = await _response_guard(request, result, request_id)
    if blocked is not None:
        return blocked
    headers = _gw_headers(result.attempts, result.provider, result.resolved_model, request_id)
    return JSONResponse(
        status_code=result.http_status, content=result.body, headers=headers
    )