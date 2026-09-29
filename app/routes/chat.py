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

    config = request.app.state.config
    registry = request.app.state.registry
    transport = getattr(request.app.state, "http_transport", None)
    session_factory = getattr(request.app.state, "session_factory", None)
    tag = request.headers.get("x-gw-tag")

    if body.get("stream"):
        stream_result = await routing.execute_chat_stream(
            config,
            registry,
            body,
            tag,
            transport=transport,
            session_factory=session_factory,
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
        return StreamingResponse(
            stream_result.stream, media_type="text/event-stream", headers=headers
        )

    result = await routing.execute_chat(
        config,
        registry,
        body,
        tag,
        transport=transport,
        session_factory=session_factory,
    )
    headers = _gw_headers(result.attempts, result.provider, result.resolved_model, request_id)
    return JSONResponse(
        status_code=result.http_status, content=result.body, headers=headers
    )