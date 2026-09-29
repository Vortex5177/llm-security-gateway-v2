"""核心编排：硬顶注入 + 回退链 + 请求日志落库（非流式 / 流式）。"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import proxy
from app.config import GatewayConfig
from app.db import SessionLocal
from app.models import RequestLog
from app.registry import Registry, UnknownModelError

ERROR_SNIPPET_LIMIT = 1000


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """递归合并：overlay 覆盖 base（dict 递归下钻，其余整体替换）。"""
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def effective_injection(config: GatewayConfig, tag: str | None) -> dict[str, Any]:
    """硬顶 = default 行 ∪ tag 行（tag 行优先，递归合并）。

    "extra" 键会展开合并到请求顶级（provider 特有参数如 chat_template_kwargs
    必须位于顶级才能被上游识别）。
    """
    merged = dict(config.injection.get("default", {}))
    if tag and tag != "default":
        row = config.injection.get(tag)
        if row:
            merged = deep_merge(merged, row)
    extra = merged.pop("extra", None)
    if isinstance(extra, dict):
        merged = deep_merge(merged, extra)
    return merged


def build_effective_body(
    config: GatewayConfig, body: dict[str, Any], tag: str | None
) -> dict[str, Any]:
    """客户端参数 → 硬顶注入后的完整请求参数（override 语义）。"""
    return deep_merge(body, effective_injection(config, tag))


def openai_error(
    message: str, *, type_: str = "upstream_error", code: str | None = None
) -> dict[str, Any]:
    return {"error": {"message": message, "type": type_, "code": code}}


@dataclass
class ChatResult:
    http_status: int
    body: dict[str, Any]
    provider: str | None = None
    resolved_model: str | None = None
    attempts: int = 0
    fallback_used: bool = False


@dataclass
class StreamResult:
    ok: bool
    http_status: int
    body: dict[str, Any] | None = None  # 失败时的 OpenAI 错误体
    provider: str | None = None
    resolved_model: str | None = None
    attempts: int = 0
    fallback_used: bool = False
    ttft_ms: float | None = None
    stream: AsyncIterator[bytes] | None = None  # 成功时的 SSE 字节流（结束后自动落库）


def _usage_tokens(payload: dict[str, Any] | None) -> tuple[int, int, int]:
    usage = (payload or {}).get("usage") or {}
    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)
    total = int(usage.get("total_tokens") or (prompt + completion))
    return prompt, completion, total


def _sse_data_payload(line: bytes) -> dict[str, Any] | None:
    """SSE data 行 → JSON dict（[DONE]/注释/非 JSON 返回 None）。"""
    if not line.startswith(b"data:"):
        return None
    data = line[5:].strip()
    if not data or data == b"[DONE]":
        return None
    try:
        parsed = json.loads(data)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


async def _write_log(session_factory, **fields: Any) -> None:
    factory = session_factory or SessionLocal
    async with factory() as session:
        session.add(RequestLog(**fields))
        await session.commit()


async def execute_chat(
    config: GatewayConfig,
    registry: Registry,
    body: dict[str, Any],
    tag: str | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> ChatResult:
    """按候选链逐个尝试上游；成功即返回，全失败返回最后错误。成功与失败都落库。"""
    requested_model = str(body.get("model") or "")
    effective = build_effective_body(config, body, tag)
    injected_json = json.dumps(effective, ensure_ascii=False)
    started = time.perf_counter()

    try:
        candidates = registry.candidates(requested_model, tag)
    except UnknownModelError as exc:
        await _write_log(
            session_factory,
            tag=tag,
            requested_model=requested_model,
            resolved_model="",
            provider="",
            streamed=False,
            status="invalid_request",
            http_status=404,
            attempts=0,
            fallback_used=False,
            error=str(exc)[:ERROR_SNIPPET_LIMIT],
            injected_json=injected_json,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return ChatResult(
            http_status=404,
            body=openai_error(
                str(exc), type_="invalid_request_error", code="model_not_found"
            ),
        )

    last: proxy.CompletionResult | None = None
    last_provider: str | None = None
    attempt_count = 0
    for candidate in candidates:
        provider_cfg = config.providers[candidate.provider]
        payload = dict(effective)
        payload["model"] = candidate.upstream
        last = await proxy.acomplete(
            provider_cfg,
            payload,
            config.server.upstream_timeout_seconds,
            transport=transport,
        )
        last_provider = candidate.provider
        attempt_count += 1
        if last.ok:
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            prompt, completion, total = _usage_tokens(last.payload)
            await _write_log(
                session_factory,
                tag=tag,
                requested_model=requested_model,
                resolved_model=candidate.name,
                provider=candidate.provider,
                streamed=False,
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=total,
                latency_ms=latency_ms,
                status="ok",
                http_status=last.http_status,
                attempts=attempt_count,
                fallback_used=attempt_count > 1,
                error=None,
                injected_json=injected_json,
            )
            return ChatResult(
                http_status=200,
                body=last.payload or {},
                provider=candidate.provider,
                resolved_model=candidate.name,
                attempts=attempt_count,
                fallback_used=attempt_count > 1,
            )

    # 全部候选失败：状态码取上游值（非 4xx/5xx 或非数字则 502）
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    status = "timeout" if (last is not None and last.timeout) else "upstream_error"
    if last is not None and last.http_status is not None and last.http_status >= 400:
        http_status = last.http_status
    else:
        http_status = 502
    message = last.error if (last is not None and last.error) else "没有可用的上游候选"
    await _write_log(
        session_factory,
        tag=tag,
        requested_model=requested_model,
        resolved_model=candidates[0].name,
        provider=last_provider or candidates[0].provider,
        streamed=False,
        latency_ms=latency_ms,
        status=status,
        http_status=http_status,
        attempts=attempt_count,
        fallback_used=attempt_count > 1,
        error=message[:ERROR_SNIPPET_LIMIT],
        injected_json=injected_json,
    )
    return ChatResult(
        http_status=http_status,
        body=openai_error(message),
        provider=last_provider,
        resolved_model=candidates[0].name,
        attempts=attempt_count,
        fallback_used=attempt_count > 1,
    )


async def execute_chat_stream(
    config: GatewayConfig,
    registry: Registry,
    body: dict[str, Any],
    tag: str | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> StreamResult:
    """流式版 execute_chat：等首块到达才提交；首块前失败走回退；生成结束后落库。

    上游请求自动补 stream_options.include_usage=true；客户端中断（生成器被关闭/
    取消）记为 client_abort。
    """
    requested_model = str(body.get("model") or "")
    effective = build_effective_body(config, body, tag)
    injected_json = json.dumps(effective, ensure_ascii=False)
    started = time.perf_counter()

    try:
        candidates = registry.candidates(requested_model, tag)
    except UnknownModelError as exc:
        await _write_log(
            session_factory,
            tag=tag,
            requested_model=requested_model,
            resolved_model="",
            provider="",
            streamed=True,
            status="invalid_request",
            http_status=404,
            attempts=0,
            fallback_used=False,
            error=str(exc)[:ERROR_SNIPPET_LIMIT],
            injected_json=injected_json,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return StreamResult(
            ok=False,
            http_status=404,
            body=openai_error(
                str(exc), type_="invalid_request_error", code="model_not_found"
            ),
        )

    session: proxy.StreamSession | None = None
    last: proxy.StreamSession | None = None
    last_provider: str | None = None
    attempt_count = 0
    for candidate in candidates:
        provider_cfg = config.providers[candidate.provider]
        payload = dict(effective)
        payload["model"] = candidate.upstream
        payload["stream"] = True
        stream_options = dict(payload.get("stream_options") or {})
        stream_options["include_usage"] = True
        payload["stream_options"] = stream_options
        session = await proxy.open_stream(
            provider_cfg,
            payload,
            config.server.upstream_timeout_seconds,
            transport=transport,
        )
        last = session
        last_provider = candidate.provider
        attempt_count += 1
        if session.ok:
            break

    # 全部候选失败：规则同非流式（4xx/5xx 透传，否则 502）
    if session is None or not session.ok:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        status = "timeout" if (last is not None and last.timeout) else "upstream_error"
        if last is not None and last.http_status is not None and last.http_status >= 400:
            http_status = last.http_status
        else:
            http_status = 502
        message = last.error if (last is not None and last.error) else "没有可用的上游候选"
        await _write_log(
            session_factory,
            tag=tag,
            requested_model=requested_model,
            resolved_model=candidates[0].name,
            provider=last_provider or candidates[0].provider,
            streamed=True,
            latency_ms=latency_ms,
            status=status,
            http_status=http_status,
            attempts=attempt_count,
            fallback_used=attempt_count > 1,
            error=message[:ERROR_SNIPPET_LIMIT],
            injected_json=injected_json,
        )
        return StreamResult(
            ok=False,
            http_status=http_status,
            body=openai_error(message),
            provider=last_provider,
            resolved_model=candidates[0].name,
            attempts=attempt_count,
            fallback_used=attempt_count > 1,
        )

    active = session
    active_candidate = candidates[attempt_count - 1]
    fallback_used = attempt_count > 1
    ttft_ms = round((time.perf_counter() - started) * 1000, 2)

    async def _forward() -> AsyncIterator[bytes]:
        """透传首块 + 后续 SSE 行；捕获尾部 usage；结束（含中断）后落库。"""
        status = "ok"
        error: str | None = None
        completed = False
        prompt = completion = total = 0
        try:
            yield active.first_event
            async for line in active.iter_rest():
                chunk = _sse_data_payload(line)
                if chunk is not None:
                    usage = chunk.get("usage")
                    if isinstance(usage, dict):
                        prompt = int(usage.get("prompt_tokens") or 0)
                        completion = int(usage.get("completion_tokens") or 0)
                        total = int(usage.get("total_tokens") or (prompt + completion))
                yield line
            completed = True
        except asyncio.CancelledError:
            status = "client_abort"
            raise
        except httpx.TimeoutException as exc:
            status, error = "timeout", f"流式读取超时: {exc}"
        except httpx.HTTPError as exc:
            status, error = "upstream_error", f"流式读取失败: {exc}"
        except Exception as exc:  # 兜底：保证落库
            status, error = "upstream_error", f"流式转发异常: {exc}"
        finally:
            if not completed and status == "ok":
                status = "client_abort"  # 生成器被提前关闭（客户端断开）
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            output_tps = None
            if ttft_ms is not None and completion > 0 and latency_ms > ttft_ms:
                output_tps = round(completion / ((latency_ms - ttft_ms) / 1000), 2)

            async def _cleanup() -> None:
                await active.aclose()
                try:
                    await _write_log(
                        session_factory,
                        tag=tag,
                        requested_model=requested_model,
                        resolved_model=active_candidate.name,
                        provider=active_candidate.provider,
                        streamed=True,
                        prompt_tokens=prompt,
                        completion_tokens=completion,
                        total_tokens=total,
                        latency_ms=latency_ms,
                        ttft_ms=ttft_ms,
                        output_tps=output_tps,
                        status=status,
                        http_status=active.http_status,
                        attempts=attempt_count,
                        fallback_used=fallback_used,
                        error=error[:ERROR_SNIPPET_LIMIT] if error else None,
                        injected_json=injected_json,
                    )
                except Exception:
                    pass  # 落库失败不影响已提交的流

            # 取消路径下清理等待会被立即打断：shield 兜底，让清理在后台完成
            cleanup = asyncio.ensure_future(_cleanup())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                pass  # 取消正在向外传播，清理任务留在后台

    return StreamResult(
        ok=True,
        http_status=200,
        provider=active_candidate.provider,
        resolved_model=active_candidate.name,
        attempts=attempt_count,
        fallback_used=fallback_used,
        ttft_ms=ttft_ms,
        stream=_forward(),
    )