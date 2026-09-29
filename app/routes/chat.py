"""POST /v1/chat/completions（非流式 JSON + 流式 SSE 透传）。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app import routing

router = APIRouter(tags=["chat"])


def _gw_headers(
    attempts: int, provider: str | None, resolved: str | None
) -> dict[str, str]:
    headers = {"X-GW-Attempts": str(attempts)}
    if provider:
        headers["X-GW-Provider"] = provider
    if resolved:
        headers["X-GW-Resolved-Model"] = resolved
    return headers


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    try:
        body: Any = await request.json()
    except ValueError:
        return JSONResponse(
            status_code=400,
            content=routing.openai_error(
                "请求体不是合法 JSON", type_="invalid_request_error"
            ),
        )
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content=routing.openai_error(
                "请求体必须是 JSON 对象", type_="invalid_request_error"
            ),
        )
    if not body.get("model"):
        return JSONResponse(
            status_code=400,
            content=routing.openai_error(
                "缺少 model 字段", type_="invalid_request_error"
            ),
        )

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
            stream_result.attempts, stream_result.provider, stream_result.resolved_model
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
    headers = _gw_headers(result.attempts, result.provider, result.resolved_model)
    return JSONResponse(
        status_code=result.http_status, content=result.body, headers=headers
    )