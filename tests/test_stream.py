"""模块 3：流式支持（SSE 透传 / usage 捕获 / TTFT / 客户端中断 / 首块前回退）测试。"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import routing
from app.config import parse_config
from app.models import Base, RequestLog
from app.registry import Registry


# ------------------------------------------------------------ fixtures

@pytest.fixture()
def config(config_dict):
    return parse_config(config_dict)


@pytest.fixture()
def registry(config):
    return Registry(config)


@pytest.fixture()
async def session_factory(tmp_path):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def fetch_logs(session_factory):
    async with session_factory() as session:
        rows = (
            (await session.execute(select(RequestLog).order_by(RequestLog.id)))
            .scalars()
            .all()
        )
        return rows


# ------------------------------------------------------------ SSE stub

SSE_HEADERS = {"content-type": "text/event-stream; charset=utf-8"}


def sse_chunk(content="", *, finish=None, model="qwen3-1.7b"):
    return {
        "id": "chatcmpl-stream",
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": ({"content": content} if content else {}),
                "finish_reason": finish,
            }
        ],
    }


def usage_chunk(prompt=9, completion=11):
    return {
        "id": "chatcmpl-stream",
        "object": "chat.completion.chunk",
        "model": "qwen3-1.7b",
        "choices": [],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    }


def sse_body(chunks, done=True):
    text = "".join(f"data: {json.dumps(c, ensure_ascii=False)}\n\n" for c in chunks)
    if done:
        text += "data: [DONE]\n\n"
    return text.encode("utf-8")


async def _slow_chunks(data: bytes, size: int = 24, delay: float = 0.002):
    """模拟分块到达的上游字节流（块间 2ms，保证 ttft 与总延迟可区分）。"""
    for i in range(0, len(data), size):
        await asyncio.sleep(delay)
        yield data[i : i + size]


def make_transport(seen, plan):
    """plan: {"host:port": (status, bytes) | (status, dict) | callable(request, payload)}"""

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        key = f"{request.url.host}:{port}"
        seen.append(
            {"url": str(request.url), "payload": payload, "headers": dict(request.headers)}
        )
        spec = plan.get(key)
        if spec is None:
            return httpx.Response(599, json={"error": {"message": f"no stub for {key}"}})
        if callable(spec):
            return spec(request, payload)
        status, body = spec
        if isinstance(body, bytes):
            return httpx.Response(status, headers=SSE_HEADERS, content=_slow_chunks(body))
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


async def drain(result) -> bytes:
    assert result.ok, result.body
    parts = []
    async for line in result.stream:
        parts.append(line)
    return b"".join(parts)


CHAT_BODY = {
    "model": "qwen3-1.7b",
    "messages": [{"role": "user", "content": "ping"}],
    "max_tokens": 32,
    "stream": True,
}


# ------------------------------------------------------------ 透传与 usage

async def test_stream_forward_usage_ttft_and_log(config, registry, session_factory):
    body_bytes = sse_body([sse_chunk("你"), sse_chunk("好", finish="stop"), usage_chunk()])
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, body_bytes)})
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY, stream_options={"keep": True}),
        tag="speclens/scan",
        transport=transport,
        session_factory=session_factory,
    )
    assert result.ok and result.http_status == 200
    assert result.attempts == 1 and result.fallback_used is False
    assert result.provider == "local-vllm" and result.resolved_model == "qwen3-1.7b"
    assert result.ttft_ms is not None and result.ttft_ms >= 0

    forwarded = await drain(result)
    assert forwarded == body_bytes  # 字节级透传
    assert forwarded.endswith(b"data: [DONE]\n\n")

    upstream = seen[0]["payload"]
    assert upstream["stream"] is True
    assert upstream["stream_options"] == {"keep": True, "include_usage": True}
    assert upstream["max_tokens"] == 4096  # tag 硬顶注入对流式同样生效

    row = (await fetch_logs(session_factory))[0]
    assert row.streamed is True
    assert row.status == "ok"
    assert row.prompt_tokens == 9
    assert row.completion_tokens == 11
    assert row.total_tokens == 20
    assert row.ttft_ms is not None and row.ttft_ms >= 0
    assert row.latency_ms is not None and row.latency_ms >= row.ttft_ms
    assert row.output_tps is not None and row.output_tps > 0
    assert row.attempts == 1 and row.fallback_used is False
    assert row.http_status == 200
    assert row.tag == "speclens/scan"


async def test_stream_without_done_chunk_still_ok(config, registry, session_factory):
    body_bytes = sse_body([sse_chunk("hi", finish="stop")], done=False)
    transport = make_transport([], {"localhost:8200": (200, body_bytes)})
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=transport,
        session_factory=session_factory,
    )
    assert await drain(result) == body_bytes
    row = (await fetch_logs(session_factory))[0]
    assert row.status == "ok"
    assert row.completion_tokens == 0  # 上游未给 usage → 记 0
    assert row.total_tokens == 0


# ------------------------------------------------------------ 回退

async def test_stream_first_chunk_failure_falls_back(
    config, registry, session_factory, monkeypatch
):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-unit-test")
    good = sse_body([sse_chunk("hi", finish="stop"), usage_chunk()])

    def sse_ok(request, payload):
        return httpx.Response(200, headers=SSE_HEADERS, content=_slow_chunks(good))

    seen = []
    plan = {
        "localhost:8200": (503, {"error": {"message": "engine overloaded"}}),
        "api.deepseek.com:443": sse_ok,
    }
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=make_transport(seen, plan),
        session_factory=session_factory,
    )
    assert result.ok is True
    assert result.attempts == 2 and result.fallback_used is True
    assert result.provider == "deepseek" and result.resolved_model == "deepseek-chat"
    assert await drain(result) == good

    row = (await fetch_logs(session_factory))[0]
    assert row.status == "ok"
    assert row.attempts == 2 and row.fallback_used is True
    assert row.provider == "deepseek"
    assert row.resolved_model == "deepseek-chat"
    assert row.streamed is True
    assert row.total_tokens == 20


async def test_stream_connect_error_before_first_chunk_falls_back(
    config, registry, session_factory, monkeypatch
):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-unit-test")
    good = sse_body([sse_chunk("hi", finish="stop")])

    def raise_connect(request, payload):
        raise httpx.ConnectError("connection refused", request=request)

    def sse_ok(request, payload):
        return httpx.Response(200, headers=SSE_HEADERS, content=_slow_chunks(good))

    plan = {"localhost:8200": raise_connect, "api.deepseek.com:443": sse_ok}
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.ok is True and result.attempts == 2
    assert await drain(result) == good


async def test_stream_empty_200_stream_treated_as_failure(config, registry, session_factory):
    # 200 但没有任何 data 行 → 视为上游失败（不可提交空流）
    plan = {"localhost:8200": (200, b""), "api.deepseek.com:443": (200, b"")}
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.ok is False
    assert result.http_status == 502
    assert result.attempts == 2
    row = (await fetch_logs(session_factory))[0]
    assert row.status == "upstream_error"
    assert row.streamed is True


async def test_stream_all_candidates_fail_returns_last_status(config, registry, session_factory):
    plan = {
        "localhost:8200": (429, {"error": {"message": "rate limited"}}),
        "api.deepseek.com:443": (503, {"error": {"message": "unavailable"}}),
    }
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.ok is False
    assert result.http_status == 503  # 取最后一个上游状态码
    assert "unavailable" in result.body["error"]["message"]
    row = (await fetch_logs(session_factory))[0]
    assert row.status == "upstream_error"
    assert row.http_status == 503
    assert row.attempts == 2
    assert row.streamed is True


# ------------------------------------------------------------ 客户端中断

async def test_stream_client_abort_logged_as_client_abort(config, registry, session_factory):
    body_bytes = sse_body(
        [sse_chunk("a" * 8), sse_chunk("b" * 8), sse_chunk("c" * 8), usage_chunk()]
    )
    transport = make_transport([], {"localhost:8200": (200, body_bytes)})
    result = await routing.execute_chat_stream(
        config,
        registry,
        dict(CHAT_BODY),
        transport=transport,
        session_factory=session_factory,
    )
    assert result.ok

    agen = result.stream
    first = await agen.__anext__()
    assert first.startswith(b"data:")
    await agen.aclose()  # 客户端中断：提前关闭生成器

    row = (await fetch_logs(session_factory))[0]
    assert row.streamed is True
    assert row.status == "client_abort"
    assert row.ttft_ms is not None
    assert row.completion_tokens == 0
    assert row.error is None


# ------------------------------------------------------------ route 层

async def test_route_stream_sse_via_asgi(config, registry, session_factory):
    from app.main import create_app

    body_bytes = sse_body([sse_chunk("hi", finish="stop"), usage_chunk()])
    app = create_app()
    app.state.config = config
    app.state.registry = registry
    app.state.session_factory = session_factory
    app.state.http_transport = make_transport([], {"localhost:8200": (200, body_bytes)})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        async with client.stream(
            "POST", "/v1/chat/completions", json=dict(CHAT_BODY)
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            assert resp.headers["x-gw-attempts"] == "1"
            assert resp.headers["x-gw-provider"] == "local-vllm"
            assert resp.headers["x-gw-resolved-model"] == "qwen3-1.7b"
            assert float(resp.headers["x-gw-ttft-ms"]) >= 0
            received = b""
            async for piece in resp.aiter_bytes():
                received += piece

    assert received == body_bytes
    row = (await fetch_logs(session_factory))[0]
    assert row.streamed is True and row.status == "ok"
    assert row.total_tokens == 20


async def test_route_stream_unknown_model_404(config, registry, session_factory):
    from app.main import create_app

    app = create_app()
    app.state.config = config
    app.state.registry = registry
    app.state.session_factory = session_factory
    app.state.http_transport = make_transport([], {})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions", json={"model": "ghost", "messages": [], "stream": True}
        )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "model_not_found"