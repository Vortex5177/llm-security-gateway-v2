"""模块 2：非流式代理（硬顶注入/回退链/请求日志）测试。"""

from __future__ import annotations

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


def ok_body(model="qwen3-1.7b", prompt=12, completion=7):
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    }


def make_transport(seen, plan):
    """plan: {"host:port": (status, body) 或 callable(request, payload)}"""

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
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


async def fetch_logs(session_factory):
    async with session_factory() as session:
        rows = (
            (await session.execute(select(RequestLog).order_by(RequestLog.id)))
            .scalars()
            .all()
        )
        return rows


CHAT_BODY = {
    "model": "qwen3-1.7b",
    "messages": [{"role": "user", "content": "ping"}],
    "max_tokens": 123,
}


# ------------------------------------------------------------ 硬顶注入

async def test_injection_tag_overrides_client_values(config, registry, session_factory):
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, ok_body())})
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag="speclens/scan",
        transport=transport,
        session_factory=session_factory,
    )
    assert result.http_status == 200
    payload = seen[0]["payload"]
    assert payload["max_tokens"] == 4096  # 客户端 123 被硬顶覆盖
    assert payload["repetition_penalty"] == 1.05
    assert payload["model"] == "qwen3-1.7b"  # 上游名
    assert payload["messages"] == CHAT_BODY["messages"]  # 未触碰客户端字段
    assert "extra" not in payload  # 注入的 extra 已展开到顶级


async def test_default_injection_without_tag(config, registry, session_factory):
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, ok_body())})
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=transport,
        session_factory=session_factory,
    )
    assert result.http_status == 200
    assert seen[0]["payload"]["max_tokens"] == 2048  # default 行硬顶
    assert "repetition_penalty" not in seen[0]["payload"]  # tag 行未生效


async def test_default_row_merges_into_tag_row(config_dict):
    config_dict["injection"]["default"]["extra"] = {
        "chat_template_kwargs": {"enable_thinking": False}
    }
    cfg = parse_config(config_dict)
    merged = routing.effective_injection(cfg, "speclens/scan")
    assert merged["max_tokens"] == 4096  # tag 行覆盖
    assert merged["repetition_penalty"] == 1.05
    assert merged["chat_template_kwargs"]["enable_thinking"] is False  # extra 展开到顶级


async def test_client_kwargs_merge_with_hard_override(config_dict, session_factory):
    config_dict["injection"]["default"]["extra"] = {
        "chat_template_kwargs": {"enable_thinking": False}
    }
    cfg = parse_config(config_dict)
    reg = Registry(cfg)
    body = dict(CHAT_BODY)
    body["chat_template_kwargs"] = {"client_hint": True}
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, ok_body())})
    await routing.execute_chat(
        cfg, reg, body, tag=None, transport=transport, session_factory=session_factory
    )
    payload = seen[0]["payload"]
    assert "extra" not in payload  # extra 已展开到顶级
    kwargs = payload["chat_template_kwargs"]
    assert kwargs["client_hint"] is True  # 客户端子键保留
    assert kwargs["enable_thinking"] is False  # 硬顶子键注入


# ------------------------------------------------------------ 回退链

async def test_fallback_second_candidate_succeeds(
    config, registry, session_factory, monkeypatch
):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-unit-test")
    seen = []
    plan = {
        "localhost:8200": (500, {"error": {"message": "local engine crashed"}}),
        "api.deepseek.com:443": (200, ok_body(model="deepseek-chat")),
    }
    transport = make_transport(seen, plan)
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=transport,
        session_factory=session_factory,
    )
    assert result.http_status == 200
    assert result.attempts == 2
    assert result.fallback_used is True
    assert result.provider == "deepseek"
    assert result.resolved_model == "deepseek-chat"
    assert seen[1]["payload"]["model"] == "deepseek-chat"

    logs = await fetch_logs(session_factory)
    assert len(logs) == 1
    row = logs[0]
    assert row.status == "ok"
    assert row.attempts == 2
    assert row.fallback_used is True
    assert row.provider == "deepseek"
    assert row.resolved_model == "deepseek-chat"


async def test_fallback_uses_tag_specific_chain(config_dict, session_factory, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-unit-test")
    config_dict["fallbacks"] = {"qwen3-1.7b@scan": ["deepseek-chat"]}
    cfg = parse_config(config_dict)
    reg = Registry(cfg)
    seen = []
    plan = {
        "localhost:8200": (500, {"error": {"message": "boom"}}),
        "api.deepseek.com:443": (200, ok_body(model="deepseek-chat")),
    }
    result = await routing.execute_chat(
        cfg,
        reg,
        dict(CHAT_BODY),
        tag="scan",
        transport=make_transport(seen, plan),
        session_factory=session_factory,
    )
    assert result.attempts == 2
    assert result.resolved_model == "deepseek-chat"


async def test_all_candidates_fail_returns_last_upstream_status(
    config, registry, session_factory
):
    seen = []
    plan = {
        "localhost:8200": (503, {"error": {"message": "engine overloaded"}}),
        "api.deepseek.com:443": (429, {"error": {"message": "rate limited"}}),
    }
    transport = make_transport(seen, plan)
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=transport,
        session_factory=session_factory,
    )
    assert result.http_status == 429  # 取最后一个上游状态码
    assert result.attempts == 2
    assert result.fallback_used is True
    assert "rate limited" in result.body["error"]["message"]

    logs = await fetch_logs(session_factory)
    row = logs[0]
    assert row.status == "upstream_error"
    assert row.http_status == 429
    assert row.attempts == 2
    assert "rate limited" in row.error


async def test_connection_error_maps_to_502(config, registry, session_factory):
    def raise_connect(request, payload):
        raise httpx.ConnectError("connection refused", request=request)

    plan = {"localhost:8200": raise_connect, "api.deepseek.com:443": raise_connect}
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.http_status == 502
    logs = await fetch_logs(session_factory)
    assert logs[0].status == "upstream_error"
    assert logs[0].http_status == 502


async def test_timeout_maps_to_502_and_timeout_status(config, registry, session_factory):
    def raise_timeout(request, payload):
        raise httpx.ConnectTimeout("timed out", request=request)

    plan = {"localhost:8200": raise_timeout, "api.deepseek.com:443": raise_timeout}
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.http_status == 502
    logs = await fetch_logs(session_factory)
    assert logs[0].status == "timeout"
    assert logs[0].http_status == 502


async def test_upstream_non_json_maps_to_502(config, registry, session_factory):
    def html_response(request, payload):
        return httpx.Response(200, text="<html>oops</html>")

    plan = {"localhost:8200": html_response, "api.deepseek.com:443": html_response}
    result = await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag=None,
        transport=make_transport([], plan),
        session_factory=session_factory,
    )
    assert result.http_status == 502  # 2xx 但非 JSON 不暴露为 200
    logs = await fetch_logs(session_factory)
    assert logs[0].status == "upstream_error"


async def test_unknown_model_returns_404_and_logs_invalid_request(
    config, registry, session_factory
):
    result = await routing.execute_chat(
        config,
        registry,
        {"model": "ghost", "messages": []},
        transport=make_transport([], {}),
        session_factory=session_factory,
    )
    assert result.http_status == 404
    assert result.body["error"]["code"] == "model_not_found"
    assert result.attempts == 0
    logs = await fetch_logs(session_factory)
    assert logs[0].status == "invalid_request"
    assert logs[0].http_status == 404
    assert "ghost" in logs[0].error


# ------------------------------------------------------------ 请求日志

async def test_request_log_fields_complete(config, registry, session_factory):
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, ok_body())})
    await routing.execute_chat(
        config,
        registry,
        dict(CHAT_BODY),
        tag="speclens/scan",
        transport=transport,
        session_factory=session_factory,
    )
    logs = await fetch_logs(session_factory)
    row = logs[0]
    assert row.tag == "speclens/scan"
    assert row.requested_model == "qwen3-1.7b"
    assert row.resolved_model == "qwen3-1.7b"
    assert row.provider == "local-vllm"
    assert row.streamed is False
    assert row.prompt_tokens == 12
    assert row.completion_tokens == 7
    assert row.total_tokens == 19
    assert row.latency_ms is not None and row.latency_ms >= 0
    assert row.ttft_ms is None
    assert row.status == "ok"
    assert row.http_status == 200
    assert row.attempts == 1
    assert row.fallback_used is False
    assert row.error is None
    assert row.created_at is not None
    injected = json.loads(row.injected_json)
    assert injected["max_tokens"] == 4096  # 生效参数快照


async def test_alias_resolution_uses_upstream_name(config, registry, session_factory):
    seen = []
    transport = make_transport(seen, {"localhost:8200": (200, ok_body())})
    body = dict(CHAT_BODY, model="default")
    result = await routing.execute_chat(
        config, registry, body, transport=transport, session_factory=session_factory
    )
    assert result.resolved_model == "qwen3-1.7b"
    assert seen[0]["payload"]["model"] == "qwen3-1.7b"
    logs = await fetch_logs(session_factory)
    assert logs[0].requested_model == "default"
    assert logs[0].resolved_model == "qwen3-1.7b"


async def test_api_key_sent_as_bearer(config, registry, session_factory, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-unit-test")
    seen = []
    transport = make_transport(
        seen, {"api.deepseek.com:443": (200, ok_body(model="deepseek-chat"))}
    )
    body = dict(CHAT_BODY, model="deepseek-chat")
    await routing.execute_chat(
        config, registry, body, transport=transport, session_factory=session_factory
    )
    assert seen[0]["headers"]["authorization"] == "Bearer sk-unit-test"


# ------------------------------------------------------------ route 层

async def test_route_headers_and_openai_body(config, registry, session_factory):
    from app.main import create_app

    app = create_app()
    app.state.config = config
    app.state.registry = registry
    app.state.session_factory = session_factory
    app.state.http_transport = make_transport([], {"localhost:8200": (200, ok_body())})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=dict(CHAT_BODY, model="default"),
            headers={"x-gw-tag": "speclens/scan"},
        )
    assert resp.status_code == 200
    assert resp.headers["x-gw-attempts"] == "1"
    assert resp.headers["x-gw-provider"] == "local-vllm"
    assert resp.headers["x-gw-resolved-model"] == "qwen3-1.7b"
    assert resp.json()["object"] == "chat.completion"
