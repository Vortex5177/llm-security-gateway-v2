"""API Key 鉴权 / RBAC / 模型白名单 / 限流入口 / 引导签发。

覆盖：密钥哈希存储、authenticate 各分支、chat 数据平面 401/403/429、
/api/keys 管理平面角色控制、/v1/models 鉴权、引导 key 一次性签发。
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import auth
from app.config import parse_config
from app.models import ApiKey, Base, SecurityEvent
from app.ratelimit import RateLimiter
from app.registry import Registry

# ------------------------------------------------------------ fixtures


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


@pytest.fixture()
def secured_config(config_dict):
    config_dict["server"]["auth"] = {"enabled": True}
    return parse_config(config_dict)


CHAT_COMPLETION = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 1,
    "model": "qwen3-1.7b",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "收到"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
}


def _mock_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json=CHAT_COMPLETION)
        return httpx.Response(200, json={"object": "list", "data": []})

    return httpx.MockTransport(handler)


@pytest.fixture()
async def api(secured_config, session_factory):
    from app.main import create_app

    app = create_app()
    app.state.config = secured_config
    app.state.registry = Registry(secured_config)
    app.state.session_factory = session_factory
    app.state.http_transport = _mock_transport()
    app.state.rate_limiter = RateLimiter()
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
        yield client


async def _make_key(session_factory, **kwargs) -> str:
    kwargs.setdefault("name", "k1")
    kwargs.setdefault("role", auth.ROLE_USER)
    plaintext, _row = await auth.create_key(session_factory, **kwargs)
    return plaintext


def _bearer(plaintext: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {plaintext}"}


CHAT_BODY = {"model": "qwen3-1.7b", "messages": [{"role": "user", "content": "hi"}]}


async def _events(session_factory) -> list[SecurityEvent]:
    async with session_factory() as session:
        return (
            (await session.execute(select(SecurityEvent).order_by(SecurityEvent.ts)))
            .scalars()
            .all()
        )


# ------------------------------------------------------------ 密钥生成与存储


def test_generate_key_format_and_hash():
    plaintext, key_hash = auth.generate_api_key()
    assert plaintext.startswith("gw_") and len(plaintext) > 20
    assert key_hash == hashlib.sha256(plaintext.encode()).hexdigest()
    assert plaintext != key_hash


async def test_create_key_stores_hash_only(session_factory):
    plaintext, row = await auth.create_key(session_factory, name="svc", role="user")
    assert row.name == "svc"
    async with session_factory() as session:
        stored = (
            await session.execute(select(ApiKey).where(ApiKey.name == "svc"))
        ).scalar_one()
    assert stored.key_hash == auth.hash_key(plaintext)
    assert plaintext not in (stored.key_hash, stored.allowed_models)


async def test_create_key_rejects_duplicate_name_and_bad_role(session_factory):
    await auth.create_key(session_factory, name="dup", role="user")
    with pytest.raises(ValueError, match="已存在"):
        await auth.create_key(session_factory, name="dup", role="user")
    with pytest.raises(ValueError, match="未知角色"):
        await auth.create_key(session_factory, name="x", role="root")


def test_key_allows_model():
    key = ApiKey(key_hash="h", name="k", role="user", allowed_models='["*"]')
    assert auth.key_allows_model(key, "anything") is True
    key.allowed_models = '["qwen3-1.7b", "deepseek-chat"]'
    assert auth.key_allows_model(key, "qwen3-1.7b") is True
    assert auth.key_allows_model(key, "gpt-x") is False
    key.allowed_models = "not-json"
    assert auth.key_allows_model(key, "qwen3-1.7b") is False


async def test_bootstrap_key_created_once(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "BOOTSTRAP_KEY_FILE", tmp_path / "bootstrap.txt")
    await auth.ensure_bootstrap_key(session_factory)
    rows = await auth.list_keys(session_factory)
    assert len(rows) == 1 and rows[0].role == auth.ROLE_ADMIN
    content = (tmp_path / "bootstrap.txt").read_text(encoding="utf-8")
    assert content.startswith("gw_")
    # 已有 key 时不再签发
    await auth.ensure_bootstrap_key(session_factory)
    assert len(await auth.list_keys(session_factory)) == 1


# ------------------------------------------------------------ 数据平面（/v1/*）


async def test_chat_without_key_401_and_event(api, session_factory):
    resp = await api.post("/v1/chat/completions", json=CHAT_BODY)
    assert resp.status_code == 401
    assert resp.json()["error"]["type"] == "authentication_error"
    assert resp.headers["X-GW-Request-Id"]
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["auth_failure"]
    assert events[0].source_ip == "127.0.0.1"


async def test_chat_with_wrong_key_401(api, session_factory):
    resp = await api.post(
        "/v1/chat/completions", json=CHAT_BODY, headers=_bearer("gw_wrong")
    )
    assert resp.status_code == 401


async def test_chat_with_valid_key_200(api, session_factory):
    plaintext = await _make_key(session_factory)
    resp = await api.post(
        "/v1/chat/completions", json=CHAT_BODY, headers=_bearer(plaintext)
    )
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == "收到"
    rows = await auth.list_keys(session_factory)
    assert rows[0].last_used_at is not None


async def test_model_permission_denied_403_and_event(api, session_factory):
    plaintext = await _make_key(session_factory, allowed_models=["qwen3-1.7b"])
    resp = await api.post(
        "/v1/chat/completions",
        json={"model": "deepseek-chat", "messages": []},
        headers=_bearer(plaintext),
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "permission_error"
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["model_permission_denied"]
    assert events[0].resource == "deepseek-chat"
    assert events[0].key_name == "k1"
    assert events[0].request_id == resp.headers["X-GW-Request-Id"]


async def test_model_permission_allows_listed_model(api, session_factory):
    plaintext = await _make_key(session_factory, allowed_models=["qwen3-1.7b"])
    resp = await api.post(
        "/v1/chat/completions", json=CHAT_BODY, headers=_bearer(plaintext)
    )
    assert resp.status_code == 200


async def test_rate_limit_429_and_event(api, session_factory):
    plaintext = await _make_key(session_factory, rpm_limit=2, burst=2)
    headers = _bearer(plaintext)
    assert (await api.post("/v1/chat/completions", json=CHAT_BODY, headers=headers)).status_code == 200
    assert (await api.post("/v1/chat/completions", json=CHAT_BODY, headers=headers)).status_code == 200
    resp = await api.post("/v1/chat/completions", json=CHAT_BODY, headers=headers)
    assert resp.status_code == 429
    assert resp.json()["error"]["type"] == "rate_limit_error"
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["rate_limit_exceeded"]
    assert events[0].severity == "medium"


async def test_v1_models_requires_key(api, session_factory):
    assert (await api.get("/v1/models")).status_code == 401
    plaintext = await _make_key(session_factory)
    resp = await api.get("/v1/models", headers=_bearer(plaintext))
    assert resp.status_code == 200
    assert resp.json()["object"] == "list"


async def test_disabled_key_rejected(api, session_factory):
    plaintext = await _make_key(session_factory)
    await auth.disable_key(session_factory, "k1")
    resp = await api.post(
        "/v1/chat/completions", json=CHAT_BODY, headers=_bearer(plaintext)
    )
    assert resp.status_code == 401


# ------------------------------------------------------------ 管理平面（/api/keys）


async def test_keys_api_requires_admin(api, session_factory):
    user_key = await _make_key(session_factory, name="u1", role="user")
    resp = await api.post(
        "/api/keys", json={"name": "x", "role": "user"}, headers=_bearer(user_key)
    )
    assert resp.status_code == 403

    admin_key = await _make_key(session_factory, name="a1", role="admin")
    resp = await api.post(
        "/api/keys",
        json={"name": "svc", "role": "developer", "allowed_models": ["qwen3-1.7b"]},
        headers=_bearer(admin_key),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["api_key"].startswith("gw_")  # 明文仅此一次返回
    assert body["allowed_models"] == ["qwen3-1.7b"]

    resp = await api.get("/api/keys", headers=_bearer(admin_key))
    assert resp.status_code == 200
    names = {k["name"] for k in resp.json()["keys"]}
    assert {"u1", "a1", "svc"} <= names
    assert "api_key" not in resp.text  # 列表绝不回显明文/哈希


async def test_keys_api_rejects_bad_payload(api, session_factory):
    admin_key = await _make_key(session_factory, name="a1", role="admin")
    headers = _bearer(admin_key)
    resp = await api.post("/api/keys", json={"name": "x", "role": "root"}, headers=headers)
    assert resp.status_code == 400
    resp = await api.post("/api/keys", json={"name": "x2", "role": "user"}, headers=headers)
    assert resp.status_code == 201
    resp = await api.post("/api/keys", json={"name": "x2", "role": "user"}, headers=headers)
    assert resp.status_code == 409


async def test_disable_key_flow_and_self_guard(api, session_factory):
    admin_key = await _make_key(session_factory, name="a1", role="admin")
    user_key = await _make_key(session_factory, name="u1", role="user")
    headers = _bearer(admin_key)

    # admin 不能禁用自己正在使用的 key
    resp = await api.post("/api/keys/a1/disable", headers=headers)
    assert resp.status_code == 400

    resp = await api.post("/api/keys/u1/disable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["disabled"] is True

    # 禁用后立即失效
    resp = await api.post(
        "/v1/chat/completions", json=CHAT_BODY, headers=_bearer(user_key)
    )
    assert resp.status_code == 401

    events = await _events(session_factory)
    assert "key_disabled" in [e.event_type for e in events]


async def test_key_events_do_not_leak_plaintext(api, session_factory):
    admin_key = await _make_key(session_factory, name="a1", role="admin")
    await api.post(
        "/api/keys", json={"name": "svc", "role": "user"}, headers=_bearer(admin_key)
    )
    events = await _events(session_factory)
    assert events, "应记录 key_created 事件"
    for e in events:
        assert admin_key not in (e.metadata_json or "")
