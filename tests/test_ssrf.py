"""SSRF 校验：validate_provider_base_url 表驱动用例 + /api/providers 接口级验证。"""

from __future__ import annotations

import httpx
import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import parse_config, reset_config_cache
from app.models import Base, SecurityEvent
from app.registry import Registry
from app.security.ssrf import validate_provider_base_url

# ------------------------------------------------------------ 纯函数表驱动

OK_URLS = [
    "https://api.deepseek.com/v1",
    "https://api.moonshot.cn/v1",
    "http://8.8.8.8/v1",
    "https://example.com:8443/openai/v1",
    "http://172.15.0.1/v1",   # 172.16/12 之外，非公网语义豁免
    "http://172.32.0.1/v1",
]

REJECTED_URLS = [
    "http://localhost:8200/v1",
    "http://foo.localhost/v1",
    "http://nas.local/v1",
    "http://gateway.internal/v1",
    "http://127.0.0.1:8200/v1",
    "http://127.1.2.3/v1",
    "http://[::1]:8200/v1",
    "http://10.0.0.8/v1",
    "http://192.168.1.10/v1",
    "http://172.16.0.1/v1",
    "http://172.31.255.255/v1",
    "http://169.254.169.254/latest/meta-data",
    "https://metadata.google.internal/v1",
    "http://0.0.0.0/v1",
    "http://user@8.8.8.8/v1",            # userinfo
    "ftp://example.com/v1",              # 非 http/https
    "http://",                            # 无主机名
    "http://exam ple.com/v1",            # 控制字符/非法字符
]


@pytest.mark.parametrize("url", OK_URLS)
def test_public_urls_accepted(url):
    assert validate_provider_base_url(url, []) is None


@pytest.mark.parametrize("url", REJECTED_URLS)
def test_internal_or_malformed_urls_rejected(url):
    reason = validate_provider_base_url(url, [])
    assert isinstance(reason, str) and reason, f"应被拒绝: {url}"


def test_allowlist_by_host():
    assert validate_provider_base_url("http://localhost:8200/v1", ["localhost"]) is None
    # host 条目不限制端口
    assert validate_provider_base_url("http://localhost:9999/v1", ["localhost"]) is None


def test_allowlist_by_host_port():
    allow = ["127.0.0.1:8200"]
    assert validate_provider_base_url("http://127.0.0.1:8200/v1", allow) is None
    # 同主机不同端口仍拒绝
    assert validate_provider_base_url("http://127.0.0.1:9999/v1", allow) is not None
    # 其他内网地址仍拒绝
    assert validate_provider_base_url("http://10.0.0.1/v1", allow) is not None


# ------------------------------------------------------------ 接口级（/api/providers）

def _mock_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization"):
            return httpx.Response(200, json={"object": "list", "data": []})
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


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


def _make_app(config_dict, transport, session_factory):
    from app.main import create_app

    app = create_app()
    app.state.config = parse_config(config_dict)
    app.state.registry = Registry(app.state.config)
    app.state.http_transport = transport
    app.state.session_factory = session_factory
    return app


def _isolate_writes(tmp_path, monkeypatch, config_dict):
    import app.config as config_module
    import app.routes.models as models_module

    main_yaml = tmp_path / "gateway.yaml"
    main_yaml.write_text(yaml.safe_dump(config_dict), encoding="utf-8")
    monkeypatch.setenv("GATEWAY_CONFIG", str(main_yaml))
    monkeypatch.setattr(config_module, "USER_CONFIG_PATH", tmp_path / "gateway.user.yaml")
    monkeypatch.setattr(models_module, "ENV_FILE", tmp_path / ".env")


async def _post_provider(client, base_url: str, name: str = "x-gw"):
    return await client.post(
        "/api/providers",
        json={"preset": "custom", "name": name, "base_url": base_url, "api_key": "sk-x"},
    )


async def test_provider_api_rejects_metadata_and_records_event(
    tmp_path, monkeypatch, config_dict, session_factory
):
    _isolate_writes(tmp_path, monkeypatch, config_dict)
    app = _make_app(config_dict, _mock_transport(), session_factory)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
            base_url="http://gw",
        ) as client:
            resp = await _post_provider(client, "http://169.254.169.254/latest/meta-data")
            assert resp.status_code == 400
            assert "SSRF" in resp.text or "回环" in resp.text or "内网" in resp.text

            resp = await _post_provider(client, "http://127.0.0.1:6333/v1")
            assert resp.status_code == 400
    finally:
        reset_config_cache()

    async with session_factory() as session:
        rows = (
            (await session.execute(select(SecurityEvent).order_by(SecurityEvent.ts)))
            .scalars()
            .all()
        )
    assert len(rows) == 2
    assert all(r.event_type == "ssrf_rejected" for r in rows)
    assert all(r.severity == "high" and r.action == "deny" for r in rows)
    assert rows[0].resource == "http://169.254.169.254/latest/meta-data"
    assert rows[0].source_ip == "127.0.0.1"
    # 事件不含密钥
    assert all("sk-x" not in (r.metadata_json or "") for r in rows)


async def test_provider_api_allowlisted_local_address_accepted(
    tmp_path, monkeypatch, config_dict, session_factory
):
    config_dict["security"] = {"ssrf": {"allow_hosts": ["127.0.0.1:9999"]}}
    _isolate_writes(tmp_path, monkeypatch, config_dict)
    app = _make_app(config_dict, _mock_transport(), session_factory)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
            base_url="http://gw",
        ) as client:
            resp = await _post_provider(client, "http://127.0.0.1:9999/v1")
            assert resp.status_code == 200
            assert resp.json()["provider"] == "x-gw"
            # 同主机不同端口仍被拦
            resp = await _post_provider(client, "http://127.0.0.1:8888/v1", name="y-gw")
            assert resp.status_code == 400
    finally:
        reset_config_cache()
