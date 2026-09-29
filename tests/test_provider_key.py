"""POST /api/providers/{name}/key：密钥写入 .env 并即时生效；含安全防护断言。"""

from __future__ import annotations

import os

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import parse_config
from app.models import Base


@pytest.fixture()
async def session_factory(tmp_path):
    """临时 DB：避免事件落库经 SessionLocal 兜底写入真实 gateway.db。"""
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _mock_transport() -> httpx.MockTransport:
    """携带 Authorization（密钥已配）→ 200；否则连接失败。"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization"):
            return httpx.Response(200, json={"object": "list", "data": []})
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


def _client(config_dict, transport, env_file, monkeypatch, session_factory) -> httpx.AsyncClient:
    import app.routes.models as models_module
    from app.main import create_app
    from app.registry import Registry

    monkeypatch.setattr(models_module, "ENV_FILE", env_file)
    app = create_app()
    app.state.config = parse_config(config_dict)
    app.state.registry = Registry(app.state.config)
    app.state.http_transport = transport
    app.state.session_factory = session_factory
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    )


async def test_save_key_writes_env_and_takes_effect(config_dict, tmp_path, monkeypatch, session_factory):
    env_file = tmp_path / ".env"
    env_file.write_text("# 既有注释\nDASHSCOPE_API_KEY=keep-me\n", encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    async with _client(config_dict, _mock_transport(), env_file, monkeypatch, session_factory) as client:
        resp = await client.post(
            "/api/providers/deepseek/key", json={"api_key": "sk-new-123"}
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "deepseek"
    assert body["var"] == "DEEPSEEK_API_KEY"
    assert body["reachable"] is True  # 保存后复探测：带密钥请求被 mock 放行

    content = env_file.read_text(encoding="utf-8")
    assert "DEEPSEEK_API_KEY=sk-new-123" in content
    assert "DASHSCOPE_API_KEY=keep-me" in content  # 其他行原样保留
    assert "# 既有注释" in content
    assert os.environ["DEEPSEEK_API_KEY"] == "sk-new-123"

    assert "sk-new-123" not in resp.text  # 密钥值绝不外泄


async def test_save_key_updates_existing_line(config_dict, tmp_path, monkeypatch, session_factory):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=old-key\nOTHER=1\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "old-key")

    async with _client(config_dict, _mock_transport(), env_file, monkeypatch, session_factory) as client:
        resp = await client.post(
            "/api/providers/deepseek/key", json={"api_key": "sk-rotated"}
        )
    assert resp.status_code == 200

    lines = env_file.read_text(encoding="utf-8").splitlines()
    assert "DEEPSEEK_API_KEY=sk-rotated" in lines
    assert "DEEPSEEK_API_KEY=old-key" not in lines
    assert "OTHER=1" in lines
    assert sum(1 for line in lines if line.startswith("DEEPSEEK_API_KEY=")) == 1


async def test_save_key_rejects_unknown_and_literal(config_dict, tmp_path, monkeypatch, session_factory):
    env_file = tmp_path / ".env"
    async with _client(config_dict, _mock_transport(), env_file, monkeypatch, session_factory) as client:
        resp = await client.post("/api/providers/nope/key", json={"api_key": "x"})
        assert resp.status_code == 404
        resp = await client.post("/api/providers/local-vllm/key", json={"api_key": "x"})
        assert resp.status_code == 400  # 字面量 provider 无 env 槽位

    assert not env_file.exists()  # 任何拒绝路径都不落盘


async def test_save_key_rejects_bad_values(config_dict, tmp_path, monkeypatch, session_factory):
    env_file = tmp_path / ".env"
    async with _client(config_dict, _mock_transport(), env_file, monkeypatch, session_factory) as client:
        for bad in ("", "   ", "sk-a\nDEEPSEEK_API_KEY=injected", "sk-\x00x"):
            resp = await client.post(
                "/api/providers/deepseek/key", json={"api_key": bad}
            )
            assert resp.status_code == 400, f"payload={bad!r}"
    assert not env_file.exists()


async def test_save_key_rejects_non_json_and_cross_origin(
    config_dict, tmp_path, monkeypatch, session_factory
):
    env_file = tmp_path / ".env"
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    async with _client(config_dict, _mock_transport(), env_file, monkeypatch, session_factory) as client:
        # 浏览器跨站"简单请求"（text/plain + JSON 字符串）必须被拒：
        # FastAPI 在 body 解析层先拒（422）；端点内另有 415 媒体类型校验兜底
        resp = await client.post(
            "/api/providers/deepseek/key",
            content=b'{"api_key": "sk-csrf"}',
            headers={"Content-Type": "text/plain"},
        )
        assert resp.status_code in (415, 422)
        # 外部 Origin 被拒
        resp = await client.post(
            "/api/providers/deepseek/key",
            json={"api_key": "sk-evil"},
            headers={"Origin": "https://evil.example"},
        )
        assert resp.status_code == 403
        # 本机 Origin 放行
        resp = await client.post(
            "/api/providers/deepseek/key",
            json={"api_key": "sk-local"},
            headers={"Origin": "http://127.0.0.1:4101"},
        )
        assert resp.status_code == 200

    content = env_file.read_text(encoding="utf-8")
    assert "sk-csrf" not in content
    assert "sk-evil" not in content
    assert "sk-local" in content
