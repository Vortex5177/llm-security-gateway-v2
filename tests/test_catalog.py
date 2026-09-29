"""GET /api/models：模型目录 + provider 接入状态（密钥来源 / 本地或云 / 连通性）。"""

from __future__ import annotations

import httpx

from app.config import parse_config


def _mock_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "localhost":
            return httpx.Response(200, json={"object": "list", "data": []})
        if request.url.host == "auth-fail.example":
            return httpx.Response(401, json={"error": "unauthorized"})
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


def _client(config_dict, transport) -> httpx.AsyncClient:
    from app.main import create_app
    from app.registry import Registry

    app = create_app()
    app.state.config = parse_config(config_dict)
    app.state.registry = Registry(app.state.config)
    app.state.http_transport = transport
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    )


def _extended_config(config_dict) -> dict:
    config_dict["providers"]["dashscope"] = {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "DASHSCOPE_API_KEY",
    }
    config_dict["providers"]["with-bad-key"] = {
        "base_url": "https://auth-fail.example/v1",
        "api_key_env": "BAD_KEY",
    }
    config_dict["models"]["qwen-plus"] = {
        "provider": "dashscope",
        "upstream": "qwen-plus",
    }
    config_dict["fallbacks"]["qwen3-1.7b@scan"] = ["qwen-plus"]
    return config_dict


async def test_catalog_models_and_providers(config_dict, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.setenv("BAD_KEY", "sk-secret-bad")
    config = _extended_config(config_dict)

    async with _client(config, _mock_transport()) as client:
        resp = await client.get("/api/models")
    assert resp.status_code == 200
    body = resp.json()

    models = {m["id"]: m for m in body["models"]}
    assert models["qwen3-1.7b"]["kind"] == "local"
    assert models["qwen3-1.7b"]["provider"] == "local-vllm"
    assert models["qwen3-1.7b"]["aliases"] == ["default"]
    assert models["qwen3-1.7b"]["fallbacks"] == [
        {"tag": None, "chain": ["deepseek-chat"]},
        {"tag": "scan", "chain": ["qwen-plus"]},
    ]
    assert models["deepseek-chat"]["kind"] == "cloud"
    assert models["deepseek-chat"]["fallbacks"] == []
    assert models["qwen-plus"]["provider"] == "dashscope"
    assert body["aliases"] == {"default": "qwen3-1.7b"}

    providers = {p["name"]: p for p in body["providers"]}
    assert providers["local-vllm"]["kind"] == "local"
    assert providers["local-vllm"]["reachable"] is True
    assert providers["local-vllm"]["latency_ms"] is not None
    assert providers["local-vllm"]["models"] == ["qwen3-1.7b"]
    assert providers["local-vllm"]["key"] == {"source": "literal"}

    assert providers["deepseek"]["kind"] == "cloud"
    assert providers["deepseek"]["key"] == {
        "source": "env",
        "name": "DEEPSEEK_API_KEY",
        "configured": False,
    }
    assert providers["deepseek"]["reachable"] is False
    assert "密钥未配置" in providers["deepseek"]["detail"]
    assert providers["dashscope"]["reachable"] is False

    assert providers["with-bad-key"]["reachable"] is False
    assert "认证失败" in providers["with-bad-key"]["detail"]

    # 密钥值（字面量或环境变量）绝不外泄
    assert "EMPTY" not in resp.text
    assert "sk-secret-bad" not in resp.text


async def test_catalog_network_failure_detail(config_dict, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-x")
    config_dict["providers"]["deepseek"]["base_url"] = "https://nowhere.example/v1"

    async with _client(config_dict, _mock_transport()) as client:
        resp = await client.get("/api/models")
    provider = {p["name"]: p for p in resp.json()["providers"]}["deepseek"]
    assert provider["reachable"] is False
    assert "不可达" in provider["detail"]
    assert "sk-x" not in resp.text


async def test_dashboard_serves_catalog_panel():
    from app.main import create_app

    app = create_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        resp = await client.get("/")
    assert resp.status_code == 200
    assert "可切换模型" in resp.text
    assert "Provider 接入" in resp.text
