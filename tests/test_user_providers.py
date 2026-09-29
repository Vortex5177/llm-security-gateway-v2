"""看板手动添加 Provider：overlay 合并/落盘、热重载、前缀路由与防护。"""

from __future__ import annotations

import os

import httpx
import pytest
import yaml

from app.config import (
    ConfigError,
    load_config,
    parse_config,
    reset_config_cache,
    validate_user_overlay,
)
from app.registry import Registry, UnknownModelError


def _mock_transport() -> httpx.MockTransport:
    """携带 Authorization（密钥已配）→ 200；否则连接失败。"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization"):
            return httpx.Response(200, json={"object": "list", "data": []})
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


def _write_main_yaml(tmp_path, config_dict):
    main_yaml = tmp_path / "gateway.yaml"
    main_yaml.write_text(yaml.safe_dump(config_dict), encoding="utf-8")
    return main_yaml


def _make_app(config_dict, transport):
    from app.main import create_app

    app = create_app()
    app.state.config = parse_config(config_dict)
    app.state.registry = Registry(app.state.config)
    app.state.http_transport = transport
    return app


# ---- 前缀路由 ---------------------------------------------------------------


def test_registry_prefix_routing(config_dict):
    registry = Registry(parse_config(config_dict))

    resolved = registry.resolve("deepseek/deepseek-reasoner")
    assert (resolved.provider, resolved.upstream) == ("deepseek", "deepseek-reasoner")

    # 上游模型名自带斜杠（如 SiliconFlow 的 Qwen/Qwen3-8B）按首个斜杠切分
    resolved = registry.resolve("local-vllm/Qwen/Qwen3-8B")
    assert (resolved.provider, resolved.upstream) == ("local-vllm", "Qwen/Qwen3-8B")

    # 已登记模型精确匹配优先于前缀解析
    assert registry.resolve("deepseek-chat").provider == "deepseek"

    with pytest.raises(UnknownModelError):
        registry.resolve("nope/some-model")
    with pytest.raises(UnknownModelError):
        registry.resolve("deepseek/")  # 前缀后没有模型名


# ---- overlay 加载与合并 -----------------------------------------------------


def test_load_config_merges_user_overlay(tmp_path, monkeypatch, config_dict):
    import app.config as config_module

    main_yaml = _write_main_yaml(tmp_path, config_dict)
    overlay = tmp_path / "gateway.user.yaml"
    overlay.write_text(
        yaml.safe_dump(
            {
                "providers": {
                    "moonshot": {
                        "base_url": "https://api.moonshot.cn/v1",
                        "api_key_env": "MOONSHOT_API_KEY",
                    },
                    "deepseek": {  # 与主配置同名：主配置优先
                        "base_url": "https://hijacked.example/v1",
                        "api_key_env": "HIJACK",
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "USER_CONFIG_PATH", overlay)

    cfg = load_config(main_yaml)
    assert cfg.providers["moonshot"].base_url == "https://api.moonshot.cn/v1"
    assert cfg.providers["moonshot"].api_key_env == "MOONSHOT_API_KEY"
    assert cfg.providers["deepseek"].base_url == "https://api.deepseek.com/v1"
    assert cfg.providers["deepseek"].api_key_env == "DEEPSEEK_API_KEY"

    # overlay 不存在时行为不变
    monkeypatch.setattr(config_module, "USER_CONFIG_PATH", tmp_path / "absent.yaml")
    cfg = load_config(main_yaml)
    assert "moonshot" not in cfg.providers


def test_validate_user_overlay(tmp_path, monkeypatch, config_dict):
    main_yaml = _write_main_yaml(tmp_path, config_dict)
    monkeypatch.setenv("GATEWAY_CONFIG", str(main_yaml))

    validate_user_overlay(
        {
            "providers": {
                "ok": {
                    "base_url": "https://x.example/v1",
                    "api_key_env": "X_API_KEY",
                }
            }
        }
    )  # 合法条目：不抛异常

    with pytest.raises(ConfigError):
        validate_user_overlay({"providers": {"broken": {"api_key_env": "X_API_KEY"}}})


# ---- POST /api/providers ----------------------------------------------------


async def test_create_provider_preset_hot_reload(tmp_path, monkeypatch, config_dict):
    import app.config as config_module
    import app.routes.models as models_module

    main_yaml = _write_main_yaml(tmp_path, config_dict)
    monkeypatch.setenv("GATEWAY_CONFIG", str(main_yaml))
    monkeypatch.setattr(
        config_module, "USER_CONFIG_PATH", tmp_path / "gateway.user.yaml"
    )
    monkeypatch.setattr(models_module, "ENV_FILE", tmp_path / ".env")
    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)

    app = _make_app(config_dict, _mock_transport())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gw"
        ) as client:
            resp = await client.post(
                "/api/providers", json={"preset": "moonshot", "api_key": "sk-moon-1"}
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "moonshot"
        assert body["var"] == "MOONSHOT_API_KEY"
        assert body["reachable"] is True  # 保存后复探测：带密钥请求被 mock 放行
        assert "sk-moon-1" not in resp.text  # 密钥值绝不外泄

        overlay = yaml.safe_load(
            (tmp_path / "gateway.user.yaml").read_text(encoding="utf-8")
        )
        assert overlay["providers"]["moonshot"] == {
            "base_url": "https://api.moonshot.cn/v1",
            "api_key_env": "MOONSHOT_API_KEY",
        }
        env_text = (tmp_path / ".env").read_text(encoding="utf-8")
        assert "MOONSHOT_API_KEY=sk-moon-1" in env_text
        assert os.environ["MOONSHOT_API_KEY"] == "sk-moon-1"

        # 热重载：无需重启即可路由（前缀直通）
        assert "moonshot" in app.state.config.providers
        resolved = app.state.registry.resolve("moonshot/kimi-k2")
        assert (resolved.provider, resolved.upstream) == ("moonshot", "kimi-k2")
    finally:
        reset_config_cache()


async def test_create_provider_custom_and_rejects(tmp_path, monkeypatch, config_dict):
    import app.config as config_module
    import app.routes.models as models_module

    main_yaml = _write_main_yaml(tmp_path, config_dict)
    monkeypatch.setenv("GATEWAY_CONFIG", str(main_yaml))
    monkeypatch.setattr(
        config_module, "USER_CONFIG_PATH", tmp_path / "gateway.user.yaml"
    )
    monkeypatch.setattr(models_module, "ENV_FILE", tmp_path / ".env")

    app = _make_app(config_dict, _mock_transport())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gw"
        ) as client:
            # custom 成功：变量名由名称生成
            resp = await client.post(
                "/api/providers",
                json={
                    "preset": "custom",
                    "name": "my-gw",
                    "base_url": "http://127.0.0.1:9999/v1",
                    "api_key": "sk-custom",
                },
            )
            assert resp.status_code == 200
            assert resp.json()["var"] == "MY_GW_API_KEY"
            assert os.environ["MY_GW_API_KEY"] == "sk-custom"

            overlay = yaml.safe_load(
                (tmp_path / "gateway.user.yaml").read_text(encoding="utf-8")
            )
            assert overlay["providers"]["my-gw"]["base_url"] == "http://127.0.0.1:9999/v1"

            # 重名（overlay 内已有 / 主配置已有）
            resp = await client.post(
                "/api/providers",
                json={
                    "preset": "custom",
                    "name": "my-gw",
                    "base_url": "http://127.0.0.1:1/v1",
                    "api_key": "sk-x",
                },
            )
            assert resp.status_code == 409
            resp = await client.post(
                "/api/providers",
                json={
                    "preset": "custom",
                    "name": "deepseek",
                    "base_url": "http://127.0.0.1:1/v1",
                    "api_key": "sk-x",
                },
            )
            assert resp.status_code == 409

            # 非法输入：未知预设 / 名称非法 / URL 非法 / 空密钥 / 控制字符
            for bad in (
                {"preset": "deepseek", "api_key": "sk-x"},
                {"preset": "moonshot", "api_key": "sk-x", "name": "x"},
                {
                    "preset": "custom",
                    "name": "Bad Name",
                    "base_url": "http://x/v1",
                    "api_key": "sk-x",
                },
                {
                    "preset": "custom",
                    "name": "ok-name",
                    "base_url": "ftp://x/v1",
                    "api_key": "sk-x",
                },
                {"preset": "moonshot", "api_key": "   "},
                {"preset": "moonshot", "api_key": "bad\nnewline"},
            ):
                resp = await client.post("/api/providers", json=bad)
                assert resp.status_code == 400, bad

        # 拒绝路径不落盘
        overlay = yaml.safe_load(
            (tmp_path / "gateway.user.yaml").read_text(encoding="utf-8")
        )
        assert set(overlay["providers"]) == {"my-gw"}
        env_text = (tmp_path / ".env").read_text(encoding="utf-8")
        assert "sk-x" not in env_text
    finally:
        reset_config_cache()
        os.environ.pop("MY_GW_API_KEY", None)


async def test_create_provider_guards(tmp_path, monkeypatch, config_dict):
    import app.config as config_module
    import app.routes.models as models_module

    main_yaml = _write_main_yaml(tmp_path, config_dict)
    monkeypatch.setenv("GATEWAY_CONFIG", str(main_yaml))
    monkeypatch.setattr(
        config_module, "USER_CONFIG_PATH", tmp_path / "gateway.user.yaml"
    )
    monkeypatch.setattr(models_module, "ENV_FILE", tmp_path / ".env")

    app = _make_app(config_dict, _mock_transport())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gw"
        ) as client:
            # 浏览器跨站"简单请求"（text/plain + JSON 字符串）被拒：
            # FastAPI 在 body 解析层先拒（422）；端点内另有 415 媒体类型校验兜底
            resp = await client.post(
                "/api/providers",
                content=b'{"preset": "moonshot", "api_key": "sk-csrf"}',
                headers={"Content-Type": "text/plain"},
            )
            assert resp.status_code in (415, 422)

            # 外部 Origin 被拒
            resp = await client.post(
                "/api/providers",
                json={"preset": "moonshot", "api_key": "sk-evil"},
                headers={"Origin": "https://evil.example"},
            )
            assert resp.status_code == 403

        # 任何拒绝路径都不落盘
        assert not (tmp_path / "gateway.user.yaml").exists()
        assert not (tmp_path / ".env").exists()
    finally:
        reset_config_cache()
