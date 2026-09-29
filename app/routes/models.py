"""模型与 provider 接入：GET /v1/models、GET /api/models、密钥与添加 provider。"""

from __future__ import annotations

import asyncio
import os
import re
import threading
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.config import (
    ConfigError,
    ENV_FILE,
    GatewayConfig,
    ProviderConfig,
    get_config,
    load_user_overlay,
    provider_kind,
    reset_config_cache,
    save_user_overlay,
    validate_user_overlay,
)
from app.registry import Registry
from app.routes.health import check_provider

router = APIRouter(tags=["models"])

ALLOWED_ORIGIN_HOSTS = {"127.0.0.1", "localhost", "::1"}
_env_write_lock = threading.Lock()

PROVIDER_PRESETS: dict[str, str] = {
    # 看板"添加 Provider"预设：均提供 OpenAI 兼容端点，零适配直接转发
    "moonshot": "https://api.moonshot.cn/v1",
    "zhipu": "https://open.bigmodel.cn/api/paas/v4",
    "siliconflow": "https://api.siliconflow.cn/v1",
}
PROVIDER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")


@router.get("/v1/models")
async def list_models(request: Request) -> dict[str, Any]:
    registry = request.app.state.registry
    return {"object": "list", "data": registry.model_list()}


def _key_info(provider: ProviderConfig) -> dict[str, Any]:
    """密钥来源描述；永不返回密钥值本身。"""
    if provider.api_key:
        return {"source": "literal"}
    if provider.api_key_env:
        return {
            "source": "env",
            "name": provider.api_key_env,
            "configured": bool(os.environ.get(provider.api_key_env)),
        }
    return {"source": "none"}


def _model_entries(config: GatewayConfig) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for name, ref in config.models.items():
        fallbacks = [
            {"tag": key.split("@", 1)[1], "chain": chain}
            if "@" in key
            else {"tag": None, "chain": chain}
            for key, chain in config.fallbacks.items()
            if key == name or key.startswith(name + "@")
        ]
        fallbacks.sort(key=lambda item: (item["tag"] is not None, item["tag"] or ""))
        entries.append(
            {
                "id": name,
                "kind": provider_kind(config.providers[ref.provider]),
                "provider": ref.provider,
                "upstream": ref.upstream,
                "aliases": sorted(
                    alias
                    for alias, target in config.aliases.items()
                    if target == name
                ),
                "fallbacks": fallbacks,
            }
        )
    return entries


@router.get("/api/models")
async def model_catalog(request: Request) -> dict[str, Any]:
    """看板数据：模型目录（名称/本地或云/别名/回退链）+ provider 接入状态。"""
    config: GatewayConfig = request.app.state.config
    transport = getattr(request.app.state, "http_transport", None)

    names = list(config.providers)
    checks = await asyncio.gather(
        *(check_provider(config.providers[name], transport) for name in names)
    )
    providers = []
    for name, check in zip(names, checks):
        provider = config.providers[name]
        providers.append(
            {
                "name": name,
                "kind": provider_kind(provider),
                "base_url": provider.base_url,
                "key": _key_info(provider),
                "reachable": check["reachable"],
                "latency_ms": check["latency_ms"],
                "detail": check["detail"],
                "models": [
                    model
                    for model, ref in config.models.items()
                    if ref.provider == name
                ],
            }
        )
    return {
        "models": _model_entries(config),
        "providers": providers,
        "aliases": config.aliases,
    }


def _assert_local_origin(request: Request) -> None:
    """跨站防护：带 Origin 的请求必须来自本机（无 Origin = 非浏览器客户端，放行）。"""
    origin = request.headers.get("origin")
    if origin and (urlparse(origin).hostname or "").lower() not in ALLOWED_ORIGIN_HOSTS:
        raise HTTPException(status_code=403, detail="仅允许本机看板调用")


def _update_env_file(var_name: str, value: str) -> None:
    """更新 .env 中变量行（保留其他内容，文件不存在则创建）；先写临时文件再原子替换。"""
    pattern = re.compile(rf"^\s*{re.escape(var_name)}\s*=")
    lines = (
        ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.is_file() else []
    )
    replaced = False
    updated: list[str] = []
    for line in lines:
        if pattern.match(line):
            updated.append(f"{var_name}={value}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(f"{var_name}={value}")
    tmp = ENV_FILE.with_name(ENV_FILE.name + ".tmp")
    tmp.write_text("\n".join(updated) + "\n", encoding="utf-8")
    os.replace(tmp, ENV_FILE)


class KeyPayload(BaseModel):
    api_key: str


@router.post("/api/providers/{name}/key")
async def set_provider_key(
    name: str, payload: KeyPayload, request: Request
) -> dict[str, Any]:
    """保存 provider 密钥：更新 .env + 同步进程环境变量（下一个请求即生效）。

    防护：仅接受 JSON 媒体类型（阻断浏览器跨站简单请求）、Origin 必须为本机、
    值禁含控制字符（防 .env 行注入）；响应只返回复探测结果，永不回显密钥。
    """
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(status_code=415, detail="仅接受 application/json 请求")
    _assert_local_origin(request)

    config: GatewayConfig = request.app.state.config
    provider = config.providers.get(name)
    if provider is None:
        raise HTTPException(status_code=404, detail=f"provider 不存在: {name}")
    if not provider.api_key_env:
        raise HTTPException(
            status_code=400,
            detail=f"provider '{name}' 未声明 api_key_env（请先在 gateway.yaml 配置变量名）",
        )

    value = payload.api_key.strip()
    if not value:
        raise HTTPException(status_code=400, detail="密钥不能为空")
    if any(ord(ch) < 32 for ch in value):
        raise HTTPException(status_code=400, detail="密钥不能包含控制字符")

    with _env_write_lock:
        _update_env_file(provider.api_key_env, value)
    os.environ[provider.api_key_env] = value

    transport = getattr(request.app.state, "http_transport", None)
    check = await check_provider(provider, transport)
    return {"provider": name, "var": provider.api_key_env, **check}


def _env_var_name(name: str) -> str:
    """provider 名 → 密钥环境变量名（如 moonshot → MOONSHOT_API_KEY）。"""
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_") + "_API_KEY"


class ProviderPayload(BaseModel):
    preset: str
    name: str | None = None  # custom 时必填
    base_url: str | None = None  # custom 时必填
    api_key: str


def _reload_runtime(app: Any) -> GatewayConfig:
    """热重载：重建配置与注册表并更新 sampler 引用（路由层每请求现读 state）。"""
    reset_config_cache()
    new_config = get_config()
    app.state.config = new_config
    app.state.registry = Registry(new_config)
    sampler = getattr(app.state, "sampler", None)
    if sampler is not None:
        sampler.update_config(new_config)
    return new_config


@router.post("/api/providers")
async def create_provider(payload: ProviderPayload, request: Request) -> dict[str, Any]:
    """看板手动添加 provider：写 data/gateway.user.yaml + .env 密钥并热重载。

    新 provider 无需登记模型映射：请求 "provider/上游模型名" 前缀直通上游
    （如 moonshot/kimi-k2）。防护与密钥端点一致：仅 JSON 媒体类型、Origin 限
    本机、值禁控制字符、不回显密钥。
    """
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(status_code=415, detail="仅接受 application/json 请求")
    _assert_local_origin(request)

    preset = payload.preset.strip()
    if preset in PROVIDER_PRESETS:
        if (payload.name or "").strip() or (payload.base_url or "").strip():
            raise HTTPException(
                status_code=400, detail="仅 custom 预设可指定 name / base_url"
            )
        name, base_url = preset, PROVIDER_PRESETS[preset]
    elif preset == "custom":
        name = (payload.name or "").strip()
        if not PROVIDER_NAME_RE.match(name):
            raise HTTPException(
                status_code=400,
                detail="名称仅允许小写字母/数字/. _ -（1-32 位，如 my-gw）",
            )
        base_url = (payload.base_url or "").strip().rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=400, detail="Base URL 必须以 http:// 或 https:// 开头"
            )
    else:
        options = "、".join([*PROVIDER_PRESETS, "custom"])
        raise HTTPException(
            status_code=400, detail=f"未知预设 '{preset}'（可选: {options}）"
        )

    value = payload.api_key.strip()
    if not value:
        raise HTTPException(status_code=400, detail="密钥不能为空")
    if any(ord(ch) < 32 for ch in value):
        raise HTTPException(status_code=400, detail="密钥不能包含控制字符")

    config: GatewayConfig = request.app.state.config
    if name in config.providers:
        raise HTTPException(
            status_code=409,
            detail=f"provider '{name}' 已存在（在密钥列直接填/更新密钥即可）",
        )

    env_var = _env_var_name(name)
    user_raw = load_user_overlay()
    user_providers = user_raw.get("providers")
    user_providers = dict(user_providers) if isinstance(user_providers, dict) else {}
    user_providers[name] = {"base_url": base_url, "api_key_env": env_var}

    # 先校验合并结果，通过后才落盘（overlay / .env）
    candidate = {**user_raw, "providers": user_providers}
    try:
        validate_user_overlay(candidate)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    save_user_overlay(candidate)
    with _env_write_lock:
        _update_env_file(env_var, value)
    os.environ[env_var] = value

    try:
        new_config = _reload_runtime(request.app)
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"配置重载失败: {exc}") from exc

    transport = getattr(request.app.state, "http_transport", None)
    check = await check_provider(new_config.providers[name], transport)
    return {"provider": name, "var": env_var, "base_url": base_url, **check}
