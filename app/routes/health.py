"""GET /health：存活 + 各 provider 可达性（探测逻辑复用给 /api/models）。"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from fastapi import APIRouter, Request

from app.config import ProviderConfig, resolve_api_key

router = APIRouter(tags=["health"])

CHECK_TIMEOUT_SECONDS = 3.0


async def check_provider(
    provider: ProviderConfig, transport: httpx.AsyncBaseTransport | None = None
) -> dict[str, Any]:
    """探测单个 provider：密钥缺失 → 直接标注，不发网络请求。"""
    key = resolve_api_key(provider)
    if provider.api_key_env and key is None:
        return {
            "reachable": False,
            "latency_ms": None,
            "detail": f"密钥未配置（环境变量 {provider.api_key_env} 缺失）",
        }
    url = provider.base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=CHECK_TIMEOUT_SECONDS, transport=transport
        ) as client:
            resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return {"reachable": False, "latency_ms": None, "detail": f"不可达: {exc}"}
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    if resp.status_code < 400:
        return {
            "reachable": True,
            "latency_ms": latency_ms,
            "detail": f"HTTP {resp.status_code}",
        }
    detail = f"HTTP {resp.status_code}"
    if resp.status_code in (401, 403):
        detail += "（认证失败）"
    return {"reachable": False, "latency_ms": latency_ms, "detail": detail}


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    config = request.app.state.config
    transport = getattr(request.app.state, "http_transport", None)
    names = list(config.providers)
    checks = await asyncio.gather(
        *(check_provider(config.providers[name], transport) for name in names)
    )
    return {"status": "ok", "providers": dict(zip(names, checks))}