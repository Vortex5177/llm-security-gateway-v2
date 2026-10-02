"""FastAPI 组装与应用入口。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_config
from app.db import init_db
from app.registry import Registry
from app.routes import chat, health, keys, models, security, service, stats
from app.sampler import Sampler
from app.vllm_service import VllmService
from app import auth
from app.security import engine as engine_mod
from app.security import policy as policy_mod

# 管理面 API（服务控制/密钥/安全运营）仅接受本机回环来源，外部一律 403；
# 数据面（/v1/* 聊天）对局域网开放；看板页面为公开壳子，数据全部经鉴权 API 加载。
_ADMIN_PATHS = ("/api/service", "/api/keys", "/api/security")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _guarded_admin_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _ADMIN_PATHS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    if app.state.config.server.auth.enabled:
        await auth.ensure_bootstrap_key(app.state.session_factory)
    sampler = Sampler(
        app.state.config,
        session_factory=app.state.session_factory,
        transport=app.state.http_transport,
    )
    app.state.sampler = sampler
    sampler.start()
    try:
        yield
    finally:
        await app.state.vllm_service.close()
        await sampler.stop()


def create_app() -> FastAPI:
    config = get_config()
    application = FastAPI(title="LLM Gateway", version="0.1.0", lifespan=lifespan)
    application.state.config = config
    application.state.registry = Registry(config)
    application.state.http_transport = None  # 测试可注入 httpx.MockTransport
    application.state.session_factory = None  # 测试可注入临时会话工厂
    application.state.sampler = None
    application.state.vllm_service = VllmService(config)
    policy = policy_mod.load_policy()
    application.state.security_engine = (
        engine_mod.SecurityEngine(policy) if policy and policy.enabled else None
    )

    @application.middleware("http")
    async def admin_loopback_guard(request: Request, call_next):
        """管理面物理边界：来源非本机回环的管理请求直接 403（key 泄露也无法触达）。"""
        if _guarded_admin_path(request.url.path):
            client_host = request.client.host if request.client else ""
            if client_host not in _LOOPBACK_HOSTS:
                return JSONResponse({"detail": "管理面仅限本机访问"}, status_code=403)
        return await call_next(request)

    # CORS：手机 App 网页内核（Chatbox 等）跨域调用必须读到响应头才能收下数据；
    # 放开 CORS 只影响浏览器读响应，真正的门仍是 API Key 鉴权 + 管理面回环隔离。
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(service.router)
    application.include_router(health.router)
    application.include_router(keys.router)
    application.include_router(security.router)
    application.include_router(models.router)
    application.include_router(chat.router)
    application.include_router(stats.router)
    static_dir = Path(__file__).resolve().parent.parent / "static"
    if static_dir.is_dir():
        # 仪表盘静态单页；必须最后挂载（路由按注册顺序匹配）
        application.mount(
            "/", StaticFiles(directory=static_dir, html=True), name="dashboard"
        )
    return application


app = create_app()