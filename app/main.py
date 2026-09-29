"""FastAPI 组装与应用入口。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_config
from app.db import init_db
from app.registry import Registry
from app.routes import chat, health, models, service, stats
from app.sampler import Sampler
from app.vllm_service import VllmService


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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
    application.include_router(service.router)
    application.include_router(health.router)
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