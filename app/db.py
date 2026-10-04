"""异步引擎/会话；init_db（create_all）。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.models import Base

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "gateway.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH.as_posix()}"

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """建表（幂等）；并为已有库补齐后加列（create_all 不改既有表结构）。"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        try:
            await conn.execute(
                text("ALTER TABLE request_logs ADD COLUMN key_name VARCHAR(64)")
            )
        except OperationalError:
            pass  # 列已存在（新库由 create_all 直接建出；旧库重复启动）
        await conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_request_logs_key_name "
                "ON request_logs (key_name)"
            )
        )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI 依赖：提供一个自动关闭的会话。"""
    async with SessionLocal() as session:
        yield session
