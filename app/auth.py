"""API Key 鉴权与 RBAC（DB 存 SHA-256 哈希，明文仅创建时返回一次）。

模型：
- 数据平面（/v1/*）：server.auth.enabled=true 时任何有效 key 可用；
  模型白名单按 key.allowed_models（["*"] 全开）在别名解析前对客户端请求名检查；
- 管理平面（/api/providers、/api/keys 等写接口）：admin 角色；
  鉴权关闭时回退为本机 Origin 校验（便于本机看板引导创建首把 key）。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import audit
from app.config import GatewayConfig
from app.db import SessionLocal
from app.models import ApiKey, utcnow

ROLE_ADMIN = "admin"
ROLE_DEVELOPER = "developer"
ROLE_USER = "user"
ROLES = (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_USER)

KEY_PREFIX = "gw_"
BOOTSTRAP_KEY_FILE = Path(__file__).resolve().parent.parent / "data" / "bootstrap_admin_key.txt"


def _detach(row: ApiKey) -> ApiKey:
    """会话外行副本（避免 DetachedInstanceError）"""
    return ApiKey(
        key_hash=row.key_hash,
        name=row.name,
        role=row.role,
        allowed_models=row.allowed_models,
        rpm_limit=row.rpm_limit,
        burst=row.burst,
        disabled=row.disabled,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
    )


# ------------------------------------------------------------ 密钥生成与哈希

def generate_api_key() -> tuple[str, str]:
    """生成 (明文, sha256 哈希)；明文仅此一次可见。"""
    plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, hash_key(plaintext)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# ------------------------------------------------------------ DB 操作

async def create_key(
    session_factory: async_sessionmaker[AsyncSession] | None,
    *,
    name: str,
    role: str,
    allowed_models: list[str] | None = None,
    rpm_limit: int | None = None,
    burst: int | None = None,
) -> tuple[str, ApiKey]:
    """创建 key；返回 (明文, 行)。name 重复抛 ValueError。"""
    if role not in ROLES:
        raise ValueError(f"未知角色: {role}（可选: {'/'.join(ROLES)}）")
    factory = session_factory or SessionLocal
    plaintext, key_hash = generate_api_key()
    row = ApiKey(
        key_hash=key_hash,
        name=name,
        role=role,
        allowed_models=json.dumps(allowed_models or ["*"], ensure_ascii=False),
        rpm_limit=rpm_limit,
        burst=burst,
    )
    async with factory() as session:
        existing = (
            await session.execute(select(ApiKey).where(ApiKey.name == name))
        ).scalar_one_or_none()
        if existing is not None:
            raise ValueError(f"key 名称已存在: {name}")
        session.add(row)
        await session.commit()
        await session.refresh(row)
        detached = _detach(row)
    return plaintext, detached


async def list_keys(
    session_factory: async_sessionmaker[AsyncSession] | None,
) -> list[ApiKey]:
    factory = session_factory or SessionLocal
    async with factory() as session:
        rows = (await session.execute(select(ApiKey).order_by(ApiKey.created_at))).scalars().all()
        return [_detach(r) for r in rows]


async def disable_key(
    session_factory: async_sessionmaker[AsyncSession] | None, name: str
) -> ApiKey | None:
    factory = session_factory or SessionLocal
    async with factory() as session:
        row = (
            await session.execute(select(ApiKey).where(ApiKey.name == name))
        ).scalar_one_or_none()
        if row is None:
            return None
        row.disabled = True
        await session.commit()
        return _detach(row)


# ------------------------------------------------------------ 请求鉴权

@dataclass
class AuthResult:
    ok: bool
    key: ApiKey | None = None
    error: str | None = None


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


async def authenticate(
    request: Request,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> AuthResult:
    """校验请求身份。鉴权关闭 → ok(key=None)；失败写 auth_failure 事件。"""
    config: GatewayConfig = request.app.state.config
    if not config.server.auth.enabled:
        return AuthResult(ok=True)

    factory = session_factory or getattr(request.app.state, "session_factory", None)
    token = _extract_bearer(request)
    reason: str | None = None
    row: ApiKey | None = None
    if token is None:
        reason = "缺少 Authorization: Bearer <api-key> 头"
    else:
        async with (factory or SessionLocal)() as session:
            row = (
                await session.execute(
                    select(ApiKey).where(ApiKey.key_hash == hash_key(token))
                )
            ).scalar_one_or_none()
            if row is None:
                reason = "API Key 无效"
            elif row.disabled:
                reason = "API Key 已被禁用"
                row = None
            else:
                row.last_used_at = utcnow()
                await session.commit()
                row = _detach(row)
    if reason is not None:
        await audit.emit_event(
            factory,
            event_type=audit.EVENT_AUTH_FAILURE,
            severity="low",
            action="deny",
            source_ip=audit.client_ip(request),
            resource=request.url.path,
            metadata={"reason": reason},
        )
        return AuthResult(ok=False, error=reason)
    return AuthResult(ok=True, key=row)


def key_allows_model(key: ApiKey, model: str) -> bool:
    """模型白名单检查（别名解析之前，对客户端请求名生效）。"""
    try:
        allowed = json.loads(key.allowed_models or '["*"]')
    except ValueError:
        return False
    return "*" in allowed or model in allowed


def require_admin(result: AuthResult) -> None:
    """管理端点角色检查（鉴权关闭时 key=None 视为本机放行）。"""
    if result.key is not None and result.key.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="该操作需要 admin 角色")


async def require_admin_or_local_origin(
    request: Request,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> AuthResult:
    """管理平面统一入口：鉴权开启要 admin key；鉴权关闭回退本机 Origin 校验。"""
    result = await authenticate(request, session_factory)
    if not result.ok:
        raise HTTPException(status_code=401, detail=result.error)
    config: GatewayConfig = request.app.state.config
    if config.server.auth.enabled:
        require_admin(result)
    else:
        # 与 models.py 的本机看板防护一致：带 Origin 必须本机
        from urllib.parse import urlparse

        origin = request.headers.get("origin")
        if origin and (urlparse(origin).hostname or "").lower() not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise HTTPException(status_code=403, detail="仅允许本机看板调用")
    return result


# ------------------------------------------------------------ 引导

async def ensure_bootstrap_key(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """鉴权开启且无任何 key 时，签发引导 admin key（仅一次，明文打印 + 落 data/）。"""
    factory = session_factory or SessionLocal
    async with factory() as session:
        count = len((await session.execute(select(ApiKey))).scalars().all())
    if count > 0:
        return
    plaintext, _row = await create_key(factory, name="bootstrap-admin", role=ROLE_ADMIN)
    BOOTSTRAP_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    BOOTSTRAP_KEY_FILE.write_text(
        plaintext + "\n# 引导 admin key（仅首次启动生成；泄露请立即在 /api/keys 禁用）\n",
        encoding="utf-8",
    )
    print("=" * 64)
    print("[gateway] 已生成引导 admin API Key（仅本次显示）：")
    print(f"  {plaintext}")
    print(f"  同时已写入 {BOOTSTRAP_KEY_FILE}（该文件不入库，请妥善保管）")
    print("=" * 64)
