"""API Key 管理端点（/api/keys）：创建/列表/禁用。

鉴权开启：仅 admin；鉴权关闭：回退本机 Origin 校验（引导场景）。
明文 key 仅在创建响应中返回一次，此后列表只显示元信息。
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import audit, auth

router = APIRouter(tags=["keys"])


class CreateKeyPayload(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    role: str = auth.ROLE_USER
    allowed_models: list[str] | None = None  # None = ["*"]
    rpm_limit: int | None = Field(default=None, ge=1)
    burst: int | None = Field(default=None, ge=1)


def _key_view(row: Any) -> dict[str, Any]:
    try:
        allowed = json.loads(row.allowed_models or '["*"]')
    except ValueError:
        allowed = []
    return {
        "name": row.name,
        "role": row.role,
        "allowed_models": allowed,
        "rpm_limit": row.rpm_limit,
        "burst": row.burst,
        "disabled": row.disabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
    }


@router.post("/api/keys", status_code=201)
async def create_api_key(payload: CreateKeyPayload, request: Request) -> dict[str, Any]:
    result = await auth.require_admin_or_local_origin(request)
    name = payload.name.strip()
    if not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise HTTPException(status_code=400, detail="名称不能为空或包含控制字符")
    if payload.role not in auth.ROLES:
        raise HTTPException(
            status_code=400, detail=f"未知角色（可选: {'/'.join(auth.ROLES)}）"
        )
    if payload.allowed_models is not None:
        if not payload.allowed_models or any(
            not isinstance(m, str) or not m.strip() for m in payload.allowed_models
        ):
            raise HTTPException(status_code=400, detail="allowed_models 必须为非空模型名列表")
        payload.allowed_models = [m.strip() for m in payload.allowed_models]

    session_factory = getattr(request.app.state, "session_factory", None)
    try:
        plaintext, row = await auth.create_key(
            session_factory,
            name=name,
            role=payload.role,
            allowed_models=payload.allowed_models,
            rpm_limit=payload.rpm_limit,
            burst=payload.burst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await audit.emit_event(
        session_factory,
        event_type=audit.EVENT_KEY_CREATED,
        severity="info",
        action="allow",
        key=result.key,
        source_ip=audit.client_ip(request),
        resource=name,
        metadata={"role": payload.role, "allowed_models": payload.allowed_models or ["*"]},
    )
    return {**_key_view(row), "api_key": plaintext}


@router.get("/api/keys")
async def list_api_keys(request: Request) -> dict[str, Any]:
    await auth.require_admin_or_local_origin(request)
    session_factory = getattr(request.app.state, "session_factory", None)
    rows = await auth.list_keys(session_factory)
    return {"keys": [_key_view(row) for row in rows]}


@router.post("/api/keys/{name}/disable")
async def disable_api_key(name: str, request: Request) -> dict[str, Any]:
    result = await auth.require_admin_or_local_origin(request)
    session_factory = getattr(request.app.state, "session_factory", None)
    target = next((r for r in await auth.list_keys(session_factory) if r.name == name), None)
    if target is None:
        raise HTTPException(status_code=404, detail=f"key 不存在: {name}")
    if result.key is not None and result.key.key_hash == target.key_hash:
        raise HTTPException(status_code=400, detail="不能禁用正在使用的 key")
    row = await auth.disable_key(session_factory, name)
    await audit.emit_event(
        session_factory,
        event_type=audit.EVENT_KEY_DISABLED,
        severity="info",
        action="allow",
        key=result.key,
        source_ip=audit.client_ip(request),
        resource=name,
    )
    return _key_view(row)
