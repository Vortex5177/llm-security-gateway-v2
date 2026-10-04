"""安全运营 API：安全事件查询 / 聚合摘要 / 审计链校验（仅 admin 或本机看板）。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Query, Request
from sqlalchemy import func, select

from app import audit, auth
from app.db import SessionLocal
from app.models import RequestLog, SecurityEvent, iso_z
from app.security import policy as policy_mod

router = APIRouter(tags=["security"])


def _factory(request: Request):
    return getattr(request.app.state, "session_factory", None) or SessionLocal


def _event_view(row: SecurityEvent, *, with_metadata: bool = True) -> dict[str, Any]:
    view: dict[str, Any] = {
        "event_id": row.event_id,
        "ts": iso_z(row.ts),
        "event_type": row.event_type,
        "severity": row.severity,
        "action": row.action,
        "rule_id": row.rule_id,
        "key_name": row.key_name,
        "source_ip": row.source_ip,
        "request_id": row.request_id,
        "resource": row.resource,
    }
    if with_metadata and row.metadata_json:
        try:
            view["metadata"] = json.loads(row.metadata_json)
        except ValueError:
            view["metadata"] = None
    return view


@router.get("/api/security/events")
async def list_security_events(
    request: Request,
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    # "-" 哨兵 = 无归属事件（key_name 为 NULL：auth_failure/ssrf 等系统侧）
    key_name: str | None = Query(default=None),
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    await auth.require_admin_or_local_origin(request)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    async with _factory(request)() as session:
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.ts >= since)
            .order_by(SecurityEvent.ts.desc())
            .limit(limit)
        )
        if severity:
            stmt = stmt.where(SecurityEvent.severity == severity)
        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if rule_id:
            stmt = stmt.where(SecurityEvent.rule_id == rule_id)
        if key_name == "-":
            stmt = stmt.where(SecurityEvent.key_name.is_(None))
        elif key_name:
            stmt = stmt.where(SecurityEvent.key_name == key_name)
        rows = (await session.execute(stmt)).scalars().all()
    return {"events": [_event_view(row) for row in rows], "days": days, "limit": limit}


@router.get("/api/security/summary")
async def security_summary(
    request: Request, days: int = Query(default=7, ge=1, le=90)
) -> dict[str, Any]:
    await auth.require_admin_or_local_origin(request)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    async with _factory(request)() as session:
        def grouped(column):
            return session.execute(
                select(column, func.count())
                .where(SecurityEvent.ts >= since)
                .group_by(column)
            )

        by_type = dict((await grouped(SecurityEvent.event_type)).all())
        by_severity = dict((await grouped(SecurityEvent.severity)).all())
        by_action = dict((await grouped(SecurityEvent.action)).all())
        total = sum(by_type.values())

        top_rules = (
            await session.execute(
                select(SecurityEvent.rule_id, func.count().label("n"))
                .where(SecurityEvent.ts >= since, SecurityEvent.rule_id.is_not(None))
                .group_by(SecurityEvent.rule_id)
                .order_by(func.count().desc())
                .limit(8)
            )
        ).all()

        top_sources = (
            await session.execute(
                select(SecurityEvent.source_ip, func.count().label("n"))
                .where(SecurityEvent.ts >= since, SecurityEvent.source_ip.is_not(None))
                .group_by(SecurityEvent.source_ip)
                .order_by(func.count().desc())
                .limit(5)
            )
        ).all()

        recent = (
            await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.ts >= since)
                .order_by(SecurityEvent.ts.desc())
                .limit(20)
            )
        ).scalars().all()

        requests_total = (
            await session.execute(
                select(func.count(RequestLog.id)).where(RequestLog.created_at >= since)
            )
        ).scalar_one()

    high_risk = sum(by_severity.get(s, 0) for s in ("high", "critical"))
    return {
        "days": days,
        "requests_total": requests_total,
        "events_total": total,
        "high_risk": high_risk,
        "blocked": by_action.get("block", 0) + by_action.get("deny", 0),
        "redacted": by_action.get("redact", 0),
        "audit_only": by_action.get("audit", 0),
        "by_type": by_type,
        "by_severity": by_severity,
        "by_action": by_action,
        "top_rules": [{"rule_id": r, "count": n} for r, n in top_rules],
        "top_sources": [{"source_ip": s, "count": n} for s, n in top_sources],
        "recent": [_event_view(row) for row in recent],
    }


@router.get("/api/security/verify")
async def verify_audit_chain(request: Request) -> dict[str, Any]:
    await auth.require_admin_or_local_origin(request)
    return await audit.verify_chain(_factory(request))


@router.get("/api/security/policy")
async def security_policy_view(request: Request) -> dict[str, Any]:
    """当前生效的安全策略档位（启动时加载的那份；本机看板无需 admin）。"""
    await auth.require_admin_or_local_origin(request)
    engine = getattr(request.app.state, "security_engine", None)
    policy = getattr(engine, "policy", None)
    if policy is None:
        return {
            "enabled": False,
            "source": None,
            "mode": "off",
            "default_action": None,
            "rules": 0,
            "actions": {},
        }
    actions: dict[str, int] = {}
    for rule in policy.rules:
        if not rule.enabled:
            continue
        act = policy_mod.rule_action(policy, rule)
        actions[act] = actions.get(act, 0) + 1
    source = policy_mod.policy_source_path()
    try:
        source_str = str(source.relative_to(policy_mod.PROJECT_ROOT))
    except ValueError:
        source_str = str(source)
    return {
        "enabled": True,
        "source": source_str,
        # 有任何 block 动作即视为严格档（考卷密钥题只在严格档变绿）
        "mode": "strict" if actions.get("block", 0) > 0 else "audit",
        "default_action": policy.default_action,
        "rules": len(policy.rules),
        "actions": actions,
    }
