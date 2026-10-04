"""统一安全事件：所有安全行为（鉴权/限流/越权/SSRF/内容检测）落 security_events 表。

设计要点：
- emit_event 永不阻断请求路径：任何落库异常都被吞掉（安全事件丢失优于业务中断）；
- 事件只记录必要字段：不记录完整 API Key（只记 key 名称）、不记录敏感内容原文；
- 防篡改哈希链（M3 启用）：每条事件 hash = sha256(prev_hash + canonical_json)，
  写入在全局锁内串行（保证链序）；verify_chain 可校验整条链并定位篡改点。
  已知边界：链尾删除不可检测（需外部 checkpoint，列为 future work）。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import SessionLocal
from app.models import ApiKey, SecurityEvent

# 事件类型（M1；M2 起追加 pii_detection / secret_detection / prompt_injection 等）
EVENT_AUTH_FAILURE = "auth_failure"
EVENT_RATE_LIMIT = "rate_limit_exceeded"
EVENT_MODEL_DENIED = "model_permission_denied"
EVENT_SSRF_REJECTED = "ssrf_rejected"
EVENT_KEY_CREATED = "key_created"
EVENT_KEY_DISABLED = "key_disabled"
EVENT_KEY_ENABLED = "key_enabled"
EVENT_PROVIDER_CREATED = "provider_created"

SEVERITIES = ("info", "low", "medium", "high", "critical")


async def emit_event(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    *,
    event_type: str,
    severity: str,
    action: str,
    key: ApiKey | None = None,
    source_ip: str | None = None,
    rule_id: str | None = None,
    request_id: str | None = None,
    resource: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """写入一条安全事件（best-effort，异常静默）。"""
    if severity not in SEVERITIES:
        raise ValueError(f"未知 severity: {severity}")
    factory = session_factory or SessionLocal
    try:
        async with _chain_lock:
            async with factory() as session:
                last_hash = (
                    await session.execute(
                        select(SecurityEvent.hash)
                        .where(SecurityEvent.hash.is_not(None))
                        .order_by(text("rowid DESC"))
                        .limit(1)
                    )
                ).scalar_one_or_none()
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex,
                    ts=datetime.now(timezone.utc),
                    key_name=key.name if key is not None else None,
                    source_ip=source_ip,
                    event_type=event_type,
                    severity=severity,
                    rule_id=rule_id,
                    action=action,
                    request_id=request_id,
                    resource=resource,
                    metadata_json=(
                        json.dumps(metadata, ensure_ascii=False) if metadata else None
                    ),
                    prev_hash=last_hash if last_hash is not None else GENESIS_HASH,
                )
                event.hash = _chain_hash(event)
                session.add(event)
                await session.commit()
    except Exception:
        pass  # 事件落库失败不影响请求路径


def client_ip(request: Any) -> str | None:
    """从 FastAPI Request 提取来源 IP（无代理头信任，与 service.py 同原则）。"""
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client is not None else None


# ------------------------------------------------------------ 防篡改哈希链

_chain_lock = asyncio.Lock()
GENESIS_HASH = ""


def _canonical_ts(ts: datetime) -> str:
    """SQLite 回读为 naive datetime（视为 UTC）；写入侧为 aware——统一归一为 UTC ISO。"""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.isoformat()


def _canonical_payload(event: SecurityEvent) -> str:
    data = {
        "event_id": event.event_id,
        "ts": _canonical_ts(event.ts),
        "key_name": event.key_name,
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "severity": event.severity,
        "rule_id": event.rule_id,
        "action": event.action,
        "request_id": event.request_id,
        "resource": event.resource,
        "metadata_json": event.metadata_json,
        "prev_hash": event.prev_hash,
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _chain_hash(event: SecurityEvent) -> str:
    return hashlib.sha256(_canonical_payload(event).encode("utf-8")).hexdigest()


async def verify_chain(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> dict[str, Any]:
    """校验整条哈希链；返回 {ok, checked, legacy, first_bad, reason?}。

    hash 为 NULL 的历史行（M1/M2 遗留）不参与链，计为 legacy；
    篡改内容（hash 不匹配）与删行（prev_hash 链接断裂）都会定位到 first_bad。
    """
    factory = session_factory or SessionLocal
    async with factory() as session:
        rows = (
            (await session.execute(select(SecurityEvent).order_by(text("rowid"))))
            .scalars()
            .all()
        )
    prev = GENESIS_HASH
    checked = legacy = 0
    for row in rows:
        if row.hash is None:
            legacy += 1
            continue  # 遗留行不影响后续链行（写入时 prev 取自最后一条有 hash 的行）
        checked += 1
        if row.prev_hash != prev:
            return {
                "ok": False,
                "checked": checked,
                "legacy": legacy,
                "first_bad": row.event_id,
                "reason": "prev_hash 链接断裂（可能存在删行）",
            }
        if _chain_hash(row) != row.hash:
            return {
                "ok": False,
                "checked": checked,
                "legacy": legacy,
                "first_bad": row.event_id,
                "reason": "内容哈希不匹配（记录被篡改）",
            }
        prev = row.hash
    return {"ok": True, "checked": checked, "legacy": legacy, "first_bad": None}


if __name__ == "__main__":  # python -m app.audit verify
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        outcome = asyncio.run(verify_chain())
        print(json.dumps(outcome, ensure_ascii=False, indent=2))
        sys.exit(0 if outcome["ok"] else 1)
    print("用法: python -m app.audit verify")
    sys.exit(2)
