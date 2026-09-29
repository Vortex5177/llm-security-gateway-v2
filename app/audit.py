"""统一安全事件：所有安全行为（鉴权/限流/越权/SSRF/内容检测）落 security_events 表。

设计要点：
- emit_event 永不阻断请求路径：任何落库异常都被吞掉（安全事件丢失优于业务中断）；
- 事件只记录必要字段：不记录完整 API Key（只记 key 名称）、不记录敏感内容原文；
- prev_hash/hash 为 M3 哈希链预留，M1 写入恒为 None。
"""

from __future__ import annotations

import json
import uuid
from typing import Any

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
        async with factory() as session:
            session.add(
                SecurityEvent(
                    event_id=uuid.uuid4().hex,
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
                )
            )
            await session.commit()
    except Exception:
        pass  # 事件落库失败不影响请求路径


def client_ip(request: Any) -> str | None:
    """从 FastAPI Request 提取来源 IP（无代理头信任，与 service.py 同原则）。"""
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client is not None else None
