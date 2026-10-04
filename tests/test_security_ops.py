"""安全运营 API：/api/security/events、/summary、/verify 与角色守卫。"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import audit, auth
from app.config import parse_config
from app.models import Base
from app.registry import Registry


@pytest.fixture()
async def session_factory(tmp_path):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _seed(session_factory) -> None:
    samples = [
        ("auth_failure", "low", "deny", None),
        ("pii_detection", "high", "redact", "pii.phone"),
        ("pii_detection", "high", "audit", "pii.email"),
        ("secret_detection", "critical", "block", "secret.jwt"),
        ("prompt_injection", "medium", "audit", "injection.ignore_previous_en"),
    ]
    for event_type, severity, action, rule_id in samples:
        await audit.emit_event(
            session_factory,
            event_type=event_type,
            severity=severity,
            action=action,
            rule_id=rule_id,
            source_ip="127.0.0.1",
        )


def _make_app(config_dict, session_factory):
    from app.main import create_app

    app = create_app()
    app.state.config = parse_config(config_dict)
    app.state.registry = Registry(app.state.config)
    app.state.session_factory = session_factory
    app.state.security_engine = None
    return app


async def _client(app):
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://gw")


async def test_events_filtering(config_dict, session_factory):
    await _seed(session_factory)
    async with await _client(_make_app(config_dict, session_factory)) as client:
        resp = await client.get("/api/security/events")
        assert resp.status_code == 200
        assert len(resp.json()["events"]) == 5

        resp = await client.get("/api/security/events", params={"severity": "high"})
        assert {e["severity"] for e in resp.json()["events"]} == {"high"}

        resp = await client.get("/api/security/events", params={"event_type": "pii_detection"})
        assert len(resp.json()["events"]) == 2

        resp = await client.get("/api/security/events", params={"rule_id": "pii.phone"})
        assert [e["rule_id"] for e in resp.json()["events"]] == ["pii.phone"]

        resp = await client.get("/api/security/events", params={"limit": 2})
        assert len(resp.json()["events"]) == 2


async def test_events_key_name_filtering(config_dict, session_factory):
    from types import SimpleNamespace

    await _seed(session_factory)  # 5 条：seed 均无 key 归属（key_name 为 NULL）
    await audit.emit_event(
        session_factory,
        event_type="pii_detection",
        severity="high",
        action="block",
        rule_id="pii.phone",
        key=SimpleNamespace(name="b-cheng"),  # emit_event 只读 key.name
        source_ip="192.168.1.23",
    )
    async with await _client(_make_app(config_dict, session_factory)) as client:
        resp = await client.get(
            "/api/security/events", params={"key_name": "b-cheng"}
        )
        assert resp.status_code == 200
        events = resp.json()["events"]
        assert [e["key_name"] for e in events] == ["b-cheng"]

        resp = await client.get("/api/security/events", params={"key_name": "-"})
        events = resp.json()["events"]
        assert len(events) == 5
        assert all(e["key_name"] is None for e in events)

        resp = await client.get("/api/security/events")
        assert len(resp.json()["events"]) == 6  # 不筛 = 全部


async def test_summary_aggregates(config_dict, session_factory):
    await _seed(session_factory)
    async with await _client(_make_app(config_dict, session_factory)) as client:
        resp = await client.get("/api/security/summary", params={"days": 7})
        assert resp.status_code == 200
        data = resp.json()
        assert data["events_total"] == 5
        assert data["high_risk"] == 3  # high×2 + critical×1
        assert data["blocked"] == 2  # block×1 + deny×1
        assert data["redacted"] == 1
        assert data["audit_only"] == 2
        assert data["by_type"]["pii_detection"] == 2
        assert data["by_severity"]["critical"] == 1
        assert data["top_rules"][0]["rule_id"].startswith(("pii.", "secret.", "injection."))
        assert len(data["recent"]) == 5


async def test_verify_endpoint_ok(config_dict, session_factory):
    await _seed(session_factory)
    async with await _client(_make_app(config_dict, session_factory)) as client:
        resp = await client.get("/api/security/verify")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert resp.json()["checked"] == 5


async def test_security_apis_require_admin_when_auth_enabled(config_dict, session_factory):
    config_dict["server"]["auth"] = {"enabled": True}
    app = _make_app(config_dict, session_factory)
    user_plain, _ = await auth.create_key(session_factory, name="u1", role="user")
    admin_plain, _ = await auth.create_key(session_factory, name="a1", role="admin")
    async with await _client(app) as client:
        assert (await client.get("/api/security/events")).status_code == 401
        resp = await client.get(
            "/api/security/events", headers={"Authorization": f"Bearer {user_plain}"}
        )
        assert resp.status_code == 403
        resp = await client.get(
            "/api/security/events", headers={"Authorization": f"Bearer {admin_plain}"}
        )
        assert resp.status_code == 200
