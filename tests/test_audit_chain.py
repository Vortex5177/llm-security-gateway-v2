"""审计哈希链：链接正确性、篡改/删行检测、并发链序、遗留行兼容。"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import audit
from app.models import Base, SecurityEvent


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


async def _emit(factory, n: int, **kw) -> None:
    for i in range(n):
        await audit.emit_event(
            factory,
            event_type=kw.get("event_type", "pii_detection"),
            severity=kw.get("severity", "high"),
            action=kw.get("action", "audit"),
            rule_id=f"rule.{i}",
            source_ip="127.0.0.1",
        )


async def _rows(factory) -> list[SecurityEvent]:
    async with factory() as session:
        return (
            (await session.execute(select(SecurityEvent).order_by(text("rowid"))))
            .scalars()
            .all()
        )


async def test_chain_links_sequentially(session_factory):
    await _emit(session_factory, 3)
    rows = await _rows(session_factory)
    assert len(rows) == 3
    assert rows[0].prev_hash == audit.GENESIS_HASH
    assert rows[1].prev_hash == rows[0].hash
    assert rows[2].prev_hash == rows[1].hash
    assert all(r.hash and len(r.hash) == 64 for r in rows)

    result = await audit.verify_chain(session_factory)
    assert result == {"ok": True, "checked": 3, "legacy": 0, "first_bad": None}


async def test_tampered_content_detected_and_located(session_factory):
    await _emit(session_factory, 3)
    rows = await _rows(session_factory)
    async with session_factory() as session:
        victim = await session.get(SecurityEvent, rows[1].event_id)
        victim.severity = "critical"  # 直接改库（模拟篡改）
        await session.commit()

    result = await audit.verify_chain(session_factory)
    assert result["ok"] is False
    assert result["first_bad"] == rows[1].event_id
    assert "篡改" in result["reason"]


async def test_deleted_row_breaks_chain(session_factory):
    await _emit(session_factory, 4)
    rows = await _rows(session_factory)
    async with session_factory() as session:
        victim = await session.get(SecurityEvent, rows[1].event_id)
        await session.delete(victim)  # 删掉中间一行
        await session.commit()

    result = await audit.verify_chain(session_factory)
    assert result["ok"] is False
    assert result["first_bad"] == rows[2].event_id  # 下一行的 prev 对不上
    assert "断裂" in result["reason"]


async def test_legacy_rows_without_hash_are_skipped(session_factory):
    # M1/M2 遗留行（hash 为 NULL）：不参与链，不影响后续链行
    async with session_factory() as session:
        session.add(
            SecurityEvent(
                event_id="legacy01",
                event_type="auth_failure",
                severity="low",
                action="deny",
            )
        )
        await session.commit()
    await _emit(session_factory, 2)
    result = await audit.verify_chain(session_factory)
    assert result["ok"] is True
    assert result["legacy"] == 1
    assert result["checked"] == 2


async def test_concurrent_writes_keep_chain_valid(session_factory):
    await asyncio.gather(*[_emit(session_factory, 1, rule_id=f"r{i}") for i in range(50)])
    result = await audit.verify_chain(session_factory)
    assert result["ok"] is True
    assert result["checked"] == 50

    rows = await _rows(session_factory)
    # 链是全序的：每行的 prev 恰好是前一行的 hash
    for prev_row, row in zip(rows, rows[1:]):
        assert row.prev_hash == prev_row.hash
