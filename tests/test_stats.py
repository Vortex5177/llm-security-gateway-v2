"""模块 5：聚合查询（totals / by_tag / timeseries / GPU / engine / recent 与 days/tag 过滤）测试。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base, EngineSample, GpuSample, RequestLog
from app.stats import collect_stats


@pytest.fixture()
async def session_factory(tmp_path):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'stats.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def add(session_factory, *rows) -> None:
    async with session_factory() as session:
        for row in rows:
            session.add(row)
        await session.commit()


def log_row(
    *,
    tag: str | None = None,
    status: str = "ok",
    latency_ms: float | None = 100.0,
    ttft_ms: float | None = None,
    output_tps: float | None = None,
    total_tokens: int = 10,
    minutes_ago: float = 0.1,
    model: str = "qwen3-1.7b",
    provider: str = "local-vllm",
) -> RequestLog:
    return RequestLog(
        created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        tag=tag,
        requested_model=model,
        resolved_model=model,
        provider=provider,
        streamed=False,
        prompt_tokens=5,
        completion_tokens=max(0, total_tokens - 5),
        total_tokens=total_tokens,
        latency_ms=latency_ms,
        ttft_ms=ttft_ms,
        output_tps=output_tps,
        status=status,
        http_status=200 if status == "ok" else 502,
        attempts=1,
        fallback_used=False,
    )


# ---------------------------------------------------------------- totals / p95


async def test_totals_match_manual_sql(session_factory):
    await add(
        session_factory,
        log_row(tag="a", latency_ms=100.0, total_tokens=10, ttft_ms=50.0),
        log_row(tag="a", latency_ms=200.0, total_tokens=20, ttft_ms=60.0),
        log_row(tag="b", status="upstream_error", latency_ms=300.0, total_tokens=30),
        log_row(status="timeout", latency_ms=None, total_tokens=0),
    )
    stats = await collect_stats(session_factory, days=7)
    totals = stats["totals"]
    assert totals["requests"] == 4
    assert totals["tokens"] == 60
    assert totals["errors"] == 2
    assert totals["avg_latency_ms"] == 200.0
    assert totals["avg_ttft_ms"] == 55.0

    async with session_factory() as session:
        row = (
            (
                await session.execute(
                    text(
                        """SELECT COUNT(*) AS c,
                           COALESCE(SUM(total_tokens), 0) AS s,
                           SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS e,
                           AVG(latency_ms) AS a
                        FROM request_logs"""
                    )
                )
            )
            .mappings()
            .one()
        )
    assert totals["requests"] == row["c"]
    assert totals["tokens"] == row["s"]
    assert totals["errors"] == row["e"]
    assert totals["avg_latency_ms"] == round(float(row["a"]), 1)


async def test_totals_avg_output_tps_ignores_null(session_factory):
    await add(
        session_factory,
        log_row(output_tps=10.0),
        log_row(output_tps=30.0),
        log_row(output_tps=None, status="timeout", latency_ms=None),
    )
    stats = await collect_stats(session_factory, days=7)
    assert stats["totals"]["avg_output_tps"] == 20.0


async def test_p95_latency_percentile(session_factory):
    await add(session_factory, *[log_row(latency_ms=float(i)) for i in range(1, 101)])
    stats = await collect_stats(session_factory, days=7)
    assert stats["totals"]["p95_latency_ms"] == 95.0


async def test_p95_single_row(session_factory):
    await add(session_factory, log_row(latency_ms=42.0))
    stats = await collect_stats(session_factory, days=7)
    assert stats["totals"]["p95_latency_ms"] == 42.0


async def test_empty_db_returns_zeroed_totals(session_factory):
    stats = await collect_stats(session_factory, days=7)
    assert stats["totals"] == {
        "requests": 0,
        "tokens": 0,
        "errors": 0,
        "avg_latency_ms": None,
        "p95_latency_ms": None,
        "avg_ttft_ms": None,
        "avg_output_tps": None,
    }
    assert stats["by_tag"] == []
    assert stats["timeseries"] == []
    assert stats["recent"] == []


# ------------------------------------------------------------------- by_tag


async def test_by_tag_grouping_includes_untagged(session_factory):
    await add(
        session_factory,
        log_row(tag="speclens/scan", total_tokens=10),
        log_row(tag="speclens/scan", total_tokens=20),
        log_row(tag=None, total_tokens=30),
    )
    stats = await collect_stats(session_factory, days=7)
    by_tag = {entry["tag"]: entry for entry in stats["by_tag"]}
    assert by_tag["speclens/scan"]["requests"] == 2
    assert by_tag["speclens/scan"]["tokens"] == 30
    assert by_tag[""]["requests"] == 1


async def test_tag_filter_scopes_requests_not_by_tag(session_factory):
    await add(
        session_factory,
        log_row(tag="a", total_tokens=10),
        log_row(tag="b", total_tokens=20),
        log_row(tag="b", total_tokens=30),
    )
    stats = await collect_stats(session_factory, days=7, tag="a")
    assert stats["tag"] == "a"
    assert stats["totals"]["requests"] == 1
    assert stats["totals"]["tokens"] == 10
    assert len(stats["recent"]) == 1
    assert {entry["tag"] for entry in stats["by_tag"]} == {"a", "b"}


async def test_days_window_filters_old_rows(session_factory):
    await add(
        session_factory,
        log_row(minutes_ago=60.0),
        log_row(minutes_ago=10 * 24 * 60.0),
    )
    week = await collect_stats(session_factory, days=7)
    month = await collect_stats(session_factory, days=30)
    assert week["totals"]["requests"] == 1
    assert month["totals"]["requests"] == 2


# ----------------------------------------------------------------- timeseries


async def test_bucket_seconds_by_range(session_factory):
    assert (await collect_stats(session_factory, days=1))["bucket_seconds"] == 300
    assert (await collect_stats(session_factory, days=7))["bucket_seconds"] == 3600
    assert (await collect_stats(session_factory, days=30))["bucket_seconds"] == 3600


async def test_timeseries_hour_buckets(session_factory):
    now = datetime.now(timezone.utc)
    hour0 = now.replace(minute=0, second=0, microsecond=0)

    def at(ts: datetime) -> RequestLog:
        return RequestLog(
            created_at=ts,
            requested_model="m",
            resolved_model="m",
            provider="p",
            total_tokens=5,
            latency_ms=10.0,
            prompt_tokens=2,
            completion_tokens=3,
            status="ok",
        )

    await add(
        session_factory,
        at(hour0 - timedelta(minutes=5)),
        at(hour0),
        at(hour0 + timedelta(seconds=1)),
    )
    stats = await collect_stats(session_factory, days=7)
    points = stats["timeseries"]
    assert len(points) == 2
    assert points[0]["ts"] == (hour0 - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert points[0]["requests"] == 1
    assert points[1]["ts"] == hour0.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert points[1]["requests"] == 2
    assert points[1]["avg_latency_ms"] == 10.0
    assert points[1]["tokens"] == 10


async def test_timeseries_avg_tps_per_bucket(session_factory):
    await add(
        session_factory,
        log_row(output_tps=10.0),
        log_row(output_tps=30.0),
    )
    stats = await collect_stats(session_factory, days=7)
    points = stats["timeseries"]
    assert len(points) == 1
    assert points[0]["avg_tps"] == 20.0


async def test_timeseries_five_minute_buckets_for_one_day(session_factory):
    now = datetime.now(timezone.utc)
    base5 = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)

    def at(ts: datetime) -> RequestLog:
        return RequestLog(
            created_at=ts,
            requested_model="m",
            resolved_model="m",
            provider="p",
            total_tokens=1,
            latency_ms=1.0,
            status="ok",
        )

    await add(
        session_factory,
        at(base5 - timedelta(minutes=5)),
        at(base5),
        at(base5 + timedelta(seconds=10)),
    )
    stats = await collect_stats(session_factory, days=1)
    assert stats["bucket_seconds"] == 300
    points = stats["timeseries"]
    assert len(points) == 2
    assert points[0]["requests"] == 1
    assert points[1]["requests"] == 2


# ------------------------------------------------------------ gpu / engine


async def test_gpu_curve_aggregation(session_factory):
    now = datetime.now(timezone.utc)
    await add(
        session_factory,
        GpuSample(ts=now, util_percent=10.0, mem_used_mb=8000.0, mem_total_mb=8188.0, temperature_c=50.0, power_w=10.0),
        GpuSample(ts=now, util_percent=20.0, mem_used_mb=8200.0, mem_total_mb=8188.0, temperature_c=51.0, power_w=20.0),
        GpuSample(ts=now, util_percent=30.0, mem_used_mb=8400.0, mem_total_mb=8188.0, temperature_c=52.0, power_w=30.0),
    )
    stats = await collect_stats(session_factory, days=7)
    assert len(stats["gpu"]) == 1
    point = stats["gpu"][0]
    assert point["avg_util"] == 20.0
    assert point["avg_mem_used_mb"] == 8200.0
    assert point["max_mem_used_mb"] == 8400.0
    assert point["avg_power_w"] == 20.0


async def test_engine_curve_and_gen_tps(session_factory):
    hour0 = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    await add(
        session_factory,
        EngineSample(ts=hour0 - timedelta(hours=1), provider="local-vllm", requests_running=1, requests_waiting=0, kv_cache_usage_perc=0.1, prompt_tokens_total=100, generation_tokens_total=100),
        EngineSample(ts=hour0, provider="local-vllm", requests_running=2, requests_waiting=3, kv_cache_usage_perc=0.2, prompt_tokens_total=200, generation_tokens_total=4600),
    )
    stats = await collect_stats(session_factory, days=7)
    engine = stats["engine"]
    assert len(engine) == 2
    assert engine[0]["max_running"] == 1
    assert engine[0]["gen_tps"] is None
    assert engine[1]["max_running"] == 2
    assert engine[1]["max_waiting"] == 3
    assert engine[1]["avg_kv_cache_perc"] == 0.2
    assert engine[1]["gen_tps"] == 1.25


async def test_engine_gen_tps_none_when_counter_resets(session_factory):
    hour0 = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    await add(
        session_factory,
        EngineSample(ts=hour0 - timedelta(hours=1), provider="p", generation_tokens_total=1000),
        EngineSample(ts=hour0, provider="p", generation_tokens_total=5),
    )
    stats = await collect_stats(session_factory, days=7)
    assert stats["engine"][1]["gen_tps"] is None


# ------------------------------------------------------------------- recent


async def test_recent_orders_desc_and_limits(session_factory):
    await add(session_factory, *[log_row(minutes_ago=i * 0.01) for i in range(55)])
    stats = await collect_stats(session_factory, days=7)
    recent = stats["recent"]
    assert len(recent) == 50
    ts_list = [row["ts"] for row in recent]
    assert ts_list == sorted(ts_list, reverse=True)


async def test_recent_includes_status_and_ttft(session_factory):
    await add(
        session_factory,
        log_row(status="upstream_error", ttft_ms=None, latency_ms=15.5),
    )
    stats = await collect_stats(session_factory, days=7)
    row = stats["recent"][0]
    assert row["status"] == "upstream_error"
    assert row["latency_ms"] == 15.5
    assert row["ttft_ms"] is None
    assert row["ts"].endswith("Z")


# --------------------------------------------------------------- route 层


async def test_stats_route_via_asgi(session_factory):
    from app.main import create_app

    await add(session_factory, log_row(tag="route", total_tokens=7))
    app = create_app()
    app.state.session_factory = session_factory
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        resp = await client.get("/api/stats", params={"days": 7})
        empty = await client.get("/api/stats", params={"days": 7, "tag": "nope"})
        bad = await client.get("/api/stats", params={"days": 0})
    assert resp.status_code == 200
    body = resp.json()
    assert body["totals"]["requests"] == 1
    assert body["by_tag"][0]["tag"] == "route"
    assert empty.json()["totals"]["requests"] == 0
    assert bad.status_code == 422


async def test_dashboard_index_served(session_factory):
    from app.main import create_app

    app = create_app()
    app.state.session_factory = session_factory
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gw"
    ) as client:
        resp = await client.get("/")
        chart = await client.get("/chart.umd.min.js")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "LLM Gateway" in resp.text
    assert chart.status_code == 200