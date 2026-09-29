"""聚合查询：/api/stats 数据源（totals / by_tag / timeseries / GPU 曲线 / engine 曲线 / recent）。

- 桶粒度由范围决定：days <= 1 用 5 分钟，其余用 1 小时（服务端自动聚合）。
- 时间口径：数据库存 UTC；窗口按 UTC 计算，输出 ISO-8601（Z 结尾）供前端本地化显示。
- 吞吐类指标存原始 counter（generation_tokens_total），这里按相邻桶差值换算 tokens/s。
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.db import SessionLocal

RECENT_LIMIT = 50
_ERRORS_EXPR = "SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END)"


def _window_start(days: int) -> str:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return since.strftime("%Y-%m-%d %H:%M:%S.%f")


def _bucket_seconds(days: int) -> int:
    return 300 if days <= 1 else 3600


def _iso_z(epoch: Any) -> str:
    """bucket epoch 秒 → ISO-8601（Z）。"""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _ts_to_iso_z(value: Any) -> str | None:
    """DB 时间串 'YYYY-MM-DD HH:MM:SS[.ffffff]'（UTC）→ ISO-8601，毫秒精度。"""
    if value is None:
        return None
    raw = str(value).strip().replace(" ", "T")
    if "." in raw:
        head, frac = raw.split(".", 1)
        raw = f"{head}.{(frac + '000')[:3]}"
    else:
        raw += ".000"
    return raw + "Z"


def _round(value: Any, digits: int = 1) -> float | None:
    return None if value is None else round(float(value), digits)


def _int_or_none(value: Any) -> int | None:
    return None if value is None else int(value)


async def collect_stats(
    session_factory: Any = None, *, days: int = 7, tag: str | None = None
) -> dict[str, Any]:
    """聚合指定时间窗口的请求/采样数据。tag 过滤只作用于请求维度（GPU 为整卡口径）。"""
    factory = session_factory or SessionLocal
    since = _window_start(days)
    bucket = _bucket_seconds(days)
    base_params: dict[str, Any] = {"since": since, "bucket": bucket}
    filter_sql = ""
    params = dict(base_params)
    if tag:
        filter_sql = " AND tag = :tag"
        params["tag"] = tag

    async with factory() as session:
        totals = (
            (
                await session.execute(
                    text(
                        f"""SELECT COUNT(*) AS requests,
                               COALESCE(SUM(total_tokens), 0) AS tokens,
                               COALESCE({_ERRORS_EXPR}, 0) AS errors,
                               AVG(latency_ms) AS avg_latency_ms,
                               AVG(ttft_ms) AS avg_ttft_ms,
                               AVG(output_tps) AS avg_output_tps
                        FROM request_logs WHERE created_at >= :since{filter_sql}"""
                    ),
                    params,
                )
            )
            .mappings()
            .one()
        )

        lat_count = (
            await session.execute(
                text(
                    f"""SELECT COUNT(*) FROM request_logs
                    WHERE created_at >= :since{filter_sql} AND latency_ms IS NOT NULL"""
                ),
                params,
            )
        ).scalar_one()
        p95: float | None = None
        if lat_count:
            offset = max(0, math.ceil(lat_count * 0.95) - 1)
            p95 = (
                await session.execute(
                    text(
                        f"""SELECT latency_ms FROM request_logs
                        WHERE created_at >= :since{filter_sql} AND latency_ms IS NOT NULL
                        ORDER BY latency_ms LIMIT 1 OFFSET :offset"""
                    ),
                    {**params, "offset": offset},
                )
            ).scalar_one()

        by_tag_rows = (
            (
                await session.execute(
                    text(
                        f"""SELECT COALESCE(tag, '') AS tag, COUNT(*) AS requests,
                               COALESCE(SUM(total_tokens), 0) AS tokens,
                               COALESCE({_ERRORS_EXPR}, 0) AS errors
                        FROM request_logs WHERE created_at >= :since
                        GROUP BY COALESCE(tag, '') ORDER BY requests DESC, tag"""
                    ),
                    base_params,
                )
            )
            .mappings()
            .all()
        )

        timeseries_rows = (
            (
                await session.execute(
                    text(
                        f"""SELECT (CAST(strftime('%s', substr(created_at, 1, 19)) AS INTEGER)
                                   / :bucket) * :bucket AS bucket_epoch,
                               COUNT(*) AS requests,
                               COALESCE(SUM(total_tokens), 0) AS tokens,
                               COALESCE({_ERRORS_EXPR}, 0) AS errors,
                               AVG(latency_ms) AS avg_latency_ms,
                               AVG(ttft_ms) AS avg_ttft_ms,
                               AVG(output_tps) AS avg_tps
                        FROM request_logs WHERE created_at >= :since{filter_sql}
                        GROUP BY bucket_epoch ORDER BY bucket_epoch"""
                    ),
                    params,
                )
            )
            .mappings()
            .all()
        )

        gpu_rows = (
            (
                await session.execute(
                    text(
                        """SELECT (CAST(strftime('%s', substr(ts, 1, 19)) AS INTEGER)
                                   / :bucket) * :bucket AS bucket_epoch,
                               AVG(util_percent) AS avg_util,
                               AVG(mem_used_mb) AS avg_mem_used_mb,
                               MAX(mem_used_mb) AS max_mem_used_mb,
                               AVG(power_w) AS avg_power_w
                        FROM gpu_samples WHERE ts >= :since
                        GROUP BY bucket_epoch ORDER BY bucket_epoch"""
                    ),
                    base_params,
                )
            )
            .mappings()
            .all()
        )

        engine_rows = (
            (
                await session.execute(
                    text(
                        """SELECT (CAST(strftime('%s', substr(ts, 1, 19)) AS INTEGER)
                                   / :bucket) * :bucket AS bucket_epoch,
                               MAX(requests_running) AS max_running,
                               MAX(requests_waiting) AS max_waiting,
                               AVG(kv_cache_usage_perc) AS avg_kv_cache_perc,
                               MAX(generation_tokens_total) AS max_generation_tokens
                        FROM engine_samples WHERE ts >= :since
                        GROUP BY bucket_epoch ORDER BY bucket_epoch"""
                    ),
                    base_params,
                )
            )
            .mappings()
            .all()
        )

        recent_rows = (
            (
                await session.execute(
                    text(
                        f"""SELECT id, created_at, tag, requested_model, resolved_model,
                               provider, streamed, prompt_tokens, completion_tokens,
                               total_tokens, latency_ms, ttft_ms, output_tps, status,
                               http_status, attempts, fallback_used
                        FROM request_logs WHERE created_at >= :since{filter_sql}
                        ORDER BY created_at DESC, id DESC LIMIT {RECENT_LIMIT}"""
                    ),
                    params,
                )
            )
            .mappings()
            .all()
        )

    timeseries = [
        {
            "ts": _iso_z(r["bucket_epoch"]),
            "requests": int(r["requests"]),
            "tokens": int(r["tokens"]),
            "errors": int(r["errors"]),
            "avg_latency_ms": _round(r["avg_latency_ms"]),
            "avg_ttft_ms": _round(r["avg_ttft_ms"]),
            "avg_tps": _round(r["avg_tps"], 2),
        }
        for r in timeseries_rows
    ]
    gpu = [
        {
            "ts": _iso_z(r["bucket_epoch"]),
            "avg_util": _round(r["avg_util"]),
            "avg_mem_used_mb": _round(r["avg_mem_used_mb"]),
            "max_mem_used_mb": _round(r["max_mem_used_mb"]),
            "avg_power_w": _round(r["avg_power_w"], 2),
        }
        for r in gpu_rows
    ]
    engine: list[dict[str, Any]] = []
    prev_epoch: int | None = None
    prev_counter: int | None = None
    for r in engine_rows:
        epoch = int(r["bucket_epoch"])
        counter = _int_or_none(r["max_generation_tokens"])
        gen_tps: float | None = None
        if (
            prev_epoch is not None
            and prev_counter is not None
            and counter is not None
            and epoch > prev_epoch
            and counter >= prev_counter
        ):
            gen_tps = round((counter - prev_counter) / (epoch - prev_epoch), 2)
        engine.append(
            {
                "ts": _iso_z(epoch),
                "max_running": _int_or_none(r["max_running"]),
                "max_waiting": _int_or_none(r["max_waiting"]),
                "avg_kv_cache_perc": _round(r["avg_kv_cache_perc"], 4),
                "gen_tps": gen_tps,
            }
        )
        prev_epoch, prev_counter = epoch, counter

    recent = [
        {
            "id": int(r["id"]),
            "ts": _ts_to_iso_z(r["created_at"]),
            "tag": r["tag"],
            "requested_model": r["requested_model"],
            "resolved_model": r["resolved_model"],
            "provider": r["provider"],
            "streamed": bool(r["streamed"]),
            "prompt_tokens": int(r["prompt_tokens"] or 0),
            "completion_tokens": int(r["completion_tokens"] or 0),
            "total_tokens": int(r["total_tokens"] or 0),
            "latency_ms": _round(r["latency_ms"]),
            "ttft_ms": _round(r["ttft_ms"]),
            "output_tps": _round(r["output_tps"]),
            "status": r["status"],
            "http_status": r["http_status"],
            "attempts": int(r["attempts"] or 1),
            "fallback_used": bool(r["fallback_used"]),
        }
        for r in recent_rows
    ]

    return {
        "days": days,
        "bucket_seconds": bucket,
        "tag": tag,
        "totals": {
            "requests": int(totals["requests"]),
            "tokens": int(totals["tokens"]),
            "errors": int(totals["errors"]),
            "avg_latency_ms": _round(totals["avg_latency_ms"]),
            "p95_latency_ms": _round(p95),
            "avg_ttft_ms": _round(totals["avg_ttft_ms"]),
            "avg_output_tps": _round(totals["avg_output_tps"], 2),
        },
        "by_tag": [
            {
                "tag": r["tag"],
                "requests": int(r["requests"]),
                "tokens": int(r["tokens"]),
                "errors": int(r["errors"]),
            }
            for r in by_tag_rows
        ],
        "timeseries": timeseries,
        "gpu": gpu,
        "engine": engine,
        "recent": recent,
    }