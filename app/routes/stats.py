"""GET /api/stats：聚合数据（totals / by_tag / timeseries / GPU / engine / recent）。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from app.stats import collect_stats

router = APIRouter(tags=["stats"])


@router.get("/api/stats")
async def stats(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    tag: str | None = Query(None),
) -> dict[str, Any]:
    session_factory = getattr(request.app.state, "session_factory", None)
    return await collect_stats(session_factory, days=days, tag=tag or None)