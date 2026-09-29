"""ORM 模型：RequestLog、GpuSample、EngineSample。"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class RequestLog(Base):
    """单次 /v1/chat/completions 请求的落库记录（成功与失败都写）。"""

    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    tag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    requested_model: Mapped[str] = mapped_column(String(128))
    resolved_model: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(64), index=True)
    streamed: Mapped[bool] = mapped_column(Boolean, default=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ttft_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    output_tps: Mapped[float | None] = mapped_column(Float, nullable=True)
    # ok / upstream_error / client_abort / timeout
    status: Mapped[str] = mapped_column(String(32), default="ok")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 生效参数快照（硬顶注入后的完整请求参数，实验复现用）
    injected_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class GpuSample(Base):
    """NVML 采样（系统级时间序列，不做逐请求归因）。"""

    __tablename__ = "gpu_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    util_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_used_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_total_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    temperature_c: Mapped[float | None] = mapped_column(Float, nullable=True)
    power_w: Mapped[float | None] = mapped_column(Float, nullable=True)


class EngineSample(Base):
    """vLLM /metrics 轮询结果；吞吐类指标存原始 counter，查询时计算速率。"""

    __tablename__ = "engine_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    provider: Mapped[str] = mapped_column(String(64))
    requests_running: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requests_waiting: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kv_cache_usage_perc: Mapped[float | None] = mapped_column(Float, nullable=True)
    prompt_tokens_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generation_tokens_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
