"""模块 4：监控采集（Prometheus 解析 / GPU 采样源 / 上游不可达不中断）测试。"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import sampler as sampler_mod
from app.config import ConfigError, parse_config
from app.models import Base, EngineSample, GpuSample
from app.sampler import Sampler, parse_engine_metrics, parse_prometheus

PROM_TEXT = """\
# HELP vllm:num_requests_running Number of requests currently running.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="qwen3-1.7b"} 2.0
vllm:num_requests_running{model_name="qwen3-0.6b"} 1.0
vllm:num_requests_waiting{model_name="qwen3-1.7b"} 3.0
vllm:kv_cache_usage_perc{model_name="qwen3-1.7b"} 0.42
vllm:prompt_tokens_total{model_name="qwen3-1.7b"} 120.0
vllm:prompt_tokens_total{model_name="qwen3-0.6b"} 30.0
vllm:generation_tokens_total{model_name="qwen3-1.7b"} 456.0
"""

GPU_SAMPLE = {
    "util_percent": 37.0,
    "mem_used_mb": 4096.0,
    "mem_total_mb": 8188.0,
    "temperature_c": 61.0,
    "power_w": 55.5,
}


@pytest.fixture()
def config(config_dict):
    return parse_config(config_dict)


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


async def fetch_rows(session_factory, model):
    async with session_factory() as session:
        return (await session.execute(select(model).order_by(model.id))).scalars().all()


def stub_gpu(monkeypatch, sample=GPU_SAMPLE):
    """把阻塞式 GPU 读取替换为固定样本（不触碰真实硬件/WSL）。"""
    monkeypatch.setattr(Sampler, "_read_gpu", lambda self: dict(sample) if sample else None)


# ------------------------------------------------------------ Prometheus 解析

def test_parse_prometheus_ignores_comments_and_bad_lines():
    samples = parse_prometheus(PROM_TEXT + "\nnot a metric line\n")
    assert samples["vllm:num_requests_running"] == [2.0, 1.0]
    assert all(not name.startswith("#") for name in samples)


def test_parse_engine_metrics_aggregation():
    parsed = parse_engine_metrics(PROM_TEXT)
    assert parsed["requests_running"] == 3  # 跨标签求和（2 + 1）
    assert parsed["requests_waiting"] == 3
    assert parsed["kv_cache_usage_perc"] == pytest.approx(0.42)  # 取最大
    assert parsed["prompt_tokens_total"] == 150  # 跨标签求和（120 + 30）
    assert parsed["generation_tokens_total"] == 456


def test_parse_engine_metrics_tolerates_legacy_names_and_missing():
    text = (
        'vllm:gpu_cache_usage_perc{model_name="m"} 0.5\n'
        "vllm:num_requests_running 1.0\n"
        "vllm:generation_tokens 9.0\n"
    )
    parsed = parse_engine_metrics(text)
    assert parsed["kv_cache_usage_perc"] == pytest.approx(0.5)  # 旧指标名
    assert parsed["requests_running"] == 1
    assert parsed["generation_tokens_total"] == 9  # _total 后缀差异容忍
    assert parsed["prompt_tokens_total"] is None  # 缺失记 None


def test_parse_engine_metrics_empty_text():
    parsed = parse_engine_metrics("")
    assert all(value is None for value in parsed.values())


# ------------------------------------------------------------ GPU 采样源

def test_read_gpu_auto_falls_back_to_wsl(config, monkeypatch):
    calls = []

    def nvml_fail():
        calls.append("nvml")
        return None

    def wsl_ok(distro):
        calls.append(("wsl", distro))
        return dict(GPU_SAMPLE)

    monkeypatch.setattr(sampler_mod, "_read_gpu_nvml", nvml_fail)
    monkeypatch.setattr(sampler_mod, "_read_gpu_wsl", wsl_ok)
    sample = Sampler(config)._read_gpu()
    assert calls[0] == "nvml" and calls[1][0] == "wsl"
    assert sample["util_percent"] == 37.0


def test_read_gpu_nvml_mode_does_not_fall_back(config, monkeypatch):
    monkeypatch.setattr(sampler_mod, "_read_gpu_nvml", lambda: None)
    monkeypatch.setattr(
        sampler_mod, "_read_gpu_wsl", lambda distro: pytest.fail("不应调用 WSL 后备")
    )
    cfg = config.model_copy(deep=True)
    cfg.sampling.gpu_source = "nvml"
    assert Sampler(cfg)._read_gpu() is None


def test_read_gpu_wsl_mode_skips_nvml(config, monkeypatch):
    monkeypatch.setattr(
        sampler_mod, "_read_gpu_nvml", lambda: pytest.fail("wsl 模式不应调用 NVML")
    )
    monkeypatch.setattr(sampler_mod, "_read_gpu_wsl", lambda distro: dict(GPU_SAMPLE))
    cfg = config.model_copy(deep=True)
    cfg.sampling.gpu_source = "wsl"
    assert Sampler(cfg)._read_gpu()["mem_used_mb"] == 4096.0


def test_read_gpu_wsl_parses_csv(monkeypatch):
    class FakeCompleted:
        returncode = 0
        stdout = b"37, 4096, 8188, 61, 55.50\n"
        stderr = b""

    monkeypatch.setattr(sampler_mod.subprocess, "run", lambda *a, **k: FakeCompleted())
    sample = sampler_mod._read_gpu_wsl("Ubuntu-24.04")
    assert sample == {
        "util_percent": 37.0,
        "mem_used_mb": 4096.0,
        "mem_total_mb": 8188.0,
        "temperature_c": 61.0,
        "power_w": 55.5,
    }


def test_read_gpu_wsl_handles_command_failure(monkeypatch):
    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"No devices were found"

    monkeypatch.setattr(sampler_mod.subprocess, "run", lambda *a, **k: FakeCompleted())
    assert sampler_mod._read_gpu_wsl("Ubuntu-24.04") is None


def test_sampling_config_rejects_unknown_gpu_source(config_dict):
    config_dict["sampling"]["gpu_source"] = "bogus"
    with pytest.raises(ConfigError):
        parse_config(config_dict)


# ------------------------------------------------------------ 采样写入与容错

async def test_sample_once_writes_gpu_and_engine_rows(
    config, session_factory, monkeypatch
):
    stub_gpu(monkeypatch)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=PROM_TEXT))
    sampler = Sampler(config, session_factory=session_factory, transport=transport)
    await sampler._sample_once()

    gpu_rows = await fetch_rows(session_factory, GpuSample)
    assert len(gpu_rows) == 1
    assert gpu_rows[0].mem_used_mb == 4096.0
    assert gpu_rows[0].util_percent == 37.0
    assert gpu_rows[0].ts is not None

    engine_rows = await fetch_rows(session_factory, EngineSample)
    assert len(engine_rows) == 1
    row = engine_rows[0]
    assert row.provider == "local-vllm"  # 只有配置了 metrics_url 的 provider
    assert row.requests_running == 3
    assert row.requests_waiting == 3
    assert row.kv_cache_usage_perc == pytest.approx(0.42)
    assert row.prompt_tokens_total == 150
    assert row.generation_tokens_total == 456


async def test_sample_once_survives_metrics_upstream_down(
    config, session_factory, monkeypatch
):
    stub_gpu(monkeypatch)

    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    sampler = Sampler(
        config, session_factory=session_factory, transport=httpx.MockTransport(refuse)
    )
    await sampler._sample_once()  # 不应抛异常

    assert await fetch_rows(session_factory, EngineSample) == []
    gpu_rows = await fetch_rows(session_factory, GpuSample)
    assert len(gpu_rows) == 1  # GPU 行照常写入


async def test_sample_once_survives_metrics_http_error(
    config, session_factory, monkeypatch
):
    stub_gpu(monkeypatch)
    transport = httpx.MockTransport(lambda request: httpx.Response(500, text="boom"))
    sampler = Sampler(config, session_factory=session_factory, transport=transport)
    await sampler._sample_once()
    assert await fetch_rows(session_factory, EngineSample) == []


async def test_sampler_loop_continues_when_upstream_down(
    config, session_factory, monkeypatch
):
    """vLLM 停止（metrics 持续不可达）时采样循环不中断，GPU 行持续推进。"""
    stub_gpu(monkeypatch)

    def refuse(request):
        raise httpx.ConnectError("down", request=request)

    cfg = config.model_copy(deep=True)
    cfg.sampling.interval_seconds = 0.5
    sampler = Sampler(
        cfg, session_factory=session_factory, transport=httpx.MockTransport(refuse)
    )
    sampler.start()
    await asyncio.sleep(1.6)
    await sampler.stop()

    gpu_rows = await fetch_rows(session_factory, GpuSample)
    assert len(gpu_rows) >= 2  # 循环持续推进
    assert await fetch_rows(session_factory, EngineSample) == []


async def test_sampler_start_stop_idempotent(config, session_factory, monkeypatch):
    stub_gpu(monkeypatch)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=PROM_TEXT))
    sampler = Sampler(config, session_factory=session_factory, transport=transport)
    await sampler.stop()  # 未启动时 stop 应为 no-op
    sampler.start()
    sampler.start()  # 重复 start 不应起第二个任务
    await asyncio.sleep(0.2)
    await sampler.stop()
    await sampler.stop()
    assert sampler._task is None