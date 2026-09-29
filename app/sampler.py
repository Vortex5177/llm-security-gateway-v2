"""监控采集：GPU 采样（NVML / WSL nvidia-smi）+ vLLM /metrics 轮询（asyncio 后台任务）。

采样源由 sampling.gpu_source 控制：
  auto —— 优先 NVML（Windows 侧直读）；无读数时退回 WSL 内 nvidia-smi
  nvml —— 仅 NVML
  wsl  —— 仅 WSL 内 nvidia-smi（Windows NVML 看不见 WSL 负载时使用）

阻塞调用（NVML / subprocess）走线程池；上游不可达或解析失败时跳过本轮，不中断循环。
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from typing import Any

import httpx

from app.config import GatewayConfig
from app.db import SessionLocal
from app.models import EngineSample, GpuSample

logger = logging.getLogger("gateway.sampler")

_PROM_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{[^}]*\})?\s+"
    r"(?P<value>[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?|NaN|[+-]Inf)$"
)

# 字段 → (候选指标名, 聚合方式)；容忍 "_total" 后缀差异
_ENGINE_METRICS: dict[str, tuple[tuple[str, ...], str]] = {
    "requests_running": (("vllm:num_requests_running",), "sum"),
    "requests_waiting": (("vllm:num_requests_waiting",), "sum"),
    "kv_cache_usage_perc": (
        ("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"),
        "max",
    ),
    "prompt_tokens_total": (("vllm:prompt_tokens_total",), "sum"),
    "generation_tokens_total": (("vllm:generation_tokens_total",), "sum"),
}

_INT_FIELDS = {
    "requests_running",
    "requests_waiting",
    "prompt_tokens_total",
    "generation_tokens_total",
}


def parse_prometheus(text: str) -> dict[str, list[float]]:
    """Prometheus 文本 → {指标名: [样本值...]}（忽略标签；# 注释行跳过）。"""
    samples: dict[str, list[float]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PROM_LINE_RE.match(line)
        if match is None:
            continue
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        samples.setdefault(match.group("name"), []).append(value)
    return samples


def _strip_total(name: str) -> str:
    """去掉 Prometheus counter 惯用的 _total 后缀（容忍跨版本指标名差异）。"""
    suffix = "_total"
    return name[: -len(suffix)] if name.endswith(suffix) else name

def parse_engine_metrics(text: str) -> dict[str, Any]:
    """解析 vLLM /metrics：前缀匹配指标名、跨标签聚合；缺失记 None。

    running/waiting/token counter 求和；kv_cache 取最大；容忍 _total 后缀差异。
    """
    samples = parse_prometheus(text)
    result: dict[str, Any] = {}
    for field, (candidates, agg) in _ENGINE_METRICS.items():
        values: list[float] = []
        for key, vals in samples.items():
            if any(_strip_total(key) == _strip_total(name) for name in candidates):
                values.extend(vals)
        if not values:
            result[field] = None
            continue
        picked = sum(values) if agg == "sum" else max(values)
        result[field] = int(picked) if field in _INT_FIELDS else float(picked)
    return result


def _read_gpu_nvml() -> dict[str, float] | None:
    """Windows 侧 NVML 直读整卡五项；不可用返回 None。"""
    try:
        import pynvml
    except Exception:
        return None
    try:
        pynvml.nvmlInit()
    except Exception:
        return None
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        power = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
        return {
            "util_percent": float(util.gpu),
            "mem_used_mb": round(mem.used / 1048576, 1),
            "mem_total_mb": round(mem.total / 1048576, 1),
            "temperature_c": float(temp),
            "power_w": round(power, 2),
        }
    except Exception:
        return None
    finally:
        try:
            pynvml.nvmlShutdown()
        except Exception:
            pass


def _read_gpu_wsl(distro: str) -> dict[str, float] | None:
    """WSL 内 nvidia-smi 采样（Windows NVML 看不到 WSL 负载时的替代源）。"""
    query = "utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw"
    cmd = [
        "wsl",
        "-d",
        distro,
        "--",
        "nvidia-smi",
        f"--query-gpu={query}",
        "--format=csv,noheader,nounits",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=15)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    # bytes 手动解码：wsl.exe 的 stderr 可能是 UTF-16 警告文本，text=True 会触发 GBK 解码崩溃
    stdout = (out.stdout or b"").decode("utf-8", errors="replace")
    lines = stdout.strip().splitlines()
    if not lines:
        return None
    parts = [part.strip() for part in lines[0].split(",")]
    if len(parts) < 5:
        return None
    try:
        util, mem_used, mem_total, temp, power = (float(p) for p in parts[:5])
    except ValueError:
        return None
    return {
        "util_percent": util,
        "mem_used_mb": round(mem_used, 1),
        "mem_total_mb": round(mem_total, 1),
        "temperature_c": temp,
        "power_w": round(power, 2),
    }


class Sampler:
    """后台采样循环；start/stop 随应用 lifespan 启停。"""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        session_factory: Any = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._session_factory = session_factory
        self._transport = transport
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    # ---- 热重载 ---------------------------------------------------------
    def update_config(self, config: GatewayConfig) -> None:
        """替换配置引用（看板新增 provider 后热生效）。"""
        self._config = config

    # ---- 生命周期 -------------------------------------------------------
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="gateway-sampler")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()

    # ---- 采样循环 -------------------------------------------------------
    async def _run(self) -> None:
        interval = max(0.5, float(self._config.sampling.interval_seconds))
        loop = asyncio.get_running_loop()
        while not self._stop.is_set():
            started = loop.time()
            try:
                await self._sample_once()
            except Exception:
                logger.exception("采样轮次失败（跳过本轮，循环继续）")
            elapsed = loop.time() - started
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=max(0.1, interval - elapsed)
                )
            except asyncio.TimeoutError:
                pass

    async def _sample_once(self) -> None:
        gpu = await asyncio.get_running_loop().run_in_executor(None, self._read_gpu)
        if gpu is not None:
            await self._write(GpuSample(**gpu))
        async with httpx.AsyncClient(timeout=5.0, transport=self._transport) as client:
            for name, provider in self._config.providers.items():
                if not provider.metrics_url:
                    continue
                parsed = await self._fetch_engine_metrics(client, provider.metrics_url)
                if parsed is not None:
                    await self._write(EngineSample(provider=name, **parsed))

    def _read_gpu(self) -> dict[str, float] | None:
        """阻塞读取（线程池内执行）：按 gpu_source 选择采样源。"""
        source = self._config.sampling.gpu_source
        distro = self._config.sampling.wsl_distro
        if source in ("auto", "nvml"):
            sample = _read_gpu_nvml()
            if sample is not None or source == "nvml":
                return sample
        return _read_gpu_wsl(distro)

    @staticmethod
    async def _fetch_engine_metrics(
        client: httpx.AsyncClient, url: str
    ) -> dict[str, Any] | None:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("metrics 拉取失败（跳过本轮）: %s: %s", url, exc)
            return None
        if resp.status_code != 200:
            logger.debug("metrics 返回 HTTP %s（跳过本轮）: %s", resp.status_code, url)
            return None
        return parse_engine_metrics(resp.text)

    async def _write(self, obj: Any) -> None:
        factory = self._session_factory or SessionLocal
        async with factory() as session:
            session.add(obj)
            await session.commit()