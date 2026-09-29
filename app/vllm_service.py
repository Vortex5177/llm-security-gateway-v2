"""本机 vLLM 控制层：仅用户动作启停，Gateway 生命周期不管理模型生命周期。"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
from pathlib import Path
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import GatewayConfig, resolve_api_key

logger = logging.getLogger(__name__)
START_TIMEOUT = 300.0
POLL_SECONDS = 3.0
DETAIL_LIMIT = 4096


def bounded_text(value: object) -> str:
    text = str(value)
    text = "".join(c for c in text if ord(c) >= 32 or c in "\n\t")
    return text.encode("utf-8")[:DETAIL_LIMIT].decode("utf-8", "ignore")


class ControlUnavailable(RuntimeError):
    """WSL 命令未能得到可信状态。"""


def helper_wsl_path(helper: str | Path | None = None) -> str:
    """把工作区内的助手脚本映射为 WSL 路径。

    不能经 wsl.exe 传 Windows 反斜杠路径（会被吞掉），直接按本地盘符推导 /mnt。
    """
    target = Path(helper) if helper is not None else Path(__file__).with_name("wsl_vllm_control.py")
    target = target.resolve()
    drive = target.drive
    if len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha():
        raise ControlUnavailable("控制助手必须位于本地盘符路径才能映射到 WSL")
    return "/mnt/" + drive[0].lower() + target.as_posix()[2:]


class VllmService:
    def __init__(self, config: GatewayConfig, *, transport=None):
        self.config = config
        self.settings = config.local_vllm
        self.provider = config.providers.get(self.settings.provider)
        self.models = self.settings.model_names
        self.default = self.settings.default_name
        self.url = self.provider.base_url.rstrip("/") if self.provider else ""
        parsed = urlparse(self.url)
        self.port = parsed.port
        self.health_url = parsed._replace(path="/health", query="", fragment="").geturl()
        self.transport = transport
        self._helper_path: str | None = None
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._action: str | None = None
        self._task_model: str | None = None
        self._last_error: str | None = None

    def _view(self, state: str, detail: object, *, can_start=False, can_stop=False,
              current: str | None = None):
        return dict(state=state, model=current or self.default, models=self.models,
                    current=current, url=self.url,
                    can_start=can_start, can_stop=can_stop, detail=bounded_text(detail))

    @staticmethod
    def _run_command(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        # 不继承网关 .env 密钥，不使用 shell；避免 Windows asyncio 子进程策略差异。
        allowed = {"systemroot", "windir", "path", "pathext", "temp", "tmp",
                   "userprofile", "localappdata", "appdata", "programdata",
                   "username", "userdomain", "homedrive", "homepath"}
        env = {key: value for key, value in os.environ.items() if key.lower() in allowed}
        return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, check=False, env=env,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    async def _command(self, argv: list[str], timeout: float):
        try:
            result = await asyncio.to_thread(self._run_command, argv, timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ControlUnavailable("WSL 控制命令失败或超时，请刷新核验真实状态：" + str(exc)) from exc
        if result.returncode:
            # WSL 诊断可能为 UTF-16，不向页面转交乱码或环境信息。
            raise ControlUnavailable(f"WSL 控制命令退出码 {result.returncode}；请检查发行版、Python 和脚本路径")
        return result.stdout.decode("utf-8", "strict").strip()

    async def _invoke(self, action: str, model: str | None = None) -> dict[str, Any]:
        if action not in {"status", "start", "stop", "switch"}:
            raise ValueError("不支持的控制动作")
        if os.name != "nt":
            raise ControlUnavailable("此控制入口仅支持 Windows 主机上的 WSL")
        prefix = ["wsl.exe", "-d", self.settings.wsl_distro, "--"]
        if self._helper_path is None:
            self._helper_path = helper_wsl_path()
        argv = prefix + ["/opt/venvs/vllm/bin/python", self._helper_path, action,
                         "--port", str(self.port),
                         "--start-script", self.settings.start_script]
        for name, path in zip(self.models, self.settings.models):
            argv += ["--models", f"{name}={path}"]
        if model is not None and action in {"start", "switch"}:
            argv += ["--model", model]
            parser = self.settings.tool_parsers.get(model)
            if parser:
                argv += ["--tool-parser", parser]
        output = await self._command(argv, 45 if action in {"stop", "switch"} else 15)
        try:
            value = json.loads(output)
            if not isinstance(value, dict) or value.get("state") not in {
                "present", "stopped", "stopping", "failed", "conflict", "unavailable"
            }:
                raise ValueError("未知状态")
            if any(type(value.get(k)) is not bool for k in ("can_start", "can_stop")):
                raise ValueError("控制权限字段无效")
            if value.get("current") is not None and not isinstance(value.get("current"), str):
                raise ValueError("运行中模型字段无效")
            if value["state"] == "present":
                stamp = value.get("started_at")
                if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0:
                    raise ValueError("进程启动时间无效")
        except (ValueError, TypeError, OverflowError) as exc:
            raise ControlUnavailable("控制助手返回了无效状态") from exc
        return value

    async def _observe(self, raw=None):
        if not self.settings.enabled:
            return self._view("unavailable", "未启用本地服务控制")
        try:
            raw = await self._invoke("status") if raw is None else raw
            state = raw["state"]
            detail = raw.get("detail", "")
            can_start = bool(raw.get("can_start"))
            can_stop = bool(raw.get("can_stop"))
            current = raw.get("current")
            if state == "present":
                can_start = False
                ready, mismatch, reason = False, False, ""
                if raw.get("pid") is None:
                    state, detail = "failed", "主进程已退出，请先停止残留实例成员"
                else:
                    headers = {}
                    key = resolve_api_key(self.provider)
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                    try:
                        async with httpx.AsyncClient(timeout=2.0, transport=self.transport,
                                                     trust_env=False, follow_redirects=False) as client:
                            health, models = await asyncio.gather(
                                client.get(self.health_url, headers=headers),
                                client.get(self.url + "/models", headers=headers),
                            )
                        if models.status_code == 200:
                            data = models.json()
                            ids = {m.get("id") for m in data.get("data", []) if isinstance(m, dict)}
                            mismatch = current not in ids
                        ready = health.status_code == 200 and models.status_code == 200 and not mismatch
                        reason = f"健康检查 HTTP {health.status_code}；模型目录 HTTP {models.status_code}"
                    except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
                        reason = type(exc).__name__
                    if mismatch:
                        state, detail, can_stop = "conflict", "端口返回的模型与配置不匹配，拒绝控制", False
                    elif ready:
                        state, detail = "running", "模型已就绪"
                    elif time.time() - raw["started_at"] < START_TIMEOUT:
                        state, detail = "starting", "进程已启动，等待模型就绪（最长 300 秒）"
                    else:
                        state, detail = "failed", "模型未就绪或健康检查失败：" + reason
            if state in {"failed", "unavailable", "conflict"} and raw.get("log_tail"):
                detail = str(detail) + "\n" + str(raw["log_tail"])
            return self._view(state, detail, can_start=can_start, can_stop=can_stop,
                              current=current)
        except (ControlUnavailable, UnicodeError) as exc:
            return self._view("unavailable", exc)

    async def status(self):
        if self._task is not None and not self._task.done():
            if self._action == "switch":
                return self._view("starting", "正在切换模型，请稍候")
            return self._view("starting" if self._action == "start" else "stopping",
                              "正在启动模型，请稍候" if self._action == "start" else "正在停止模型，请稍候")
        view = await self._observe()
        if self._last_error and view["state"] not in {"conflict", "unavailable"}:
            view["detail"] = bounded_text(self._last_error + "\n" + view["detail"])
            view["state"] = "failed"
        return view

    async def operate(self, action: str, model: str | None = None):
        if action not in {"start", "stop", "switch"}:
            raise ValueError("不支持的控制动作")
        if action in {"start", "switch"}:
            model = model or self.default
            if model not in self.models:
                raise ValueError("未知候选模型")
        else:
            model = None
        async with self._lock:
            if self._task is not None and not self._task.done():
                if self._action == action and (action == "stop" or self._task_model == model):
                    return 202, await self.status()
                return 409, await self.status()
            view = await self._observe()
            unavailable = view["state"] == "unavailable"
            if action == "start":
                if view["state"] == "running":
                    if view["current"] == model:
                        return 200, view
                    return 409, dict(view, detail=bounded_text(
                        f"当前运行的是 {view['current']}；更换模型请使用切换操作"))
                if not view["can_start"]:
                    return (503 if unavailable else 409), view
            elif action == "switch":
                if view["state"] == "running" and view["current"] == model:
                    return 200, view
                allowed = (view["state"] == "running" and view["can_stop"]) or view["can_start"]
                if not allowed:
                    return (503 if unavailable else 409), view
            else:
                if view["state"] == "stopped":
                    return 200, view
                if not view["can_stop"]:
                    return (503 if unavailable else 409), view
            self._last_error = None
            self._action = action
            self._task_model = model
            self._task = asyncio.create_task(self._execute(action, model), name="local-vllm-" + action)
            logger.info("本机 vLLM 接受操作: %s %s", action, model or "")
            return 202, await self.status()

    async def _execute(self, action: str, model: str | None = None):
        try:
            raw = await self._invoke(action, model)
            view = await self._observe(raw)
            if action in {"start", "switch"}:
                deadline = time.monotonic() + START_TIMEOUT
                while view["state"] == "starting" and time.monotonic() < deadline:
                    await asyncio.sleep(POLL_SECONDS)
                    view = await self._observe()
                success = view["state"] == "running" and view["current"] == model
            else:
                success = view["state"] == "stopped"
            if not success:
                self._last_error = bounded_text("上次操作未完成：" + view["detail"])
            logger.info("本机 vLLM 操作结束: %s, %s", action, view["state"])
        except asyncio.CancelledError:
            # 只取消 Gateway 侧等待，不向模型进程发送任何信号。
            raise
        except Exception as exc:
            self._last_error = bounded_text("控制操作失败，请刷新核验状态：" + str(exc))
            logger.warning("本机 vLLM 控制失败: %s", type(exc).__name__)
        finally:
            self._action = None
            self._task_model = None

    async def close(self):
        """关闭看护协程，不停止 vLLM；重启后从 WSL 重新识别。"""
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
