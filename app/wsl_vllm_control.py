"""仅依赖标准库的 WSL vLLM 控制入口；查询只读，所有身份不明情况均拒绝控制。"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import tempfile
import time


RUNTIME_DIR = Path("/run/llm-gateway-vllm")
VLLM_BIN = "/opt/venvs/vllm/bin/vllm"
PYTHON_BINS = ("/opt/venvs/vllm/bin/python", "/opt/venvs/vllm/bin/python3")
LOG_LIMIT = 4096
TERM_TIMEOUT = 30.0
KILL_TIMEOUT = 5.0


class Unsafe(RuntimeError):
    """证据不足，不能安全执行操作。"""


class Busy(RuntimeError):
    """另一个助手正在执行写操作。"""


@dataclass(frozen=True)
class Config:
    models: tuple[tuple[str, str], ...]  # 有序的 (候选名, 模型路径)
    port: int
    start_script: str
    tool_parser: str = "hermes"  # vLLM --tool-call-parser，随本次启动一次性使用

    def __post_init__(self):
        if not 1 <= self.port <= 65535:
            raise ValueError("端口必须介于 1 和 65535")
        if not self.models:
            raise ValueError("至少需要一个候选模型")
        seen = set()
        for name, path in self.models:
            if not name or "\0" in name:
                raise ValueError("模型名称不能为空")
            if name in seen:
                raise ValueError("候选模型名称不能重复：" + name)
            seen.add(name)
            if not PurePosixPath(path).is_absolute() or "\0" in path:
                raise ValueError("模型及脚本必须使用可信 Linux 绝对路径")
        if not PurePosixPath(self.start_script).is_absolute() or "\0" in self.start_script:
            raise ValueError("模型及脚本必须使用可信 Linux 绝对路径")
        if not self.tool_parser or not all(c.isalnum() or c == "_" for c in self.tool_parser):
            raise ValueError("tool parser 名称必须由字母、数字或下划线组成")

    def resolve(self, name=None):
        """返回 (候选名, 路径)；name 为空时使用第一个候选。"""
        if name is None:
            return self.models[0]
        for entry in self.models:
            if entry[0] == name:
                return entry
        raise ValueError("未知候选模型：" + name)


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    pgid: int
    sid: int
    starttime: int
    state: str
    argv: tuple[str, ...] = ()

    @property
    def identity(self):
        return {key: getattr(self, key) for key in ("pid", "pgid", "sid", "starttime")}

    @property
    def alive(self):
        # 僵尸已不能执行或持有监听套接字，不应阻止再次启动。
        return self.state not in ("Z", "X", "x")


def parse_stat(text: str, argv=()) -> Process:
    """comm 可包含空格和右括号，不能对整行直接 split。"""
    left, right = text.find("("), text.rfind(")")
    if left < 1 or right <= left:
        raise ValueError("无法解析进程 stat")
    fields = text[right + 1:].split()
    if len(fields) < 20:
        raise ValueError("进程 stat 字段不完整")
    return Process(int(text[:left].strip()), int(fields[1]), int(fields[2]),
                   int(fields[3]), int(fields[19]), fields[0], tuple(argv))


class ProcFS:
    def __init__(self, root=Path("/proc")):
        self.root = Path(root)

    def boot_id(self):
        value = (self.root / "sys/kernel/random/boot_id").read_text().strip()
        if not value:
            raise Unsafe("无法获取内核启动身份")
        return value

    def read(self, pid):
        directory = self.root / str(pid)
        try:
            before = parse_stat((directory / "stat").read_text())
            argv = tuple(os.fsdecode(arg) for arg in
                         (directory / "cmdline").read_bytes().split(b"\0") if arg)
            after = parse_stat((directory / "stat").read_text(), argv)
        except (FileNotFoundError, ProcessLookupError):
            return None
        if before.identity != after.identity:
            raise Unsafe("读取期间进程身份发生变化")
        return after

    def scan(self):
        result = {}
        for directory in self.root.iterdir():
            if directory.name.isdecimal():
                process = self.read(int(directory.name))
                if process is not None:
                    result[process.pid] = process
        return result

    def _inodes(self, port):
        inodes = set()
        for name in ("tcp", "tcp6"):
            path = self.root / "net" / name
            try:
                rows = path.read_text().splitlines()[1:]
            except FileNotFoundError:
                if name == "tcp6":
                    continue
                raise
            for row in rows:
                fields = row.split()
                if len(fields) < 10:
                    raise Unsafe("TCP 监听信息不完整")
                if fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                    inodes.add(fields[9])
        return inodes

    def listeners(self, port, processes):
        inodes = self._inodes(port)
        if not inodes:
            return set()
        found = set()
        owners = set()
        for pid in processes:
            try:
                descriptors = tuple((self.root / str(pid) / "fd").iterdir())
            except (FileNotFoundError, ProcessLookupError):
                continue
            for descriptor in descriptors:
                try:
                    link = os.readlink(descriptor)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if link.startswith("socket:[") and link.endswith("]"):
                    inode = link[8:-1]
                    if inode in inodes:
                        found.add(inode)
                        owners.add(pid)
        if found != inodes or self._inodes(port) != inodes:
            raise Unsafe("监听端口所有者无法完整核验，请重试")
        return owners

    def started_at(self, process):
        for line in (self.root / "stat").read_text().splitlines():
            if line.startswith("btime "):
                return int(line.split()[1]) + process.starttime / os.sysconf("SC_CLK_TCK")
        raise Unsafe("无法获取进程启动时间")


def matches_vllm(process, model_name, model_path, port):
    args = process.argv
    if args and args[0] in PYTHON_BINS:
        args = args[1:]
    if len(args) < 3 or args[:3] != (VLLM_BIN, "serve", model_path):
        return False
    options = args[3:]
    # 拒绝重复参数及 served-model-name 的多个别名，避免解析歧义。
    for option, expected in (("--port", str(port)),
                             ("--served-model-name", model_name)):
        values = []
        for index, value in enumerate(options):
            if value == option:
                if index + 1 >= len(options):
                    return False
                values.append(options[index + 1])
                if index + 2 < len(options) and not options[index + 2].startswith("--"):
                    return False
            elif value.startswith(option + "="):
                values.append(value[len(option) + 1:])
                if index + 1 < len(options) and not options[index + 1].startswith("--"):
                    return False
        if values != [expected]:
            return False
    return True


def matches_bash(process, start_script, model_path, port):
    return process.argv == ("/bin/bash", start_script, model_path, str(port))


def child_environment(tool_parser="hermes"):
    # 白名单而非删几个密钥；不转交整份网关或 Windows 环境。
    allowed = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
               "LD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(PATH="/opt/venvs/vllm/bin:/usr/local/sbin:/usr/local/bin:"
                    "/usr/sbin:/usr/bin:/sbin:/bin", MAX_LEN="8192",
               GPU_UTIL="0.8", KV_DTYPE="auto", TOOL_PARSER=tool_parser)
    return env


def _flock(fd, unlock=False):
    # Windows 仅导入及 mock 测试时不能依赖 fcntl。
    import fcntl
    operation = fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB
    try:
        fcntl.flock(fd, operation)
    except BlockingIOError as exc:
        raise Busy("已有启停操作正在执行") from exc


def _open(path, flags, mode=0o600):
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)


class Controller:
    def __init__(self, config, runtime=RUNTIME_DIR, proc=None):
        self.config = config
        self.target = None  # 本次 start/switch 的目标 (候选名, 路径)
        self.runtime = Path(runtime)
        self.proc = proc if proc is not None else ProcFS()
        self.state_path = self.runtime / "state.json"
        self.log_path = self.runtime / "vllm.log"
        self.lock_path = self.runtime / "control.lock"

    def _check_runtime(self):
        if self.runtime.is_symlink():
            raise Unsafe("运行目录不能是符号链接")

    def _load(self):
        self._check_runtime()
        try:
            with os.fdopen(_open(self.state_path, os.O_RDONLY), "r", encoding="utf-8") as file:
                record = json.load(file)
        except FileNotFoundError:
            return None
        if not isinstance(record, dict) or record.get("version") != 1:
            raise Unsafe("托管状态格式无效")
        model = record.get("model")
        if (not isinstance(model, dict) or not isinstance(model.get("name"), str)
                or not isinstance(model.get("path"), str)):
            raise Unsafe("托管状态缺少模型归属")
        if (model["name"], model["path"]) not in self.config.models:
            raise Unsafe("现有托管实例不在候选模型列表中，拒绝控制")
        if (record.get("port") != self.config.port
                or record.get("start_script") != self.config.start_script):
            raise Unsafe("现有托管记录与当前配置不一致")
        if record.get("phase") not in ("present", "stopping", "stopped", "failed"):
            raise Unsafe("托管状态阶段无效")
        if not isinstance(record.get("boot_id"), str) or not record["boot_id"]:
            raise Unsafe("托管状态缺少启动身份")
        stamp = record.get("started_at")
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp < 0:
            raise Unsafe("托管状态启动时间无效")
        members = record.get("members")
        if not isinstance(members, list) or type(record.get("spawned")) is not bool:
            raise Unsafe("托管状态成员无效")
        for member in members:
            if not isinstance(member, dict) or any(
                type(member.get(key)) is not int or member[key] < (0 if key == "starttime" else 2)
                for key in ("pid", "pgid", "sid", "starttime")
            ):
                raise Unsafe("托管状态成员身份无效")
        if len({m["pid"] for m in members}) != len(members):
            raise Unsafe("托管状态存在重复成员")
        if record.get("pid") is None:
            if members or record.get("pgid") is not None or record.get("starttime") is not None:
                raise Unsafe("托管状态缺少主进程身份")
        else:
            pid = record["pid"]
            if type(pid) is not int or pid <= 1 or record.get("pgid") != pid:
                raise Unsafe("托管主进程不是独立进程组")
            if not any(m == {"pid": pid, "pgid": pid, "sid": pid,
                             "starttime": record.get("starttime")} for m in members):
                raise Unsafe("托管记录缺少主进程原始身份")
            if any(m["pgid"] != pid or m["sid"] != pid for m in members):
                raise Unsafe("托管成员不属于独立会话")
        return record

    def _save(self, record):
        fd, temporary = tempfile.mkstemp(prefix=".state-", dir=self.runtime)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(record, file, ensure_ascii=False, allow_nan=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.state_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _tail(self):
        try:
            with os.fdopen(_open(self.log_path, os.O_RDONLY), "rb") as file:
                file.seek(0, os.SEEK_END)
                file.seek(max(0, file.tell() - LOG_LIMIT))
                raw = file.read(LOG_LIMIT)
            return raw.decode("utf-8", "replace").encode("utf-8")[-LOG_LIMIT:].decode("utf-8", "ignore")
        except OSError:
            return ""

    def _current(self, record, state):
        # 仅当目标实例仍被托管（present/stopping）时报告运行中的候选名。
        if state in ("present", "stopping") and record and isinstance(record.get("model"), dict):
            return record["model"].get("name")
        return None

    def _snapshot(self, state, detail, record=None, pid=None, can_stop=False, **extra):
        return dict(state=state, pid=pid, current=self._current(record, state),
                    started_at=record["started_at"] if record else None,
                    can_start=state in ("stopped", "failed"), can_stop=can_stop,
                    detail=detail, log_tail=self._tail(), **extra)

    def _record(self, leader, members, boot, model, spawned=False, started_at=None):
        return dict(version=1, model={"name": model[0], "path": model[1]},
                    port=self.config.port, start_script=self.config.start_script,
                    boot_id=boot,
                    pid=leader.pid if leader else None, pgid=leader.pgid if leader else None,
                    starttime=leader.starttime if leader else None, spawned=spawned,
                    started_at=started_at if started_at is not None else self.proc.started_at(leader),
                    members=[p.identity for p in members], phase="present")

    def _leader_matches(self, record, process):
        model = record["model"]
        return (matches_vllm(process, model["name"], model["path"], record["port"])
                or record["spawned"] and matches_bash(
                    process, record["start_script"], model["path"], record["port"]))

    def _candidate_of(self, process):
        """进程匹配任一候选时返回 (name, path)，否则 None。"""
        for entry in self.config.models:
            if matches_vllm(process, entry[0], entry[1], self.config.port):
                return entry
        return None

    def _shell_of(self, process):
        for entry in self.config.models:
            if matches_bash(process, self.config.start_script, entry[1], self.config.port):
                return entry
        return None

    def _members(self, record, processes, boot):
        if record["boot_id"] != boot:
            raise Unsafe("内核启动身份已变化，拒绝使用旧进程记录")
        pgid = record["pgid"]
        if pgid is None:
            return []
        known = {m["pid"]: m for m in record["members"]}
        for pid, identity in known.items():
            process = processes.get(pid)
            if process is not None and process.identity != identity:
                raise Unsafe("记录中的 PID 已复用或进程组身份变化")
        group = [p for p in processes.values() if p.alive and (p.pgid == pgid or p.sid == pgid)]
        if any(p.pgid != pgid or p.sid != pgid for p in group):
            raise Unsafe("会话存在脱离目标进程组的残留成员")
        leader = processes.get(record["pid"])
        if leader is not None and leader.alive:
            if not self._leader_matches(record, leader):
                raise Unsafe("主进程命令不再匹配目标实例")
        else:
            leader = None
        for process in group:
            if process.pid in known:
                continue
            if leader is None:
                raise Unsafe("主进程已消失，存在未登记的孤儿成员")
            current, visited = process, set()
            while current.pid != leader.pid:
                if current.pid in visited:
                    raise Unsafe("进程父子关系存在循环")
                visited.add(current.pid)
                parent = processes.get(current.ppid)
                if (parent is None or parent.pgid != pgid or parent.sid != pgid or
                        parent.starttime > current.starttime):
                    raise Unsafe("进程组包含非目标树成员")
                current = parent
        # 捕获已经 setsid/setpgid 的子孙，不能只检查原组。
        descendants = {record["pid"]} | {p.pid for p in group}
        changed = True
        while changed:
            added = {p.pid for p in processes.values() if p.alive and p.ppid in descendants} - descendants
            changed = bool(added)
            descendants.update(added)
        if any(p.alive and p.pid in descendants and (p.pgid != pgid or p.sid != pgid)
               for p in processes.values()):
            raise Unsafe("目标树存在脱离会话或进程组的成员")
        return group

    def _inspect(self):
        record = self._load()
        boot = self.proc.boot_id()
        processes = self.proc.scan()
        owners = self.proc.listeners(self.config.port, processes)
        candidates = [p for p in processes.values() if p.alive and self._candidate_of(p)]
        shells = [p for p in processes.values() if p.alive and self._shell_of(p)]
        members = self._members(record, processes, boot) if record else []
        if not members:
            if owners or candidates or shells:
                if record and record["phase"] == "stopping":
                    raise Unsafe("停止期间出现未登记实例或端口占用")
                if shells or len(candidates) != 1:
                    raise Unsafe("端口或启动候选存在冲突，不能创建新实例")
                leader = candidates[0]
                if leader.pid <= 1 or leader.pgid != leader.pid or leader.sid != leader.pid:
                    raise Unsafe("现有实例不是独立会话及进程组")
                record = self._record(leader, [leader], boot, self._candidate_of(leader))
                members = self._members(record, processes, boot)
            else:
                state = "failed" if record and record["phase"] != "stopped" else "stopped"
                detail = "实例进程已退出，可重试启动" if state == "failed" else "服务已停止"
                return self._snapshot(state, detail, record), record, []
        ids = {p.pid for p in members}
        if not owners.issubset(ids) or any(p.pid not in ids for p in candidates + shells):
            raise Unsafe("监听端口或启动候选不属于唯一目标实例")
        leader = processes.get(record["pid"])
        if owners and leader is not None and leader.alive and not any(
            matches_vllm(processes[pid], record["model"]["name"],
                         record["model"]["path"], record["port"])
            for pid in owners
        ):
            raise Unsafe("真实监听者的命令无法确认为目标 vLLM")
        # 记录历史成员，不因其退出而丢失 PID 复用和孤儿核验依据。
        known = {m["pid"]: m for m in record["members"]}
        known.update({p.pid: p.identity for p in members})
        record["members"] = list(known.values())
        state = "stopping" if record["phase"] == "stopping" else "present"
        detail = "正在停止目标实例" if state == "stopping" else "已确认目标进程；就绪状态由网关检查"
        if leader is None or not leader.alive:
            detail = "主进程已退出，仍有身份可核验的实例成员"
        return self._snapshot(state, detail, record,
                              pid=leader.pid if leader and leader.alive else None,
                              can_stop=True), record, members

    @contextmanager
    def _lock(self):
        self._check_runtime()
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        with os.fdopen(_open(self.lock_path, os.O_CREAT | os.O_RDWR), "r+b") as file:
            _flock(file.fileno())
            try:
                yield
            finally:
                _flock(file.fileno(), unlock=True)

    def _busy(self):
        # 查询只打开已存在的锁文件，不建目录或创建任何文件。
        try:
            fd = _open(self.lock_path, os.O_RDONLY)
        except FileNotFoundError:
            return False
        with os.fdopen(fd, "rb") as file:
            try:
                _flock(file.fileno())
            except Busy:
                return True
            _flock(file.fileno(), unlock=True)
        return False

    def _busy_snapshot(self):
        record = self._load()
        state = "stopping" if record and record["phase"] == "stopping" else "conflict"
        return self._snapshot(state, "已有启停操作正在执行，请稍后查询", record)

    def status(self):
        try:
            if self._busy():
                return self._busy_snapshot()
            snapshot, _, _ = self._inspect()
            if self._busy():
                return self._busy_snapshot()
            return snapshot
        except Unsafe as exc:
            return self._snapshot("conflict", str(exc))
        except (OSError, ValueError, ImportError) as exc:
            return self._snapshot("unavailable", "无法读取 Linux 运行状态：" + str(exc))

    def _start(self, snapshot, record, members):
        if snapshot["state"] == "present":
            self._save(record)
            return dict(snapshot, accepted=False)
        if snapshot["state"] == "stopping":
            return dict(snapshot, can_stop=False, accepted=False)
        _, path = self.target
        started_at = time.time()
        with os.fdopen(_open(self.log_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC), "wb") as log:
            child = subprocess.Popen(
                ["/bin/bash", self.config.start_script, path, str(self.config.port)],
                start_new_session=True, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, close_fds=True,
                env=child_environment(self.config.tool_parser),
            )
            self._accepted = True
        # Popen 返回时 setsid/exec 已完成；bash 到 vLLM 的过渡保持相同内核身份。
        leader = self.proc.read(child.pid)
        if leader is None or not leader.alive:
            child.poll()
            record = self._record(None, [], self.proc.boot_id(), self.target, True, started_at)
            record["phase"] = "failed"
            self._save(record)
            return self._snapshot("failed", "启动进程已退出，请查看日志", record, accepted=True)
        record = self._record(leader, [leader], self.proc.boot_id(), self.target, True, started_at)
        self._save(record)
        snapshot, record, _ = self._inspect()
        self._save(record)
        return dict(snapshot, accepted=True)

    def _wait(self, deadline):
        while True:
            snapshot, record, members = self._inspect()
            if not members:
                record["phase"] = "stopped"
                self._save(record)
                return self._snapshot("stopped", "API、实例成员及监听端口均已退出", record), record, []
            self._save(record)
            if time.monotonic() >= deadline:
                return snapshot, record, members
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

    def _kill_member(self, process, record):
        # 不回退到按 PID 的强制 kill，避免核验后 PID 被复用的窗口。
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise Unsafe("系统缺少 pidfd，拒绝不安全的强制终止")
        try:
            fd = os.pidfd_open(process.pid, 0)
        except ProcessLookupError:
            return
        try:
            current = self.proc.read(process.pid)
            if current is None or not current.alive:
                return
            if self.proc.boot_id() != record["boot_id"] or current.identity != process.identity:
                raise Unsafe("强制终止前成员身份已变化")
            signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)

    def _stop(self, snapshot, record, members):
        if not members:
            if record:
                record["phase"] = "stopped"
                self._save(record)
            return self._snapshot("stopped", "服务已停止", record, accepted=False)
        record["phase"] = "stopping"
        self._save(record)
        # 发信号前重新扫描整个会话及监听者，持久化最新成员身份。
        _, record, members = self._inspect()
        self._save(record)
        if not members:
            record["phase"] = "stopped"
            self._save(record)
            return self._snapshot("stopped", "服务已停止", record, accepted=False)
        for process in members:
            current = self.proc.read(process.pid)
            if current is None or current.identity != process.identity:
                raise Unsafe("温和停止前成员身份已变化，请重试")
        if self.proc.boot_id() != record["boot_id"]:
            raise Unsafe("温和停止前内核身份已变化")
        try:
            os.killpg(record["pgid"], signal.SIGTERM)
        except ProcessLookupError:
            _, record, members = self._inspect()
            if members:
                raise Unsafe("进程组已变化但仍有成员，拒绝继续停止")
            record["phase"] = "stopped"
            self._save(record)
            return self._snapshot("stopped", "发出信号前实例已退出", record, accepted=False)
        self._accepted = True
        snapshot, record, members = self._wait(time.monotonic() + TERM_TIMEOUT)
        if not members:
            return dict(snapshot, accepted=True)
        # 超时后逐个重新核验；孤儿、复用 PID、陌生组成员使整个操作失败关闭。
        for process in members:
            _, latest, current_members = self._inspect()
            self._save(latest)
            current = next((p for p in current_members if p.pid == process.pid), None)
            if current is not None:
                if current.identity != process.identity:
                    raise Unsafe("超时后成员身份发生变化")
                self._kill_member(current, latest)
        snapshot, record, members = self._wait(time.monotonic() + KILL_TIMEOUT)
        if members:
            return self._snapshot("conflict", "停止超时，仍有实例成员，禁止再次启动", record,
                                  pid=snapshot["pid"], can_stop=True, accepted=True)
        return dict(snapshot, accepted=True)

    def _switch(self, snapshot, record, members):
        """停旧启新的原子切换；当前实例即目标时幂等。"""
        if snapshot["state"] == "stopping":
            return dict(snapshot, can_stop=False, accepted=False)
        if not members:
            return self._start(snapshot, record, members)
        model = record.get("model") if record else None
        if model == {"name": self.target[0], "path": self.target[1]}:
            return dict(snapshot, accepted=False)
        stop_result = self._stop(snapshot, record, members)
        if stop_result["state"] != "stopped":
            return stop_result
        snapshot, record, members = self._inspect()
        return self._start(snapshot, record, members)

    def run(self, action, model=None):
        if action == "status":
            return self.status()
        self._accepted = False
        try:
            if action not in ("start", "stop", "switch"):
                raise ValueError("不支持的控制动作")
            self.target = self.config.resolve(model) if action in ("start", "switch") else None
            with self._lock():
                snapshot, record, members = self._inspect()
                if action == "stop":
                    return self._stop(snapshot, record, members)
                if action == "switch":
                    return self._switch(snapshot, record, members)
                return self._start(snapshot, record, members)
        except Busy:
            try:
                return dict(self._busy_snapshot(), accepted=False)
            except (Unsafe, OSError, ValueError):
                return self._snapshot("conflict", "控制锁被占用，且状态无法核验", accepted=False)
        except Unsafe as exc:
            return self._snapshot("conflict", str(exc), accepted=self._accepted)
        except (OSError, ValueError, ImportError) as exc:
            return self._snapshot("unavailable", "控制操作不可用：" + str(exc), accepted=self._accepted)


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("命令参数无效：" + message)


def parse_models(values):
    entries = []
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError("候选模型参数必须为 name=path 形式：" + value)
        entries.append((name, path))
    return tuple(entries)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = JsonArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("action", choices=("status", "start", "stop", "switch"))
    parser.add_argument("--models", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--model")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--start-script", required=True)
    parser.add_argument("--tool-parser", default="hermes")
    exit_code = 0
    try:
        args = parser.parse_args(argv)
        config = Config(parse_models(args.models), args.port, args.start_script,
                        args.tool_parser)
        result = Controller(config).run(args.action, args.model)
    except Exception as exc:
        # CLI 无论成功或失败都只输出一个 JSON 对象，不向 stdout 打日志或 traceback。
        result = dict(state="unavailable", pid=None, current=None, started_at=None,
                      can_start=False, can_stop=False,
                      detail="控制助手不可用：" + str(exc), log_tail="")
        if argv and argv[0] in ("start", "stop", "switch"):
            result["accepted"] = False
        exit_code = 2
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
