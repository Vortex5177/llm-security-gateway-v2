"""Linux 助手的纯 mock 测试：不访问真实 /proc，不调用真实进程或信号。"""

from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from app import wsl_vllm_control as control


ORIGINAL_FLOCK = control._flock


@pytest.fixture(autouse=True)
def forbid_real_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("测试禁止真实进程操作")

    monkeypatch.setattr(control.subprocess, "Popen", forbidden)
    for name in ("kill", "killpg", "pidfd_open"):
        monkeypatch.setattr(control.os, name, forbidden, raising=False)
    monkeypatch.setattr(control.signal, "pidfd_send_signal", forbidden, raising=False)
    monkeypatch.setattr(control.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(control, "_flock", lambda *args, **kwargs: None)
    monkeypatch.setattr(control.ProcFS, "__init__", lambda self, root: setattr(self, "root", Path(root)))


@pytest.fixture
def config():
    return control.Config((
        ("qwen3-1.7b", "/opt/models/Qwen3-1.7B"),
        ("qwen3-1.7b-lab", "/opt/models/Qwen3-1.7B-lab"),
    ), 8200, "/opt/scripts/start-vllm.sh")


def api(config, pid=140, **kwargs):
    name, path = config.resolve()
    argv = (control.PYTHON_BINS[1], control.VLLM_BIN, "serve", path,
            "--served-model-name", name, "--port", str(config.port),
            "--max-model-len", "8192", "--gpu-memory-utilization", "0.8",
            "--kv-cache-dtype", "auto", "--tool-call-parser", "hermes")
    process = control.Process(pid, 1, pid, pid, 1000, "S", argv)
    return replace(process, **kwargs)


def engine(leader, pid=141, **kwargs):
    process = control.Process(pid, leader.pid, leader.pgid, leader.sid,
                              leader.starttime + 10, "S", ("VLLM::EngineCore",))
    return replace(process, **kwargs)


class FakeProc:
    def __init__(self):
        self.processes = {}
        self.owners = set()
        self.boot = "boot-A"
        self.scans = 0

    def boot_id(self):
        return self.boot

    def read(self, pid):
        return self.processes.get(pid)

    def scan(self):
        self.scans += 1
        return dict(self.processes)

    def listeners(self, port, processes):
        return set(self.owners)

    def started_at(self, process):
        return 1_700_000_000 + process.starttime / 100

    def add(self, *processes):
        self.processes.update({process.pid: process for process in processes})

    def remove(self, *pids):
        for pid in pids:
            self.processes.pop(pid, None)
            self.owners.discard(pid)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.hook = lambda: None

    def sleep(self, seconds):
        assert 0 < seconds <= 0.1
        self.now += 1.0
        self.hook()


@pytest.fixture
def rig(config, tmp_path, monkeypatch):
    proc = FakeProc()
    clock = FakeClock()
    monkeypatch.setattr(control.time, "time", lambda: 1_700_000_100.0)
    monkeypatch.setattr(control.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(control.time, "sleep", clock.sleep)
    controller = control.Controller(config, tmp_path / "runtime", proc)
    return SimpleNamespace(controller=controller, proc=proc, config=config, clock=clock,
                           root=tmp_path, monkeypatch=monkeypatch)


def adopt(rig, *members):
    leader = api(rig.config)
    rig.proc.add(leader, *members)
    rig.proc.owners = {leader.pid}
    result = rig.controller.run("start")
    assert result["state"] == "present" and result["accepted"] is False
    return leader


def fake_spawn(rig, *, exited=False, wrong_group=False):
    calls = []

    def spawn(argv, **kwargs):
        calls.append((argv, kwargs))
        if not exited:
            leader = api(rig.config, argv=tuple(argv), pgid=99 if wrong_group else 140)
            rig.proc.add(leader)
        kwargs["stdout"].write("本次启动日志".encode())
        return SimpleNamespace(pid=140, poll=lambda: 1 if exited else None)

    rig.monkeypatch.setattr(control.subprocess, "Popen", spawn)
    return calls


def fake_signals(rig, *, term=None, kill=None, opened=None):
    events = []
    handles = {}
    path = rig.root / "mock-pidfd"
    path.write_bytes(b"")

    def killpg(pgid, sig):
        events.append(("group", pgid, sig, rig.clock.now))
        if term:
            term()

    def pidfd_open(pid, flags):
        assert flags == 0
        fd = os.open(path, os.O_RDONLY)
        handles[fd] = pid
        if opened:
            opened(pid)
        return fd

    def send(fd, sig, info, flags):
        assert info is None and flags == 0
        pid = handles[fd]
        events.append(("member", pid, sig, rig.clock.now))
        if kill:
            kill(pid)

    rig.monkeypatch.setattr(control.os, "killpg", killpg)
    rig.monkeypatch.setattr(control.os, "pidfd_open", pidfd_open)
    rig.monkeypatch.setattr(control.signal, "pidfd_send_signal", send)
    return events


def stat_line(pid=140, comm="python (worker) )", starttime=123456):
    return f"{pid} ({comm}) S 1 140 140 " + "0 " * 15 + str(starttime) + " 0 0\n"


def test_parse_stat_handles_spaces_and_parentheses():
    process = control.parse_stat(stat_line(), ("vllm",))
    assert process.identity == {"pid": 140, "pgid": 140, "sid": 140, "starttime": 123456}
    assert process.ppid == 1 and process.state == "S" and process.argv == ("vllm",)


@pytest.mark.parametrize("text", ["", "140 python S", "140 (foo) S 1", "bad (foo) " + "0 " * 30])
def test_parse_stat_rejects_truncated_or_invalid(text):
    with pytest.raises(ValueError):
        control.parse_stat(text)


def test_proc_reads_identity_cmdline_boot_and_start_time(tmp_path, monkeypatch):
    directory = tmp_path / "140"
    directory.mkdir()
    (directory / "stat").write_text(stat_line())
    (directory / "cmdline").write_bytes(b"/bin/python\0argument with space\0")
    boot = tmp_path / "sys/kernel/random"
    boot.mkdir(parents=True)
    (boot / "boot_id").write_text("test-boot\n")
    (tmp_path / "stat").write_text("cpu 0\nbtime 1700000000\n")
    monkeypatch.setattr(control.os, "sysconf", lambda name: 100, raising=False)
    proc = control.ProcFS(tmp_path)
    process = proc.read(140)
    assert process.argv == ("/bin/python", "argument with space")
    assert proc.boot_id() == "test-boot"
    assert proc.started_at(process) == 1_700_001_234.56
    assert proc.scan() == {140: process}
    assert proc.read(999) is None


def test_proc_read_rejects_identity_change(tmp_path, monkeypatch):
    directory = tmp_path / "140"
    directory.mkdir()
    (directory / "stat").write_text(stat_line())
    (directory / "cmdline").write_bytes(b"python\0")
    original = control.parse_stat
    counter = iter((123, 456))
    monkeypatch.setattr(control, "parse_stat", lambda text, argv=(): replace(
        original(text, argv), starttime=next(counter)))
    with pytest.raises(control.Unsafe, match="身份发生变化"):
        control.ProcFS(tmp_path).read(140)


def tcp_row(inode, port=8200, state="0A", address="0100007F"):
    return f"0: {address}:{port:04X} 00000000:0000 {state} 0:0 0:0 0 0 0 {inode}\n"


@pytest.mark.parametrize("ipv6", [False, True])
def test_listener_exact_port_inode_owner(tmp_path, monkeypatch, config, ipv6):
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text("header\n" + tcp_row("999", 8201) + tcp_row("888", state="01"))
    name = "tcp6" if ipv6 else "tcp"
    (net / name).write_text("header\n" + tcp_row("123"))
    descriptors = tmp_path / "140/fd"
    descriptors.mkdir(parents=True)
    (descriptors / "3").write_text("")
    monkeypatch.setattr(control.os, "readlink", lambda path: "socket:[123]")
    assert control.ProcFS(tmp_path).listeners(8200, {140: api(config)}) == {140}


def test_listener_unknown_owner_is_unsafe(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net/tcp").write_text("header\n" + tcp_row("123"))
    with pytest.raises(control.Unsafe, match="所有者"):
        control.ProcFS(tmp_path).listeners(8200, {})


@pytest.mark.parametrize("change", [
    lambda a: ("/usr/bin/python3",) + a[1:],
    lambda a: (a[0], "/tmp/vllm") + a[2:],
    lambda a: a[:2] + ("bench",) + a[3:],
    lambda a: a[:3] + ("/opt/models/Qwen3-1.7B-copy",) + a[4:],
    lambda a: tuple("other-model" if x == "qwen3-1.7b" else x for x in a),
    lambda a: tuple("8201" if x == "8200" else x for x in a),
    lambda a: a + ("--port", "8200"),
    lambda a: a + ("--served-model-name=qwen3-1.7b",),
    lambda a: a[:6] + ("another-alias",) + a[6:],
    lambda a: a[:7],
])
def test_precise_matching_rejects_lookalikes(config, change):
    process = api(config)
    name, path = config.resolve()
    assert not control.matches_vllm(replace(process, argv=change(process.argv)),
                                    name, path, config.port)


def test_precise_matching_supports_direct_and_equals_options(config):
    name, path = config.resolve()
    assert control.matches_vllm(api(config), name, path, config.port)
    direct = (control.VLLM_BIN, "serve", path,
              "--port=8200", "--served-model-name=" + name)
    assert control.matches_vllm(api(config, argv=direct), name, path, config.port)
    assert not control.matches_vllm(api(config, argv=direct + ("extra-alias",)),
                                    name, path, config.port)


def test_precise_matching_distinguishes_candidates(config):
    name, path = config.resolve()
    lab_name, lab_path = config.resolve("qwen3-1.7b-lab")
    lab = api(config, argv=(control.PYTHON_BINS[1], control.VLLM_BIN, "serve", lab_path,
                            "--served-model-name", lab_name, "--port", "8200"))
    assert control.matches_vllm(lab, lab_name, lab_path, config.port)
    assert not control.matches_vllm(lab, name, path, config.port)


def test_status_does_not_create_runtime_or_write(rig):
    assert not rig.controller.runtime.exists()
    for method in ("_save", "_lock"):
        rig.monkeypatch.setattr(rig.controller, method, lambda *a: pytest.fail("查询发生写入"))
    rig.monkeypatch.setattr(Path, "mkdir", lambda *a, **kw: pytest.fail("查询创建了目录"))
    result = rig.controller.status()
    assert result["state"] == "stopped" and result["can_start"] and not result["can_stop"]
    assert not rig.controller.runtime.exists() and "accepted" not in result


def test_status_discovers_without_registering_or_health_probe(rig):
    leader = api(rig.config)
    rig.proc.add(leader, engine(leader))
    rig.proc.owners = {leader.pid}
    result = rig.controller.status()
    assert result["state"] == "present" and result["can_stop"]
    assert result["pid"] == leader.pid and result["started_at"] == rig.proc.started_at(leader)
    assert result["current"] == "qwen3-1.7b"
    assert not rig.controller.runtime.exists()


def test_status_existing_record_is_read_only(rig):
    adopt(rig)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in rig.controller.runtime.iterdir()}
    original_open = control._open

    def read_only(path, flags, mode=0o600):
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_RDWR | os.O_WRONLY)
        return original_open(path, flags, mode)

    rig.monkeypatch.setattr(control, "_open", read_only)
    rig.monkeypatch.setattr(rig.controller, "_save", lambda *a: pytest.fail("查询改写状态"))
    assert rig.controller.status()["state"] == "present"
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in rig.controller.runtime.iterdir()}
    assert after == before


@pytest.mark.parametrize("kind", ["port", "two_candidates", "foreign_group", "not_session", "escaped"])
def test_conflicts_never_spawn_or_signal(rig, kind):
    leader = api(rig.config)
    rig.proc.add(leader)
    if kind == "port":
        rig.proc.add(api(rig.config, pid=900, argv=("unrelated-server",)))
        rig.proc.owners = {900}
    elif kind == "two_candidates":
        rig.proc.add(api(rig.config, pid=200))
    elif kind == "foreign_group":
        rig.proc.add(engine(leader, ppid=1))
    elif kind == "not_session":
        rig.proc.add(replace(leader, sid=2))
    else:
        rig.proc.add(engine(leader, pgid=141, sid=141))
    for action in ("status", "start", "stop", "switch"):
        result = rig.controller.run(action)
        assert result["state"] == "conflict"
        assert not result["can_start"] and not result["can_stop"]


def test_unregistered_bash_blocks_duplicate_spawn(rig):
    args = ("/bin/bash", rig.config.start_script, rig.config.resolve()[1], "8200")
    rig.proc.add(api(rig.config, argv=args))
    assert rig.controller.run("start")["state"] == "conflict"


def test_start_without_listener_adopts_exact_candidate_idempotently(rig):
    leader = api(rig.config)
    rig.proc.add(leader)
    result = rig.controller.run("start")
    assert result["state"] == "present" and result["accepted"] is False
    before = rig.controller.state_path.read_bytes()
    assert rig.controller.run("start")["accepted"] is False
    assert rig.controller.state_path.read_bytes() == before


def test_start_session_fixed_arguments_clean_environment_and_log_overwrite(rig):
    rig.controller.runtime.mkdir()
    rig.controller.log_path.write_text("上一次启动")
    for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "HF_TOKEN", "BASH_ENV", "ENV",
                 "PYTHONPATH", "LD_PRELOAD", "WSLENV"):
        rig.monkeypatch.setenv(name, "secret-value")
    rig.monkeypatch.setenv("MAX_LEN", "1")
    rig.monkeypatch.setenv("GPU_UTIL", "1")
    rig.monkeypatch.setenv("KV_DTYPE", "fp8")
    calls = fake_spawn(rig)
    result = rig.controller.run("start")
    assert result["state"] == "present" and result["accepted"] is True
    assert result["started_at"] == 1_700_000_100.0
    assert result["log_tail"] == "本次启动日志"
    argv, kwargs = calls[0]
    assert argv == ["/bin/bash", rig.config.start_script, rig.config.resolve()[1], "8200"]
    assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
    assert kwargs["stdin"] == control.subprocess.DEVNULL
    assert kwargs["stderr"] == control.subprocess.STDOUT and "shell" not in kwargs
    assert kwargs["env"]["MAX_LEN"] == "8192"
    assert kwargs["env"]["GPU_UTIL"] == "0.8" and kwargs["env"]["KV_DTYPE"] == "auto"
    assert kwargs["env"]["TOOL_PARSER"] == "hermes"
    assert "secret-value" not in kwargs["env"].values()
    record = json.loads(rig.controller.state_path.read_text())
    assert record["model"] == {"name": "qwen3-1.7b", "path": "/opt/models/Qwen3-1.7B"}
    assert record["port"] == 8200 and record["start_script"] == rig.config.start_script
    assert record["pid"] == record["pgid"] == 140
    assert record["boot_id"] == "boot-A" and record["starttime"] == 1000
    assert record["members"] == [rig.proc.processes[140].identity]
    assert list(rig.controller.runtime.glob(".state-*")) == []
    assert rig.controller.status()["state"] == "present"
    rig.proc.add(api(rig.config))
    rig.proc.owners = {140}
    assert rig.controller.status()["state"] == "present"
    assert rig.controller.run("start")["accepted"] is False and len(calls) == 1


def test_start_session_uses_configured_tool_parser_environment(rig):
    rig.monkeypatch.setattr(rig.controller, "config",
                            replace(rig.config, tool_parser="qwen3_xml"))
    calls = fake_spawn(rig)
    result = rig.controller.run("start")
    assert result["state"] == "present" and result["accepted"] is True
    assert calls[0][1]["env"]["TOOL_PARSER"] == "qwen3_xml"


def test_child_environment_defaults_to_hermes():
    assert control.child_environment()["TOOL_PARSER"] == "hermes"
    assert control.child_environment("qwen3_xml")["TOOL_PARSER"] == "qwen3_xml"


def test_spawned_but_invalid_group_still_reports_accepted(rig):
    fake_spawn(rig, wrong_group=True)
    result = rig.controller.run("start")
    assert result["state"] == "conflict" and result["accepted"] is True
    assert not result["can_start"] and not result["can_stop"]


def test_spawn_exits_immediately_and_can_retry(rig):
    fake_spawn(rig, exited=True)
    result = rig.controller.run("start")
    assert result["state"] == "failed" and result["accepted"] and result["can_start"]
    assert rig.controller.status()["state"] == "failed"
    fake_spawn(rig)
    assert rig.controller.run("start")["state"] == "present"


@pytest.mark.parametrize("change", ["leader_reused", "member_reused", "boot", "unknown_orphan", "group_changed"])
def test_identity_changes_block_all_control(rig, change):
    leader = api(rig.config)
    child = engine(leader)
    adopt(rig, child)
    if change == "leader_reused":
        rig.proc.add(replace(leader, starttime=9999))
    elif change == "member_reused":
        rig.proc.add(replace(child, starttime=9999))
    elif change == "boot":
        rig.proc.boot = "boot-B"
    elif change == "group_changed":
        rig.proc.add(replace(child, pgid=999))
    else:
        rig.proc.remove(leader.pid, child.pid)
        rig.proc.add(engine(leader, pid=142, ppid=1))
    for action in ("status", "start", "stop", "switch"):
        result = rig.controller.run(action)
        assert result["state"] == "conflict" and not result["can_stop"] and not result["can_start"]


def test_registered_orphan_is_present_and_can_be_safely_stopped(rig):
    leader = api(rig.config)
    child = engine(leader)
    adopt(rig, child)
    rig.proc.remove(leader.pid)
    rig.proc.add(replace(child, ppid=1))
    result = rig.controller.status()
    assert result["state"] == "present" and result["pid"] is None
    assert result["can_stop"] and not result["can_start"]
    assert rig.controller.run("start")["accepted"] is False
    events = fake_signals(rig, term=lambda: rig.proc.remove(child.pid))
    result = rig.controller.run("stop")
    assert result["state"] == "stopped" and result["accepted"]
    assert events == [("group", leader.pgid, control.signal.SIGTERM, 0.0)]


def test_vanished_processes_are_retryable_failed_and_stop_is_idempotent(rig):
    leader = adopt(rig)
    rig.controller.log_path.write_text("启动失败信息", encoding="utf-8")
    rig.proc.remove(leader.pid)
    result = rig.controller.status()
    assert result["state"] == "failed" and result["can_start"] and not result["can_stop"]
    assert result["log_tail"] == "启动失败信息"
    assert rig.controller.run("stop")["accepted"] is False
    assert rig.controller.status()["state"] == "stopped"
    assert rig.controller.run("stop")["accepted"] is False


def test_zombies_do_not_block_restart(rig):
    leader = adopt(rig)
    rig.proc.add(replace(leader, state="Z", argv=()))
    rig.proc.owners.clear()
    assert rig.controller.status()["can_start"]


@pytest.mark.parametrize("phase,expected", [("present", "conflict"), ("stopping", "stopping")])
def test_busy_lock_is_nonblocking_and_never_spawns(rig, phase, expected):
    adopt(rig)
    record = rig.controller._load()
    record["phase"] = phase
    rig.controller._save(record)
    scans = rig.proc.scans

    def busy(*args, **kwargs):
        raise control.Busy()

    rig.monkeypatch.setattr(control, "_flock", busy)
    for action in ("status", "start", "stop"):
        result = rig.controller.run(action)
        assert result["state"] == expected and not result["can_start"] and not result["can_stop"]
    assert rig.clock.now == 0 and rig.proc.scans == scans


def test_stop_saves_members_and_stopping_before_term_then_confirms_exit(rig):
    leader = api(rig.config)
    child = engine(leader)
    rig.proc.add(leader, child)
    rig.proc.owners = {leader.pid}

    def term():
        record = rig.controller._load()
        assert record["phase"] == "stopping"
        assert {m["pid"] for m in record["members"]} == {140, 141}
        result = rig.controller.status()
        assert result["state"] == "stopping" and not result["can_start"]
        rig.proc.remove(140, 141)

    events = fake_signals(rig, term=term)
    result = rig.controller.run("stop")
    assert result["state"] == "stopped" and result["accepted"] is True
    assert len(events) == 1 and rig.clock.now == 0
    assert rig.controller.run("stop")["accepted"] is False


def test_stop_timeout_uses_pidfd_only_for_remaining_verified_members(rig):
    leader = api(rig.config)
    child = engine(leader)
    adopt(rig, child)
    events = fake_signals(rig, term=lambda: rig.proc.remove(leader.pid), kill=rig.proc.remove)
    result = rig.controller.run("stop")
    assert result["state"] == "stopped" and result["accepted"]
    assert events == [("group", 140, control.signal.SIGTERM, 0.0),
                      ("member", 141, control.signal.SIGKILL, 30.0)]


@pytest.mark.parametrize("change", ["pid", "boot", "group", "foreign_port", "unknown_orphan"])
def test_stop_timeout_revalidates_before_force_signal(rig, change):
    leader = api(rig.config)
    child = engine(leader)
    adopt(rig, child)
    events = fake_signals(rig)

    def changed():
        if rig.clock.now < 30:
            return
        if change == "pid":
            rig.proc.add(replace(child, starttime=99999))
        elif change == "boot":
            rig.proc.boot = "boot-B"
        elif change == "group":
            rig.proc.add(engine(leader, pid=142, ppid=1))
        elif change == "foreign_port":
            rig.proc.owners = {900}
        else:
            rig.proc.remove(140)
            rig.proc.add(engine(leader, pid=142, ppid=1))

    rig.clock.hook = changed
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and result["accepted"]
    assert not result["can_start"] and not result["can_stop"]
    assert len(events) == 1


@pytest.mark.parametrize("change", ["pid", "boot"])
def test_pidfd_last_check_rejects_changed_identity(rig, change):
    leader = adopt(rig)

    def changed(pid):
        if change == "pid":
            rig.proc.add(replace(leader, starttime=99999))
        else:
            rig.proc.boot = "boot-B"

    events = fake_signals(rig, opened=changed)
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and result["accepted"]
    assert len(events) == 1


def test_no_pidfd_means_no_unsafe_kill_fallback(rig):
    adopt(rig)
    events = fake_signals(rig)
    rig.monkeypatch.delattr(control.os, "pidfd_open")
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and "pidfd" in result["detail"]
    assert len(events) == 1


def test_force_signal_waits_five_seconds_and_never_claims_stopped(rig):
    adopt(rig)
    events = fake_signals(rig)
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and result["accepted"]
    assert not result["can_start"] and result["can_stop"]
    assert rig.clock.now == 35 and len(events) == 2


def test_term_revalidation_rejects_pid_change_without_any_signal(rig):
    leader = adopt(rig)
    rig.monkeypatch.setattr(rig.proc, "read", lambda pid: replace(leader, starttime=9999))
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and not result["accepted"]


def test_unavailable_proc_is_not_stopped(rig):
    def denied():
        raise PermissionError("模拟 /proc 权限不足")

    rig.monkeypatch.setattr(rig.proc, "scan", denied)
    for action in ("status", "start", "stop", "switch"):
        result = rig.controller.run(action)
        assert result["state"] == "unavailable" and not result["can_start"]


@pytest.mark.parametrize("payload", [b"\xff" * 6000, "汉字😀".encode() * 2000, b"x" * 6000 + b"\xe4"],
                         ids=["invalid-utf8", "multibyte", "truncated-utf8"])
def test_log_tail_is_valid_utf8_at_most_4096_bytes(rig, payload):
    rig.controller.runtime.mkdir()
    rig.controller.log_path.write_bytes(payload)
    tail = rig.controller.status()["log_tail"]
    assert len(tail.encode("utf-8")) <= 4096
    assert tail.encode().decode() == tail
    assert rig.controller.log_path.read_bytes() == payload


@pytest.mark.parametrize("field,value", [("members", None), ("version", 2), ("started_at", "bad"),
                                          ("pgid", 999), ("phase", "unknown")])
def test_corrupt_record_fails_closed(rig, field, value):
    adopt(rig)
    record = rig.controller._load()
    record[field] = value
    rig.controller._save(record)
    result = rig.controller.status()
    assert result["state"] == "conflict" and not result["can_start"]


def test_atomic_record_keeps_previous_on_replace_failure(rig):
    adopt(rig)
    old = rig.controller.state_path.read_bytes()

    def fail(*args):
        raise OSError("模拟原子替换失败")

    rig.monkeypatch.setattr(control.os, "replace", fail)
    assert rig.controller.run("start")["state"] == "unavailable"
    assert rig.controller.state_path.read_bytes() == old
    assert list(rig.controller.runtime.glob(".state-*")) == []


def test_flock_is_lazy_nonblocking_and_releases(monkeypatch):
    calls = []
    fake = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8,
                           flock=lambda fd, flags: calls.append((fd, flags)))
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    ORIGINAL_FLOCK(123)
    ORIGINAL_FLOCK(123, unlock=True)
    assert calls == [(123, 6), (123, 8)]

    def busy(fd, flags):
        assert flags == 6
        raise BlockingIOError()

    fake.flock = busy
    with pytest.raises(control.Busy):
        ORIGINAL_FLOCK(123)


def test_lock_released_on_start_failure(rig):
    events = []
    rig.monkeypatch.setattr(control, "_flock", lambda fd, unlock=False: events.append(unlock))

    def failed(*args, **kwargs):
        raise OSError("模拟启动失败")

    rig.monkeypatch.setattr(control.subprocess, "Popen", failed)
    result = rig.controller.run("start")
    assert result["state"] == "unavailable" and result["accepted"] is False
    assert events == [False, True]


def test_managed_bash_parent_and_api_child_are_one_tree(rig):
    fake_spawn(rig)
    assert rig.controller.run("start")["state"] == "present"
    parent = rig.proc.processes[140]
    child = api(rig.config, pid=141, ppid=140, pgid=140, sid=140, starttime=1010)
    rig.proc.add(child, engine(parent, pid=142, ppid=141, starttime=1020))
    rig.proc.owners = {141}
    result = rig.controller.status()
    assert result["state"] == "present" and result["pid"] == 140
    assert rig.controller.run("start")["accepted"] is False
    assert len(rig.controller._load()["members"]) == 3


def test_stop_tracks_new_child_before_it_becomes_orphan(rig):
    leader = adopt(rig)
    child = engine(leader)
    events = fake_signals(rig, kill=rig.proc.remove)

    def change():
        if rig.clock.now == 10:
            rig.proc.add(child)
        if rig.clock.now == 20:
            rig.proc.remove(leader.pid)
            rig.proc.add(replace(child, ppid=1))

    rig.clock.hook = change
    result = rig.controller.run("stop")
    assert result["state"] == "stopped"
    assert events[-1] == ("member", 141, control.signal.SIGKILL, 30.0)


def test_target_exits_before_term_is_an_idempotent_noop(rig):
    leader = adopt(rig)

    def gone(pgid, sig):
        rig.proc.remove(leader.pid)
        raise ProcessLookupError()

    rig.monkeypatch.setattr(control.os, "killpg", gone)
    result = rig.controller.run("stop")
    assert result["state"] == "stopped" and result["accepted"] is False


def test_group_missing_with_members_cannot_claim_stopped(rig):
    adopt(rig)

    def missing(pgid, sig):
        raise ProcessLookupError()

    rig.monkeypatch.setattr(control.os, "killpg", missing)
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and not result["can_start"]


def test_config_mismatch_does_not_control_previous_instance(rig):
    adopt(rig)
    other = control.Controller(replace(rig.config, port=8201), rig.controller.runtime, rig.proc)
    assert other.run("stop")["state"] == "conflict"


def test_stop_does_not_adopt_replacement_instance(rig):
    leader = adopt(rig)
    events = fake_signals(rig)

    def change():
        if rig.clock.now == 1:
            rig.proc.remove(leader.pid)
            rig.proc.add(api(rig.config, pid=200))
            rig.proc.owners = {200}

    rig.clock.hook = change
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and len(events) == 1


def test_port_must_be_released_even_if_api_and_engine_exit(rig):
    leader = adopt(rig)

    def term():
        rig.proc.remove(leader.pid)
        rig.proc.owners = {999}

    events = fake_signals(rig, term=term)
    result = rig.controller.run("stop")
    assert result["state"] == "conflict" and len(events) == 1
    assert not result["can_start"] and not result["can_stop"]


def test_switch_stops_current_and_starts_target_candidate(rig):
    leader = adopt(rig)
    events = fake_signals(rig, term=lambda: rig.proc.remove(leader.pid))
    calls = fake_spawn(rig)
    result = rig.controller.run("switch", "qwen3-1.7b-lab")
    assert result["state"] == "present" and result["accepted"] is True
    assert result["current"] == "qwen3-1.7b-lab"
    assert events == [("group", 140, control.signal.SIGTERM, 0.0)]
    assert calls[0][0] == ["/bin/bash", rig.config.start_script,
                           "/opt/models/Qwen3-1.7B-lab", "8200"]
    record = json.loads(rig.controller.state_path.read_text())
    assert record["model"] == {"name": "qwen3-1.7b-lab", "path": "/opt/models/Qwen3-1.7B-lab"}


def test_switch_to_running_candidate_is_idempotent_without_events(rig):
    adopt(rig)
    events = fake_signals(rig)
    calls = fake_spawn(rig)
    result = rig.controller.run("switch")
    assert result["state"] == "present" and result["accepted"] is False
    assert result["current"] == "qwen3-1.7b"
    assert events == [] and calls == []


def test_switch_when_stopped_starts_target_without_stop(rig):
    calls = fake_spawn(rig)
    result = rig.controller.run("switch", "qwen3-1.7b-lab")
    assert result["state"] == "present" and result["accepted"] is True
    assert calls[0][0] == ["/bin/bash", rig.config.start_script,
                           "/opt/models/Qwen3-1.7B-lab", "8200"]
    assert json.loads(rig.controller.state_path.read_text())["model"]["name"] == "qwen3-1.7b-lab"


def test_switch_aborts_when_stop_does_not_reach_stopped(rig):
    adopt(rig)
    fake_signals(rig)
    calls = fake_spawn(rig)
    result = rig.controller.run("switch", "qwen3-1.7b-lab")
    assert result["state"] == "conflict" and result["accepted"] is True
    assert calls == []


def test_switch_while_stopping_is_rejected_without_events(rig):
    adopt(rig)
    record = rig.controller._load()
    record["phase"] = "stopping"
    rig.controller._save(record)
    calls = fake_spawn(rig)
    result = rig.controller.run("switch", "qwen3-1.7b-lab")
    assert result["state"] == "stopping" and result["accepted"] is False
    assert not result["can_stop"] and calls == []


def test_record_outside_candidates_fails_closed_for_all_actions(rig):
    adopt(rig)
    record = rig.controller._load()
    record["model"] = {"name": "removed", "path": "/opt/models/Removed"}
    rig.controller._save(record)
    for action in ("status", "start", "stop", "switch"):
        result = rig.controller.run(action)
        assert result["state"] == "conflict"
        assert not result["can_start"] and not result["can_stop"]


def test_legacy_record_without_model_field_fails_closed(rig):
    adopt(rig)
    record = rig.controller._load()
    record.pop("model")
    record["config"] = {"model_path": "/opt/models/Qwen3-1.7B", "model_name": "qwen3-1.7b"}
    rig.controller._save(record)
    result = rig.controller.status()
    assert result["state"] == "conflict" and "归属" in result["detail"]


def test_different_candidate_set_does_not_control_previous_instance(rig):
    adopt(rig)
    other = control.Controller(
        replace(rig.config, models=(("qwen3-1.7b", "/opt/models/Qwen3-1.7B-copy"),)),
        rig.controller.runtime, rig.proc)
    assert other.run("stop")["state"] == "conflict"


def test_parse_models_and_resolve_candidates():
    models = control.parse_models(["a=/opt/a", "b=/opt/b"])
    config = control.Config(models, 8200, "/opt/scripts/start-vllm.sh")
    assert config.resolve() == ("a", "/opt/a")
    assert config.resolve("b") == ("b", "/opt/b")
    with pytest.raises(ValueError, match="未知候选模型"):
        config.resolve("ghost")


def test_config_rejects_empty_duplicate_or_relative_candidates():
    with pytest.raises(ValueError, match="至少"):
        control.Config((), 8200, "/opt/scripts/start-vllm.sh")
    with pytest.raises(ValueError, match="重复"):
        control.Config((("a", "/opt/a"), ("a", "/opt/b")), 8200, "/opt/scripts/start-vllm.sh")
    with pytest.raises(ValueError, match="绝对路径"):
        control.Config((("a", "relative/path"),), 8200, "/opt/scripts/start-vllm.sh")


@pytest.mark.parametrize("value", ["", "bad name", "qwen3-xml", "-x"])
def test_config_rejects_invalid_tool_parser(value):
    with pytest.raises(ValueError, match="tool parser"):
        control.Config((("a", "/opt/a"),), 8200, "/opt/scripts/start-vllm.sh", value)


def cli_args():
    return ["status",
            "--models", "qwen3-1.7b=/opt/models/Qwen3-1.7B",
            "--models", "qwen3-1.7b-lab=/opt/models/Qwen3-1.7B-lab",
            "--port", "8200", "--start-script", "/opt/scripts/start-vllm.sh"]


def cli_result(state="stopped", **changes):
    result = dict(state=state, pid=None, current=None, started_at=None, can_start=True,
                  can_stop=False, detail="服务已停止", log_tail="")
    result.update(changes)
    return result


def test_cli_single_json_object_and_exact_configuration(monkeypatch, capsys, config):
    seen = []

    class StubController:
        def __init__(self, received):
            assert received == config

        def run(self, action, model=None):
            seen.append((action, model))
            return cli_result()

    monkeypatch.setattr(control, "Controller", StubController)
    assert control.main(cli_args()) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    assert json.loads(captured.out)["state"] == "stopped" and seen == [("status", None)]


def test_cli_switch_with_model_reaches_controller(monkeypatch, capsys, config):
    seen = []

    class StubController:
        def __init__(self, received):
            assert received == config

        def run(self, action, model=None):
            seen.append((action, model))
            return cli_result(state="present", current="qwen3-1.7b-lab",
                              can_start=False, can_stop=True, accepted=True)

    monkeypatch.setattr(control, "Controller", StubController)
    args = cli_args()
    args[0] = "switch"
    args += ["--model", "qwen3-1.7b-lab"]
    assert control.main(args) == 0
    assert seen == [("switch", "qwen3-1.7b-lab")]
    assert json.loads(capsys.readouterr().out)["current"] == "qwen3-1.7b-lab"


def test_cli_tool_parser_defaults_to_hermes_and_accepts_override(monkeypatch, capsys):
    seen = []

    class StubController:
        def __init__(self, received):
            seen.append(received.tool_parser)

        def run(self, action, model=None):
            return cli_result()

    monkeypatch.setattr(control, "Controller", StubController)
    assert control.main(cli_args()) == 0
    assert control.main(cli_args() + ["--tool-parser", "qwen3_xml"]) == 0
    assert seen == ["hermes", "qwen3_xml"]


@pytest.mark.parametrize("option", ["--models", "--port", "--start-script"])
def test_cli_required_options(option, capsys):
    args = cli_args()
    while option in args:
        index = args.index(option)
        del args[index:index + 2]
    assert control.main(args) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["state"] == "unavailable" and not captured.err


@pytest.mark.parametrize("value", ["no-separator", "name-only=", "=path-only", ""])
def test_cli_malformed_models_is_json_unavailable(value, capsys):
    args = cli_args()
    args[args.index("--models") + 1] = value
    assert control.main(args) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "unavailable"


@pytest.mark.parametrize("extra", [["--runtime", "/tmp/not-allowed"], ["--help"], ["--unknown"]])
def test_cli_no_runtime_override_or_non_json_output(extra, capsys):
    assert control.main(cli_args() + extra) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["state"] == "unavailable" and not captured.err


@pytest.mark.parametrize("value", ["not-an-int", "0", "65536"])
def test_cli_invalid_port_is_json(value, capsys):
    args = cli_args()
    args[args.index("--port") + 1] = value
    assert control.main(args) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "unavailable"


def test_cli_rejects_abbreviated_options(capsys):
    args = cli_args()
    args[args.index("--start-script")] = "--start-scr"
    assert control.main(args) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "unavailable"


def test_cli_action_error_includes_accepted(capsys):
    assert control.main(["start"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "unavailable" and result["accepted"] is False
