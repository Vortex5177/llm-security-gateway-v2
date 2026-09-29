"""本机服务状态与异步控制测试；禁止真实子进程、网络和环境文件访问。"""

import asyncio
import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import httpx
import pytest

from app import config as config_module
from app import vllm_service as service_module
from app.config import parse_config
from app.vllm_service import VllmService


NOW = 1_800_000_000.0
ORIGINAL_RUN_COMMAND = VllmService._run_command


def helper_state(state="present", **changes):
    result = dict(state=state, pid=140 if state == "present" else None,
                  current="qwen3-1.7b" if state in ("present", "stopping") else None,
                  started_at=NOW - 10 if state == "present" else None,
                  can_start=state == "stopped", can_stop=state == "present",
                  detail="模拟助手状态", log_tail="")
    result.update(changes)
    return result


@pytest.fixture(autouse=True)
def isolated_system(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("测试禁止真实命令、网络或环境文件访问")

    monkeypatch.setattr(VllmService, "_run_command", staticmethod(forbidden))
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(config_module, "load_dotenv", forbidden)
    # 仅替换被测模块的 os 引用，绝不修改全局 os.name，避免破坏 pathlib。
    monkeypatch.setattr(service_module, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(service_module, "time", SimpleNamespace(
        time=lambda: NOW, monotonic=time.monotonic))


@pytest.fixture
async def service(config_dict):
    config_dict["local_vllm"] = {"enabled": True, "models": [
        "/opt/models/Qwen3-1.7B", "/opt/models/Qwen3-1.7B-lab"]}
    config_dict["models"]["qwen3-1.7b-lab"] = {
        "provider": "local-vllm", "upstream": "qwen3-1.7b-lab"}
    requests = []
    responses = {
        "/health": httpx.Response(200),
        "/v1/models": httpx.Response(200, json={"data": [{"id": "qwen3-1.7b"}]}),
    }

    def handler(request):
        assert request.method == "GET"
        assert request.url.host == "localhost" and request.url.port == 8200
        assert request.headers["authorization"] == "Bearer EMPTY"
        requests.append(request)
        response = responses[request.url.path]
        if isinstance(response, Exception):
            raise response
        return response

    controller = VllmService(parse_config(config_dict), transport=httpx.MockTransport(handler))
    result = SimpleNamespace(controller=controller, requests=requests, responses=responses)
    try:
        yield result
    finally:
        await controller.close()


@pytest.fixture
async def rig(service, monkeypatch):
    service.invoke = AsyncMock(return_value=helper_state("stopped"))
    monkeypatch.setattr(service.controller, "_invoke", service.invoke)
    return service


async def test_disabled_status_and_operations_never_issue_commands(service, monkeypatch):
    controller = service.controller
    controller.settings.enabled = False
    invoke = AsyncMock(side_effect=AssertionError("禁用控制时不得调用助手"))
    monkeypatch.setattr(controller, "_invoke", invoke)
    for _ in range(2):
        view = await controller.status()
        assert view["state"] == "unavailable"
        assert view["can_start"] is False and view["can_stop"] is False
    for action in ("start", "stop", "switch"):
        code, view = await controller.operate(action)
        assert code == 503 and view["state"] == "unavailable"
    invoke.assert_not_called()
    assert service.requests == [] and controller._task is None


async def test_status_is_read_only_and_rechecks_helper(rig):
    rig.invoke.side_effect = [helper_state("stopped"), helper_state("present")]
    assert (await rig.controller.status())["state"] == "stopped"
    view = await rig.controller.status()
    assert view == dict(state="running", model="qwen3-1.7b",
                        models=["qwen3-1.7b", "qwen3-1.7b-lab"], current="qwen3-1.7b",
                        url="http://localhost:8200/v1",
                        can_start=False, can_stop=True, detail="模型已就绪")
    assert rig.invoke.await_args_list == [call("status"), call("status")]
    assert {str(r.url) for r in rig.requests} == {
        "http://localhost:8200/health", "http://localhost:8200/v1/models"}
    assert rig.controller._task is None


@pytest.mark.parametrize("action", ["start", "stop"])
@pytest.mark.parametrize("models", [[{"id": "another-model"}], [{"id": "qwen3-1.7b-lab"}], []],
                         ids=["wrong-model", "other-candidate", "empty"])
async def test_model_mismatch_is_conflict_and_forbids_both_actions(rig, action, models):
    rig.invoke.return_value = helper_state(can_start=True)
    rig.responses["/v1/models"] = httpx.Response(200, json={"data": models})
    code, view = await rig.controller.operate(action)
    assert code == 409 and view["state"] == "conflict"
    assert view["can_start"] is False and view["can_stop"] is False
    rig.invoke.assert_awaited_once_with("status")
    assert rig.controller._task is None


@pytest.mark.parametrize("age,expected", [(0, "starting"), (299.999, "starting"),
                                           (300, "failed"), (301, "failed")])
@pytest.mark.parametrize("failure", ["health-http", "models-http", "network", "models-json"])
async def test_unready_process_respects_300_second_deadline(rig, age, expected, failure):
    rig.invoke.return_value = helper_state(started_at=NOW - age)
    if failure == "health-http":
        rig.responses["/health"] = httpx.Response(503)
    elif failure == "models-http":
        rig.responses["/v1/models"] = httpx.Response(503)
    elif failure == "network":
        rig.responses["/health"] = httpx.ConnectError("模拟连接失败")
    else:
        rig.responses["/v1/models"] = httpx.Response(200, content=b"not-json")
    view = await rig.controller.status()
    assert view["state"] == expected
    assert view["can_start"] is False and view["can_stop"] is True
    rig.invoke.assert_awaited_once_with("status")
    assert rig.controller._task is None


async def test_orphan_engine_without_main_pid_only_allows_stop(rig):
    orphan = helper_state(pid=None, can_start=True, detail="残留 EngineCore")
    rig.invoke.side_effect = lambda action, model=None: helper_state("stopped") if action == "stop" else orphan
    code, view = await rig.controller.operate("start")
    assert code == 409 and view["state"] == "failed"
    assert view["can_start"] is False and view["can_stop"] is True
    assert rig.requests == []
    code, view = await rig.controller.operate("stop")
    assert code == 202 and view["state"] == "stopping"
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.invoke.await_args_list == [call("status"), call("status"), call("stop", None)]
    assert rig.requests == []


@pytest.mark.parametrize("action,state", [("start", "present"), ("stop", "stopped")])
async def test_already_running_or_stopped_is_idempotent_200(rig, action, state):
    rig.invoke.return_value = helper_state(state)
    for _ in range(2):
        code, view = await rig.controller.operate(action)
        assert code == 200
        assert view["state"] == ("running" if action == "start" else "stopped")
    assert rig.invoke.await_args_list == [call("status"), call("status")]
    assert rig.controller._task is None


async def test_start_with_other_model_running_is_409_with_switch_hint(rig):
    rig.invoke.return_value = helper_state()
    code, view = await rig.controller.operate("start", "qwen3-1.7b-lab")
    assert code == 409 and view["state"] == "running"
    assert view["current"] == "qwen3-1.7b" and "切换" in view["detail"]
    assert rig.controller._task is None


async def test_unknown_model_is_rejected_before_any_command(rig):
    for action in ("start", "switch"):
        with pytest.raises(ValueError, match="未知候选模型"):
            await rig.controller.operate(action, "ghost")
    rig.invoke.assert_not_awaited()


async def test_switch_current_model_is_200_without_task(rig):
    rig.invoke.return_value = helper_state()
    code, view = await rig.controller.operate("switch", "qwen3-1.7b")
    assert code == 200 and view["state"] == "running"
    assert view["current"] == "qwen3-1.7b"
    assert rig.controller._task is None
    rig.invoke.assert_awaited_once_with("status")


async def test_switch_while_running_other_model_waits_for_target_current(rig, monkeypatch):
    monkeypatch.setattr(service_module, "POLL_SECONDS", 0)
    switched = {"on": False}

    async def invoke(action, model=None):
        if action == "switch":
            assert model == "qwen3-1.7b-lab"
            switched["on"] = True
            rig.responses["/v1/models"] = httpx.Response(
                200, json={"data": [{"id": "qwen3-1.7b-lab"}]})
            return helper_state(current="qwen3-1.7b-lab")
        return helper_state(current="qwen3-1.7b-lab" if switched["on"] else "qwen3-1.7b")

    rig.invoke.side_effect = invoke
    code, view = await rig.controller.operate("switch", "qwen3-1.7b-lab")
    assert code == 202 and view["state"] == "starting"
    assert view["detail"] == "正在切换模型，请稍候"
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.controller._last_error is None
    assert rig.invoke.await_args_list == [call("status"), call("switch", "qwen3-1.7b-lab")]
    view = await rig.controller.status()
    assert view["state"] == "running" and view["current"] == "qwen3-1.7b-lab"


async def test_switch_while_stopped_is_accepted_and_reaches_running(rig, monkeypatch):
    monkeypatch.setattr(service_module, "POLL_SECONDS", 0)
    rig.responses["/v1/models"] = httpx.Response(200, json={"data": [{"id": "qwen3-1.7b-lab"}]})
    responses = iter([helper_state("stopped"), helper_state(current="qwen3-1.7b-lab")])

    async def invoke(action, model=None):
        if action == "switch":
            assert model == "qwen3-1.7b-lab"
        return next(responses)

    rig.invoke.side_effect = invoke
    code, view = await rig.controller.operate("switch", "qwen3-1.7b-lab")
    assert code == 202 and view["state"] == "starting"
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.controller._last_error is None


async def test_switch_success_requires_target_model_on_port(rig, monkeypatch):
    monkeypatch.setattr(service_module, "POLL_SECONDS", 0)

    async def invoke(action, model=None):
        if action == "switch":
            return helper_state(current="qwen3-1.7b-lab")
        return helper_state()

    rig.invoke.side_effect = invoke
    code, _ = await rig.controller.operate("switch", "qwen3-1.7b-lab")
    assert code == 202
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.controller._last_error is not None
    view = await rig.controller.status()
    assert view["state"] == "failed" and view["current"] == "qwen3-1.7b"


@pytest.mark.parametrize("action", ["start", "stop"])
async def test_async_operation_deduplicates_concurrent_requests_and_conflicts(rig, action):
    entered, release = asyncio.Event(), asyncio.Event()
    initial = helper_state("stopped" if action == "start" else "present")
    final = helper_state("present" if action == "start" else "stopped")
    actual = initial

    async def invoke(requested, model=None):
        nonlocal actual
        if requested == "status":
            return actual
        assert requested == action
        entered.set()
        await release.wait()
        actual = final
        return actual

    rig.invoke.side_effect = invoke
    code, view = await asyncio.wait_for(rig.controller.operate(action), 1)
    assert code == 202 and view["state"] == ("starting" if action == "start" else "stopping")
    task = rig.controller._task
    await asyncio.wait_for(entered.wait(), 1)
    results = await asyncio.gather(*(rig.controller.operate(action) for _ in range(8)))
    assert all(code == 202 and value == view for code, value in results)
    opposite = "stop" if action == "start" else "start"
    code, opposite_view = await rig.controller.operate(opposite)
    assert code == 409 and opposite_view == view
    assert rig.controller._task is task and not task.done()
    assert rig.invoke.await_args_list == [
        call("status"), call(action, "qwen3-1.7b" if action == "start" else None)]
    release.set()
    await asyncio.wait_for(task, 1)
    assert rig.controller._last_error is None
    code, view = await rig.controller.operate(action)
    assert code == 200 and view["state"] == ("running" if action == "start" else "stopped")
    assert rig.invoke.await_args_list == [
        call("status"), call(action, "qwen3-1.7b" if action == "start" else None), call("status")]


@pytest.mark.parametrize("action", ["start", "stop"])
@pytest.mark.parametrize("actual_state", ["present", "stopped"])
async def test_close_only_cancels_coroutine_and_new_service_observes_reality(
    rig, monkeypatch, action, actual_state
):
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def invoke(requested, model=None):
        if requested == "status":
            return helper_state("stopped" if action == "start" else "present")
        assert requested == action
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    rig.invoke.side_effect = invoke
    assert (await rig.controller.operate(action))[0] == 202
    await asyncio.wait_for(entered.wait(), 1)
    task = rig.controller._task
    before = list(rig.invoke.await_args_list)
    await asyncio.wait_for(rig.controller.close(), 1)
    await rig.controller.close()
    assert task.cancelled() and cancelled.is_set()
    assert rig.invoke.await_args_list == before == [
        call("status"), call(action, "qwen3-1.7b" if action == "start" else None)]
    recreated = VllmService(rig.controller.config, transport=rig.controller.transport)
    observed = AsyncMock(return_value=helper_state(actual_state))
    monkeypatch.setattr(recreated, "_invoke", observed)
    view = await recreated.status()
    assert view["state"] == ("running" if actual_state == "present" else "stopped")
    observed.assert_awaited_once_with("status")
    assert recreated._task is None and recreated._last_error is None
    await recreated.close()
    observed.assert_awaited_once_with("status")


async def test_start_polls_until_model_is_ready_without_second_start(rig, monkeypatch):
    monkeypatch.setattr(service_module, "POLL_SECONDS", 0)
    rig.responses["/health"] = httpx.Response(503)
    states = iter([helper_state("stopped"), helper_state(), helper_state()])

    async def invoke(action, model=None):
        raw = next(states)
        if action == "status" and raw["state"] == "present":
            rig.responses["/health"] = httpx.Response(200)
        return raw

    rig.invoke.side_effect = invoke
    assert (await rig.controller.operate("start"))[0] == 202
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.invoke.await_args_list == [call("status"), call("start", "qwen3-1.7b"), call("status")]
    assert rig.controller._last_error is None


@pytest.mark.parametrize("state", ["failed", "conflict", "unavailable"])
async def test_error_detail_and_log_are_limited_to_4k_utf8_bytes(rig, state):
    rig.invoke.return_value = helper_state(state, detail="错误\0\x1b", log_tail="日志\x01" * 5000)
    view = await rig.controller.status()
    assert view["state"] == state and view["detail"].startswith("错误\n日志")
    assert len(view["detail"].encode("utf-8")) <= 4096
    assert all(ord(c) >= 32 or c in "\n\t" for c in view["detail"])


@pytest.mark.parametrize("failure", ["exception", "unready"])
async def test_failed_background_operation_bounds_saved_error(rig, failure):
    rig.responses["/health"] = httpx.Response(503)
    result = RuntimeError("模拟失败\0" * 5000) if failure == "exception" else helper_state(
        started_at=NOW - 301, log_tail="模型失败" * 5000)
    rig.invoke.side_effect = [helper_state("stopped"), result, helper_state("stopped")]
    assert (await rig.controller.operate("start"))[0] == 202
    await asyncio.wait_for(rig.controller._task, 1)
    assert rig.controller._action is None
    assert len(rig.controller._last_error.encode("utf-8")) <= 4096
    view = await rig.controller.status()
    assert view["state"] == "failed" and "\0" not in view["detail"]
    assert len(view["detail"].encode("utf-8")) <= 4096


async def test_helper_uses_fixed_argv_path_cache_and_action_timeouts(service, monkeypatch):
    translated = "/mnt/c/mock directory/wsl_vllm_control.py"
    resolved = Mock(return_value=translated)
    monkeypatch.setattr(service_module, "helper_wsl_path", resolved)
    raw = helper_state("stopped")
    command = Mock(side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps(raw).encode()) for _ in range(6)
    ])
    monkeypatch.setattr(service.controller, "_run_command", command)
    for action in ("status", "start", "stop", "switch"):
        assert await service.controller._invoke(action) == raw
    assert await service.controller._invoke("switch") == raw
    assert await service.controller._invoke("switch", "qwen3-1.7b-lab") == raw
    prefix = ["wsl.exe", "-d", "Ubuntu-24.04", "--"]
    base = ["/opt/venvs/vllm/bin/python", translated]
    tail = ["--port", "8200", "--start-script", "/opt/scripts/start-vllm.sh",
            "--models", "qwen3-1.7b=/opt/models/Qwen3-1.7B",
            "--models", "qwen3-1.7b-lab=/opt/models/Qwen3-1.7B-lab"]
    expected = [call(prefix + base + [action] + tail, timeout)
                for action, timeout in (("status", 15), ("start", 15),
                                        ("stop", 45), ("switch", 45))]
    expected.append(call(prefix + base + ["switch"] + tail, 45))
    expected.append(call(prefix + base + ["switch"] + tail + ["--model", "qwen3-1.7b-lab"], 45))
    assert command.call_args_list == expected
    assert resolved.call_count == 1  # 路径只在首次调用时推导并缓存


async def test_tool_parser_mapping_selects_parser_only_for_mapped_model(service, monkeypatch):
    monkeypatch.setattr(service_module, "helper_wsl_path",
                        Mock(return_value="/mnt/c/mock/wsl_vllm_control.py"))
    service.controller.settings.tool_parsers["qwen3-1.7b-lab"] = "qwen3_xml"
    raw = helper_state("stopped")
    command = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(raw).encode()))
    monkeypatch.setattr(service.controller, "_run_command", command)
    assert await service.controller._invoke("switch", "qwen3-1.7b-lab") == raw
    assert command.call_args.args[0][-4:] == ["--model", "qwen3-1.7b-lab",
                                              "--tool-parser", "qwen3_xml"]
    command.reset_mock()
    assert await service.controller._invoke("switch", "qwen3-1.7b") == raw
    assert "--tool-parser" not in command.call_args.args[0]
    command.reset_mock()
    assert await service.controller._invoke("stop") == raw
    assert "--tool-parser" not in command.call_args.args[0]


def test_helper_wsl_path_maps_local_drive():
    mapped = service_module.helper_wsl_path("D:/x/My Dir/wsl_vllm_control.py")
    assert mapped == "/mnt/d/x/My Dir/wsl_vllm_control.py"
    # 工作区内的真实助手同样可映射
    assert service_module.helper_wsl_path().startswith("/mnt/")


@pytest.mark.parametrize("bad", ["\\\\server\\share\\wsl_vllm_control.py"])
def test_helper_wsl_path_rejects_non_drive_paths(bad):
    with pytest.raises(service_module.ControlUnavailable):
        service_module.helper_wsl_path(bad)


@pytest.mark.parametrize("action", ["start", "stop", "switch"])
async def test_unmappable_helper_path_fails_closed(service, monkeypatch, action):
    def broken():
        raise service_module.ControlUnavailable("模拟助手路径无法映射")

    monkeypatch.setattr(service_module, "helper_wsl_path", broken)
    code, view = await service.controller.operate(action)
    assert code == 503 and view["state"] == "unavailable"
    assert view["can_start"] is False and view["can_stop"] is False
    assert service.controller._helper_path is None and service.controller._task is None


@pytest.mark.parametrize("failure", ["missing-wsl", "timeout", "exit-code", "invalid-utf8"])
async def test_wsl_failure_is_unavailable_never_stopped(service, monkeypatch, failure):
    failures = {
        "missing-wsl": OSError("模拟 WSL 不可用"),
        "timeout": subprocess.TimeoutExpired(["wsl.exe"], 15),
        "exit-code": subprocess.CompletedProcess([], 1, b"", b"secret-diagnostic"),
        "invalid-utf8": subprocess.CompletedProcess([], 0, b"\xff"),
    }
    result = failures[failure]
    command = Mock(side_effect=result) if isinstance(result, Exception) else Mock(return_value=result)
    monkeypatch.setattr(service.controller, "_run_command", command)
    service.controller._helper_path = "/mock/helper.py"
    for action in (None, "start", "stop", "switch"):
        if action is None:
            view = await service.controller.status()
        else:
            code, view = await service.controller.operate(action)
            assert code == 503
        assert view["state"] == "unavailable"
        assert view["can_start"] is False and view["can_stop"] is False
        assert "secret-diagnostic" not in view["detail"]
    assert all(c.args[0][6] == "status" for c in command.call_args_list)
    assert service.controller._task is None


BAD_JSON = [
    pytest.param(b"not-json", id="malformed"),
    pytest.param(b"{} {}", id="multiple-objects"),
    pytest.param(b"[]", id="array"),
    pytest.param(b"null", id="null"),
    pytest.param(b"{}", id="missing-state"),
    pytest.param(json.dumps(helper_state("unknown")).encode(), id="unknown-state"),
    pytest.param(json.dumps(helper_state("stopped", can_start="true")).encode(), id="string-permission"),
    pytest.param(json.dumps(helper_state("stopped", can_stop=0)).encode(), id="integer-permission"),
    pytest.param(json.dumps(helper_state("present", current=5)).encode(), id="integer-current"),
    pytest.param(b'{"state":"stopped","can_start":true}', id="missing-permission"),
]


@pytest.mark.parametrize("payload", BAD_JSON)
async def test_invalid_helper_json_never_authorizes_operation(service, monkeypatch, payload):
    service.controller._helper_path = "/mock/helper.py"
    command = Mock(return_value=subprocess.CompletedProcess([], 0, payload))
    monkeypatch.setattr(service.controller, "_run_command", command)
    for action in ("start", "stop"):
        code, view = await service.controller.operate(action)
        assert code == 503 and view["state"] == "unavailable"
        assert view["can_start"] is False and view["can_stop"] is False
    assert all(c.args[0][6] == "status" for c in command.call_args_list)
    assert service.controller._task is None and service.requests == []


@pytest.mark.parametrize("stamp", [None, True, "1700000000", 0, -1, float("nan"),
                                    float("inf"), -float("inf"), {}, 10 ** 400],
                         ids=["null", "bool", "string", "zero", "negative", "nan",
                              "infinity", "negative-infinity", "object", "overflow"])
async def test_invalid_started_at_never_authorizes_operation(service, monkeypatch, stamp):
    service.controller._helper_path = "/mock/helper.py"
    payload = json.dumps(helper_state(started_at=stamp)).encode()
    command = Mock(return_value=subprocess.CompletedProcess([], 0, payload))
    monkeypatch.setattr(service.controller, "_run_command", command)
    for action in ("start", "stop"):
        code, view = await service.controller.operate(action)
        assert code == 503 and view["state"] == "unavailable"
        assert view["can_start"] is False and view["can_stop"] is False
    assert all(c.args[0][6] == "status" for c in command.call_args_list)
    assert service.controller._task is None and service.requests == []


async def test_missing_started_at_fails_closed(service, monkeypatch):
    raw = helper_state()
    del raw["started_at"]
    service.controller._helper_path = "/mock/helper.py"
    command = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(raw).encode()))
    monkeypatch.setattr(service.controller, "_run_command", command)
    view = await service.controller.status()
    assert view["state"] == "unavailable"
    assert view["can_start"] is False and view["can_stop"] is False
    assert service.requests == []


@pytest.mark.parametrize("action", ["restart", "start; echo injected", "--help", ""])
async def test_unsupported_actions_never_reach_command(service, monkeypatch, action):
    command = Mock(side_effect=AssertionError("不允许执行注入动作"))
    monkeypatch.setattr(service.controller, "_run_command", command)
    for method in (service.controller._invoke, service.controller.operate):
        with pytest.raises(ValueError, match="不支持"):
            await method(action)
    command.assert_not_called()


async def test_non_windows_host_is_unavailable_without_command(service, monkeypatch):
    monkeypatch.setattr(service_module, "os", SimpleNamespace(name="posix", environ={}))
    command = Mock(side_effect=AssertionError("非 Windows 不应调用 WSL"))
    monkeypatch.setattr(service.controller, "_run_command", command)
    assert (await service.controller.status())["state"] == "unavailable"
    command.assert_not_called()


@pytest.mark.parametrize("timeout", [10, 15, 45])
def test_run_command_does_not_pass_secrets_or_use_shell(monkeypatch, timeout):
    allowed = {"SystemRoot": "C:\\Windows", "Path": "mock-path", "TEMP": "mock-temp"}
    secrets = {name: "test-secret" for name in (
        "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "HF_TOKEN", "GW_API_KEY", "WSLENV",
        "BASH_ENV", "ENV", "PYTHONPATH", "LD_PRELOAD", "UNRELATED_SECRET")}
    monkeypatch.setattr(service_module, "os", SimpleNamespace(name="nt", environ={**allowed, **secrets}))
    result = subprocess.CompletedProcess([], 0, b"{}")
    run = Mock(return_value=result)
    monkeypatch.setattr(subprocess, "run", run)
    argv = ["wsl.exe", "-d", "Ubuntu-24.04", "--", "/mock path/helper.py", "status"]
    assert ORIGINAL_RUN_COMMAND(argv, timeout) is result
    run.assert_called_once()
    assert run.call_args.args == (argv,)
    assert run.call_args.kwargs == dict(
        stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False,
        env=allowed, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert "test-secret" not in run.call_args.kwargs["env"].values()
