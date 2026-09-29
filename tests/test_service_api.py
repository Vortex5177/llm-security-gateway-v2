"""真实路由的内存 ASGI 测试；只注入假服务，不启动 Gateway 生命周期。"""

from types import SimpleNamespace
import subprocess
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from app import config as config_module
from app.config import parse_config
from app.registry import Registry
from app.routes import health, models, service
from app.vllm_service import VllmService


BASE_URL = "http://127.0.0.1:4101"
ROOT = "/api/local-vllm"


class FakeService:
    def __init__(self):
        self.view = dict(state="stopped", model="qwen3-1.7b", models=["qwen3-1.7b"],
                         current=None, url="http://localhost:8200/v1",
                         can_start=True, can_stop=False, detail="假服务状态")
        self.status = AsyncMock(return_value=self.view)
        self.operate = AsyncMock(return_value=(202, self.view))

    def assert_not_called(self):
        self.status.assert_not_called()
        self.operate.assert_not_called()


@pytest.fixture(autouse=True)
def forbid_real_operations(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("API 测试禁止真实控制器、网络与环境文件访问")

    for name in ("status", "operate", "_invoke", "_run_command", "close"):
        monkeypatch.setattr(VllmService, name, forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(config_module, "load_dotenv", forbidden)
    monkeypatch.setattr(config_module, "get_config", forbidden)


@pytest.fixture
async def api(config_dict, monkeypatch):
    # 不导入会在模块级加载 .env 的 app.main；直接注册实际生产路由。
    config_dict["local_vllm"] = {"enabled": True, "models": ["/opt/models/Qwen3-1.7B"]}
    application = FastAPI()
    application.state.config = parse_config(config_dict)
    application.state.registry = Registry(application.state.config)
    fake = FakeService()
    application.state.vllm_service = fake
    application.include_router(service.router)
    application.include_router(health.router)
    application.include_router(models.router)
    application.state.http_transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"data": []}))
    monkeypatch.setattr(health, "resolve_api_key", lambda provider: "mock-key")
    transport = httpx.ASGITransport(app=application, client=("127.0.0.1", 12345))
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL, trust_env=False) as client:
        yield SimpleNamespace(app=application, fake=fake, client=client)


async def test_get_returns_fake_status_without_cache_or_operation(api):
    response = await api.client.get(ROOT)
    assert response.status_code == 200 and response.json() == api.fake.view
    assert response.headers["cache-control"] == "no-store"
    api.fake.status.assert_awaited_once_with()
    api.fake.operate.assert_not_called()


@pytest.mark.parametrize("action", ["start", "stop", "switch"])
@pytest.mark.parametrize("code,state", [(202, "starting"), (200, "running"),
                                         (409, "conflict"), (503, "unavailable")])
async def test_post_preserves_service_result_and_only_passes_action(api, action, code, state):
    view = {**api.fake.view, "state": state}
    api.fake.operate.return_value = (code, view)
    response = await api.client.post(ROOT + "/" + action, json={}, headers={"Origin": BASE_URL})
    assert response.status_code == code and response.json() == view
    assert response.headers["cache-control"] == "no-store"
    api.fake.operate.assert_awaited_once_with(action, None)
    api.fake.status.assert_not_called()


@pytest.mark.parametrize("authority", ["127.0.0.1:4101", "localhost:4101", "[::1]:4101"])
async def test_exact_loopback_host_and_origin_are_allowed(api, authority):
    headers = {"Host": authority, "Origin": "http://" + authority}
    response = await api.client.get(ROOT, headers=headers)
    assert response.status_code == 200
    response = await api.client.post(ROOT + "/start", json={}, headers=headers)
    assert response.status_code == 202
    api.fake.status.assert_awaited_once_with()
    api.fake.operate.assert_awaited_once_with("start", None)


BAD_ORIGINS = [
    pytest.param("https://evil.example", id="cross-origin"),
    pytest.param("null", id="null"),
    pytest.param("", id="empty"),
    pytest.param("http://127.0.0.1:4102", id="other-port"),
    pytest.param("https://127.0.0.1:4101", id="other-scheme"),
    pytest.param("http://localhost:4101", id="other-loopback-host"),
    pytest.param("http://127.0.0.1", id="missing-port"),
    pytest.param(BASE_URL + "/", id="trailing-slash"),
    pytest.param(BASE_URL + " https://evil.example", id="multiple-origins"),
]


@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/start"),
                                          ("POST", ROOT + "/switch"), ("POST", ROOT + "/stop")])
@pytest.mark.parametrize("origin", BAD_ORIGINS)
async def test_invalid_origin_rejected_before_fake_service(api, method, path, origin):
    response = await api.client.request(method, path, json={}, headers={"Origin": origin})
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("action", ["start", "stop", "switch"])
async def test_missing_write_origin_is_forbidden(api, action):
    response = await api.client.post(ROOT + "/" + action, json={})
    assert response.status_code == 403
    api.fake.assert_not_called()


BAD_HOSTS = ["evil.example:4101", "127.0.0.1.evil.example:4101", "127.0.0.1:4102",
             "127.0.0.1", "localhost", "127.0.0.1:invalid", "localhost:65536",
             "user@127.0.0.1:4101", "0.0.0.0:4101", "[::]:4101"]


@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/start")])
@pytest.mark.parametrize("host", BAD_HOSTS)
async def test_spoofed_host_or_wrong_port_rejected_even_with_matching_origin(api, method, path, host):
    response = await api.client.request(method, path, json={}, headers={
        "Host": host, "Origin": "http://" + host})
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("header,value", [
    ("Forwarded", "for=127.0.0.1;host=127.0.0.1:4101"),
    ("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-Host", "127.0.0.1:4101"),
    ("X-Forwarded-Proto", "http"), ("X-Forwarded-Port", "4101"),
    ("X-Forwarded-Anything", ""), ("X-Real-IP", "127.0.0.1"),
])
@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/stop")])
async def test_proxy_headers_never_authorize_local_control(api, header, value, method, path):
    response = await api.client.request(method, path, json={}, headers={"Origin": BASE_URL, header: value})
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("header,value", [("Host", "127.0.0.1:4101"), ("Origin", BASE_URL)])
@pytest.mark.parametrize("duplicate", ["same", "different"])
@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/start")])
async def test_duplicate_host_or_origin_rejected(api, header, value, duplicate, method, path):
    headers = [("Host", "127.0.0.1:4101"), ("Origin", BASE_URL)]
    headers.append((header.lower(), value if duplicate == "same" else "evil.example"))
    request = api.client.build_request(method, path, json={}, headers=headers)
    assert len(request.headers.get_list(header)) == 2
    response = await api.client.send(request)
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/stop")])
async def test_missing_host_is_forbidden(api, method, path):
    request = api.client.build_request(method, path, json={}, headers={"Origin": BASE_URL})
    del request.headers["host"]
    response = await api.client.send(request)
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("remote", [("192.0.2.1", 12345), ("192.168.1.9", 12345),
                                     ("::ffff:192.0.2.1", 12345), ("localhost", 12345), None])
@pytest.mark.parametrize("method,path", [("GET", ROOT), ("POST", ROOT + "/stop")])
async def test_remote_or_missing_client_rejected_despite_local_headers(api, remote, method, path):
    transport = httpx.ASGITransport(app=api.app, client=remote)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL, trust_env=False) as client:
        response = await client.request(method, path, json={}, headers={"Origin": BASE_URL})
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("action", ["start", "stop", "switch"])
@pytest.mark.parametrize("body", [
    b'{"command":"echo injected"}', b'{"model_path":"/tmp/other"}',
    b'{"action":"stop"}', b'{"args":["--port","9999"]}',
    b'{"model":"ghost"}', b'{"model":5}', b'{"model":"qwen3-1.7b","extra":1}',
    b"null", b"[]", b"1", b"true", b'"text"', b"", b"{broken", b"{}{}", b"\xff",
], ids=["command", "model-path", "action", "argv", "unknown-model", "non-string-model",
        "extra-key", "null", "array", "number", "bool", "string", "no-body",
        "invalid-json", "multiple-json", "invalid-utf8"])
async def test_nonempty_or_invalid_json_rejected_before_fake_service(api, action, body):
    response = await api.client.post(ROOT + "/" + action, content=body, headers={
        "Origin": BASE_URL, "Content-Type": "application/json"})
    assert response.status_code == 400
    api.fake.assert_not_called()


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded",
                                           "multipart/form-data", "application/jsonp", "text/json"])
@pytest.mark.parametrize("action", ["start", "stop", "switch"])
async def test_non_json_media_type_rejected_before_body_or_service(api, content_type, action):
    headers = {"Origin": BASE_URL}
    if content_type is not None:
        headers["Content-Type"] = content_type
    response = await api.client.post(ROOT + "/" + action, content=b"{}", headers=headers)
    assert response.status_code == 415
    api.fake.assert_not_called()


async def test_empty_json_with_charset_is_allowed(api):
    response = await api.client.post(ROOT + "/stop", content=b" {} \n", headers={
        "Origin": BASE_URL, "Content-Type": "application/json; charset=utf-8"})
    assert response.status_code == 202
    api.fake.operate.assert_awaited_once_with("stop", None)


@pytest.mark.parametrize("action", ["start", "switch"])
async def test_model_body_selects_candidate(api, action):
    response = await api.client.post(ROOT + "/" + action, json={"model": "qwen3-1.7b"},
                                     headers={"Origin": BASE_URL})
    assert response.status_code == 202
    api.fake.operate.assert_awaited_once_with(action, "qwen3-1.7b")


@pytest.mark.parametrize("action", ["start", "switch"])
async def test_null_model_body_equals_default(api, action):
    response = await api.client.post(ROOT + "/" + action, json={"model": None},
                                     headers={"Origin": BASE_URL})
    assert response.status_code == 202
    api.fake.operate.assert_awaited_once_with(action, None)


async def test_stop_rejects_model_body(api):
    response = await api.client.post(ROOT + "/stop", json={"model": "qwen3-1.7b"},
                                     headers={"Origin": BASE_URL})
    assert response.status_code == 400
    api.fake.assert_not_called()


async def test_origin_check_precedes_media_type_and_json_validation(api):
    response = await api.client.post(ROOT + "/start", content=b"invalid", headers={
        "Origin": "https://evil.example", "Content-Type": "text/plain"})
    assert response.status_code == 403
    api.fake.assert_not_called()


@pytest.mark.parametrize("path", ["/restart", "/status", "/command", "/start;echo-injected",
                                  "/start/stop", "/%73tart%3Becho-injected"])
async def test_no_dynamic_control_command_endpoint(api, path):
    response = await api.client.post(ROOT + path, json={}, headers={"Origin": BASE_URL})
    assert response.status_code == 404
    api.fake.assert_not_called()


@pytest.mark.parametrize("method,path", [("GET", ROOT + "/start"), ("GET", ROOT + "/stop"),
                                          ("GET", ROOT + "/switch"), ("POST", ROOT),
                                          ("PUT", ROOT + "/start"),
                                          ("DELETE", ROOT + "/stop")])
async def test_control_actions_cannot_use_other_http_methods(api, method, path):
    response = await api.client.request(method, path, json={}, headers={"Origin": BASE_URL})
    assert response.status_code == 405
    api.fake.assert_not_called()


async def test_query_parameters_cannot_change_fixed_action(api):
    response = await api.client.post(ROOT + "/start?command=echo-injected&action=stop&port=9999",
                                     json={}, headers={"Origin": BASE_URL})
    assert response.status_code == 202
    api.fake.operate.assert_awaited_once_with("start", None)
    api.fake.status.assert_not_called()


@pytest.mark.parametrize("path", ["/v1/models", "/health", "/api/models"])
async def test_existing_api_routes_do_not_inherit_control_origin_restrictions(api, path):
    response = await api.client.get(path, headers={"Host": "gw", "Origin": "https://other.example"})
    assert response.status_code == 200
    if path == "/v1/models":
        assert response.json()["object"] == "list"
    elif path == "/health":
        assert response.json()["status"] == "ok"
    else:
        assert "providers" in response.json() and "models" in response.json()
    api.fake.assert_not_called()
