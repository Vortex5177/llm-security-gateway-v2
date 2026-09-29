"""本机 vLLM 管理接口；来源校验必须先于任何系统操作。"""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["local-vllm"])


def assert_local_control(request: Request, *, write=False) -> None:
    # 代理头不能成为本机来源证据，也避免 Uvicorn 代理中间件已改写 client 的情况。
    if any(name == "forwarded" or name.startswith("x-forwarded-")
           or name == "x-real-ip" for name in request.headers):
        raise HTTPException(403, "控制接口不接受代理转发请求")
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    port = request.app.state.config.server.port
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    hosts = request.headers.getlist("host")
    if not local or len(hosts) != 1 or hosts[0].lower() not in allowed:
        raise HTTPException(403, "仅允许本机看板调用服务控制接口")
    origins = request.headers.getlist("origin")
    expected = request.url.scheme + "://" + hosts[0].lower()
    if (write or origins) and (len(origins) != 1 or origins[0].lower() != expected):
        raise HTTPException(403, "服务控制要求严格同源 Origin")
    if write and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "仅接受 application/json 请求")


@router.get("/api/local-vllm")
async def local_vllm_status(request: Request):
    assert_local_control(request)
    view = await request.app.state.vllm_service.status()
    return JSONResponse(view, headers={"Cache-Control": "no-store"})


async def _operate(request: Request, action: str):
    assert_local_control(request, write=True)
    # 不使用动态命令端点；body 最多携带受控的候选模型名。
    try:
        body = await request.json()
    except (ValueError, UnicodeError):
        raise HTTPException(400, "请求体必须是 JSON 对象") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "请求体必须是 JSON 对象")
    if action == "stop":
        if body:
            raise HTTPException(400, "停止请求不接受运行参数")
        model = None
    else:
        if set(body) - {"model"}:
            raise HTTPException(400, "请求体只接受 model 字段，不接受运行参数")
        model = body.get("model")
        if model is not None and (
                not isinstance(model, str)
                or model not in request.app.state.config.local_vllm.model_names):
            raise HTTPException(400, "未知的候选模型")
    code, view = await request.app.state.vllm_service.operate(action, model)
    return JSONResponse(view, status_code=code, headers={"Cache-Control": "no-store"})


@router.post("/api/local-vllm/start")
async def local_vllm_start(request: Request):
    return await _operate(request, "start")


@router.post("/api/local-vllm/switch")
async def local_vllm_switch(request: Request):
    return await _operate(request, "switch")


@router.post("/api/local-vllm/stop")
async def local_vllm_stop(request: Request):
    return await _operate(request, "stop")
