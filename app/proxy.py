"""httpx 上游调用：acomplete（非流式）/ open_stream（流式）。

返回统一的 CompletionResult / StreamSession，由 routing 决定是否回退到下一候选。
transport 参数用于测试注入 httpx.MockTransport。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

import httpx

from app.config import ProviderConfig, resolve_api_key


@dataclass
class CompletionResult:
    ok: bool
    http_status: int | None
    payload: dict[str, Any] | None  # 成功时的上游 JSON 响应
    error: str | None  # 失败描述（面向日志/客户端）
    timeout: bool = False


def _extract_error(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        text = resp.text[:500]
        return text or f"HTTP {resp.status_code}"
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str):
            return err
    return str(data)[:500]


def _build_headers(provider: ProviderConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = resolve_api_key(provider)
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


async def acomplete(
    provider: ProviderConfig,
    payload: dict[str, Any],
    timeout: float,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CompletionResult:
    """调用上游 POST {base_url}/chat/completions（非流式）。"""
    url = provider.base_url.rstrip("/") + "/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            resp = await client.post(url, json=payload, headers=_build_headers(provider))
    except httpx.TimeoutException as exc:
        return CompletionResult(
            ok=False, http_status=None, payload=None, error=f"上游超时: {exc}", timeout=True
        )
    except httpx.HTTPError as exc:
        return CompletionResult(
            ok=False, http_status=None, payload=None, error=f"上游不可达: {exc}"
        )
    if 200 <= resp.status_code < 300:
        try:
            body = resp.json()
        except ValueError:
            return CompletionResult(
                ok=False,
                http_status=resp.status_code,
                payload=None,
                error=f"上游返回非 JSON 响应: {resp.text[:200]}",
            )
        return CompletionResult(ok=True, http_status=resp.status_code, payload=body, error=None)
    return CompletionResult(
        ok=False,
        http_status=resp.status_code,
        payload=None,
        error=_extract_error(resp),
    )


class _LineReader:
    """字节流 → 行 的增量切分器（跨 chunk 保留半行缓冲，可转交后续读取）。"""

    def __init__(self, raw_iter: AsyncIterator[bytes]) -> None:
        self._raw = raw_iter
        self._buffer = b""

    async def next_line(self) -> bytes | None:
        while True:
            idx = self._buffer.find(b"\n")
            if idx >= 0:
                line, self._buffer = self._buffer[: idx + 1], self._buffer[idx + 1 :]
                return line
            try:
                chunk = await self._raw.__anext__()
            except StopAsyncIteration:
                if self._buffer:
                    line, self._buffer = self._buffer, b""
                    return line
                return None
            self._buffer += chunk

    async def iter_lines(self) -> AsyncIterator[bytes]:
        while True:
            line = await self.next_line()
            if line is None:
                return
            yield line


@dataclass
class StreamSession:
    """一次流式上游会话（成功时持有未读完的连接，必须 aclose）。

    first_event 为“流首 → 第一条 data 行”的原始字节（含之前的注释/空行）；
    其余行经 iter_rest() 读取。
    """

    ok: bool
    http_status: int | None = None
    error: str | None = None
    timeout: bool = False
    first_event: bytes = b""
    ttft_ms: float | None = None
    reader: _LineReader | None = None
    close_fn: Callable[[], Awaitable[None]] | None = None

    async def iter_rest(self) -> AsyncIterator[bytes]:
        if self.reader is not None:
            async for line in self.reader.iter_lines():
                yield line

    async def aclose(self) -> None:
        fn, self.close_fn = self.close_fn, None
        if fn is not None:
            try:
                await fn()
            except Exception:
                pass


async def open_stream(
    provider: ProviderConfig,
    payload: dict[str, Any],
    timeout: float,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> StreamSession:
    """发起流式请求并等待第一条 data 行。

    首条 data 行到达才算成功——首块前的任何失败（连接错/超时/非 2xx/无数据即结束）
    都返回 ok=False，由 routing 决定回退到下一候选。
    """
    url = provider.base_url.rstrip("/") + "/chat/completions"
    client = httpx.AsyncClient(timeout=timeout, transport=transport)
    started = time.perf_counter()
    try:
        request = client.build_request(
            "POST", url, json=payload, headers=_build_headers(provider)
        )
        resp = await client.send(request, stream=True)
    except httpx.TimeoutException as exc:
        await client.aclose()
        return StreamSession(ok=False, error=f"上游超时: {exc}", timeout=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        return StreamSession(ok=False, error=f"上游不可达: {exc}")

    if resp.status_code >= 400:
        await resp.aread()
        error = _extract_error(resp)
        await resp.aclose()
        await client.aclose()
        return StreamSession(ok=False, http_status=resp.status_code, error=error)

    async def _close() -> None:
        await resp.aclose()
        await client.aclose()

    reader = _LineReader(resp.aiter_bytes())
    prefix = b""
    try:
        while True:
            line = await reader.next_line()
            if line is None:
                await _close()
                return StreamSession(
                    ok=False,
                    http_status=resp.status_code,
                    error="上游流在输出任何数据前结束",
                )
            prefix += line
            if line.startswith(b"data:"):
                break
    except httpx.TimeoutException as exc:
        await _close()
        return StreamSession(
            ok=False, http_status=resp.status_code, error=f"等待首块超时: {exc}", timeout=True
        )
    except httpx.HTTPError as exc:
        await _close()
        return StreamSession(
            ok=False, http_status=resp.status_code, error=f"读取首块失败: {exc}"
        )

    return StreamSession(
        ok=True,
        http_status=resp.status_code,
        first_event=prefix,
        ttft_ms=round((time.perf_counter() - started) * 1000, 2),
        reader=reader,
        close_fn=_close,
    )