r"""LLM Gateway 冒烟脚本。

覆盖：
  模块 1：/health（provider 可达性）、/v1/models、SQLite 建表
  模块 2：非流式 /v1/chat/completions（真调本地 vLLM）、x-gw-tag 硬顶注入与落库校验、
          DeepSeek 直连（未配置 DEEPSEEK_API_KEY 时自动跳过）、
          回退链演示（--fallback-demo，配合 gateway.fallback_demo.yaml 启动的网关）
  模块 3：流式 SSE（逐块接收/[DONE] 收尾/X-GW-TTFT-Ms/tokens 落库）、
          客户端中断记 client_abort、回退演示模式下的流式回退

用法（走项目 .venv，规避 PowerShell curl 剥壳问题）:
    .\.venv\Scripts\python.exe smoke_test.py
    .\.venv\Scripts\python.exe smoke_test.py --fallback-demo --base-url http://127.0.0.1:4101
退出码：0 = 全部通过（含跳过），1 = 存在失败项，2 = 脚本环境问题
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "gateway.db"
REQUIRED_TABLES = {"request_logs", "gpu_samples", "engine_samples"}
EXPECTED_MODEL_IDS = {"qwen3-1.7b", "deepseek-chat", "default"}
EXPECTED_PROVIDERS = {"local-vllm", "deepseek", "dashscope"}

_results: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    _results.append((name, status))
    suffix = f" | {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def skip(name: str, reason: str) -> None:
    _results.append((name, "SKIP"))
    print(f"[SKIP] {name} | {reason}")


def _first_content(payload: dict) -> str:
    try:
        return payload["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""


def _latest_request_log(db_path: Path):
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM request_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    return row


def _expected_tag_cap(tag: str) -> int | None:
    """从 gateway.yaml 读取指定 tag 的硬顶 max_tokens（断言随配置走，不硬编码）。"""
    cfg_path = PROJECT_ROOT / "gateway.yaml"
    if not cfg_path.is_file():
        return None
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None
    row = (data.get("injection") or {}).get(tag) or {}
    cap = row.get("max_tokens")
    return cap if isinstance(cap, int) else None


def _auth_headers(extra: dict | None = None) -> dict:
    """鉴权开启（V2 默认）时附带引导 admin key 的 Bearer 头。"""
    headers = dict(extra or {})
    key_file = PROJECT_ROOT / "data" / "bootstrap_admin_key.txt"
    if key_file.is_file():
        token = key_file.read_text(encoding="utf-8").splitlines()[0].strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def _chat_once(client, base_url: str, body: dict, tag: str | None = None):
    headers = _auth_headers({"x-gw-tag": tag} if tag else None)
    return client.post(
        f"{base_url}/v1/chat/completions", json=body, headers=headers, timeout=120.0
    )


# ------------------------------------------------------------ 模块 1

def check_health(client, base_url: str) -> dict:
    try:
        resp = client.get(f"{base_url}/health", timeout=30.0)
    except Exception as exc:
        check("GET /health 可访问", False, f"请求失败: {exc}")
        return {}
    if resp.status_code != 200:
        check("GET /health 可访问", False, f"HTTP {resp.status_code}: {resp.text[:200]}")
        return {}
    payload = resp.json()
    providers = payload.get("providers") or {}
    print("      /health providers:")
    for name, info in providers.items():
        state = "可达" if info.get("reachable") else "不可达"
        print(f"        - {name}: {state} ({info.get('detail')})")
    check("GET /health 返回 200 且 status=ok", payload.get("status") == "ok")
    check(
        "provider 清单完整（local-vllm/deepseek/dashscope）",
        EXPECTED_PROVIDERS <= set(providers),
        f"实际: {sorted(providers)}",
    )
    local = providers.get("local-vllm") or {}
    check(
        "local-vllm 可达",
        bool(local.get("reachable")),
        f"detail: {local.get('detail')}",
    )
    return providers


def check_models(client, base_url: str) -> None:
    try:
        resp = client.get(f"{base_url}/v1/models", headers=_auth_headers(), timeout=30.0)
    except Exception as exc:
        check("GET /v1/models 可访问", False, f"请求失败: {exc}")
        return
    if resp.status_code != 200:
        check("GET /v1/models 可访问", False, f"HTTP {resp.status_code}: {resp.text[:200]}")
        return
    payload = resp.json()
    data = payload.get("data") or []
    ids = {item.get("id") for item in data}
    print(f"      /v1/models: {sorted(str(i) for i in ids)}")
    check("GET /v1/models 返回 object=list", payload.get("object") == "list")
    missing = EXPECTED_MODEL_IDS - ids
    check(
        "模型列表包含 qwen3-1.7b/deepseek-chat/default",
        not missing,
        f"缺失: {sorted(missing)}" if missing else "",
    )


def check_db(db_path: Path) -> None:
    if not db_path.is_file():
        check("SQLite 已建表", False, f"数据库文件不存在: {db_path}")
        return
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    tables = {row[0] for row in rows}
    missing = REQUIRED_TABLES - tables
    check(
        "SQLite 已建表（request_logs/gpu_samples/engine_samples）",
        not missing,
        f"缺失: {sorted(missing)}" if missing else str(db_path),
    )


# ------------------------------------------------------------ 模块 2（非流式）

def check_chat_basic(client, base_url: str) -> None:
    body = {
        "model": "qwen3-1.7b",
        "messages": [{"role": "user", "content": "请只回复两个字：收到"}],
        "max_tokens": 16,
    }
    try:
        resp = _chat_once(client, base_url, body)
    except Exception as exc:
        check("POST /v1/chat/completions 可访问", False, f"请求失败: {exc}")
        return
    if resp.status_code != 200:
        check(
            "POST /v1/chat/completions 返回 200",
            False,
            f"HTTP {resp.status_code}: {resp.text[:200]}",
        )
        return
    payload = resp.json()
    check(
        "POST /v1/chat/completions 返回 200",
        True,
        f"content={_first_content(payload)[:20]!r}",
    )
    check(
        "响应为标准 OpenAI 格式（object=chat.completion + choices）",
        payload.get("object") == "chat.completion" and bool(payload.get("choices")),
    )
    usage = payload.get("usage") or {}
    check(
        "响应含 usage token 计数",
        (usage.get("total_tokens") or 0) > 0,
        f"prompt={usage.get('prompt_tokens')} completion={usage.get('completion_tokens')} total={usage.get('total_tokens')}",
    )
    check(
        "X-GW-Attempts=1（无回退）",
        resp.headers.get("x-gw-attempts") == "1",
        f"attempts={resp.headers.get('x-gw-attempts')}",
    )
    check(
        "X-GW-Provider=local-vllm",
        resp.headers.get("x-gw-provider") == "local-vllm",
        resp.headers.get("x-gw-provider", ""),
    )
    check(
        "X-GW-Resolved-Model=qwen3-1.7b",
        resp.headers.get("x-gw-resolved-model") == "qwen3-1.7b",
        resp.headers.get("x-gw-resolved-model", ""),
    )


def check_tag_injection(client, base_url: str, db_path: Path) -> None:
    expected_cap = _expected_tag_cap("speclens/scan")
    body = {
        "model": "qwen3-1.7b",
        "messages": [{"role": "user", "content": "请只回复两个字：收到"}],
        "max_tokens": 8,  # 客户端给 8，应被 x-gw-tag 行硬顶覆盖为配置值
    }
    try:
        resp = _chat_once(client, base_url, body, tag="speclens/scan")
    except Exception as exc:
        check("x-gw-tag 注入请求返回 200", False, f"请求失败: {exc}")
        return
    if resp.status_code != 200:
        check(
            "x-gw-tag 注入请求返回 200",
            False,
            f"HTTP {resp.status_code}: {resp.text[:200]}",
        )
        return
    check("x-gw-tag 注入请求返回 200", True)

    row = _latest_request_log(db_path)
    if row is None:
        check("request_logs 最新记录可校验注入", False, "未找到记录")
        return
    try:
        injected = json.loads(row["injected_json"] or "{}")
    except ValueError:
        injected = {}
    check(
        f"落库 injected_json.max_tokens=配置硬顶（{expected_cap}，客户端 8 被覆盖）",
        expected_cap is not None
        and injected.get("max_tokens") == expected_cap
        and injected.get("max_tokens") != 8,
        f"实际: {injected.get('max_tokens')}",
    )
    check(
        "落库 injected_json.chat_template_kwargs（extra 展开到顶级）",
        (injected.get("chat_template_kwargs") or {}).get("enable_thinking") is False,
        f"chat_template_kwargs={injected.get('chat_template_kwargs')}",
    )
    check(
        "落库 tag/status 正确",
        row["tag"] == "speclens/scan" and row["status"] == "ok",
        f"tag={row['tag']} status={row['status']}",
    )
    check(
        "落库 provider/tokens/延迟完整",
        row["provider"] == "local-vllm"
        and (row["total_tokens"] or 0) > 0
        and row["latency_ms"] is not None,
        f"provider={row['provider']} tokens={row['total_tokens']} "
        f"latency={row['latency_ms']}ms attempts={row['attempts']}",
    )


def check_deepseek(client, base_url: str, health_providers: dict) -> None:
    info = (health_providers or {}).get("deepseek") or {}
    if not info.get("reachable"):
        skip(
            "DeepSeek 直连调用",
            f"deepseek 不可达（{info.get('detail') or '未知'}）；在 .env 配置 DEEPSEEK_API_KEY 后自动启用",
        )
        skip("DeepSeek 流式调用", "依赖 DEEPSEEK_API_KEY，未配置")
        return
    body = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": "请只回复两个字：收到"}],
        "max_tokens": 16,
    }
    try:
        resp = _chat_once(client, base_url, body)
    except Exception as exc:
        check("DeepSeek 直连调用返回 200", False, f"请求失败: {exc}")
        return
    ok = resp.status_code == 200
    check(
        "DeepSeek 直连调用返回 200",
        ok,
        f"HTTP {resp.status_code}" if ok else f"HTTP {resp.status_code}: {resp.text[:150]}",
    )
    if not ok:
        skip("DeepSeek 流式调用", "非流式直连失败，跳过")
        return
    check(
        "DeepSeek 响应 X-GW-Provider=deepseek",
        resp.headers.get("x-gw-provider") == "deepseek",
        resp.headers.get("x-gw-provider", ""),
    )

    # 流式直连
    stream_body = dict(body, stream=True, max_tokens=32)
    try:
        with client.stream(
            "POST", f"{base_url}/v1/chat/completions", json=stream_body, headers=_auth_headers(), timeout=120.0
        ) as sresp:
            sresp_status = sresp.status_code
            provider_header = sresp.headers.get("x-gw-provider")
            data_lines = [
                line for line in sresp.iter_lines() if line.startswith("data:")
            ]
    except Exception as exc:
        check("DeepSeek 流式调用返回 200", False, f"请求失败: {exc}")
        return
    if sresp_status != 200:
        check("DeepSeek 流式调用返回 200", False, f"HTTP {sresp_status}")
        return
    check("DeepSeek 流式调用返回 200", True, f"data 行数={len(data_lines)}")
    check(
        "DeepSeek 流式以 [DONE] 收尾",
        bool(data_lines) and data_lines[-1].strip() == "data: [DONE]",
    )
    check(
        "DeepSeek 流式 X-GW-Provider=deepseek",
        provider_header == "deepseek",
        provider_header or "",
    )
# ------------------------------------------------------------ 回退链演示（模块 2/3）

def check_fallback_demo(client, base_url: str) -> None:
    body = {
        "model": "default",  # gateway.fallback_demo.yaml：default -> qwen3-broken（坏端口）
        "messages": [{"role": "user", "content": "请只回复两个字：收到"}],
        "max_tokens": 16,
    }
    try:
        resp = _chat_once(client, base_url, body)
    except Exception as exc:
        check("回退链：最终返回 200", False, f"请求失败: {exc}")
        return
    if resp.status_code != 200:
        check(
            "回退链：最终返回 200（客户端无感）",
            False,
            f"HTTP {resp.status_code}: {resp.text[:200]}",
        )
        return
    check(
        "回退链：最终返回 200（客户端无感）",
        True,
        f"content={_first_content(resp.json())[:20]!r}",
    )
    check(
        "回退链：X-GW-Attempts=2（主模型失败后自动回退）",
        resp.headers.get("x-gw-attempts") == "2",
        f"attempts={resp.headers.get('x-gw-attempts')}",
    )
    check(
        "回退链：X-GW-Resolved-Model=qwen3-1.7b（回退后的真实模型）",
        resp.headers.get("x-gw-resolved-model") == "qwen3-1.7b",
        f"resolved={resp.headers.get('x-gw-resolved-model')}",
    )
    check(
        "回退链：X-GW-Provider=local-vllm",
        resp.headers.get("x-gw-provider") == "local-vllm",
        resp.headers.get("x-gw-provider", ""),
    )


def check_fallback_demo_stream(client, base_url: str) -> None:
    body = {
        "model": "default",  # 首块前失败（连接被拒）→ 自动回退，客户端无感
        "messages": [{"role": "user", "content": "请只回复两个字：收到"}],
        "max_tokens": 16,
        "stream": True,
    }
    try:
        with client.stream(
            "POST", f"{base_url}/v1/chat/completions", json=body, headers=_auth_headers(), timeout=120.0
        ) as resp:
            status_code = resp.status_code
            attempts = resp.headers.get("x-gw-attempts")
            resolved = resp.headers.get("x-gw-resolved-model")
            provider = resp.headers.get("x-gw-provider")
            data_lines = [
                line for line in resp.iter_lines() if line.startswith("data:")
            ]
    except Exception as exc:
        check("流式回退链：流式请求可访问", False, f"请求失败: {exc}")
        return
    if status_code != 200:
        check("流式回退链：最终返回 200（客户端无感）", False, f"HTTP {status_code}")
        return
    check("流式回退链：最终返回 200（客户端无感）", True)
    check(
        "流式回退链：X-GW-Attempts=2（首块前失败自动回退）",
        attempts == "2",
        f"attempts={attempts}",
    )
    check(
        "流式回退链：X-GW-Resolved-Model=qwen3-1.7b",
        resolved == "qwen3-1.7b",
        f"resolved={resolved}",
    )
    check(
        "流式回退链：X-GW-Provider=local-vllm",
        provider == "local-vllm",
        provider or "",
    )
    check(
        "流式回退链：以 [DONE] 收尾",
        bool(data_lines) and data_lines[-1].strip() == "data: [DONE]",
        f"data 行数={len(data_lines)}",
    )


# ------------------------------------------------------------ 模块 3（流式）

def check_stream_basic(client, base_url: str, db_path: Path) -> None:
    body = {
        "model": "qwen3-1.7b",
        "messages": [{"role": "user", "content": "请用一句话介绍你自己"}],
        "max_tokens": 96,
        "stream": True,
    }
    try:
        with client.stream(
            "POST", f"{base_url}/v1/chat/completions", json=body, headers=_auth_headers(), timeout=120.0
        ) as resp:
            resp_status = resp.status_code
            content_type = resp.headers.get("content-type", "")
            ttft_header = resp.headers.get("x-gw-ttft-ms")
            attempts_header = resp.headers.get("x-gw-attempts")
            data_lines = [
                line for line in resp.iter_lines() if line.startswith("data:")
            ]
    except Exception as exc:
        check("流式请求可访问", False, f"请求失败: {exc}")
        return
    if resp_status != 200:
        check("流式请求返回 200", False, f"HTTP {resp_status}")
        return
    check(
        "流式请求返回 200（text/event-stream）",
        "text/event-stream" in content_type,
        f"content-type={content_type}",
    )
    check("逐块接收 data 行", len(data_lines) >= 2, f"data 行数={len(data_lines)}")
    tail = data_lines[-1].strip() if data_lines else ""
    check("以 data: [DONE] 收尾", tail == "data: [DONE]", f"末尾={tail[:40] or 'N/A'}")
    check("响应头含 X-GW-TTFT-Ms", ttft_header is not None, f"ttft={ttft_header}ms")
    check("X-GW-Attempts=1（无回退）", attempts_header == "1", f"attempts={attempts_header}")

    row = _latest_request_log(db_path)
    if row is None:
        check("落库流式记录", False, "未找到记录")
        return
    check(
        "落库 streamed=1 且 status=ok",
        bool(row["streamed"]) and row["status"] == "ok",
        f"streamed={row['streamed']} status={row['status']}",
    )
    ttft = row["ttft_ms"]
    latency = row["latency_ms"]
    check(
        "落库 ttft_ms 显著小于 latency_ms",
        ttft is not None and latency is not None and 0 < ttft <= latency * 0.8,
        f"ttft={ttft}ms latency={latency}ms",
    )
    check(
        "落库流式 tokens>0（尾部 usage 捕获）",
        (row["total_tokens"] or 0) > 0,
        f"tokens={row['total_tokens']}",
    )


def check_stream_client_abort(client, base_url: str, db_path: Path) -> None:
    body = {
        "model": "qwen3-1.7b",
        "messages": [{"role": "user", "content": "请写一段约两百字的散文，主题是秋天"}],
        "max_tokens": 400,
        "stream": True,
    }
    got = 0
    try:
        with client.stream(
            "POST", f"{base_url}/v1/chat/completions", json=body, headers=_auth_headers(), timeout=120.0
        ) as resp:
            if resp.status_code != 200:
                check("中断演示：流式请求建立成功", False, f"HTTP {resp.status_code}")
                return
            for line in resp.iter_lines():
                if line.startswith("data:"):
                    got += 1
                    if got >= 2:
                        break  # 收到首块后主动断开（with 退出即关闭连接）
    except Exception as exc:
        check("中断演示：流式请求建立成功", False, f"请求失败: {exc}")
        return
    check("中断演示：收到首块后主动断开", got >= 1, f"断开前收到 {got} 个 data 块")

    row = None
    for _ in range(24):  # 最多等约 6 秒，服务端需要感知断连并落库
        row = _latest_request_log(db_path)
        if row is not None and row["status"] == "client_abort":
            break
        time.sleep(0.25)
    check(
        "中断请求落库 status=client_abort",
        row is not None and row["status"] == "client_abort" and bool(row["streamed"]),
        f"status={row['status'] if row else 'N/A'} "
        f"streamed={row['streamed'] if row else 'N/A'} "
        f"attempts={row['attempts'] if row else 'N/A'}",
    )


def check_dashboard(client, base_url: str, db_path: Path) -> None:
    """模块 5/6：仪表盘静态页 + 聚合 API 与手写 SQL 对照。"""
    from datetime import datetime, timedelta, timezone

    resp = client.get(f"{base_url}/")
    html_ok = resp.status_code == 200 and "text/html" in resp.headers.get("content-type", "")
    check(
        "仪表盘页面可访问（/ -> 200 HTML）",
        html_ok,
        f"HTTP {resp.status_code}, {len(resp.content)} bytes",
    )
    check("页面标题存在", "LLM Gateway" in resp.text, "含 'LLM Gateway'")

    chart = client.get(f"{base_url}/chart.umd.min.js")
    check(
        "本地 Chart.js 可访问（零 CDN）",
        chart.status_code == 200 and len(chart.content) > 50000,
        f"HTTP {chart.status_code}, {len(chart.content)} bytes",
    )

    api = client.get(f"{base_url}/api/stats", params={"days": 1})
    if api.status_code != 200:
        check("聚合 API /api/stats 可访问", False, f"HTTP {api.status_code}")
        return
    data = api.json()
    expect_keys = {"totals", "by_tag", "timeseries", "gpu", "engine", "recent"}
    check(
        "聚合 API 结构完整",
        expect_keys.issubset(data.keys()),
        ",".join(sorted(data.keys())),
    )

    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )
    con = sqlite3.connect(db_path)
    try:
        count, tokens = con.execute(
            "SELECT COUNT(*), COALESCE(SUM(total_tokens), 0) FROM request_logs "
            "WHERE created_at >= ?",
            (since,),
        ).fetchone()
    finally:
        con.close()
    totals = data.get("totals", {})
    check(
        "totals 与手写 SQL 一致（requests/tokens）",
        totals.get("requests") == count and totals.get("tokens") == int(tokens),
        f"api {totals.get('requests')}/{totals.get('tokens')} vs sql {count}/{int(tokens)}",
    )
    check(
        "recent 行数与窗口一致（<=50）",
        len(data.get("recent", [])) == min(count, 50),
        f"recent={len(data.get('recent', []))} window={count}",
    )

# ------------------------------------------------------------ main

def main() -> int:
    parser = argparse.ArgumentParser(description="LLM Gateway 冒烟测试")
    parser.add_argument("--base-url", default="http://127.0.0.1:4101", help="网关地址")
    parser.add_argument(
        "--db-path", default=str(DEFAULT_DB_PATH), help="SQLite 文件路径"
    )
    parser.add_argument(
        "--fallback-demo",
        action="store_true",
        help="回退链演示模式（配合 gateway.fallback_demo.yaml 启动的网关使用）",
    )
    args = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("缺少 httpx，请使用项目 .venv 运行: .venv\\Scripts\\python.exe smoke_test.py")
        return 2

    base_url = args.base_url.rstrip("/")
    db_path = Path(args.db_path)

    if args.fallback_demo:
        print(f"== LLM Gateway 回退链演示冒烟 ==  目标: {base_url}")
        with httpx.Client(timeout=120.0) as client:
            check_fallback_demo(client, base_url)
            check_fallback_demo_stream(client, base_url)
    else:
        print(f"== LLM Gateway 冒烟测试 ==  目标: {base_url}")
        health_providers: dict = {}
        with httpx.Client(timeout=120.0) as client:
            health_providers = check_health(client, base_url)
            check_models(client, base_url)
            check_chat_basic(client, base_url)
            check_tag_injection(client, base_url, db_path)
            check_stream_basic(client, base_url, db_path)
            check_stream_client_abort(client, base_url, db_path)
            check_deepseek(client, base_url, health_providers)
            check_dashboard(client, base_url, db_path)
        check_db(db_path)

    failed = [name for name, status in _results if status == "FAIL"]
    passed = sum(1 for _, s in _results if s == "PASS")
    skipped = sum(1 for _, s in _results if s == "SKIP")
    print()
    if failed:
        print(f"结果: {passed} 通过 / {len(failed)} 失败 / {skipped} 跳过 -> FAIL")
        for name in failed:
            print(f"  - 失败: {name}")
        return 1
    print(f"结果: {passed} 通过 / {skipped} 跳过 -> PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())