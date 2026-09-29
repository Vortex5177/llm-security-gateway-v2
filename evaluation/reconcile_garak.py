r"""garak 子集 ↔ 网关 security_events 三方对账。

garak 用它自己的 detector 判定"模型层是否被攻破"；本网关的职责是在代理层
检出/阻断。本脚本对 garak 子集运行结果做三方对账：

  garak 探针 attempt（prompt 文本） × 网关规则检出（离线复扫） × security_events（运行窗口）

分类每个 in-scope attempt：
- blocked：网关规则 action=block（strict-demo 下 secret.*）→ 请求会被 400 拦截；
- detected：命中任一网关规则（audit/redact/block）→ 代理层可观测；
- passed：网关规则未命中（多为语义/编码绕过，属模型层职责）。

用法：
    .\.venv\Scripts\python.exe evaluation/reconcile_garak.py \
        --hitlog evaluation/reports/garak/<prefix>.hitlog.jsonl \
        --report evaluation/reports/garak/<prefix>.report.json \
        [--since 2026-09-29T14:00:00]

garak 为可选外部重型工具（torch），在独立 .garak-venv 运行；本脚本只用网关
自身依赖（无 torch），对 garak 产物做离线解析，故即使 garak 未安装也可对
既有 hitlog 复算。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "gateway.db"
REPORTS = PROJECT_ROOT / "evaluation" / "reports"

sys.path.insert(0, str(PROJECT_ROOT))

from app.security.engine import SecurityEngine  # noqa: E402
from app.security.policy import load_policy  # noqa: E402

# garak 探针 → 网关职责映射（in-scope 才纳入对账；其余归模型层）
PROBE_SCOPE = {
    "promptinject": "injection",
    "dan": "injection",
    "knownbadsignatures": "injection",
    "leakreplay": "secret",
    "credential_leak": "secret",
    "xss": "response",
    "snowball": "out_of_scope",
    "glitch": "out_of_scope",
    "encoding": "out_of_scope",
    "misleading": "out_of_scope",
}

DISCLAIMER = (
    "Metrics are evaluated on garak probe outputs against the gateway's rule "
    "engine and do not represent production performance."
)


def classify_scope(probe: str) -> str:
    """garak 探针名（如 promptinject.PromptInjectTests）→ 职责域。"""
    head = probe.split(".")[0].lower()
    for key, scope in PROBE_SCOPE.items():
        if key in head:
            return scope
    return "unknown"


def load_hitlog(path: Path) -> list[dict]:
    """解析 garak .hitlog.jsonl，抽取每条 attempt 的 prompt 文本。"""
    attempts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        # garak hitlog 结构随版本变化，尽量兼容地取 prompt 文本
        probe = rec.get("probe", "")
        detector = rec.get("detector", "")
        prompt = _extract_prompt(rec)
        attempts.append({
            "probe": probe,
            "detector": detector,
            "prompt": prompt,
            "status": rec.get("status"),
            "raw_keys": sorted(rec.keys()),
        })
    return attempts


def _extract_prompt(rec: dict) -> str:
    for key in ("prompt", "messages", "attempt", "input"):
        val = rec.get(key)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, list) and val:
            # messages 形式：拼接所有 user/content 文本
            parts = []
            for m in val:
                if isinstance(m, dict):
                    parts.append(str(m.get("content", "")))
                else:
                    parts.append(str(m))
            joined = "\n".join(p for p in parts if p)
            if joined:
                return joined
        if isinstance(val, dict):
            content = val.get("content")
            if isinstance(content, str):
                return content
    return ""


def load_report(path: Path | None) -> dict:
    if not path or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def events_in_window(since_iso: str | None) -> dict:
    """运行窗口内的 security_events 聚合（按 rule_id/action 计数）。"""
    if not DB_PATH.is_file():
        return {"total": 0, "by_rule": {}, "by_action": {}}
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        if since_iso:
            rows = conn.execute(
                "SELECT rule_id, action FROM security_events WHERE ts >= ? AND rule_id IS NOT NULL",
                (since_iso,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT rule_id, action FROM security_events WHERE rule_id IS NOT NULL"
            ).fetchall()
    finally:
        conn.close()
    by_rule: dict[str, int] = {}
    by_action: dict[str, int] = {}
    for row in rows:
        by_rule[row["rule_id"]] = by_rule.get(row["rule_id"], 0) + 1
        by_action[row["action"]] = by_action.get(row["action"], 0) + 1
    return {"total": len(rows), "by_rule": by_rule, "by_action": by_action}


def reconcile(attempts: list[dict], engine: SecurityEngine) -> dict:
    in_scope = [a for a in attempts if classify_scope(a["probe"]) not in ("out_of_scope", "unknown")]
    blocked = detected = passed = 0
    per_probe: dict[str, dict] = {}
    no_prompt = 0

    for a in in_scope:
        probe = a["probe"] or "(unknown-probe)"
        slot = per_probe.setdefault(probe, {"total": 0, "blocked": 0, "detected": 0, "passed": 0})
        slot["total"] += 1
        prompt = a["prompt"]
        if not prompt:
            no_prompt += 1
            continue
        findings = engine.scan_text(prompt)
        actions = {f.action for f in findings}
        if findings:
            slot["detected"] += 1
            detected += 1
            if "block" in actions:
                slot["blocked"] += 1
                blocked += 1
        else:
            slot["passed"] += 1
            passed += 1

    out_of_scope = [a for a in attempts if classify_scope(a["probe"]) in ("out_of_scope", "unknown")]
    return {
        "attempts_total": len(attempts),
        "in_scope_total": len(in_scope),
        "out_of_scope_total": len(out_of_scope),
        "no_prompt_text": no_prompt,
        "blocked": blocked,
        "detected": detected,
        "passed": passed,
        "detection_rate": round(detected / len(in_scope), 3) if in_scope else None,
        "block_rate": round(blocked / len(in_scope), 3) if in_scope else None,
        "per_probe": per_probe,
    }


def render_markdown(recon: dict, events: dict, meta: dict) -> str:
    lines = [
        f"# garak 子集对账报告（{meta['run_id']}）",
        "",
        f"- garak hitlog: {meta['hitlog']}",
        f"- 策略: {meta['policy']} ｜ 时间: {meta['ts']}",
        f"- attempt 总数 {recon['attempts_total']}（in-scope {recon['in_scope_total']}，"
        f"out-of-scope {recon['out_of_scope_total']}，无 prompt 文本 {recon['no_prompt_text']}）",
        "",
        "## 网关职责内 attempt 分类",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| blocked（规则 action=block） | {recon['blocked']} |",
        f"| detected（命中任一规则） | {recon['detected']} |",
        f"| passed（未命中，属模型层） | {recon['passed']} |",
        f"| detection_rate | {recon['detection_rate']} |",
        f"| block_rate | {recon['block_rate']} |",
        "",
        "## 按 garak 探针",
        "",
        "| 探针 | total | blocked | detected | passed |",
        "| --- | --- | --- | --- | --- |",
    ]
    for probe, v in sorted(recon["per_probe"].items()):
        lines.append(
            f"| {probe} | {v['total']} | {v['blocked']} | {v['detected']} | {v['passed']} |"
        )
    lines += [
        "",
        "## 运行窗口 security_events 聚合（交叉核对）",
        "",
        f"- 事件总数: {events['total']}",
        f"- 按 action: {json.dumps(events['by_action'], ensure_ascii=False)}",
        "",
        "## 边界说明",
        "",
        "- garak 判定的是**模型层**是否被攻破；网关职责是**代理层**检出/阻断。",
        "- in-scope = promptinject/dan/knownbadsignatures/leakreplay/xss（规则可判定）。",
        "- out-of-scope = 语义改写/编码绕过/glitch 等，属模型层防御，网关如实标为 passed。",
        "- detected 为离线复扫 garak prompt 文本的结果（确定性，不依赖 request-id 关联）。",
        "",
        f"> {DISCLAIMER}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="garak 子集三方对账")
    parser.add_argument("--hitlog", required=True, help="garak .hitlog.jsonl 路径")
    parser.add_argument("--report", default="", help="garak .report.json 路径（可选）")
    parser.add_argument("--since", default="", help="security_events 起始时间（ISO，可选）")
    parser.add_argument("--policy", default="", help="策略文件（默认读 GATEWAY_SECURITY_CONFIG）")
    args = parser.parse_args()

    hitlog = Path(args.hitlog)
    if not hitlog.is_file():
        print(f"hitlog 不存在: {hitlog}", file=sys.stderr)
        return 2

    policy = load_policy(args.policy or None)
    engine = SecurityEngine(policy)
    attempts = load_hitlog(hitlog)
    if not attempts:
        print("hitlog 无可用 attempt（格式不兼容或为空）", file=sys.stderr)
        return 2

    recon = reconcile(attempts, engine)
    events = events_in_window(args.since or None)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"garak-recon-{ts}"
    meta = {
        "run_id": run_id,
        "hitlog": str(hitlog),
        "policy": args.policy or "GATEWAY_SECURITY_CONFIG/default",
        "ts": ts,
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"{run_id}.json").write_text(
        json.dumps({"meta": meta, "recon": recon, "events": events}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path = REPORTS / f"{run_id}.md"
    md_path.write_text(render_markdown(recon, events, meta), encoding="utf-8")

    print(
        f"in_scope={recon['in_scope_total']} blocked={recon['blocked']} "
        f"detected={recon['detected']} passed={recon['passed']} "
        f"detection_rate={recon['detection_rate']}"
    )
    print(f"报告: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
