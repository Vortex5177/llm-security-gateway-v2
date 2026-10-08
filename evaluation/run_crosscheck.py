# -*- coding: utf-8 -*-
r"""三方对照评测 · LLM Guard 侧（跑在仓库根 .venv-llmguard312，独立于网关 venv）。

对 crosscheck-v1 基准集（evaluation/datasets_benchmark/，510 条中英文）逐条跑
LLM Guard 四个输入扫描器：PromptInjection / Secrets / Anonymize / InvisibleText，
逐条明细落盘 JSON，供 gateway 侧 run_crosscheck_ours.py 聚合成三方对照报告。

判定口径：is_valid=False 表示该扫描器判定存在风险（llm-guard 惯例，
sanitized 文本被改写即视为检出）。

用法（仓库根，模型经 hf-mirror 下载）：
    $env:HF_ENDPOINT="https://hf-mirror.com"
    ..\.venv-llmguard312\Scripts\python.exe gateway-v2\evaluation\run_crosscheck.py

中文翻译版（--ds-dir 指向 datasets_benchmark_zh，--tag 体现在产物名）：
    ..\.venv-llmguard312\Scripts\python.exe gateway-v2\evaluation\run_crosscheck.py ^
        --ds-dir gateway-v2\evaluation\datasets_benchmark_zh --tag zh

产物：
    gateway-v2\evaluation\reports\crosscheck-llmguard[-tag]-<时间戳>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
sys.stdout.reconfigure(encoding="utf-8")

REPO = Path(__file__).resolve().parent.parent  # gateway-v2/
DS_DIR = REPO / "evaluation" / "datasets_benchmark"
REPORTS = REPO / "evaluation" / "reports"

from llm_guard.input_scanners import Anonymize, InvisibleText, PromptInjection, Secrets  # noqa: E402
from llm_guard.vault import Vault  # noqa: E402


def load_samples(ds_dir: Path) -> list[dict]:
    samples = []
    for p in sorted(ds_dir.glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                samples.append(json.loads(line))
    if not samples:
        raise SystemExit(f"未找到基准集 {ds_dir}，先运行 evaluation/curate_benchmark.py")
    return samples


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ds-dir", default=str(REPO / "evaluation" / "datasets_benchmark"))
    ap.add_argument("--tag", default="", help="产物名标记（如 zh），不影响默认复现链")
    args = ap.parse_args()

    ds_dir = Path(args.ds_dir)
    samples = load_samples(ds_dir)
    print(f"样本总数 {len(samples)}（{ds_dir}）", flush=True)

    t0 = time.perf_counter()
    pi = PromptInjection(threshold=0.9)
    print(f"PromptInjection 就绪 {time.perf_counter() - t0:.1f}s", flush=True)
    sec = Secrets()
    anon = Anonymize(vault=Vault())
    print("Secrets / Anonymize / InvisibleText 就绪", flush=True)
    inv = InvisibleText()

    rows: list[dict] = []
    for i, s in enumerate(samples, 1):
        text = s["text"]
        t = time.perf_counter()
        _, ok_pi, score_pi = pi.scan(text)
        ms_pi = (time.perf_counter() - t) * 1000
        t = time.perf_counter()
        _, ok_sec, score_sec = sec.scan(text)
        ms_sec = (time.perf_counter() - t) * 1000
        t = time.perf_counter()
        _, ok_anon, score_anon = anon.scan(text)
        ms_anon = (time.perf_counter() - t) * 1000
        _, ok_inv, score_inv = inv.scan(text)

        rows.append(
            {
                "id": s["id"],
                "category": s.get("category", "?"),
                "source": s.get("source", "?"),
                "lang": s.get("lang", ""),
                "pi": {"valid": bool(ok_pi), "score": round(float(score_pi), 3), "ms": round(ms_pi, 1)},
                "sec": {"valid": bool(ok_sec), "score": round(float(score_sec), 3), "ms": round(ms_sec, 1)},
                "anon": {"valid": bool(ok_anon), "score": round(float(score_anon), 3), "ms": round(ms_anon, 1)},
                "inv": {"valid": bool(ok_inv), "score": round(float(score_inv), 3)},
            }
        )
        if i % 50 == 0:
            print(f"  进度 {i}/{len(samples)}", flush=True)

    # 快速自检：各类别各扫描器命中数（valid=False 计检出）
    quick: dict[tuple[str, str], list[int]] = {}
    for r in rows:
        for key in ("pi", "sec", "anon", "inv"):
            quick.setdefault((r["category"], key), [0, 0])
            quick[(r["category"], key)][0] += 0 if r[key]["valid"] else 1
            quick[(r["category"], key)][1] += 1
    print("\n== 快速自检（类别 × 扫描器：检出数/总数）==", flush=True)
    for (cat, key), (hit, n) in sorted(quick.items()):
        print(f"  {cat:18s} {key:4s} {hit}/{n}")

    ms_pi_avg = sum(r["pi"]["ms"] for r in rows) / len(rows)
    ms_anon_avg = sum(r["anon"]["ms"] for r in rows) / len(rows)
    meta = {
        "n": len(samples),
        "benchmark": str(ds_dir),
        "tool": "llm-guard 0.3.15",
        "scanners": ["PromptInjection(protectai/deberta-v3-base-prompt-injection-v2, thr=0.9)", "Secrets", "Anonymize(Presidio)", "InvisibleText"],
        "ms_avg": {"prompt_injection": round(ms_pi_avg, 1), "anonymize": round(ms_anon_avg, 1)},
    }

    REPORTS.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = f"{args.tag}-" if args.tag else ""
    out = REPORTS / f"crosscheck-llmguard-{tag}{ts}.json"
    out.write_text(
        json.dumps({"meta": meta, "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"\n明细 {out}")


if __name__ == "__main__":
    main()
