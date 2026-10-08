# -*- coding: utf-8 -*-
r"""三方对照评测 · ModernGuard-1 第四方（跑在仓库根 .venv-mg312，独立于其他 venv）。

对 crosscheck 基准集逐条跑 guardion/ModernGuard-1（mmBERT-base 307M，二分类
SAFE / PROMPT INJECTION，11 语言微调含中文，自称防 jailbreak translation），
逐条明细落盘 JSON，供第四方对照聚合。

判定口径：PROMPT INJECTION 概率 ≥ 0.5（模型卡默认阈值）判注入；
injection / jailbreak 类任一命中即检出，benign 任一命中即误报
（与 PromptGuard 的 label==injection 口径同构；external 卷无 pii/secret/obfuscation）。

用法（仓库根，模型经 hf-mirror 下载约 1.2GB）：
    $env:HF_ENDPOINT="https://hf-mirror.com"; $env:HF_HUB_DISABLE_XET="1"
    ..\.venv-mg312\Scripts\python.exe gateway-v2\evaluation\run_crosscheck_mg.py ^
        --file gateway-v2\evaluation\datasets_benchmark\benchmark_external_en.jsonl --tag en
    ..\.venv-mg312\Scripts\python.exe gateway-v2\evaluation\run_crosscheck_mg.py ^
        --file gateway-v2\evaluation\datasets_benchmark_zh\benchmark_external_zh.jsonl --tag zh

产物：
    gateway-v2\evaluation\reports\crosscheck-mg-<tag>-<时间戳>.json
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
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
sys.stdout.reconfigure(encoding="utf-8")

import torch  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: E402

REPO = Path(__file__).resolve().parent.parent  # gateway-v2/
REPORTS = REPO / "evaluation" / "reports"
MODEL_ID = "guardion/ModernGuard-1"
THRESHOLD = 0.5


def load_samples(path: Path) -> list[dict]:
    samples = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not samples:
        raise SystemExit(f"未找到样本 {path}")
    return samples


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(REPO / "evaluation" / "datasets_benchmark" / "benchmark_external_en.jsonl"))
    ap.add_argument("--tag", default="", help="产物名标记（en / zh）")
    ap.add_argument("--threshold", type=float, default=THRESHOLD)
    args = ap.parse_args()

    ds_path = Path(args.file)
    samples = load_samples(ds_path)
    print(f"样本总数 {len(samples)}（{ds_path}）", flush=True)

    t0 = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()
    print(f"模型就绪 {time.perf_counter() - t0:.1f}s（id2label={model.config.id2label}）", flush=True)

    # 注入类 label 的索引：按名字找（SAFE 之外的另一个）
    id2label = {int(k): str(v) for k, v in model.config.id2label.items()}
    inj_idx = None
    for idx, name in id2label.items():
        if "injection" in name.lower().replace("_", " "):
            inj_idx = idx
            break
    if inj_idx is None:
        raise SystemExit(f"未在 id2label 中找到注入类标签：{id2label}")
    print(f"注入类标签 = {inj_idx}:{id2label[inj_idx]}，阈值 {args.threshold}", flush=True)

    rows: list[dict] = []
    with torch.no_grad():
        for i, s in enumerate(samples, 1):
            text = s["text"]
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=2048)
            t = time.perf_counter()
            logits = model(**inputs).logits
            ms = (time.perf_counter() - t) * 1000
            probs = torch.softmax(logits, dim=-1)[0]
            score = float(probs[inj_idx])
            rows.append(
                {
                    "id": s["id"],
                    "category": s.get("category", "?"),
                    "source": s.get("source", "?"),
                    "lang": s.get("lang", ""),
                    "mg_label": "injection" if score >= args.threshold else "benign",
                    "mg_score": round(score, 3),
                    "ms": round(ms, 1),
                }
            )
            if i <= 3:
                print(f"  冒烟 {s['id']} score={score:.3f} ms={ms:.0f}", flush=True)
            if i % 50 == 0:
                print(f"  进度 {i}/{len(samples)}", flush=True)

    # 快速自检
    quick: dict[tuple[str, bool], int] = {}
    for r in rows:
        key = (r["category"], r["mg_label"] == "injection")
        quick[key] = quick.get(key, 0) + 1
    print("\n== 快速自检（类别 × 判定）==", flush=True)
    for cat in sorted({c for c, _ in quick}):
        hit = quick.get((cat, True), 0)
        n = hit + quick.get((cat, False), 0)
        tag = "误报" if cat == "benign" else "检出"
        print(f"  {cat:18s} {tag} {hit}/{n}")

    ms_avg = sum(r["ms"] for r in rows) / len(rows)
    meta = {
        "n": len(samples),
        "benchmark": str(ds_path),
        "tool": "ModernGuard-1 (guardion, mmBERT-base 307M)",
        "threshold": args.threshold,
        "cpu_only": True,
        "ms_avg": round(ms_avg, 1),
    }

    REPORTS.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = f"{args.tag}-" if args.tag else ""
    out = REPORTS / f"crosscheck-mg-{tag}{ts}.json"
    out.write_text(
        json.dumps({"meta": meta, "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"\n明细 {out}")


if __name__ == "__main__":
    main()
