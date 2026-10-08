# -*- coding: utf-8 -*-
"""外部独立测试集评测：规则引擎 × PromptGuard 双检测器，按类别出矩阵。

判定口径：
- 攻击样本（injection/jailbreak）：命中任一 injection.* 规则 = 规则检出；
  仅命中 pii/secret 类 = 域外巧合命中，单独统计，不算检出。
- 良性样本：任一规则命中 = 规则误报。
- 模型检出 = PromptGuard 判 injection（ONNX 标签 MALICIOUS，含注入与越狱语义）。
  注意 score 为所判标签的置信度（判良性时高分 = 确信良性），不是恶意概率。

用法：
    python evaluation/run_external_eval.py [--model-dir data/models/promptguard2-86m]

产物：
    evaluation/reports/external-eval-<时间戳>.json  逐条明细
    evaluation/reports/external-eval-<时间戳>.md    汇总矩阵
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, ".")

from app.security.engine import SecurityEngine  # noqa: E402
from app.security.model_audit import (  # noqa: E402
    PromptGuardOnnxClassifier,
    StubInjectionClassifier,
)
from app.security.policy import load_policy  # noqa: E402

DS_DIR = Path("evaluation/datasets_external")
REPORTS = Path("evaluation/reports")
DEFAULT_MODEL_DIR = "data/models/promptguard2-86m"


def load_samples() -> list[dict]:
    samples = []
    for p in sorted(DS_DIR.glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                samples.append(json.loads(line))
    if not samples:
        raise SystemExit(f"未找到外部测试集，先运行 evaluation/import_external_benchmarks.py")
    return samples


def make_classifier(model_dir: str | None):
    if model_dir:
        return PromptGuardOnnxClassifier(model_dir)
    if Path(DEFAULT_MODEL_DIR).exists():
        return PromptGuardOnnxClassifier(DEFAULT_MODEL_DIR)
    print("[warn] 未指定且未找到真模型目录，回退 Stub 关键词分类器（结果仅演示管线）")
    return StubInjectionClassifier()


def evaluate(samples: list[dict], model_dir: str | None) -> tuple[list[dict], dict]:
    engine = SecurityEngine(load_policy())
    clf = make_classifier(model_dir)

    rows: list[dict] = []
    rule_ms = model_ms = 0.0
    for i, s in enumerate(samples, 1):
        t = time.perf_counter()
        findings = engine.scan_text(s["text"])
        rule_ms += time.perf_counter() - t

        fams = Counter(f.rule_id.split(".")[0] for f in findings)
        t = time.perf_counter()
        verdict = clf.classify(s["text"])
        model_ms += time.perf_counter() - t

        rows.append(
            {
                **s,
                "rule_hit": bool(fams.get("injection")),
                "rule_ids": [f.rule_id for f in findings],
                "model_hit": verdict.label == "injection",
                "model_score": verdict.score,
            }
        )
        if i % 200 == 0:
            print(f"  进度 {i}/{len(samples)}", flush=True)

    meta = {
        "n": len(samples),
        "classifier": clf.model_id,
        "rule_ms_avg": rule_ms / len(samples) * 1000,
        "model_ms_avg": model_ms / len(samples) * 1000,
    }
    return rows, meta


def stat(rows: list[dict]) -> dict:
    def bucket(rs: list[dict]) -> dict:
        n = len(rs)
        return {
            "n": n,
            "rule": sum(1 for x in rs if x["rule_hit"]),
            "model": sum(1 for x in rs if x["model_hit"]),
            "either": sum(1 for x in rs if x["rule_hit"] or x["model_hit"]),
        }

    out = {"by_cat": {}, "by_src_cat": {}, "rules": {}, "fp_rules": Counter()}
    for cat in ("injection", "jailbreak", "benign"):
        out["by_cat"][cat] = bucket([x for x in rows if x["category"] == cat])
    groups = defaultdict(list)
    for r in rows:
        groups[(r["source"], r["category"])].append(r)
    for (src, cat), rs in sorted(groups.items()):
        out["by_src_cat"][f"{src} | {cat}"] = bucket(rs)
    for cat in ("injection", "jailbreak", "benign"):
        out["rules"][cat] = Counter(
            rid
            for x in rows
            if x["category"] == cat
            for rid in x["rule_ids"]
            if rid.startswith("injection.")
        )
    out["fp_rules"] = Counter(
        rid for x in rows if x["category"] == "benign" for rid in x["rule_ids"]
    )
    return out


def render_markdown(meta: dict, s: dict) -> str:
    pct = lambda b, k: f"{b[k]/b['n']:.1%}"
    lines = [
        "# 外部独立测试集评测报告",
        "",
        f"- 样本 {meta['n']} 条（evaluation/datasets_external/，构建见 import_external_benchmarks.py）",
        f"- 分类器：{meta['classifier']}",
        f"- 平均延迟：规则 {meta['rule_ms_avg']:.2f} ms/条，模型 {meta['model_ms_avg']:.0f} ms/条",
        "",
        "## 类别 × 检测器",
        "",
        "| 类别 | n | 规则检出/误报 | 模型检出/误报 | 联合 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for cat in ("injection", "jailbreak", "benign"):
        b = s["by_cat"][cat]
        tag = "误报" if cat == "benign" else "检出"
        lines.append(
            f"| {cat} | {b['n']} | {tag} {b['rule']} ({pct(b,'rule')}) "
            f"| {tag} {b['model']} ({pct(b,'model')}) "
            f"| {b['either']} ({pct(b,'either')}) |"
        )
    lines += ["", "## 来源 × 类别", "", "| 来源 \\| 类别 | n | 规则 | 模型 | 联合 |", "| --- | --- | --- | --- | --- | --- |"]
    for key, b in s["by_src_cat"].items():
        src, cat = key.split(" | ")
        lines.append(
            f"| {src} | {cat} | {b['n']} | {b['rule']} ({pct(b,'rule')}) "
            f"| {b['model']} ({pct(b,'model')}) | {b['either']} |"
        )
    lines += ["", "## 规则命中明细（injection.*，按类别）", ""]
    for cat in ("injection", "jailbreak", "benign"):
        hit = s["by_cat"][cat]["rule"]
        detail = "，".join(f"{rid} {n} 次" for rid, n in s["rules"][cat].most_common()) or "-"
        lines.append(f"- {cat}（命中样本 {hit} 条）：{detail}")
    if s["fp_rules"]:
        lines += [
            "",
            "## 良性误报明细",
            "",
            "外部独立测试集构建时不参照本项目规则（不筛选、不预置答案），",
            "检出与漏检如实报告；口径声明见评测集文档。",
        ]
        for rid, n in s["fp_rules"].most_common():
            lines.append(f"- {rid}：{n} 次")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=None, help="PromptGuard ONNX 模型目录")
    args = ap.parse_args()

    samples = load_samples()
    print(f"样本总数 {len(samples)}")
    rows, meta = evaluate(samples, args.model_dir)
    s = stat(rows)

    REPORTS.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = REPORTS / f"external-eval-{ts}.json"
    md_path = REPORTS / f"external-eval-{ts}.md"
    json_path.write_text(
        json.dumps({"meta": meta, "stat": {k: dict(v) for k, v in s.items()}, "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(meta, s), encoding="utf-8", newline="\n")
    print(f"\n明细 {json_path}\n汇总 {md_path}")


if __name__ == "__main__":
    main()
