# -*- coding: utf-8 -*-
r"""三方对照评测 · 网关侧与聚合（跑在 gateway-v2/.venv）。

对 crosscheck-v1 基准集（evaluation/datasets_benchmark/，510 条中英文）跑本网关
双检测器（规则引擎 + PromptGuard），再读 LLM Guard 侧明细（run_crosscheck.py
产物，跑在仓库根 .venv-llmguard312），聚合成三方对照报告。

判定口径（同一张卷子，三方各按自己"考官"判）：
- 注入五类（injection/prompt_injection/system_prompt_leak/role_manipulation/jailbreak）：
  规则 = injection.* 家族命中；PromptGuard = label==injection；
  LLM Guard = PromptInjection scanner 判风险（is_valid=False）。
- pii：规则 = pii.*；LLM Guard = Anonymize（Presidio）。
- secret：规则 = secret.*；LLM Guard = Secrets。
- obfuscation：规则 = injection.invisible_text；LLM Guard = InvisibleText。
- benign：三方各自任一命中即为误报。
- PromptGuard 对 pii/secret/obfuscation 并非责任方，照跑并如实报告（语义边界展示）。

用法：
    .\.venv\Scripts\python.exe evaluation\run_crosscheck_ours.py ^
        --llmguard evaluation\reports\crosscheck-llmguard-<ts>.json

中文翻译版（跑中文版须显式 --llmguard 指定中文版明细，避免误读英文版）：
    .\.venv\Scripts\python.exe evaluation\run_crosscheck_ours.py ^
        --ds-dir evaluation\datasets_benchmark_zh --tag zh ^
        --llmguard evaluation\reports\crosscheck-llmguard-zh-<ts>.json

产物：
    evaluation/reports/crosscheck[-tag]-<时间戳>.md / .json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, ".")

from app.security.engine import SecurityEngine  # noqa: E402
from app.security.model_audit import PromptGuardOnnxClassifier  # noqa: E402
from app.security.policy import load_policy  # noqa: E402

DS_DIR = Path("evaluation/datasets_benchmark")
REPORTS = Path("evaluation/reports")
DEFAULT_MODEL_DIR = "data/models/promptguard2-86m"

INJ_CATS = {"injection", "prompt_injection", "system_prompt_leak", "role_manipulation", "jailbreak"}
CATS = ["injection", "prompt_injection", "system_prompt_leak", "role_manipulation", "jailbreak", "pii", "secret", "obfuscation", "benign"]
CJK = re.compile(r"[\u4e00-\u9fff]")


def load_benchmark(ds_dir: Path) -> list[dict]:
    samples = []
    for p in sorted(ds_dir.glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                samples.append(json.loads(line))
    if not samples:
        raise SystemExit(f"未找到基准集 {ds_dir}，先运行 evaluation/curate_benchmark.py")
    return samples


def norm_lang(s: dict) -> str:
    lang = s.get("lang", "")
    if lang.startswith(("zh", "cn")):
        return "中文"
    if lang.startswith("en"):
        return "英文"
    return "中文" if CJK.search(s["text"][:200]) else "英文"


def rule_hit(cat: str, rule_ids: list[str]) -> bool:
    if cat == "pii":
        return any(r.startswith("pii.") for r in rule_ids)
    if cat == "secret":
        return any(r.startswith("secret.") for r in rule_ids)
    if cat == "obfuscation":
        return "injection.invisible_text" in rule_ids
    if cat == "benign":
        return bool(rule_ids)
    return any(r.startswith("injection.") for r in rule_ids)


def llg_hit(cat: str, g: dict) -> bool:
    if cat == "pii":
        return not g["anon"]["valid"]
    if cat == "secret":
        return not g["sec"]["valid"]
    if cat == "obfuscation":
        return not g["inv"]["valid"]
    if cat == "benign":
        return any(not g[k]["valid"] for k in ("pi", "sec", "anon", "inv"))
    return not g["pi"]["valid"]


def find_llmguard_json(path: str | None, tag: str = "") -> Path:
    if path:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f"未找到 {p}")
        return p
    if tag:
        # 翻译版：只匹配带 tag 的明细，避免读到英文版（两侧 id 相同会静默错配）
        cands = sorted(REPORTS.glob(f"crosscheck-llmguard-{tag}-*.json"))
    else:
        cands = sorted(REPORTS.glob("crosscheck-llmguard-*.json"))
    if not cands:
        raise SystemExit("未找到 LLM Guard 明细，先跑 evaluation/run_crosscheck.py（.venv-llmguard312）")
    return cands[-1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=DEFAULT_MODEL_DIR)
    ap.add_argument("--llmguard", default=None, help="LLM Guard 明细 json（缺省取最新）")
    ap.add_argument("--ds-dir", default=str(DS_DIR), help="基准集目录（默认英文版 datasets_benchmark）")
    ap.add_argument("--tag", default="", help="产物名标记（如 zh），不影响默认复现链")
    args = ap.parse_args()

    samples = load_benchmark(Path(args.ds_dir))
    print(f"基准集 {len(samples)} 条（{args.ds_dir}）", flush=True)

    engine = SecurityEngine(load_policy())
    clf = PromptGuardOnnxClassifier(args.model_dir)

    rows: list[dict] = []
    rule_ms = pg_ms = 0.0
    for i, s in enumerate(samples, 1):
        t = time.perf_counter()
        findings = engine.scan_text(s["text"])
        rule_ms += time.perf_counter() - t
        t = time.perf_counter()
        verdict = clf.classify(s["text"])
        pg_ms += time.perf_counter() - t
        rows.append(
            {
                "id": s["id"],
                "category": s.get("category", "?"),
                "source": s.get("source", "?"),
                "lang": norm_lang(s),
                "text": s["text"],
                "rule_ids": [f.rule_id for f in findings],
                "pg_label": verdict.label,
                "pg_score": verdict.score,
            }
        )
        if i % 100 == 0:
            print(f"  进度 {i}/{len(samples)}", flush=True)

    lg_path = find_llmguard_json(args.llmguard, args.tag)
    lg = json.loads(lg_path.read_text(encoding="utf-8"))
    lg_by_id = {r["id"]: r for r in lg["rows"]}
    missing = [r["id"] for r in rows if r["id"] not in lg_by_id]
    if missing:
        raise SystemExit(f"LLM Guard 明细缺 {len(missing)} 条（如 {missing[:3]}），两侧样本不一致")
    for r in rows:
        g = lg_by_id[r["id"]]
        cat = r["category"]
        r["llg"] = g
        r["rule_hit"] = rule_hit(cat, r["rule_ids"])
        r["pg_hit"] = r["pg_label"] == "injection"
        r["llg_hit"] = llg_hit(cat, g)

    # ---- 聚合
    def bucket(rs: list[dict]) -> dict:
        return {
            "n": len(rs),
            "rule": sum(1 for x in rs if x["rule_hit"]),
            "pg": sum(1 for x in rs if x["pg_hit"]),
            "llg": sum(1 for x in rs if x["llg_hit"]),
        }

    by_cat = {c: bucket([r for r in rows if r["category"] == c]) for c in CATS if any(r["category"] == c for r in rows)}
    by_lang_cat = {}
    for langv in ("中文", "英文"):
        for c in by_cat:
            sub = [r for r in rows if r["lang"] == langv and r["category"] == c]
            if sub:
                by_lang_cat[(langv, c)] = bucket(sub)

    meta = {
        "n": len(samples),
        "benchmark": "crosscheck-v1-zh (人工翻译 translate_external_zh.xlsx，380 条)" if args.tag == "zh"
                    else "crosscheck-v1 (curate_benchmark.py, seed=42)",
        "ours": {"rules": "security.yaml 15 条", "model": clf.model_id,
                 "rule_ms_avg": round(rule_ms / len(rows) * 1000, 3), "pg_ms_avg": round(pg_ms / len(rows) * 1000, 1)},
        "llmguard": {"path": lg_path.name, **lg.get("meta", {}).get("ms_avg", {})},
        "known_gap_ids": [r["id"] for r in rows if r["id"] in ("inj-en-017", "garak-dan-001")],
    }

    # ---- 报告
    def cell(b: dict, k: str) -> str:
        return f"{b[k]} ({b[k] / b['n']:.0%})" if b["n"] else "-"

    lines = [
        f"# 三方对照评测报告（{'crosscheck-v1-zh 翻译版' if args.tag == 'zh' else 'crosscheck-v1 基准集'}）",
        "",
        f"- 样本 {meta['n']} 条（{args.ds_dir}，"
        + ("translate_external_zh.xlsx 人工翻译派生，lang=zh" if args.tag == "zh"
           else "curate_benchmark.py seed=42 派生，中英文")
        + "）",
        f"- 我方：规则引擎（security.yaml 15 条，{meta['ours']['rule_ms_avg']} ms/条）+ "
        f"PromptGuard-2 86M ONNX（{meta['ours']['pg_ms_avg']:.0f} ms/条）",
        f"- 三方：LLM Guard 0.3.15 四扫描器（PromptInjection thr=0.9 / Secrets / Anonymize / InvisibleText，"
        f"明细 {lg_path.name}）",
        "",
        "判定口径：注入五类由注入考官判（规则 injection.* / PromptGuard 模型 / LLM Guard PI scanner）；"
        "pii、secret、obfuscation 各由对应检测器判；良性任一命中记误报。"
        "自建攻击集含 2 条 known_gap（base64 注入、AntiDAN），保留在分母（三方同卷）。",
        "",
        "## 类别 × 三方（主矩阵）",
        "",
        "| 类别 | n | 规则 | PromptGuard | LLM Guard |",
        "| --- | --- | --- | --- | --- |",
    ]
    for c, b in by_cat.items():
        tag = "误报" if c == "benign" else "检出"
        lines.append(f"| {c} | {b['n']} | {tag} {cell(b, 'rule')} | {tag} {cell(b, 'pg')} | {tag} {cell(b, 'llg')} |")

    lines += ["", "## 中文 / 英文分桶", "", "| 语言 | 类别 | n | 规则 | PromptGuard | LLM Guard |", "| --- | --- | --- | --- | --- | --- |"]
    for (langv, c), b in by_lang_cat.items():
        tag = "误报" if c == "benign" else "检出"
        lines.append(f"| {langv} | {c} | {b['n']} | {cell(b, 'rule')} | {cell(b, 'pg')} | {cell(b, 'llg')} |")

    lines += ["", "## 良性误报明细", ""]
    rule_fp = Counter(r["rule_ids"][0] for r in rows if r["category"] == "benign" and r["rule_hit"])
    lines.append(f"- 规则误报 {sum(rule_fp.values())} 条：" + ("，".join(f"{k} {v}" for k, v in rule_fp.most_common()) or "无"))
    pg_fp = [r for r in rows if r["category"] == "benign" and r["pg_hit"]]
    lines.append(f"- PromptGuard 误报 {len(pg_fp)} 条：" + ("；".join(f"{r['id']} score={r['pg_score']:.2f}" for r in pg_fp) or "无"))
    llg_fp = [(k, r) for r in rows if r["category"] == "benign" and r["llg_hit"]
              for k in ("pi", "sec", "anon", "inv") if not r["llg"][k]["valid"]]
    llg_fp_ids = {r["id"] for _, r in llg_fp}
    lines.append(f"- LLM Guard 误报 {len(llg_fp_ids)} 条：" + ("；".join(f"{i} ({', '.join(k for k, r in llg_fp if r['id'] == i)})" for i in sorted(llg_fp_ids)) or "无"))

    REPORTS.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = f"{args.tag}-" if args.tag else ""
    json_path = REPORTS / f"crosscheck-{tag}{ts}.json"
    md_path = REPORTS / f"crosscheck-{tag}{ts}.md"
    slim_rows = rows  # 逐条含三方判定与 LLM Guard 明细，便于对账
    json_path.write_text(
        json.dumps({"meta": meta, "by_cat": by_cat, "by_lang_cat": {f"{k[0]}|{k[1]}": v for k, v in by_lang_cat.items()}, "rows": slim_rows},
                   ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"\n明细 {json_path}\n汇总 {md_path}")


if __name__ == "__main__":
    main()
