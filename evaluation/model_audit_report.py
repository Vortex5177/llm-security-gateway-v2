r"""M5 Rule vs Model 对比报告：离线扫 request_logs，规则判定 × CPU 分类器判定。

分类器：
- 缺省 StubInjectionClassifier（关键词启发式，仅演示管线，报告显式标注非真实模型）；
- --model-dir 指向 PromptGuard 2 ONNX 目录则用真实模型（需 onnxruntime/transformers）；
- 第二引擎（ModernGuard-1 ONNX）默认自动探测：--model-dir 给定且
  data/models/modernguard1-307m/model.onnx 存在即双引擎并跑（2026-10-08 起的默认形态），
  各自独立 audit 落库（model_audit_results 按引擎 model_id 分组），另合成"并集视角"
  指标（任一判 injection 即 injection，延迟按串行相加的保守口径）；
  --model-dir2 off 可显式禁用（单引擎兼容旧链）。

指标以"规则判定为参照"计算模型 injection 检出的 precision/recall/F1，并对比延迟。
结论聚焦：哪类问题适合确定性规则、哪类适合语义模型。

用法：
    .\.venv\Scripts\python.exe evaluation/model_audit_report.py [--limit 500] [--model-dir <dir>]
    双引擎（自 2026-10-08 起默认，只要两个模型目录都在）：
    .\.venv\Scripts\python.exe evaluation/model_audit_report.py --model-dir data/models/promptguard2-86m
    显式单引擎：
    .\.venv\Scripts\python.exe evaluation/model_audit_report.py --model-dir data/models/promptguard2-86m --model-dir2 off

报告：evaluation/reports/model-audit-YYYYMMDD-HHMMSS.{json,md}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.db import DB_PATH  # noqa: E402
from app.models import Base  # noqa: E402
from app.security.engine import SecurityEngine  # noqa: E402
from app.security.model_audit import (  # noqa: E402
    audit_request_logs,
    build_classifier,
    comparison_metrics,
)
from app.security.policy import load_policy  # noqa: E402

REPORTS = PROJECT_ROOT / "evaluation" / "reports"
DEFAULT_MG_DIR = PROJECT_ROOT / "data" / "models" / "modernguard1-307m"

DISCLAIMER = (
    "Model-vs-rule comparison uses rule verdicts as the reference label on the "
    "gateway's own historical request logs; it is not an absolute ground-truth "
    "benchmark and does not represent production performance."
)

CONCLUSION = [
    "确定性规则更合适：PII/Secret 等有固定格式且可校验（Luhn/身份证校验位）的泄露，"
    "误报可控、延迟极低（微秒级）、可解释、可脱敏改写——模型不覆盖这类。",
    "语义模型更合适：改写/翻译/编码绕过、语义等价的新颖注入、多轮渐进越狱等无固定表面特征的攻击，"
    "规则易漏检，小分类器（PromptGuard 2 86M CPU）可补足召回。",
    "工程结论：规则做第一道确定性防线（block/redact），模型做异步补检（audit）扩大召回，"
    "二者判定分歧样本正是规则调优的输入（闭环）。",
    "双引擎并集（adoption 实验）：审计位可并跑两个低误报 CPU 分类器（PromptGuard 2 + "
    "ModernGuard-1）取并集——注入召回高于任一单引擎、误报增幅有限，代价是延迟相加"
    "（串行口径）；两引擎的分歧样本与规则分歧一样，同样是规则调优的输入。",
]


async def _run(
    model_dir: str | None, model_dir2: str | None, limit: int | None
) -> list[dict]:
    """跑 1-2 个引擎：model_dir 缺省时第一个用 Stub（演示管线）；model_dir2 缺省则单引擎。

    双引擎时各自独立 audit（规则判定确定性重算，两轮结果一致），
    model_audit_results 落两套 model_id 行，供按引擎分组回查。
    """
    engine = SecurityEngine(load_policy())
    engine_db = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH.as_posix()}")
    async with engine_db.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine_db, class_=AsyncSession, expire_on_commit=False)
    specs = [(model_dir, "promptguard")]
    if model_dir2:
        specs.append((model_dir2, "modernguard"))
    runs: list[dict] = []
    try:
        for model_dir_i, kind in specs:
            classifier = build_classifier(model_dir_i, kind)
            rows = await audit_request_logs(factory, engine, classifier, limit=limit)
            runs.append(
                {
                    "model_id": classifier.model_id,
                    "rows": rows,
                    "metrics": comparison_metrics(rows),
                }
            )
    finally:
        await engine_db.dispose()
    return runs


def union_rows(rows_a: list[dict], rows_b: list[dict]) -> list[dict]:
    """双引擎并集视角：任一判 injection 即 injection；延迟按串行相加（保守口径）。"""
    b_by_id = {r["request_log_id"]: r for r in rows_b}
    merged: list[dict] = []
    for a in rows_a:
        b = b_by_id.get(a["request_log_id"])
        if b is None:
            continue
        inj_a = a["model_label"] == "injection"
        inj_b = b["model_label"] == "injection"
        union_inj = inj_a or inj_b
        if union_inj:
            score = max(r["model_score"] for r, inj in ((a, inj_a), (b, inj_b)) if inj)
        else:
            score = max(a["model_score"], b["model_score"])
        merged.append(
            {
                **a,
                "model_id": f"{a['model_id']}+{b['model_id']}-union",
                "model_label": "injection" if union_inj else "benign",
                "model_score": score,
                "model_latency_ms": round(
                    a["model_latency_ms"] + b["model_latency_ms"], 4
                ),
                "agree": a["rule_injection"] == union_inj,
            }
        )
    return merged


def render_markdown(metrics: dict, model_id: str, meta: dict) -> str:
    is_stub = model_id == "stub-keyword"
    lines = [
        f"# Rule vs Model 对比报告（{meta['run_id']}）",
        "",
        f"- 分类器: {model_id}"
        + ("（**Stub 关键词启发式，仅演示审计管线，非真实语义模型评测**）" if is_stub else "（PromptGuard 2 ONNX CPU）"),
        f"- 数据源: {meta['db']} ｜ 策略: {meta['policy']} ｜ 时间: {meta['ts']}",
        f"- 审计样本（request_logs 有 prompt 者）: {metrics['total']}",
        "",
        "## 混淆矩阵（正类=injection，以规则判定为参照）",
        "",
        "| | 模型=injection | 模型=benign |",
        "| --- | --- | --- |",
        f"| 规则=injection | TP={metrics['tp']} | FN={metrics['fn']} |",
        f"| 规则=benign | FP={metrics['fp']} | TN={metrics['tn']} |",
        "",
        "## 指标",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| precision | {metrics['precision']} |",
        f"| recall | {metrics['recall']} |",
        f"| F1 | {metrics['f1']} |",
        f"| agreement（规则/模型一致率） | {metrics['agreement']} |",
        f"| 模型平均延迟 (ms) | {metrics['avg_model_latency_ms']} |",
        f"| 规则平均延迟 (ms) | {metrics['avg_rule_latency_ms']} |",
        "",
        "## 结论：规则 vs 模型分工",
        "",
    ]
    lines += [f"- {c}" for c in CONCLUSION]
    lines += ["", f"> {DISCLAIMER}", ""]
    return "\n".join(lines)


def render_markdown_dual(runs: list[dict], union: dict, meta: dict) -> str:
    """双引擎版：每个引擎一块混淆矩阵+指标，末尾并集视角一块。"""
    ids = " + ".join(r["model_id"] for r in runs)
    lines = [
        f"# Rule vs Model 对比报告（{meta['run_id']}）",
        "",
        f"- 分类器: {ids}（双引擎 ONNX CPU），另合成**并集视角**",
        f"- 并集口径: 任一引擎判 injection 即 injection；延迟为两引擎串行相加（保守口径）",
        f"- 数据源: {meta['db']} ｜ 策略: {meta['policy']} ｜ 时间: {meta['ts']}",
        f"- 审计样本（request_logs 有 prompt 者）: {union['total']}",
        "",
    ]
    blocks = [
        ("引擎 1：PromptGuard 2", runs[0]["model_id"], runs[0]["metrics"]),
        ("引擎 2：ModernGuard-1", runs[1]["model_id"], runs[1]["metrics"]),
        ("并集（任一判 injection 即 injection）", union["model_id"], union),
    ]
    for title, model_id, m in blocks:
        lines += [
            f"## {title}（{model_id}）",
            "",
            "| 规则参照 | 模型=injection | 模型=benign |",
            "| --- | --- | --- |",
            f"| 规则=injection | TP={m['tp']} | FN={m['fn']} |",
            f"| 规则=benign | FP={m['fp']} | TN={m['tn']} |",
            "",
            f"precision={m['precision']} recall={m['recall']} F1={m['f1']} "
            f"agreement={m['agreement']} 模型延迟={m['avg_model_latency_ms']}ms "
            f"规则延迟={m['avg_rule_latency_ms']}ms",
            "",
        ]
    lines += ["## 结论：规则 vs 模型分工", ""]
    lines += [f"- {c}" for c in CONCLUSION]
    lines += ["", f"> {DISCLAIMER}", ""]
    return "\n".join(lines)


def resolve_second_dir(model_dir: str, model_dir2: str) -> str | None:
    """解析第二引擎目录：auto=探测默认路径（存在即双跑）；off/none/空=禁用。

    2026-10-08 起双跑为默认形态：--model-dir 给定且 ModernGuard ONNX 工件在位
    即自动双引擎；演示管线（无 --model-dir）不变，始终单 Stub。
    """
    if not model_dir:
        return None
    v = (model_dir2 or "").strip().lower()
    if v in ("", "off", "none"):
        return None
    if v == "auto":
        return str(DEFAULT_MG_DIR) if (DEFAULT_MG_DIR / "model.onnx").is_file() else None
    return model_dir2


def main() -> int:
    parser = argparse.ArgumentParser(description="M5 Rule vs Model 对比报告")
    parser.add_argument("--model-dir", default="", help="PromptGuard 2 ONNX 目录（缺省用 Stub）")
    parser.add_argument(
        "--model-dir2",
        default="auto",
        help="第二引擎（ModernGuard-1）ONNX 目录；缺省 auto=探测 data/models/modernguard1-307m，"
        "在位即双跑（默认形态）；off=显式单引擎",
    )
    parser.add_argument("--limit", type=int, default=None, help="最多审计的 request_logs 行数")
    args = parser.parse_args()

    second = resolve_second_dir(args.model_dir, args.model_dir2)
    if second is None and args.model_dir and (args.model_dir2 or "").strip().lower() == "auto":
        print(
            f"提示：未找到 ModernGuard-1 ONNX（{DEFAULT_MG_DIR}），单引擎运行；"
            "如需双跑先运行 evaluation/export_modernguard_onnx.py",
            file=sys.stderr,
        )

    if not DB_PATH.is_file():
        print(f"未找到网关 DB: {DB_PATH}", file=sys.stderr)
        return 2

    runs = asyncio.run(
        _run(args.model_dir or None, second, args.limit)
    )
    first = runs[0]
    metrics = first["metrics"]
    if metrics["total"] == 0:
        print("request_logs 无可审计 prompt（injected_json 为空）", file=sys.stderr)
        return 1

    union = None
    if len(runs) == 2:
        union = comparison_metrics(union_rows(runs[0]["rows"], runs[1]["rows"]))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"model-audit-{ts}"
    meta = {
        "run_id": run_id,
        "db": str(DB_PATH),
        "policy": "config/security.yaml",
        "ts": ts,
        "model_id": first["model_id"],
        "model_ids": [r["model_id"] for r in runs],
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    # json 兼容旧读者：顶层保留 metrics（首引擎）；新读者用 runs/union
    (REPORTS / f"{run_id}.json").write_text(
        json.dumps(
            {
                "meta": meta,
                "metrics": metrics,
                "runs": [{"model_id": r["model_id"], "metrics": r["metrics"]} for r in runs],
                "union": union,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    md_path = REPORTS / f"{run_id}.md"
    if union is not None:
        md_path.write_text(render_markdown_dual(runs, union, meta), encoding="utf-8")
    else:
        md_path.write_text(
            render_markdown(metrics, first["model_id"], meta), encoding="utf-8"
        )

    print(
        f"model={first['model_id']} total={metrics['total']} "
        f"P={metrics['precision']} R={metrics['recall']} F1={metrics['f1']} "
        f"agree={metrics['agreement']}"
    )
    if union is not None:
        print(
            f"union total={union['total']} P={union['precision']} "
            f"R={union['recall']} F1={union['f1']} agree={union['agreement']} "
            f"latency={union['avg_model_latency_ms']}ms"
        )
    print(f"报告: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
