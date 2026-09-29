r"""M5 Rule vs Model 对比报告：离线扫 request_logs，规则判定 × CPU 分类器判定。

分类器：
- 缺省 StubInjectionClassifier（关键词启发式，仅演示管线，报告显式标注非真实模型）；
- --model-dir 指向 PromptGuard 2 ONNX 目录则用真实模型（需 onnxruntime/transformers）。

指标以"规则判定为参照"计算模型 injection 检出的 precision/recall/F1，并对比延迟。
结论聚焦：哪类问题适合确定性规则、哪类适合语义模型。

用法：
    .\.venv\Scripts\python.exe evaluation/model_audit_report.py [--limit 500] [--model-dir <dir>]

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
]


async def _run(model_dir: str | None, limit: int | None) -> tuple[list[dict], dict, str]:
    classifier = build_classifier(model_dir)
    engine = SecurityEngine(load_policy())
    engine_db = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH.as_posix()}")
    async with engine_db.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine_db, class_=AsyncSession, expire_on_commit=False)
    try:
        rows = await audit_request_logs(factory, engine, classifier, limit=limit)
    finally:
        await engine_db.dispose()
    metrics = comparison_metrics(rows)
    return rows, metrics, classifier.model_id


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


def main() -> int:
    parser = argparse.ArgumentParser(description="M5 Rule vs Model 对比报告")
    parser.add_argument("--model-dir", default="", help="PromptGuard 2 ONNX 目录（缺省用 Stub）")
    parser.add_argument("--limit", type=int, default=None, help="最多审计的 request_logs 行数")
    args = parser.parse_args()

    if not DB_PATH.is_file():
        print(f"未找到网关 DB: {DB_PATH}", file=sys.stderr)
        return 2

    rows, metrics, model_id = asyncio.run(_run(args.model_dir or None, args.limit))
    if metrics["total"] == 0:
        print("request_logs 无可审计 prompt（injected_json 为空）", file=sys.stderr)
        return 1

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"model-audit-{ts}"
    meta = {
        "run_id": run_id,
        "db": str(DB_PATH),
        "policy": "config/security.yaml",
        "ts": ts,
        "model_id": model_id,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"{run_id}.json").write_text(
        json.dumps({"meta": meta, "metrics": metrics}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path = REPORTS / f"{run_id}.md"
    md_path.write_text(render_markdown(metrics, model_id, meta), encoding="utf-8")

    print(
        f"model={model_id} total={metrics['total']} "
        f"P={metrics['precision']} R={metrics['recall']} F1={metrics['f1']} "
        f"agree={metrics['agreement']}"
    )
    print(f"报告: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
