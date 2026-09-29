r"""M5 模型辅助审计：CPU 小分类器离线扫 request_logs，与规则引擎判定对比。

设计要点（对齐"不引重型依赖"与事件纪律）：
- 分类器可插拔：真实 PromptGuard 2 ONNX（懒加载 onnxruntime/transformers，属可选依赖）
  与确定性 StubInjectionClassifier（无模型时演示管线用，报告会明确标注）；
- 离线批处理：读 request_logs.injected_json 里的 prompt，重算规则判定（确定性，
  不依赖 request_id join），再跑模型分类，二者对比落 model_audit_results 表；
- 正类聚焦 injection（PromptGuard 职责）；PII/secret 属规则专属，不入模型对比；
- 不存 prompt 原文，仅存 sha256 前 16 位 digest。

指标以"规则判定为参照"计算模型的 precision/recall/F1，并对比二者延迟——
结论用于回答"哪类问题适合确定性规则、哪类适合语义模型"。
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import ModelAuditResult, RequestLog
from app.security.engine import SecurityEngine


# ------------------------------------------------------------------ 分类器接口
@dataclass
class ModelVerdict:
    label: str  # injection / benign
    score: float  # 该 label 的置信度 [0,1]
    latency_ms: float


class Classifier(Protocol):
    model_id: str

    def classify(self, text: str) -> ModelVerdict:  # pragma: no cover - 接口
        ...


# 注入标记（Stub 用；故意保持简单，与规则引擎独立，避免对比退化）
_STUB_MARKERS = (
    "ignore all previous",
    "ignore previous",
    "disregard",
    "system prompt",
    "initial instructions",
    "jailbreak",
    "do anything now",
    "you are now",
    "dan mode",
    "忽略",
    "无视",
    "系统提示",
    "初始指令",
    "越狱",
    "从现在开始你是",
)


class StubInjectionClassifier:
    """确定性桩分类器：关键词启发式，仅用于无真实模型时演示审计管线。

    报告须明确标注 model_id=stub-keyword，非真实语义模型评测。
    """

    model_id = "stub-keyword"

    def classify(self, text: str) -> ModelVerdict:
        start = time.perf_counter()
        low = text.lower()
        hits = sum(1 for m in _STUB_MARKERS if m in low)
        label = "injection" if hits else "benign"
        # 命中越多置信越高，封顶 0.99；无命中给 benign 0.9
        score = min(0.99, 0.5 + 0.15 * hits) if hits else 0.9
        latency_ms = (time.perf_counter() - start) * 1000
        return ModelVerdict(label=label, score=round(score, 4), latency_ms=latency_ms)


class PromptGuardOnnxClassifier:
    """PromptGuard 2（86M）ONNX CPU 分类器；onnxruntime/transformers 为可选依赖。

    model_dir 需含 model.onnx 与 tokenizer 文件。依赖或模型缺失时抛出带安装提示的
    RuntimeError（不静默降级），由调用方决定回退到 Stub。
    """

    model_id = "promptguard2-86m-onnx"

    # PromptGuard 2 86M 标签序（meta-llama/Prompt-Guard-86M）：0=BENIGN,1=INJECTION
    _LABELS = ("benign", "injection")

    def __init__(self, model_dir: str, max_length: int = 512) -> None:
        try:
            import onnxruntime as ort  # noqa: PLC0415
            from transformers import AutoTokenizer  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - 取决于环境
            raise RuntimeError(
                "PromptGuard ONNX 需要 onnxruntime 与 transformers（可选依赖）。"
                "安装：pip install onnxruntime transformers；或改用 StubInjectionClassifier。"
            ) from exc
        import os  # noqa: PLC0415

        onnx_path = os.path.join(model_dir, "model.onnx")
        if not os.path.isfile(onnx_path):
            raise RuntimeError(f"未找到 ONNX 模型: {onnx_path}")
        self._tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self._session = ort.InferenceSession(
            onnx_path, providers=["CPUExecutionProvider"]
        )
        self._max_length = max_length

    def classify(self, text: str) -> ModelVerdict:  # pragma: no cover - 需真实模型
        start = time.perf_counter()
        enc = self._tokenizer(
            text[:4000],
            truncation=True,
            max_length=self._max_length,
            padding="max_length",
            return_tensors="np",
        )
        inputs = {
            "input_ids": enc["input_ids"].astype("int64"),
            "attention_mask": enc["attention_mask"].astype("int64"),
        }
        # 部分导出版本需要 token_type_ids
        if "token_type_ids" in [i.name for i in self._session.get_inputs()]:
            inputs["token_type_ids"] = enc.get(
                "token_type_ids", enc["attention_mask"] * 0
            ).astype("int64")
        logits = self._session.run(None, inputs)[0][0]
        probs = _softmax(logits)
        idx = int(max(range(len(probs)), key=lambda i: probs[i]))
        label = self._LABELS[idx] if idx < len(self._LABELS) else "benign"
        latency_ms = (time.perf_counter() - start) * 1000
        return ModelVerdict(label=label, score=float(probs[idx]), latency_ms=latency_ms)


def _softmax(xs: Sequence[float]) -> list[float]:
    import math  # noqa: PLC0415

    m = max(xs)
    exps = [math.exp(x - m) for x in xs]
    s = sum(exps) or 1.0
    return [e / s for e in exps]


# ------------------------------------------------------------------ prompt 抽取
def extract_prompt_text(injected_json: str | None) -> str:
    """从 request_logs.injected_json（完整请求参数快照）抽取拼接后的 prompt 文本。"""
    if not injected_json:
        return ""
    try:
        payload = json.loads(injected_json)
    except (ValueError, TypeError):
        return ""
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list):
        return ""
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for piece in content:
                if isinstance(piece, dict) and isinstance(piece.get("text"), str):
                    parts.append(piece["text"])
    return "\n".join(p for p in parts if p)


def prompt_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def rule_flags_injection(engine: SecurityEngine, text: str) -> tuple[bool, float]:
    """重算规则判定：是否命中任一 injection.* 规则；返回 (flag, latency_ms)。"""
    start = time.perf_counter()
    findings = engine.scan_text(text)
    latency_ms = (time.perf_counter() - start) * 1000
    flag = any(f.rule_id.startswith("injection.") for f in findings)
    return flag, latency_ms


# ------------------------------------------------------------------ 审计主流程
async def audit_request_logs(
    session_factory: async_sessionmaker[AsyncSession],
    engine: SecurityEngine,
    classifier: Classifier,
    *,
    limit: int | None = None,
    since_id: int = 0,
    persist: bool = True,
) -> list[dict]:
    """离线扫 request_logs，对每条 prompt 跑规则重算 + 模型分类，对比落库。

    返回逐条对比结果（dict），供 comparison_metrics 汇总。persist=False 时只算不写。
    """
    rows: list[dict] = []
    async with session_factory() as session:
        stmt = select(RequestLog).where(RequestLog.id > since_id).order_by(RequestLog.id)
        if limit is not None:
            stmt = stmt.limit(limit)
        logs = (await session.execute(stmt)).scalars().all()

        for log in logs:
            text = extract_prompt_text(log.injected_json)
            if not text:
                continue
            rule_inj, rule_ms = rule_flags_injection(engine, text)
            verdict = classifier.classify(text)
            model_inj = verdict.label == "injection"
            row = {
                "request_log_id": log.id,
                "prompt_digest": prompt_digest(text),
                "model_id": classifier.model_id,
                "model_label": verdict.label,
                "model_score": verdict.score,
                "model_latency_ms": round(verdict.latency_ms, 4),
                "rule_injection": rule_inj,
                "rule_latency_ms": round(rule_ms, 4),
                "agree": rule_inj == model_inj,
            }
            rows.append(row)
            if persist:
                session.add(ModelAuditResult(**row))
        if persist:
            await session.commit()
    return rows


def comparison_metrics(rows: list[dict]) -> dict:
    """以规则判定为参照，计算模型 injection 检出的 precision/recall/F1 + 延迟对比。"""
    n = len(rows)
    if n == 0:
        return {
            "total": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0,
            "agreement": None, "precision": None, "recall": None, "f1": None,
            "avg_model_latency_ms": None, "avg_rule_latency_ms": None,
            "model_id": None,
        }
    tp = sum(1 for r in rows if r["rule_injection"] and r["model_label"] == "injection")
    fp = sum(1 for r in rows if not r["rule_injection"] and r["model_label"] == "injection")
    fn = sum(1 for r in rows if r["rule_injection"] and r["model_label"] != "injection")
    tn = sum(1 for r in rows if not r["rule_injection"] and r["model_label"] != "injection")
    agree = sum(1 for r in rows if r["agree"])
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall and (precision + recall)
        else None
    )
    avg_model = sum(r["model_latency_ms"] for r in rows) / n
    avg_rule = sum(r["rule_latency_ms"] for r in rows) / n
    return {
        "total": n,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "agreement": round(agree / n, 3),
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "avg_model_latency_ms": round(avg_model, 3),
        "avg_rule_latency_ms": round(avg_rule, 3),
        "model_id": rows[0]["model_id"],
    }


def build_classifier(model_dir: str | None) -> Classifier:
    """有 model_dir 则尝试真实 PromptGuard ONNX，失败或缺省回退 Stub。"""
    if model_dir:
        return PromptGuardOnnxClassifier(model_dir)
    return StubInjectionClassifier()


# 便于报告层复用的类型别名
MetricFn = Callable[[list[dict]], dict]
