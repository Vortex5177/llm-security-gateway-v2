"""安全回归：回放 evaluation/datasets 全量样本（引擎级，不依赖运行中的网关）。

闭环约定：每发现一个绕过样本，先入数据集再加规则；本文件保证旧漏洞不复发。
- 攻击样本（expected_rules 非空）：必须命中至少一条期望规则；
- known_gap 样本：记录但不断言（缺口清单见评测报告边界分析）；
- 良性样本：必须零命中（误报回归）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.engine import SecurityEngine
from app.security.policy import load_policy

DATASETS = Path(__file__).resolve().parent.parent.parent / "evaluation" / "datasets"

_engine = SecurityEngine(load_policy())


def _load(pattern: str) -> list[dict]:
    samples = []
    for path in sorted(DATASETS.glob(pattern)):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if line:
                sample = json.loads(line)
                sample.setdefault("id", f"{path.stem}#{lineno}")
                samples.append(sample)
    return samples


ATTACK = [s for s in _load("attack_*.jsonl") if s["expected_rules"]]
KNOWN_GAP = [s for s in _load("attack_*.jsonl") if s.get("known_gap")]
BENIGN = _load("benign_*.jsonl")


@pytest.mark.parametrize("sample", ATTACK, ids=[s["id"] for s in ATTACK])
def test_attack_sample_detected(sample):
    findings = _engine.scan_text(sample["text"])
    hit_rules = {f.rule_id for f in findings}
    missing = set(sample["expected_rules"]) - hit_rules
    assert not missing, f"应命中 {missing}（实际命中 {sorted(hit_rules) or '无'}）"


@pytest.mark.parametrize("sample", BENIGN, ids=[s["id"] for s in BENIGN])
def test_benign_sample_clean(sample):
    findings = _engine.scan_text(sample["text"])
    assert not findings, (
        f"良性样本误报: {[f.rule_id for f in findings]}（标注陷阱: {sample.get('fp_trap', '无')}）"
    )


def test_known_gap_inventory_is_explicit():
    """known_gap 样本是'明确声明的缺口'：数量受控，新增必须有意为之。"""
    assert len(KNOWN_GAP) <= 5, f"known_gap 清单膨胀到 {len(KNOWN_GAP)} 条，需要评审"
    # 缺口样本当前确实未被检出（若已能检出，应转为普通攻击样本纳入回归）
    for sample in KNOWN_GAP:
        findings = _engine.scan_text(sample["text"])
        if findings:
            pytest.fail(
                f"{sample['id']} 已能被 {[f.rule_id for f in findings]} 检出，"
                "请移除其 known_gap 标记并补充 expected_rules"
            )
