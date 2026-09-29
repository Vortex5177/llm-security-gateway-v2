"""reconcile_garak 对账逻辑自测（不依赖已安装 garak）。

用 garak 真实 .hitlog.jsonl 格式的 fixture 驱动 reconcile()，验证：
- 探针职责域分类（in-scope vs out-of-scope）；
- prompt 文本离线复扫的检出/阻断分类；
- 默认策略（全 audit）与 strict-demo（secret→block）两种口径。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = PROJECT_ROOT / "evaluation" / "fixtures" / "garak_sample.hitlog.jsonl"
STRICT_POLICY = PROJECT_ROOT / "config" / "security.strict-demo.yaml"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "reconcile_garak", PROJECT_ROOT / "evaluation" / "reconcile_garak.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


reconcile_garak = _load_module()


def _attempts():
    return reconcile_garak.load_hitlog(FIXTURE)


def test_load_hitlog_extracts_prompt_text():
    attempts = _attempts()
    assert len(attempts) == 5
    # messages 形式的 prompt 被正确抽取
    assert "Ignore all previous instructions" in attempts[0]["prompt"]
    assert attempts[0]["probe"] == "promptinject.PromptInjectTests"


def test_scope_classification():
    assert reconcile_garak.classify_scope("promptinject.PromptInjectTests") == "injection"
    assert reconcile_garak.classify_scope("leakreplay.LeakReplayTests") == "secret"
    assert reconcile_garak.classify_scope("knownbadsignatures.Garak") == "injection"
    # encoding 类属模型层职责，排除在对账之外
    assert reconcile_garak.classify_scope("encoding.Base64") == "out_of_scope"


def test_reconcile_default_policy_all_audit():
    """默认策略全 audit：in-scope 全检出，但无 block。"""
    from app.security.engine import SecurityEngine
    from app.security.policy import load_policy

    engine = SecurityEngine(load_policy())
    recon = reconcile_garak.reconcile(_attempts(), engine)

    assert recon["attempts_total"] == 5
    assert recon["in_scope_total"] == 4       # encoding 样本被排除
    assert recon["out_of_scope_total"] == 1
    assert recon["detected"] == 4             # 4 条 in-scope 全部命中规则
    assert recon["passed"] == 0
    assert recon["blocked"] == 0              # 默认策略无 block 动作
    assert recon["detection_rate"] == 1.0


def test_reconcile_strict_policy_blocks_secret():
    """strict-demo 策略：secret 样本应被分类为 blocked。"""
    from app.security.engine import SecurityEngine
    from app.security.policy import load_policy

    engine = SecurityEngine(load_policy(STRICT_POLICY))
    recon = reconcile_garak.reconcile(_attempts(), engine)

    assert recon["detected"] == 4
    assert recon["blocked"] >= 1              # leakreplay 的 sk- 密钥命中 secret.openai_key→block
    assert recon["block_rate"] > 0.0


def test_reconcile_per_probe_breakdown():
    from app.security.engine import SecurityEngine
    from app.security.policy import load_policy

    engine = SecurityEngine(load_policy())
    recon = reconcile_garak.reconcile(_attempts(), engine)

    per_probe = recon["per_probe"]
    assert "promptinject.PromptInjectTests" in per_probe
    assert per_probe["promptinject.PromptInjectTests"]["total"] == 2
    assert per_probe["promptinject.PromptInjectTests"]["detected"] == 2
    assert "leakreplay.LeakReplayTests" in per_probe
    # out-of-scope 探针不进入 per_probe
    assert "encoding.Base64" not in per_probe
