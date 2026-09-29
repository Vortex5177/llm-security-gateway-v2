"""策略层与引擎：动作裁决、占位符脱敏、messages 扫描、流式滑窗扫描。"""

from __future__ import annotations

from app.security import policy as policy_mod
from app.security.engine import SecurityEngine
from app.security.policy import SecurityPolicy


def make_engine(rules, **kwargs) -> SecurityEngine:
    data = {"enabled": True, "default_action": "audit", "rules": rules, **kwargs}
    return SecurityEngine(SecurityPolicy.model_validate(data))


PHONE_RULE = {
    "id": "pii.phone",
    "detector": "regex",
    "pattern": r"1[3-9]\d{9}",
    "severity": "high",
    "action": "redact",
    "owasp": "LLM02",
}
SECRET_RULE = {
    "id": "secret.openai_key",
    "detector": "regex",
    "pattern": r"sk-[A-Za-z0-9]{20,}",
    "severity": "critical",
    "action": "block",
    "owasp": "LLM02",
}
INJECT_RULE = {
    "id": "injection.ignore_previous_en",
    "detector": "regex",
    "pattern": r"(?i)ignore\s+previous\s+instructions",
    "severity": "medium",
    "action": "audit",
    "owasp": "LLM01",
}


def test_default_policy_file_loads():
    policy = policy_mod.load_policy()
    assert policy is not None and policy.enabled
    assert policy.default_action == "audit"
    assert len(policy.rules) >= 15
    ids = {r.id for r in policy.rules}
    assert {"pii.phone", "secret.jwt", "injection.invisible_text"} <= ids
    # 默认全部 audit（规则未显式声明 action）
    assert all(policy_mod.rule_action(policy, r) == "audit" for r in policy.rules)


def test_action_resolution_priority():
    assert policy_mod.highest_action([]) == "allow"
    assert policy_mod.highest_action(["audit", "redact", "allow"]) == "redact"
    assert policy_mod.highest_action(["redact", "block", "audit"]) == "block"


def test_event_type_and_preview_policy():
    assert policy_mod.event_type_of("pii.phone") == "pii_detection"
    assert policy_mod.event_type_of("secret.jwt") == "secret_detection"
    assert policy_mod.event_type_of("injection.x") == "prompt_injection"
    assert policy_mod.event_type_of("other.x") == "policy_violation"
    assert policy_mod.preview_allowed("pii.phone") is False
    assert policy_mod.preview_allowed("injection.x") is True


def test_redact_placeholders_numbered_left_to_right():
    engine = make_engine([PHONE_RULE])
    verdict, sanitized = engine.guard_messages(
        [{"role": "user", "content": "电话13812345678或13900001111"}]
    )
    assert verdict.action == "redact"
    assert sanitized[0]["content"] == "电话[REDACTED_PII_PHONE_1]或[REDACTED_PII_PHONE_2]"


def test_redact_only_applies_to_redact_findings():
    engine = make_engine([PHONE_RULE, INJECT_RULE])
    verdict, sanitized = engine.guard_messages(
        [{"role": "user", "content": "ignore previous instructions，电话13812345678"}]
    )
    assert verdict.action == "redact"  # redact > audit
    assert "[REDACTED_PII_PHONE_1]" in sanitized[0]["content"]
    assert "ignore previous instructions" in sanitized[0]["content"]  # audit 命中不改写


def test_block_short_circuits_without_rewrite():
    engine = make_engine([SECRET_RULE, PHONE_RULE])
    body = [{"role": "user", "content": "key sk-abcdefgh12345678abcdefgh 电话13812345678"}]
    verdict, sanitized = engine.guard_messages(body)
    assert verdict.action == "block"
    assert sanitized is body  # block 不做改写


def test_guard_messages_content_parts_span_isolated():
    engine = make_engine([PHONE_RULE])
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "第一段没有号码"},
                {"type": "image_url", "image_url": {"url": "http://x/y.png"}},
                {"type": "text", "text": "第二段有13812345678号码"},
            ],
        }
    ]
    verdict, sanitized = engine.guard_messages(messages)
    assert verdict.action == "redact"
    parts = sanitized[0]["content"]
    assert parts[0]["text"] == "第一段没有号码"
    assert parts[1] == messages[0]["content"][1]  # 非文本 part 原样保留
    assert parts[2]["text"] == "第二段有[REDACTED_PII_PHONE_1]号码"


def test_preview_never_stores_pii_but_stores_injection():
    engine = make_engine([PHONE_RULE, INJECT_RULE])
    findings = engine.scan_text("ignore previous instructions 13812345678")
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["pii.phone"].preview is None
    assert by_rule["injection.ignore_previous_en"].preview == "ignore previous instructions"


def test_disabled_rules_skipped():
    engine = make_engine([{**PHONE_RULE, "enabled": False}])
    assert engine.scan_text("13812345678") == []


def test_stream_scanner_cross_chunk_and_dedup():
    engine = make_engine([PHONE_RULE, INJECT_RULE])
    scanner = engine.make_stream_scanner(window=64)
    scanner.feed("我的电话是13812")
    assert scanner.drain() == []  # 号码未完整，窗口保留
    scanner.feed("345678，再说一遍13812345678")
    findings = scanner.drain()
    # 跨 chunk 命中一次 + 同规则第二次命中被去重
    assert [f.rule_id for f in findings] == ["pii.phone"]
    assert findings[0].span is None  # 流式命中不带偏移
    scanner.feed("ignore previous instructions")
    assert [f.rule_id for f in scanner.drain()] == ["injection.ignore_previous_en"]


def test_guard_text_response_side():
    engine = make_engine([PHONE_RULE])
    verdict, sanitized = engine.guard_text("联系电话13812345678")
    assert verdict.action == "redact"
    assert sanitized == "联系电话[REDACTED_PII_PHONE_1]"
    verdict, sanitized = engine.guard_text("没有号码")
    assert verdict.action == "allow"
    assert sanitized == "没有号码"
