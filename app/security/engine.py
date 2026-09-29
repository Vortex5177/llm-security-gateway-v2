"""Security Engine：Detection → Finding → Policy 裁决 → Action。

与 HTTP 层完全解耦（chat.py 只调用 guard_messages / guard_text / 流式扫描器）：
- scan_text：全部启用规则扫描，返回 Finding（含策略裁决后的动作）；
- redact 采用占位符替换（llm-guard 模式，保持句子结构），同规则序号递增；
- 流式扫描器用滑动窗口解决跨 chunk 命中，audit-only 语义（只报不改）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.security import policy as policy_mod
from app.security.detectors import Detector, build_detector
from app.security.policy import SecurityPolicy

PREVIEW_LIMIT = 80


@dataclass
class Finding:
    rule_id: str
    name: str
    detector: str
    severity: str
    action: str  # 裁决后动作（规则值或全局默认）
    span: tuple[int, int] | None
    preview: str | None  # pii/secret 恒为 None（不记原文）
    owasp: str | None = None
    message_index: int | None = None  # 命中第几条 message（请求护栏用）
    part_index: int | None = None  # content parts 中的第几段（多模态消息用）


@dataclass
class Verdict:
    action: str  # allow / audit / redact / block（多命中取最高）
    findings: list[Finding] = field(default_factory=list)


class _CompiledRule:
    def __init__(self, config: Any, detector: Detector, action: str) -> None:
        self.config = config
        self.detector = detector
        self.action = action


class SecurityEngine:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy
        self._rules: list[_CompiledRule] = []
        for rule in policy.rules:
            if not rule.enabled:
                continue
            detector = build_detector(rule.detector, rule.pattern)
            self._rules.append(
                _CompiledRule(rule, detector, policy_mod.rule_action(policy, rule))
            )

    # ------------------------------------------------------------ 扫描

    def scan_text(self, text: str, *, message_index: int | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            cfg = rule.config
            for match in rule.detector.find(text):
                preview = None
                if policy_mod.preview_allowed(cfg.id):
                    preview = match.text[:PREVIEW_LIMIT]
                findings.append(
                    Finding(
                        rule_id=cfg.id,
                        name=cfg.name or cfg.id,
                        detector=cfg.detector,
                        severity=cfg.severity,
                        action=rule.action,
                        span=match.span,
                        preview=preview,
                        owasp=cfg.owasp,
                        message_index=message_index,
                    )
                )
        return findings

    @staticmethod
    def verdict_of(findings: list[Finding]) -> Verdict:
        return Verdict(
            action=policy_mod.highest_action([f.action for f in findings]),
            findings=findings,
        )

    # ------------------------------------------------------------ 脱敏

    @staticmethod
    def _placeholder(rule_id: str, seq: int) -> str:
        tag = re.sub(r"[^A-Z0-9]+", "_", rule_id.upper())
        return f"[REDACTED_{tag}_{seq}]"

    def apply_redactions(self, text: str, findings: list[Finding]) -> str:
        """占位符替换（仅 action=redact 的命中；左到右编号，右到左替换）。"""
        targets = sorted(
            [f for f in findings if f.action == "redact" and f.span is not None],
            key=lambda x: x.span[0],
        )
        counters: dict[str, int] = {}
        seq_of: dict[int, int] = {}
        for f in targets:
            counters[f.rule_id] = counters.get(f.rule_id, 0) + 1
            seq_of[id(f)] = counters[f.rule_id]
        result = text
        for f in reversed(targets):
            start, end = f.span
            result = result[:start] + self._placeholder(f.rule_id, seq_of[id(f)]) + result[end:]
        return result

    # ------------------------------------------------------------ 请求/响应护栏

    def guard_messages(self, messages: list[Any]) -> tuple[Verdict, list[Any]]:
        """请求侧：扫描全部 message 文本；redact 时返回重写后的 messages。"""
        all_findings: list[Finding] = []
        for idx, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                all_findings.extend(self.scan_text(content, message_index=idx))
            elif isinstance(content, list):
                for p_idx, part in enumerate(content):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        findings = self.scan_text(part["text"], message_index=idx)
                        for f in findings:
                            f.part_index = p_idx
                        all_findings.extend(findings)
        verdict = self.verdict_of(all_findings)
        if verdict.action != "redact":
            return verdict, messages

        def _redact_of(msg_idx: int, part_idx: int | None) -> list[Finding]:
            return [
                f
                for f in all_findings
                if f.message_index == msg_idx and f.part_index == part_idx and f.action == "redact"
            ]

        sanitized = []
        for idx, message in enumerate(messages):
            if not isinstance(message, dict):
                sanitized.append(message)
                continue
            content = message.get("content")
            if isinstance(content, str):
                fs = _redact_of(idx, None)
                if not fs:
                    sanitized.append(message)
                    continue
                sanitized.append({**message, "content": self.apply_redactions(content, fs)})
            elif isinstance(content, list):
                new_parts = []
                for p_idx, part in enumerate(content):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        fs = _redact_of(idx, p_idx)
                        if fs:
                            part = {**part, "text": self.apply_redactions(part["text"], fs)}
                    new_parts.append(part)
                sanitized.append({**message, "content": new_parts})
            else:
                sanitized.append(message)
        return verdict, sanitized

    def guard_text(self, text: str) -> tuple[Verdict, str]:
        """响应侧（非流式）：扫描整段文本，redact 返回重写文本。"""
        findings = self.scan_text(text)
        verdict = self.verdict_of(findings)
        if verdict.action == "redact":
            return verdict, self.apply_redactions(text, findings)
        return verdict, text

    # ------------------------------------------------------------ 流式审计

    def make_stream_scanner(self, window: int = 512) -> "StreamAuditScanner":
        return StreamAuditScanner(self, window=window)


class StreamAuditScanner:
    """流式增量扫描（audit-only）：滑窗解决跨 chunk 命中，每条规则每请求只报一次。

    只读流量、绝不修改；feed() 后通过 drain() 取走新命中由调用方落事件。
    """

    def __init__(self, engine: SecurityEngine, window: int = 512) -> None:
        self._engine = engine
        self._window = max(64, window)
        self._tail = ""
        self._emitted: set[str] = set()
        self._pending: list[Finding] = []

    def feed(self, text: str) -> None:
        if not text:
            return
        buffer = self._tail + text
        for finding in self._engine.scan_text(buffer):
            if finding.rule_id not in self._emitted:
                self._emitted.add(finding.rule_id)
                finding.span = None  # 滑窗内偏移无业务含义，避免误导
                self._pending.append(finding)
        self._tail = buffer[-(self._window - 1) :]

    def drain(self) -> list[Finding]:
        findings, self._pending = self._pending, []
        return findings
