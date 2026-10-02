"""策略层：security.yaml 的加载与校验；动作裁决与事件分类规则。

裁决优先级：block > redact > audit > allow（同文本多命中取最高动作）。
事件映射：rule_id 前缀决定 event_type（pii.*/secret.*/injection.* → 对应事件类）；
pii/secret 类命中绝不记录原文（只记 rule_id 与 span），injection 类记录截断预览。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "security.yaml"

Action = Literal["allow", "audit", "redact", "block"]
Severity = Literal["low", "medium", "high", "critical"]

ACTION_RANK: dict[str, int] = {"allow": 0, "audit": 1, "redact": 2, "block": 3}

CATEGORY_TO_EVENT = {
    "pii": "pii_detection",
    "secret": "secret_detection",
    "injection": "prompt_injection",
}
# 这些类别只记规则与位置，不记命中原文（防止审计表本身成为泄露面）
NO_PREVIEW_CATEGORIES = {"pii", "secret"}


class RuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str | None = None
    detector: str
    pattern: str | None = None
    severity: Severity
    action: Action | None = None  # 缺省用全局 default_action
    owasp: str | None = None
    description: str | None = None
    enabled: bool = True


class GuardStageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    stream_mode: Literal["audit", "off"] = "audit"


class SecurityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    default_action: Action = "audit"
    request_guard: GuardStageConfig = Field(default_factory=GuardStageConfig)
    response_guard: GuardStageConfig = Field(default_factory=GuardStageConfig)
    rules: list[RuleConfig] = Field(default_factory=list)


def policy_source_path() -> Path:
    """环境变量指向（或默认）的策略文件路径；启动加载与档位查询共用同一解析。"""
    return Path(os.environ.get("GATEWAY_SECURITY_CONFIG") or DEFAULT_POLICY_PATH)


def load_policy(path: str | os.PathLike[str] | None = None) -> SecurityPolicy | None:
    """加载 security.yaml；文件不存在返回 None（引擎不启用，等价于 V1 行为）。"""
    resolved = Path(path or policy_source_path())
    if not resolved.is_file():
        return None
    raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"安全策略文件必须是 YAML 映射: {resolved}")
    return SecurityPolicy.model_validate(raw)


def rule_action(policy: SecurityPolicy, rule: RuleConfig) -> str:
    return rule.action or policy.default_action


def highest_action(actions: list[str]) -> str:
    if not actions:
        return "allow"
    return max(actions, key=lambda a: ACTION_RANK[a])


def category_of(rule_id: str) -> str:
    return rule_id.split(".", 1)[0]


def event_type_of(rule_id: str) -> str:
    return CATEGORY_TO_EVENT.get(category_of(rule_id), "policy_violation")


def preview_allowed(rule_id: str) -> bool:
    return category_of(rule_id) not in NO_PREVIEW_CATEGORIES
