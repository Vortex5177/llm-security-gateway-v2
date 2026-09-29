"""模型名解析：别名 -> 模型映射 -> provider/模型名前缀直通；回退候选链。"""

from __future__ import annotations

import time
from dataclasses import dataclass

from app.config import GatewayConfig


class UnknownModelError(Exception):
    """请求的模型名既不是已配置模型也不是别名。"""


@dataclass(frozen=True)
class ResolvedModel:
    name: str  # 解析后的模型名（别名已展开）
    provider: str
    upstream: str  # 发往上游的实际模型名


class Registry:
    def __init__(self, config: GatewayConfig) -> None:
        self._config = config

    # ---- 解析 ----------------------------------------------------------
    def resolve(self, requested: str) -> ResolvedModel:
        name = self._config.aliases.get(requested, requested)
        ref = self._config.models.get(name)
        if ref is not None:
            return ResolvedModel(name=name, provider=ref.provider, upstream=ref.upstream)
        # 前缀直通："provider/上游模型名"（如 moonshot/kimi-k2、siliconflow/Qwen/Qwen3-8B）
        provider_name, sep, upstream = name.partition("/")
        if sep and upstream and provider_name in self._config.providers:
            return ResolvedModel(name=name, provider=provider_name, upstream=upstream)
        raise UnknownModelError(
            f"未知模型 '{requested}'（可用: {self._available_names()}）"
        )

    def _available_names(self) -> str:
        names = sorted(self._config.models) + sorted(self._config.aliases)
        return "、".join(names) if names else "（无）"

    # ---- 回退候选链 -----------------------------------------------------
    def candidates(self, requested: str, tag: str | None = None) -> list[ResolvedModel]:
        """主模型 + fallbacks 链。

        fallbacks 键优先精确匹配 "{模型名}@{tag}"，否则回落到 "{模型名}"。
        候选链仅服务端可见（客户端无感）；按模型名去重。
        """
        primary = self.resolve(requested)
        keys = [f"{primary.name}@{tag}"] if tag else []
        keys.append(primary.name)
        chain: list[str] = []
        for key in keys:
            if key in self._config.fallbacks:
                chain = self._config.fallbacks[key]
                break
        result = [primary]
        seen = {primary.name}
        for target in chain:
            candidate = self.resolve(target)
            if candidate.name in seen:
                continue
            seen.add(candidate.name)
            result.append(candidate)
        return result

    # ---- /v1/models -----------------------------------------------------
    def model_list(self) -> list[dict]:
        created = int(time.time())
        data = [
            {"id": name, "object": "model", "created": created, "owned_by": ref.provider}
            for name, ref in sorted(self._config.models.items())
        ]
        data.extend(
            {"id": alias, "object": "model", "created": created, "owned_by": "alias"}
            for alias in sorted(self._config.aliases)
        )
        return data
