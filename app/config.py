"""gateway.yaml 的加载与校验；.env 密钥解析；看板 overlay 合并。

设计要点：
- pydantic 严格校验（extra="forbid"），配置写错立刻报错且信息清晰；
- 交叉引用检查（models->provider、aliases->model、fallbacks->model）在
  parse 阶段一次性列出全部问题，而不是遇到第一个就退出；
- 密钥两类来源：providers.<name>.api_key（字面量，如本地 vLLM 的 EMPTY）
  或 api_key_env 指向的环境变量（.env 由 python-dotenv 载入）；
- 看板新增的 provider 写入 data/gateway.user.yaml（overlay，仅 providers 段），
  加载时与主配置合并，同名以主配置为准。
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "gateway.yaml"
ENV_FILE = PROJECT_ROOT / ".env"
USER_CONFIG_PATH = PROJECT_ROOT / "data" / "gateway.user.yaml"  # 看板写入的用户 overlay


class ConfigError(Exception):
    """配置加载/校验失败（启动时直接抛出，信息面向人读）。"""


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    key_env: str = "GW_API_KEY"


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = 4101
    upstream_timeout_seconds: float = 300.0
    auth: AuthConfig = Field(default_factory=AuthConfig)


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str
    api_key: str | None = None  # 字面量密钥（本地 vLLM 用 "EMPTY"）
    api_key_env: str | None = None  # 从环境变量读取的密钥名
    metrics_url: str | None = None  # 可空 = 不采集该 provider 的引擎指标
    type: Literal["local", "cloud"] | None = None  # 缺省按 base_url 推断（见 provider_kind）


class ModelRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    upstream: str


class SamplingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interval_seconds: float = 5.0
    gpu_source: Literal["auto", "nvml", "wsl"] = "auto"  # GPU 采样源
    wsl_distro: str = "Ubuntu-24.04"  # gpu_source=wsl 时使用的发行版


class SsrfConfig(BaseModel):
    """看板动态添加 provider 的 SSRF 校验豁免（配置文件的 provider 可信不校验）。

    allow_hosts 条目支持 "host" 或 "host:port" 两种形式；
    默认空表 = 回环/内网/元数据地址一律拒绝。
    """

    model_config = ConfigDict(extra="forbid")

    allow_hosts: list[str] = Field(default_factory=list)


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ssrf: SsrfConfig = Field(default_factory=SsrfConfig)


class LocalVllmConfig(BaseModel):
    """仅由可信本地配置指定目标，网页不能编辑启动命令。

    models 为候选模型路径列表（至少一项），候选名即目录名小写；
    default 可选，缺省取第一个候选；
    tool_parsers 可选，按候选名覆盖 vLLM 工具调用解析器（缺省 hermes）。
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    provider: str = "local-vllm"
    wsl_distro: str = "Ubuntu-24.04"
    start_script: str = "/opt/scripts/start-vllm.sh"
    models: list[str] = Field(default_factory=list)
    default: str | None = None
    tool_parsers: dict[str, str] = Field(default_factory=dict)

    @field_validator("provider", "wsl_distro")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not value.strip() or value.startswith("-") or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("名称不能为空、以 - 开头或包含控制字符")
        return value

    @field_validator("start_script")
    @classmethod
    def linux_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (not path.is_absolute() or not path.name or ".." in path.parts
                or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("必须为不含 .. 或控制字符的 Linux 绝对路径")
        return str(path)

    @field_validator("models")
    @classmethod
    def linux_paths(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("至少需要一个候选模型路径")
        checked = []
        for value in values:
            path = PurePosixPath(value)
            if (not path.is_absolute() or not path.name or ".." in path.parts
                    or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ValueError(f"候选模型路径必须为不含 .. 或控制字符的 Linux 绝对路径：{value}")
            checked.append(str(path))
        return checked

    @property
    def model_names(self) -> list[str]:
        return [PurePosixPath(path).name.lower() for path in self.models]

    @property
    def default_name(self) -> str | None:
        if self.default is not None:
            return self.default
        names = self.model_names
        return names[0] if names else None


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerConfig = Field(default_factory=ServerConfig)
    providers: dict[str, ProviderConfig]
    models: dict[str, ModelRef] = Field(default_factory=dict)
    aliases: dict[str, str] = Field(default_factory=dict)
    fallbacks: dict[str, list[str]] = Field(default_factory=dict)
    injection: dict[str, dict[str, Any]] = Field(default_factory=dict)
    sampling: SamplingConfig = Field(default_factory=SamplingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    local_vllm: LocalVllmConfig = Field(default_factory=LocalVllmConfig)


def resolve_api_key(provider: ProviderConfig) -> str | None:
    """字面量 api_key 优先；否则读 api_key_env 指向的环境变量。"""
    if provider.api_key:
        return provider.api_key
    if provider.api_key_env:
        return os.environ.get(provider.api_key_env) or None
    return None


def provider_kind(provider: ProviderConfig) -> Literal["local", "cloud"]:
    """本地/云端判定：显式 type 优先；否则按 base_url 主机名推断。

    主机名为 localhost / *.local / host.docker.internal，或解析为回环/内网
    IP（127.x、::1、10.x、192.168.x、172.16-31.x 等）时视为本地，其余云端。
    """
    if provider.type is not None:
        return provider.type
    host = (urlparse(provider.base_url).hostname or "").lower()
    if host in ("localhost", "host.docker.internal") or host.endswith(".local"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "cloud"
    return "local" if ip.is_loopback or ip.is_private else "cloud"


def _format_validation_error(exc: ValidationError) -> str:
    lines = ["配置格式错误："]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "(根)"
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)


def _collect_reference_errors(cfg: GatewayConfig) -> list[str]:
    """交叉引用检查；收集全部问题一次性返回。"""
    errors: list[str] = []
    if not cfg.providers:
        errors.append("providers: 至少需要定义一个 provider")
    known_providers = "、".join(sorted(cfg.providers)) or "（无）"
    known_models = "、".join(sorted(cfg.models)) or "（无）"
    for name, ref in cfg.models.items():
        if ref.provider not in cfg.providers:
            errors.append(
                f"models.{name}.provider 引用了不存在的 provider '{ref.provider}'"
                f"（已定义: {known_providers}）"
            )
    for alias, target in cfg.aliases.items():
        if alias in cfg.models:
            errors.append(f"aliases.{alias}: 别名与模型重名，会造成解析歧义")
        if target not in cfg.models:
            errors.append(
                f"aliases.{alias} 指向不存在的模型 '{target}'（已定义: {known_models}）"
            )
    for key, chain in cfg.fallbacks.items():
        base = key.split("@", 1)[0]
        if base not in cfg.models:
            errors.append(
                f"fallbacks.{key}: 主模型 '{base}' 不存在（已定义: {known_models}）"
            )
        if not chain:
            errors.append(f"fallbacks.{key}: 候选链为空，请删除该键或填入模型名")
        for target in chain:
            if target not in cfg.models:
                errors.append(
                    f"fallbacks.{key}: 候选模型 '{target}' 不存在（已定义: {known_models}）"
                )
    local = cfg.local_vllm
    if local.enabled:
        # 注：服务控制接口的安全边界已下沉到运行时——main.py 的 admin_loopback_guard
        # 按“请求来源是否本机回环”拦截，不再与 server.host 监听地址绑定。
        provider = cfg.providers.get(local.provider)
        if provider is None:
            errors.append("local_vllm.provider 引用了不存在的 provider")
        else:
            try:
                url = urlparse(provider.base_url)
                valid = (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
                         and url.port is not None and url.port > 0
                         and url.path.rstrip("/") == "/v1"
                         and url.username is None and url.password is None
                         and not (url.query or url.fragment)
                         and not any(ord(c) < 32 or ord(c) == 127 for c in provider.base_url)
                         and provider.type != "cloud")
            except ValueError:
                valid = False
            if not valid:
                errors.append("local_vllm: Provider 必须使用本机 http://主机:端口/v1 地址")
        names = local.model_names
        counts = {}
        for name in names:
            counts[name] = counts.get(name, 0) + 1
        for name, count in counts.items():
            if count > 1:
                errors.append(f"local_vllm: 候选模型名称 '{name}' 重复（目录名小写后必须唯一）")
        if local.default is not None and local.default not in names:
            options = "、".join(sorted(counts)) or "（无）"
            errors.append(f"local_vllm.default 必须是候选模型之一（可选: {options}）")
        for name in sorted(counts):
            if not any(ref.provider == local.provider and ref.upstream == name
                       for ref in cfg.models.values()):
                errors.append(
                    f"local_vllm: 候选模型 '{name}' 缺少 provider '{local.provider}'"
                    f" 且 upstream '{name}' 的上游模型映射"
                )
        for name, parser in local.tool_parsers.items():
            if name not in counts:
                options = "、".join(sorted(counts)) or "（无）"
                errors.append(
                    f"local_vllm.tool_parsers: '{name}' 不是候选模型名（可选: {options}）"
                )
            elif not parser or not all(c.isalnum() or c == "_" for c in parser):
                errors.append(
                    f"local_vllm.tool_parsers.{name}: 解析器名称必须由字母、数字或下划线组成"
                )
    return errors


def parse_config(raw: dict[str, Any]) -> GatewayConfig:
    """校验原始 dict 并完成交叉引用检查；有错则一次性列全。"""
    try:
        cfg = GatewayConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc
    errors = _collect_reference_errors(cfg)
    if errors:
        raise ConfigError("配置校验失败：\n" + "\n".join(f"  - {e}" for e in errors))
    return cfg


def _load_dotenv_once() -> None:
    # override=False：已存在的环境变量优先（便于临时覆盖）
    load_dotenv(ENV_FILE, override=False)


def _resolve_config_path(path: str | os.PathLike[str] | None) -> Path:
    """path 优先级：显式参数 > 环境变量 GATEWAY_CONFIG > 项目根 gateway.yaml。"""
    if path is None:
        path = os.environ.get("GATEWAY_CONFIG") or DEFAULT_CONFIG_PATH
    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = PROJECT_ROOT / resolved
    return resolved


def _read_yaml_mapping(resolved: Path) -> dict[str, Any]:
    if not resolved.is_file():
        raise ConfigError(f"配置文件不存在: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"配置文件 YAML 解析失败: {resolved}\n  {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"配置文件内容必须是 YAML 映射（dict）: {resolved}")
    return raw


def load_user_overlay() -> dict[str, Any]:
    """读取看板写入的 overlay（data/gateway.user.yaml）；不存在返回空 dict。"""
    if not USER_CONFIG_PATH.is_file():
        return {}
    return _read_yaml_mapping(USER_CONFIG_PATH)


def save_user_overlay(raw: dict[str, Any]) -> None:
    """原子写入 overlay（看板添加 provider 时调用）。"""
    USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = USER_CONFIG_PATH.with_name(USER_CONFIG_PATH.name + ".tmp")
    tmp.write_text(
        yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    os.replace(tmp, USER_CONFIG_PATH)


def _merge_user_overlay(raw: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    """合并 overlay 的 providers 段；同名以主配置（手写）为准。"""
    user_providers = user.get("providers")
    if not isinstance(user_providers, dict) or not user_providers:
        return raw
    base_providers = raw.get("providers")
    merged_providers = dict(base_providers) if isinstance(base_providers, dict) else {}
    for name, provider in user_providers.items():
        merged_providers.setdefault(name, provider)
    merged = dict(raw)
    merged["providers"] = merged_providers
    return merged


def load_config(path: str | os.PathLike[str] | None = None) -> GatewayConfig:
    """加载并校验配置（主配置 + 看板 overlay 合并后校验）。

    path 优先级：显式参数 > 环境变量 GATEWAY_CONFIG > 项目根 gateway.yaml；
    相对路径按项目根解析。
    """
    _load_dotenv_once()
    resolved = _resolve_config_path(path)
    raw = _read_yaml_mapping(resolved)
    user = load_user_overlay()
    if user:
        raw = _merge_user_overlay(raw, user)
    try:
        return parse_config(raw)
    except ConfigError as exc:
        raise ConfigError(f"{exc}\n（配置文件: {resolved}）") from exc


def validate_user_overlay(user_overlay: dict[str, Any]) -> None:
    """预校验「主配置 + 指定 overlay」的合并结果（不落盘）；供看板添加 provider。"""
    raw = _read_yaml_mapping(_resolve_config_path(None))
    parse_config(_merge_user_overlay(raw, user_overlay))


_config_cache: GatewayConfig | None = None


def get_config() -> GatewayConfig:
    """进程级单例；测试通过 reset_config_cache() 清理。"""
    global _config_cache
    if _config_cache is None:
        _config_cache = load_config()
    return _config_cache


def reset_config_cache() -> None:
    global _config_cache
    _config_cache = None
