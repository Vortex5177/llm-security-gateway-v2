"""模块 1：配置校验与 registry 解析测试。"""

from __future__ import annotations

import pytest

from app import config as config_module
from app.config import (
    ConfigError,
    ProviderConfig,
    load_config,
    parse_config,
    provider_kind,
    resolve_api_key,
)
from app.registry import Registry, UnknownModelError

YAML_TEMPLATE = """\
server:
  port: 4200
providers:
  local-vllm:
    base_url: http://localhost:8200/v1
    api_key: EMPTY
models:
  qwen3-1.7b: { provider: local-vllm, upstream: qwen3-1.7b }
aliases:
  default: qwen3-1.7b
"""


@pytest.fixture(autouse=True)
def isolate_environment_files(monkeypatch):
    """保留原有临时 YAML 测试，但不读取真实 .env 或用户 overlay。"""
    monkeypatch.setattr(config_module, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr(config_module, "load_user_overlay", lambda: {})


# ------------------------------------------------------------ parse_config

def test_valid_config_parses(config_dict):
    cfg = parse_config(config_dict)
    assert cfg.server.port == 4101
    assert set(cfg.providers) == {"local-vllm", "deepseek"}
    assert cfg.models["qwen3-1.7b"].provider == "local-vllm"
    assert cfg.aliases["default"] == "qwen3-1.7b"
    assert cfg.fallbacks["qwen3-1.7b"] == ["deepseek-chat"]
    assert cfg.injection["speclens/scan"]["max_tokens"] == 4096
    assert cfg.sampling.interval_seconds == 5


def test_defaults_applied(config_dict):
    config_dict.pop("server")
    config_dict.pop("sampling")
    cfg = parse_config(config_dict)
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 4101
    assert cfg.server.upstream_timeout_seconds == 300
    assert cfg.server.auth.enabled is False
    assert cfg.sampling.interval_seconds == 5


def test_injection_nested_structure_kept(config_dict):
    config_dict["injection"]["default"]["extra"] = {
        "chat_template_kwargs": {"enable_thinking": False}
    }
    cfg = parse_config(config_dict)
    assert (
        cfg.injection["default"]["extra"]["chat_template_kwargs"]["enable_thinking"]
        is False
    )


def test_model_unknown_provider_raises(config_dict):
    config_dict["models"]["qwen3-1.7b"]["provider"] = "nope"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    message = str(excinfo.value)
    assert "nope" in message
    assert "provider" in message


def test_alias_unknown_target_raises(config_dict):
    config_dict["aliases"]["default"] = "ghost"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "ghost" in str(excinfo.value)


def test_alias_conflicts_with_model_raises(config_dict):
    config_dict["aliases"]["qwen3-1.7b"] = "deepseek-chat"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "重名" in str(excinfo.value)


def test_fallback_unknown_main_model_raises(config_dict):
    config_dict["fallbacks"] = {"ghost": ["deepseek-chat"]}
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "ghost" in str(excinfo.value)


def test_fallback_unknown_target_raises(config_dict):
    config_dict["fallbacks"]["qwen3-1.7b"] = ["ghost"]
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "ghost" in str(excinfo.value)


def test_fallback_tag_key_is_valid(config_dict):
    config_dict["fallbacks"] = {"qwen3-1.7b@scan": ["deepseek-chat"]}
    cfg = parse_config(config_dict)
    assert cfg.fallbacks["qwen3-1.7b@scan"] == ["deepseek-chat"]


def test_fallback_empty_chain_raises(config_dict):
    config_dict["fallbacks"] = {"qwen3-1.7b": []}
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "候选链为空" in str(excinfo.value)


def test_unknown_top_level_key_raises(config_dict):
    config_dict["routes"] = {}
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "routes" in str(excinfo.value)


def test_unknown_provider_field_raises(config_dict):
    config_dict["providers"]["local-vllm"]["metric_url"] = "typo"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "metric_url" in str(excinfo.value)


def test_empty_providers_raises(config_dict):
    config_dict["providers"] = {}
    config_dict["models"] = {}
    config_dict["aliases"] = {}
    config_dict["fallbacks"] = {}
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "至少" in str(excinfo.value)


def test_multiple_errors_reported_together(config_dict):
    config_dict["models"]["qwen3-1.7b"]["provider"] = "nope"
    config_dict["aliases"]["default"] = "ghost"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    message = str(excinfo.value)
    assert "nope" in message
    assert "ghost" in message


# ------------------------------------------------------------ load_config

def test_load_config_from_file(tmp_path):
    path = tmp_path / "gateway.yaml"
    path.write_text(YAML_TEMPLATE, encoding="utf-8")
    cfg = load_config(path)
    assert cfg.server.port == 4200
    assert cfg.models["qwen3-1.7b"].upstream == "qwen3-1.7b"


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "missing.yaml")
    assert "不存在" in str(excinfo.value)


def test_load_config_invalid_yaml_raises(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("providers: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "YAML" in str(excinfo.value)


def test_load_config_uses_env_var(tmp_path, monkeypatch):
    path = tmp_path / "gateway-env.yaml"
    path.write_text(YAML_TEMPLATE, encoding="utf-8")
    monkeypatch.setenv("GATEWAY_CONFIG", str(path))
    cfg = load_config()
    assert cfg.server.port == 4200


def test_load_config_error_includes_file_path(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "providers:\n"
        "  local-vllm:\n"
        "    base_url: http://x/v1\n"
        "models:\n"
        "  m1: { provider: ghost, upstream: m1 }\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    assert "ghost" in message
    assert str(path) in message


# ------------------------------------------------------------ api key 解析

def test_resolve_api_key_literal(config_dict):
    cfg = parse_config(config_dict)
    assert resolve_api_key(cfg.providers["local-vllm"]) == "EMPTY"


def test_resolve_api_key_from_env(config_dict, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-123")
    cfg = parse_config(config_dict)
    assert resolve_api_key(cfg.providers["deepseek"]) == "sk-test-123"


def test_resolve_api_key_env_missing(config_dict, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    cfg = parse_config(config_dict)
    assert resolve_api_key(cfg.providers["deepseek"]) is None


# ------------------------------------------------------------ provider kind


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("http://localhost:8200/v1", "local"),
        ("http://127.0.0.1:8200/v1", "local"),
        ("http://192.168.1.10:8200/v1", "local"),
        ("http://[::1]:8200/v1", "local"),
        ("https://api.deepseek.com/v1", "cloud"),
        ("https://dashscope.aliyuncs.com/compatible-mode/v1", "cloud"),
    ],
)
def test_provider_kind_inference(base_url, expected):
    assert provider_kind(ProviderConfig(base_url=base_url)) == expected


def test_provider_kind_explicit_override():
    provider = ProviderConfig(base_url="http://localhost:8200/v1", type="cloud")
    assert provider_kind(provider) == "cloud"


def test_provider_type_invalid_raises(config_dict):
    config_dict["providers"]["local-vllm"]["type"] = "hybrid"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_dict)
    assert "type" in str(excinfo.value)


# ------------------------------------------------------------ registry

@pytest.fixture()
def registry(config_dict):
    return Registry(parse_config(config_dict))


def test_resolve_alias(registry):
    resolved = registry.resolve("default")
    assert resolved.name == "qwen3-1.7b"
    assert resolved.provider == "local-vllm"
    assert resolved.upstream == "qwen3-1.7b"


def test_resolve_direct_model(registry):
    resolved = registry.resolve("deepseek-chat")
    assert resolved.provider == "deepseek"
    assert resolved.upstream == "deepseek-chat"


def test_resolve_unknown_model_lists_available(registry):
    with pytest.raises(UnknownModelError) as excinfo:
        registry.resolve("gpt-4")
    message = str(excinfo.value)
    assert "gpt-4" in message
    assert "qwen3-1.7b" in message
    assert "default" in message


def test_candidates_default_chain(registry):
    chain = registry.candidates("default")
    assert [c.name for c in chain] == ["qwen3-1.7b", "deepseek-chat"]


def test_candidates_without_fallbacks(registry):
    chain = registry.candidates("deepseek-chat")
    assert [c.name for c in chain] == ["deepseek-chat"]


def test_candidates_tag_override(config_dict):
    config_dict["models"]["qwen-plus"] = {
        "provider": "deepseek",
        "upstream": "qwen-plus",
    }
    config_dict["fallbacks"] = {
        "qwen3-1.7b": ["deepseek-chat"],
        "qwen3-1.7b@scan": ["qwen-plus"],
    }
    reg = Registry(parse_config(config_dict))
    plain = reg.candidates("qwen3-1.7b")
    tagged = reg.candidates("qwen3-1.7b", tag="scan")
    assert [c.name for c in plain] == ["qwen3-1.7b", "deepseek-chat"]
    assert [c.name for c in tagged] == ["qwen3-1.7b", "qwen-plus"]


def test_candidates_tag_falls_back_to_plain_key(registry):
    chain = registry.candidates("qwen3-1.7b", tag="no-such-tag")
    assert [c.name for c in chain] == ["qwen3-1.7b", "deepseek-chat"]


def test_candidates_dedupe(config_dict):
    config_dict["fallbacks"]["qwen3-1.7b"] = ["qwen3-1.7b", "deepseek-chat"]
    reg = Registry(parse_config(config_dict))
    chain = reg.candidates("qwen3-1.7b")
    assert [c.name for c in chain] == ["qwen3-1.7b", "deepseek-chat"]


def test_model_list_contains_models_and_aliases(registry):
    entries = {item["id"]: item for item in registry.model_list()}
    assert set(entries) == {"qwen3-1.7b", "deepseek-chat", "default"}
    assert entries["qwen3-1.7b"]["owned_by"] == "local-vllm"
    assert entries["default"]["owned_by"] == "alias"
    assert all(item["object"] == "model" for item in entries.values())


@pytest.fixture
def local_config(config_dict):
    config_dict["local_vllm"] = {"enabled": True, "models": ["/opt/models/Qwen3-1.7B"]}
    return config_dict


def test_local_vllm_defaults_disabled_without_changing_old_config(config_dict):
    cfg = parse_config(config_dict)
    assert cfg.local_vllm.enabled is False
    assert cfg.local_vllm.provider == "local-vllm"
    assert cfg.local_vllm.wsl_distro == "Ubuntu-24.04"
    assert cfg.local_vllm.start_script == "/opt/scripts/start-vllm.sh"
    assert cfg.local_vllm.models == [] and cfg.local_vllm.default is None
    assert cfg.local_vllm.model_names == [] and cfg.local_vllm.default_name is None
    assert cfg.local_vllm.tool_parsers == {}


@pytest.mark.parametrize("url", ["http://localhost:8200/v1", "http://127.0.0.1:8200/v1",
                                 "http://[::1]:8200/v1", "http://localhost:1/v1",
                                 "http://127.0.0.1:65535/v1/"])
def test_local_vllm_enabled_accepts_explicit_loopback_url_and_matching_model(local_config, url):
    local_config["providers"]["local-vllm"]["base_url"] = url
    cfg = parse_config(local_config)
    assert cfg.local_vllm.enabled is True
    assert cfg.providers[cfg.local_vllm.provider].base_url == url
    assert cfg.models["qwen3-1.7b"].upstream == cfg.local_vllm.default_name == "qwen3-1.7b"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_local_vllm_accepts_loopback_gateway_host(local_config, host):
    local_config["server"]["host"] = host
    assert parse_config(local_config).server.host == host


def test_local_vllm_candidate_name_comes_from_lowercase_directory_basename(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Custom-Qwen/"]
    local_config["models"]["qwen3-1.7b"]["upstream"] = "custom-qwen"
    cfg = parse_config(local_config)
    assert cfg.local_vllm.models == ["/opt/models/Custom-Qwen"]
    assert cfg.local_vllm.model_names == ["custom-qwen"]
    assert cfg.local_vllm.default_name == "custom-qwen"


def test_local_vllm_tool_parsers_map_candidate_to_parser(local_config):
    local_config["local_vllm"]["tool_parsers"] = {"qwen3-1.7b": "qwen3_xml"}
    cfg = parse_config(local_config)
    assert cfg.local_vllm.tool_parsers == {"qwen3-1.7b": "qwen3_xml"}


def test_local_vllm_rejects_tool_parser_for_unknown_candidate(local_config):
    local_config["local_vllm"]["tool_parsers"] = {"ghost": "qwen3_xml"}
    with pytest.raises(ConfigError, match="tool_parsers"):
        parse_config(local_config)


@pytest.mark.parametrize("value", ["", "bad name", "qwen3-xml", "-x"])
def test_local_vllm_rejects_invalid_tool_parser_name(local_config, value):
    local_config["local_vllm"]["tool_parsers"] = {"qwen3-1.7b": value}
    with pytest.raises(ConfigError, match="tool_parsers"):
        parse_config(local_config)


@pytest.mark.parametrize("field", ["command", "port", "model_name", "helper_path", "model_path"])
def test_local_vllm_unknown_fields_are_forbidden(local_config, field):
    local_config["local_vllm"][field] = "injected"
    with pytest.raises(ConfigError, match=field):
        parse_config(local_config)


@pytest.mark.parametrize("url", [
    "https://api.example.com:8200/v1", "http://192.168.1.10:8200/v1",
    "http://host.docker.internal:8200/v1", "http://0.0.0.0:8200/v1",
    "http://localhost/v1", "http://localhost:/v1", "http://localhost:invalid/v1",
    "http://localhost:0/v1", "http://localhost:-1/v1", "http://localhost:65536/v1",
    "http://user:password@localhost:8200/v1", "http://user@localhost:8200/v1",
    "http://@localhost:8200/v1", "http://localhost:8200/v1?command=start",
    "http://localhost:8200/v1#fragment", "https://localhost:8200/v1",
    "ftp://localhost:8200/v1", "http://localhost:8200/other",
], ids=["remote", "private-remote", "docker-host", "all-interfaces", "missing-port", "empty-port",
        "invalid-port", "zero-port", "negative-port", "overflow-port", "credentials", "username",
        "empty-userinfo", "query", "fragment", "https", "ftp", "wrong-path"])
def test_local_vllm_rejects_unsafe_provider_url(local_config, url):
    local_config["providers"]["local-vllm"].update(base_url=url, type="local")
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


def test_local_vllm_rejects_cloud_type_even_on_loopback(local_config):
    local_config["providers"]["local-vllm"]["type"] = "cloud"
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


def test_local_vllm_rejects_remote_selected_provider(local_config):
    local_config["local_vllm"]["provider"] = "deepseek"
    local_config["models"]["deepseek-chat"]["upstream"] = "qwen3-1.7b"
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


def test_local_vllm_rejects_missing_provider(local_config):
    local_config["local_vllm"]["provider"] = "missing-provider"
    with pytest.raises(ConfigError, match="local_vllm.provider"):
        parse_config(local_config)


@pytest.mark.parametrize("field,value", [("upstream", "another-model"),
                                         ("upstream", "Qwen3-1.7B"), ("provider", "deepseek")])
def test_local_vllm_requires_matching_provider_and_upstream_model(local_config, field, value):
    local_config["models"]["qwen3-1.7b"][field] = value
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


def test_local_vllm_requires_at_least_one_model_mapping(local_config):
    for section in ("models", "aliases", "fallbacks"):
        local_config[section] = {}
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.9", "example.com"])
def test_local_vllm_rejects_non_loopback_gateway(local_config, host):
    local_config["server"]["host"] = host
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


UNSAFE_PATHS = ["opt/relative", "./start.sh", "../model", "/",
                "/opt/../tmp/model", "C:\\models\\Qwen", "/opt/model\\child"]


@pytest.mark.parametrize("path", UNSAFE_PATHS)
def test_local_vllm_requires_safe_absolute_start_script(local_config, path):
    local_config["local_vllm"]["start_script"] = path
    with pytest.raises(ConfigError, match="start_script"):
        parse_config(local_config)


@pytest.mark.parametrize("path", UNSAFE_PATHS)
def test_local_vllm_requires_safe_absolute_model_paths(local_config, path):
    local_config["local_vllm"]["models"] = [path]
    with pytest.raises(ConfigError, match="local_vllm.models"):
        parse_config(local_config)


@pytest.mark.parametrize("field", ["provider", "wsl_distro", "start_script", "models"])
@pytest.mark.parametrize("control", ["\x00", "\t", "\n", "\r", "\x1f", "\x7f"],
                         ids=["nul", "tab", "newline", "return", "unit-separator", "delete"])
def test_local_vllm_rejects_control_characters(local_config, field, control):
    # 保持交叉映射一致，避免不存在的 provider 或模型掩盖控制字符校验漏洞。
    value = ("/opt/unsafe" if field in ("start_script", "models") else "unsafe") + control + "name"
    if field == "models":
        local_config["local_vllm"]["models"] = [value]
    else:
        local_config["local_vllm"][field] = value
    if field == "provider":
        local_config["providers"][value] = local_config["providers"]["local-vllm"]
        local_config["models"]["qwen3-1.7b"]["provider"] = value
    with pytest.raises(ConfigError, match="local_vllm\\." + field):
        parse_config(local_config)


@pytest.mark.parametrize("control", ["\t", "\n", "\r"], ids=["tab", "newline", "return"])
def test_local_vllm_provider_url_must_not_strip_control_characters(local_config, control):
    local_config["providers"]["local-vllm"]["base_url"] = "http://local" + control + "host:8200/v1"
    with pytest.raises(ConfigError, match="local_vllm"):
        parse_config(local_config)


@pytest.mark.parametrize("field", ["provider", "wsl_distro"])
@pytest.mark.parametrize("value", ["", "   ", "--option"])
def test_local_vllm_rejects_empty_names_and_option_like_names(local_config, field, value):
    local_config["local_vllm"][field] = value
    with pytest.raises(ConfigError, match=field):
        parse_config(local_config)


def test_disabled_local_control_does_not_restrict_existing_remote_gateway(config_dict):
    config_dict["local_vllm"] = {"enabled": False, "provider": "deepseek"}
    config_dict["server"]["host"] = "0.0.0.0"
    cfg = parse_config(config_dict)
    assert cfg.local_vllm.enabled is False
    assert cfg.server.host == "0.0.0.0"
    assert cfg.providers["deepseek"].base_url == "https://api.deepseek.com/v1"


def test_local_vllm_accepts_multiple_candidates_with_default(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/Qwen3-1.7B-lab"]
    local_config["local_vllm"]["default"] = "qwen3-1.7b-lab"
    local_config["models"]["qwen3-1.7b-lab"] = {
        "provider": "local-vllm", "upstream": "qwen3-1.7b-lab"}
    cfg = parse_config(local_config)
    assert cfg.local_vllm.model_names == ["qwen3-1.7b", "qwen3-1.7b-lab"]
    assert cfg.local_vllm.default_name == "qwen3-1.7b-lab"


def test_local_vllm_default_falls_back_to_first_candidate(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/Qwen3-1.7B-lab"]
    local_config["models"]["qwen3-1.7b-lab"] = {
        "provider": "local-vllm", "upstream": "qwen3-1.7b-lab"}
    assert parse_config(local_config).local_vllm.default_name == "qwen3-1.7b"


def test_local_vllm_duplicate_candidate_names_rejected(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/qwen3-1.7b"]
    with pytest.raises(ConfigError, match="重复"):
        parse_config(local_config)


def test_local_vllm_rejects_unknown_default(local_config):
    local_config["local_vllm"]["default"] = "ghost"
    with pytest.raises(ConfigError, match="default"):
        parse_config(local_config)


def test_local_vllm_candidate_requires_upstream_mapping(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/Qwen3-1.7B-lab"]
    with pytest.raises(ConfigError, match="qwen3-1.7b-lab"):
        parse_config(local_config)


def test_local_vllm_candidate_mapping_must_use_configured_provider(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/Qwen3-1.7B-lab"]
    local_config["models"]["qwen3-1.7b-lab"] = {
        "provider": "deepseek", "upstream": "qwen3-1.7b-lab"}
    with pytest.raises(ConfigError, match="qwen3-1.7b-lab"):
        parse_config(local_config)


def test_local_vllm_candidate_mapping_must_match_candidate_name(local_config):
    local_config["local_vllm"]["models"] = ["/opt/models/Qwen3-1.7B",
                                             "/opt/models/Qwen3-1.7B-lab"]
    local_config["models"]["qwen3-1.7b-lab"] = {
        "provider": "local-vllm", "upstream": "Qwen3-1.7B-lab"}
    with pytest.raises(ConfigError, match="qwen3-1.7b-lab"):
        parse_config(local_config)


def test_local_vllm_empty_models_rejected(local_config):
    local_config["local_vllm"]["models"] = []
    with pytest.raises(ConfigError, match="local_vllm.models"):
        parse_config(local_config)