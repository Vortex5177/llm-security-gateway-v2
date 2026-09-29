"""Provider base_url 的 SSRF 校验（仅作用于看板 API 动态添加的 provider）。

边界：gateway.yaml 配置文件中的 provider 视为操作者可信输入，不校验；
本模块只拦"经网络可达入口新增的上游地址"。仅按字面 host 判定，
不做 DNS 解析（DNS rebinding 防护超出本地工具范围，README 威胁模型已声明）。
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

METADATA_HOSTS = {"metadata.google.internal"}
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local  # 169.254.0.0/16（含云元数据 169.254.169.254）
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _allowlisted(host: str, port: int | None, allow_hosts: list[str]) -> bool:
    for entry in allow_hosts:
        entry = entry.strip().lower()
        if not entry:
            continue
        if ":" in entry:
            # host:port 精确匹配
            eh, _, ep = entry.rpartition(":")
            if host == eh and port is not None and str(port) == ep:
                return True
        elif host == entry:
            return True
    return False


def validate_provider_base_url(base_url: str, allow_hosts: list[str]) -> str | None:
    """合法返回 None；非法返回面向用户的拒绝原因。"""
    try:
        url = urlparse(base_url)
        host = (url.hostname or "").lower().rstrip(".")
        port = url.port
    except ValueError:
        return "base_url 无法解析"
    if url.scheme not in ("http", "https"):
        return "base_url 仅允许 http/https 协议"
    if not host:
        return "base_url 缺少主机名"
    if url.username is not None or url.password is not None:
        return "base_url 不允许携带用户信息"
    if any(ord(c) < 32 or ord(c) == 127 for c in base_url):
        return "base_url 不允许包含控制字符"
    if _allowlisted(host, port, allow_hosts):
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _is_forbidden_ip(ip):
            return f"base_url 指向回环/内网/保留地址（{host}），如需放行请加入 security.ssrf.allow_hosts"
        return None
    if not HOSTNAME_RE.match(host):
        return "base_url 主机名含有非法字符"
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
        or host in METADATA_HOSTS
    ):
        return f"base_url 指向本机/内网主机名（{host}），如需放行请加入 security.ssrf.allow_hosts"
    return None
