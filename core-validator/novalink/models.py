"""
NovaLink Data Models & Validation Schemas
Supports Python 3.8+ (Windows 7 SP1 compatible) through Python 3.11+.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import uuid
import time
import hashlib
import json


SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
}
SUPPORTED_TRANSPORTS = {
    "tcp",
    "ws",
    "grpc",
    "httpupgrade",
    "splithttp",
    "xhttp",
    "kcp",
    "quic",
}
SUPPORTED_SECURITY = {"none", "tls", "reality"}
SUPPORTED_ROUTING_OUTBOUNDS = {"proxy", "direct", "block"}
SUPPORTED_ROUTING_TYPES = {"domain", "ip", "port", "protocol"}


@dataclass
class Profile:
    """Represents a validated proxy server profile."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Unnamed Server"
    protocol: str = "vless"          # vless, vmess, trojan, shadowsocks, socks, http, hysteria2, tuic, wireguard
    address: str = ""
    port: int = 443
    # Auth fields
    uuid_or_password: str = ""       # UUID for vless/vmess/tuic, password for trojan/ss/socks/http/hy2
    username: str = ""               # Optional username for socks/http
    alter_id: int = 0                # VMess alterId (0 for AEAD)
    cipher: str = "auto"             # VMess security or Shadowsocks method (e.g., aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-256-gcm)
    flow: str = ""                   # XTLS flow (e.g., xtls-rprx-vision)
    # Transport fields
    network: str = "tcp"             # tcp, ws, grpc, httpupgrade, splithttp, xhttp, kcp, quic
    header_type: str = "none"        # none, http, srtp, utp, wechat-video, dtls, wireguard
    host: str = ""                   # WS / HTTPUpgrade / TCP-HTTP / XHTTP host header
    path: str = ""                   # WS / HTTPUpgrade / XHTTP path or gRPC serviceName
    grpc_mode: str = "gun"           # gun, multi
    # TLS / REALITY fields
    security: str = "none"           # none, tls, reality
    sni: str = ""                    # Server Name Indication
    alpn: List[str] = field(default_factory=list)  # e.g., ["h2", "http/1.1"]
    fingerprint: str = "chrome"      # uTLS fingerprint
    allow_insecure: bool = False     # False by default per security rules
    pbk: str = ""                    # REALITY publicKey
    sid: str = ""                    # REALITY shortId
    spx: str = ""                    # REALITY spiderX
    # Metadata & Testing state
    group: str = "Default"
    subscription_id: str = "manual"  # "manual" or subscription UUID
    latency_ms: Optional[int] = None
    last_test_status: str = "Untested"  # Untested, OK, Timeout, Failed
    last_test_method: str = ""          # TCP, HTTP-Proxy, ICMP
    last_test_time: Optional[float] = None
    created_at: float = field(default_factory=time.time)

    def fingerprint_key(self) -> str:
        """
        Generates a deterministic deduplication hash based on canonical connection parameters
        (excluding mutable metadata like name, id, latency, or timestamps).
        """
        canonical = "|".join([
            self.protocol.lower().strip(),
            self.address.lower().strip(),
            str(int(self.port)),
            self.uuid_or_password.strip(),
            self.username.strip(),
            self.cipher.lower().strip(),
            self.flow.lower().strip(),
            self.network.lower().strip(),
            self.header_type.lower().strip(),
            self.host.lower().strip(),
            self.path.strip(),
            self.security.lower().strip(),
            self.sni.lower().strip(),
            ",".join(sorted(self.alpn)),
            self.pbk.strip(),
            self.sid.strip(),
        ])
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Profile":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        if "port" in filtered:
            filtered["port"] = int(filtered["port"])
        if "alpn" in filtered and isinstance(filtered["alpn"], str):
            filtered["alpn"] = [x.strip() for x in filtered["alpn"].split(",") if x.strip()]
        return cls(**filtered)


@dataclass
class Subscription:
    """Represents a remote profile subscription source."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Subscription"
    url: str = ""
    enabled: bool = True
    auto_update_interval_min: int = 360
    last_update_time: Optional[float] = None
    last_status: str = "Never Updated"
    last_error: str = ""
    profile_count: int = 0
    last_added_count: int = 0
    last_updated_count: int = 0
    last_duplicate_count: int = 0
    last_invalid_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Subscription":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class RoutingRule:
    """Represents an ordered routing rule translated directly into Xray-core routing.rules."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Rule"
    enabled: bool = True
    priority: int = 100
    rule_type: str = "domain"        # domain, ip, port, protocol
    match_expression: str = ""       # e.g., domain:example.com, geosite:ir, 192.168.0.0/16, 1.1.1.1/32
    outbound_tag: str = "direct"     # proxy, direct, block
    network_type: str = "tcp,udp"    # tcp, udp, tcp,udp
    dns_server_override: str = ""    # optional DNS server linked to this route

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RoutingRule":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        if "priority" in filtered:
            filtered["priority"] = int(filtered["priority"])
        return cls(**filtered)


@dataclass
class AppSettings:
    """Persistent application and engine settings."""
    language: str = "fa"             # "fa" (Persian RTL) or "en" (English LTR)
    theme: str = "dark"              # "dark" or "light"
    local_socks_port: int = 10808
    local_http_port: int = 10809
    enable_http_proxy: bool = True
    allow_lan: bool = False
    system_proxy_mode: str = "clear"  # "clear", "system_http", "pac"
    routing_domain_strategy: str = "IPIfNonMatch"  # AsIs, IPIfNonMatch, IPOnDemand
    primary_dns: str = "1.1.1.1"
    secondary_dns: str = "8.8.8.8"
    direct_dns: str = "223.5.5.5"
    enable_fake_dns: bool = False
    kill_switch_enabled: bool = False
    kill_switch_mode: str = "firewall_strict"  # "firewall_strict" or "system_proxy_guard"
    auto_start_windows: bool = False
    auto_update_subscriptions: bool = True
    subscription_concurrency: int = 3
    ping_concurrency: int = 10
    ping_timeout_ms: int = 3000
    ping_test_method: str = "tcp"    # "tcp" or "http_proxy"
    ping_test_url: str = "http://cp.cloudflare.com/generate_204"
    log_level: str = "warning"       # debug, info, warning, error, none
    enable_notifications: bool = True
    selected_profile_id: Optional[str] = None
    mux_enabled: bool = False
    mux_concurrency: int = 8

    def validate(self) -> List[str]:
        errors = []
        if not (1024 <= self.local_socks_port <= 65535):
            errors.append(f"Invalid SOCKS port: {self.local_socks_port} (must be 1024-65535)")
        if not (1024 <= self.local_http_port <= 65535):
            errors.append(f"Invalid HTTP port: {self.local_http_port} (must be 1024-65535)")
        if self.local_socks_port == self.local_http_port:
            errors.append("Local SOCKS port and HTTP port cannot be identical.")
        if self.language not in ("fa", "en"):
            errors.append(f"Unsupported language: {self.language}")
        if self.theme not in ("dark", "light"):
            errors.append(f"Unsupported theme: {self.theme}")
        if self.routing_domain_strategy not in ("AsIs", "IPIfNonMatch", "IPOnDemand"):
            errors.append(f"Invalid routing domainStrategy: {self.routing_domain_strategy}")
        if self.log_level not in ("debug", "info", "warning", "error", "none"):
            errors.append(f"Invalid log level: {self.log_level}")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppSettings":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)
