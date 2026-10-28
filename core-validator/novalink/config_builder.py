"""
NovaLink Xray-core Configuration Builder
Translates validated Profile, AppSettings, and ordered RoutingRule objects into a complete,
standards-compliant Xray-core JSON configuration.
"""

from typing import List, Dict, Any, Tuple
import ipaddress
import re
from .models import Profile, AppSettings, RoutingRule
from .parser import validate_profile


DOMAIN_RULE_PREFIXES = ("domain:", "full:", "keyword:", "regexp:", "geosite:", "ext:")


def validate_routing_rule(rule: RoutingRule) -> Tuple[bool, str]:
    """Validates a single user routing rule before applying it to Xray-core."""
    if rule.outbound_tag not in ("proxy", "direct", "block"):
        return False, f"Rule '{rule.name}': Invalid outbound '{rule.outbound_tag}'."

    rtype = (rule.rule_type or "").lower().strip()
    expr = (rule.match_expression or "").strip()
    if not expr:
        return False, f"Rule '{rule.name}': Empty match expression."

    tokens = [t.strip() for t in expr.split(",") if t.strip()]
    if not tokens:
        return False, f"Rule '{rule.name}': No valid match tokens found."

    if rtype == "ip":
        for tok in tokens:
            if tok.startswith("geoip:") or tok.startswith("ext:"):
                if len(tok.split(":", 1)[1].strip()) == 0:
                    return False, f"Rule '{rule.name}': Empty geoip tag '{tok}'."
                continue
            try:
                if "/" in tok:
                    ipaddress.ip_network(tok, strict=False)
                else:
                    ipaddress.ip_address(tok)
            except ValueError:
                return False, f"Rule '{rule.name}': Invalid IP or CIDR '{tok}'."

    elif rtype == "domain":
        for tok in tokens:
            if any(tok.startswith(p) for p in DOMAIN_RULE_PREFIXES):
                val = tok.split(":", 1)[1].strip()
                if not val:
                    return False, f"Rule '{rule.name}': Empty domain expression '{tok}'."
            else:
                if " " in tok or "/" in tok:
                    return False, f"Rule '{rule.name}': Invalid domain pattern '{tok}'."

    elif rtype == "port":
        for tok in tokens:
            if "-" in tok:
                parts = tok.split("-", 1)
                try:
                    p1, p2 = int(parts[0]), int(parts[1])
                    if not (1 <= p1 <= p2 <= 65535):
                        return False, f"Rule '{rule.name}': Invalid port range '{tok}'."
                except ValueError:
                    return False, f"Rule '{rule.name}': Non-numeric port range '{tok}'."
            else:
                try:
                    p = int(tok)
                    if not (1 <= p <= 65535):
                        return False, f"Rule '{rule.name}': Port out of range '{tok}'."
                except ValueError:
                    return False, f"Rule '{rule.name}': Invalid port '{tok}'."

    elif rtype == "protocol":
        allowed_protos = {"http", "tls", "bittorrent"}
        for tok in tokens:
            if tok.lower() not in allowed_protos:
                return False, f"Rule '{rule.name}': Unsupported protocol sniff token '{tok}' (use http, tls, bittorrent)."
    else:
        return False, f"Rule '{rule.name}': Unknown rule_type '{rtype}'."

    return True, "OK"


def build_xray_config(
    profile: Profile,
    settings: AppSettings,
    routing_rules: List[RoutingRule],
) -> Dict[str, Any]:
    """
    Constructs a full Xray-core configuration dictionary.
    Raises ValueError if the profile, settings, or active routing rules fail validation.
    """
    ok, err = validate_profile(profile)
    if not ok:
        raise ValueError(f"Profile validation failed: {err}")

    setting_errors = settings.validate()
    if setting_errors:
        raise ValueError("Settings validation failed: " + "; ".join(setting_errors))

    listen_ip = "0.0.0.0" if settings.allow_lan else "127.0.0.1"

    # 1. Log configuration
    log_config = {
        "loglevel": settings.log_level,
        "dnsLog": settings.log_level == "debug",
    }

    # 2. Inbounds (Local SOCKS5 + optional Local HTTP)
    inbounds: List[Dict[str, Any]] = [
        {
            "tag": "socks-in",
            "port": settings.local_socks_port,
            "listen": listen_ip,
            "protocol": "socks",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "fakedns"] if settings.enable_fake_dns else ["http", "tls"],
                "routeOnly": False,
            },
            "settings": {
                "auth": "noauth",
                "udp": True,
                "allowTransparent": False,
            },
        }
    ]

    if settings.enable_http_proxy:
        inbounds.append(
            {
                "tag": "http-in",
                "port": settings.local_http_port,
                "listen": listen_ip,
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
                "settings": {
                    "allowTransparent": False,
                },
            }
        )

    # 3. Primary Proxy Outbound
    proxy_outbound = _build_proxy_outbound(profile, settings)

    outbounds: List[Dict[str, Any]] = [
        proxy_outbound,
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
        },
        {
            "tag": "dns-out",
            "protocol": "dns",
        },
    ]

    # 4. DNS & Routing Configuration
    dns_servers: List[Any] = []
    xray_rules: List[Dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["socks-in", "http-in"] if settings.enable_http_proxy else ["socks-in"],
            "port": 53,
            "outboundTag": "dns-out",
        }
    ]

    # Sort user routing rules by priority ascending
    sorted_rules = sorted(routing_rules, key=lambda r: r.priority)
    direct_domains: List[str] = []
    proxy_domains: List[str] = []

    for rule in sorted_rules:
        if not rule.enabled:
            continue
        valid, r_err = validate_routing_rule(rule)
        if not valid:
            raise ValueError(r_err)

        tokens = [t.strip() for t in rule.match_expression.split(",") if t.strip()]
        rule_obj: Dict[str, Any] = {
            "type": "field",
            "outboundTag": rule.outbound_tag,
        }
        if rule.network_type and rule.network_type != "tcp,udp":
            rule_obj["network"] = rule.network_type

        rtype = rule.rule_type.lower().strip()
        if rtype == "domain":
            rule_obj["domain"] = tokens
            if rule.outbound_tag == "direct":
                direct_domains.extend(tokens)
            elif rule.outbound_tag == "proxy":
                proxy_domains.extend(tokens)
            if rule.dns_server_override:
                dns_servers.append({
                    "address": rule.dns_server_override.strip(),
                    "domains": tokens,
                })
        elif rtype == "ip":
            rule_obj["ip"] = tokens
        elif rtype == "port":
            rule_obj["port"] = ",".join(tokens)
        elif rtype == "protocol":
            rule_obj["protocol"] = [t.lower() for t in tokens]

        xray_rules.append(rule_obj)

    # Assemble DNS servers list
    if direct_domains and settings.direct_dns:
        dns_servers.append({
            "address": settings.direct_dns,
            "domains": direct_domains,
            "expectIPs": [],
        })
    if proxy_domains and settings.primary_dns:
        dns_servers.append({
            "address": settings.primary_dns,
            "domains": proxy_domains,
        })
    if settings.primary_dns:
        dns_servers.append(settings.primary_dns)
    if settings.secondary_dns and settings.secondary_dns != settings.primary_dns:
        dns_servers.append(settings.secondary_dns)

    dns_config: Dict[str, Any] = {
        "servers": dns_servers,
        "queryStrategy": "UseIPv4",
    }

    routing_config: Dict[str, Any] = {
        "domainStrategy": settings.routing_domain_strategy,
        "rules": xray_rules,
    }

    return {
        "log": log_config,
        "dns": dns_config,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing_config,
        "stats": {},
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
    }


def _build_proxy_outbound(profile: Profile, settings: AppSettings) -> Dict[str, Any]:
    proto = profile.protocol.lower().strip()
    outbound: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": proto,
        "settings": {},
        "streamSettings": _build_stream_settings(profile),
    }

    if proto == "vless":
        user_obj: Dict[str, Any] = {
            "id": profile.uuid_or_password,
            "encryption": "none",
        }
        if profile.flow:
            user_obj["flow"] = profile.flow
        outbound["settings"] = {
            "vnext": [
                {
                    "address": profile.address,
                    "port": int(profile.port),
                    "users": [user_obj],
                }
            ]
        }

    elif proto == "vmess":
        outbound["settings"] = {
            "vnext": [
                {
                    "address": profile.address,
                    "port": int(profile.port),
                    "users": [
                        {
                            "id": profile.uuid_or_password,
                            "alterId": int(profile.alter_id),
                            "security": profile.cipher or "auto",
                        }
                    ],
                }
            ]
        }

    elif proto in ("trojan", "hysteria2", "tuic", "wireguard"):
        outbound["settings"] = {
            "servers": [
                {
                    "address": profile.address,
                    "port": int(profile.port),
                    "password": profile.uuid_or_password,
                }
            ]
        }

    elif proto == "shadowsocks":
        outbound["settings"] = {
            "servers": [
                {
                    "address": profile.address,
                    "port": int(profile.port),
                    "method": profile.cipher,
                    "password": profile.uuid_or_password,
                    "uot": True,
                }
            ]
        }

    elif proto in ("socks", "http"):
        server_entry: Dict[str, Any] = {
            "address": profile.address,
            "port": int(profile.port),
        }
        if profile.username or profile.uuid_or_password:
            server_entry["users"] = [
                {
                    "user": profile.username,
                    "pass": profile.uuid_or_password,
                }
            ]
        outbound["settings"] = {"servers": [server_entry]}

    # Mux only if enabled and not using XTLS vision flow
    if settings.mux_enabled and not profile.flow:
        outbound["mux"] = {
            "enabled": True,
            "concurrency": settings.mux_concurrency,
        }

    return outbound


def _build_stream_settings(profile: Profile) -> Dict[str, Any]:
    net = (profile.network or "tcp").lower().strip()
    sec = (profile.security or "none").lower().strip()

    stream: Dict[str, Any] = {
        "network": net,
        "security": sec,
    }

    # Transport-specific settings
    if net == "tcp":
        if profile.header_type == "http":
            hosts = [h.strip() for h in (profile.host or "").split(",") if h.strip()]
            paths = [p.strip() for p in (profile.path or "/").split(",") if p.strip()] or ["/"]
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": paths,
                        "headers": {
                            "Host": hosts,
                            "User-Agent": [
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                            ],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                            "Pragma": "no-cache",
                        },
                    },
                }
            }
    elif net == "ws":
        ws_headers: Dict[str, str] = {}
        if profile.host:
            ws_headers["Host"] = profile.host
        stream["wsSettings"] = {
            "path": profile.path or "/",
            "headers": ws_headers,
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": profile.path or "",
            "multiMode": profile.grpc_mode == "multi",
            "idle_timeout": 60,
            "health_check_timeout": 20,
        }
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": profile.path or "/",
            "host": profile.host or profile.sni or profile.address,
        }
    elif net in ("splithttp", "xhttp"):
        x_host = profile.host or profile.sni or profile.address
        x_mode = profile.grpc_mode if profile.grpc_mode in ("packet-up", "stream-up", "stream-one", "auto") else "packet-up"
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {
            "path": profile.path or "/",
            "host": x_host,
            "mode": x_mode,
            "headers": {"Host": x_host},
        }
    elif net == "kcp":
        stream["kcpSettings"] = {
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "congestion": False,
            "header": {"type": profile.header_type or "none"},
        }
    elif net == "quic":
        stream["quicSettings"] = {
            "security": "none",
            "key": "",
            "header": {"type": profile.header_type or "none"},
        }

    # Security-specific settings
    if sec == "tls":
        tls_settings: Dict[str, Any] = {
            "serverName": profile.sni or profile.host or profile.address,
            "allowInsecure": bool(profile.allow_insecure),
            "fingerprint": profile.fingerprint or "chrome",
        }
        if profile.alpn:
            tls_settings["alpn"] = profile.alpn
        stream["tlsSettings"] = tls_settings

    elif sec == "reality":
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": profile.fingerprint or "chrome",
            "serverName": profile.sni,
            "publicKey": profile.pbk,
            "shortId": profile.sid or "",
            "spiderX": profile.spx or "/",
        }

    return stream
