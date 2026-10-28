"""
NovaLink Protocol URI Parser, Validator & Subscription Decoder
Supports VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, Hysteria2, TUIC, and WireGuard URIs,
as well as Marzban / PasarGuard / Hiddify / X-UI / V2board subscription URLs (Base64, Plaintext, JSON, HTML-wrapped).
Performs strict parameter validation so unsupported or malformed profiles are rejected with human-readable errors.
"""

import base64
import json
import re
import urllib.parse
from typing import Tuple, Optional, List, Dict, Any
from .models import (
    Profile,
    SUPPORTED_PROTOCOLS,
    SUPPORTED_TRANSPORTS,
    SUPPORTED_SECURITY,
)


SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "plain",
}

SUPPORTED_VMESS_CIPHERS = {
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
    "none",
    "zero",
}

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
UUID_HEX32_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)


def normalize_uuid(raw_id: str) -> str:
    """Normalizes a 32-char hex string into standard 8-4-4-4-12 UUID format if applicable."""
    s = (raw_id or "").strip()
    if UUID_HEX32_REGEX.match(s):
        return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
    return s


def inspect_subscription_url(url: str) -> Dict[str, Any]:
    """
    Analyzes a subscription URL (including Marzban/PasarGuard v3 signed tokens such as
    https://link.ircdn.org/sub/djMsNDM2OSwxNzkyOTI3ODMw.cEBVg4Y9UKl5yqqZxKlUI3QDdoxVQ3xFVlzFHljiRM0)
    and extracts structural metadata without leaking secrets in logs.
    """
    info: Dict[str, Any] = {
        "valid_url": False,
        "scheme": "",
        "host": "",
        "path": "",
        "panel_type": "generic_sub",
        "token_version": None,
        "sub_user_id": None,
        "sub_timestamp": None,
        "hmac_signature_bytes": 0,
    }
    raw = (url or "").strip()
    if not raw:
        return info
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return info
    info["valid_url"] = True
    info["scheme"] = parsed.scheme.lower()
    info["host"] = parsed.hostname
    info["path"] = parsed.path

    if "/sub/" in parsed.path:
        token = parsed.path.split("/sub/", 1)[1].strip("/")
        if "." in token:
            p1, p2 = token.split(".", 1)
            try:
                dec1 = safe_b64decode(p1).decode("utf-8", errors="ignore")
                parts = dec1.split(",")
                if len(parts) >= 3 and parts[0].startswith("v"):
                    info["panel_type"] = "marzban_pasarguard_v3"
                    info["token_version"] = parts[0]
                    info["sub_user_id"] = int(parts[1])
                    info["sub_timestamp"] = int(parts[2])
                sig_bytes = safe_b64decode(p2)
                info["hmac_signature_bytes"] = len(sig_bytes)
            except Exception:
                pass
    return info


def is_valid_host_or_ip(address: str) -> bool:
    if not address or len(address.strip()) == 0:
        return False
    addr = address.strip()
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    if ":" in addr:
        parts = addr.split(":")
        return 2 <= len(parts) <= 8
    return bool(IPV4_REGEX.match(addr) or HOSTNAME_REGEX.match(addr))


def safe_b64decode(s: str) -> bytes:
    """Safely decodes URL-safe or standard Base64 with missing padding."""
    cleaned = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    return base64.b64decode(cleaned)


def validate_profile(profile: Profile) -> Tuple[bool, str]:
    """
    Validates a Profile against supported Xray-core capabilities.
    Returns (is_valid, human_readable_error_message).
    """
    proto = (profile.protocol or "").lower().strip()
    if proto not in SUPPORTED_PROTOCOLS:
        return False, f"Unsupported protocol '{profile.protocol}'. Supported: {', '.join(sorted(SUPPORTED_PROTOCOLS))}."

    if not is_valid_host_or_ip(profile.address):
        return False, f"Invalid server address or hostname: '{profile.address}'."

    try:
        port = int(profile.port)
    except (ValueError, TypeError):
        return False, f"Port must be an integer, got '{profile.port}'."
    if not (1 <= port <= 65535):
        return False, f"Port out of valid range (1-65535): {port}."

    net = (profile.network or "tcp").lower().strip()
    if net not in SUPPORTED_TRANSPORTS:
        return False, f"Unsupported transport '{profile.network}'. Supported: {', '.join(sorted(SUPPORTED_TRANSPORTS))}."

    sec = (profile.security or "none").lower().strip()
    if sec not in SUPPORTED_SECURITY:
        return False, f"Unsupported transport security '{profile.security}'. Supported: none, tls, reality."

    # Protocol-specific validation
    if proto in ("vless", "vmess"):
        uid = normalize_uuid(profile.uuid_or_password)
        profile.uuid_or_password = uid
        if not uid or not UUID_REGEX.match(uid):
            return False, f"{proto.upper()} requires a valid 36-character UUID."
        if proto == "vmess":
            cipher = (profile.cipher or "auto").lower().strip()
            if cipher not in SUPPORTED_VMESS_CIPHERS:
                return False, f"Unsupported VMess cipher '{profile.cipher}'."
            if sec == "reality":
                return False, "REALITY security is only supported with VLESS or Trojan, not VMess."

    elif proto in ("trojan", "hysteria2", "tuic", "wireguard"):
        if not profile.uuid_or_password or len(profile.uuid_or_password.strip()) == 0:
            return False, f"{proto.capitalize()} profile requires a non-empty password or key."

    elif proto == "shadowsocks":
        if not profile.uuid_or_password or len(profile.uuid_or_password.strip()) == 0:
            return False, "Shadowsocks profile requires a non-empty password/key."
        cipher = (profile.cipher or "").lower().strip()
        if cipher not in SUPPORTED_SS_CIPHERS:
            return (
                False,
                f"Unsupported or insecure legacy Shadowsocks cipher '{profile.cipher}'. "
                f"Xray-core requires AEAD or 2022 ciphers (e.g., aes-256-gcm, chacha20-ietf-poly1305).",
            )

    # REALITY specific checks
    if sec == "reality":
        if not profile.pbk or len(profile.pbk.strip()) < 20:
            return False, "REALITY security requires a valid public key ('pbk')."
        if not profile.sni or len(profile.sni.strip()) == 0:
            return False, "REALITY security requires a target Server Name Indication ('sni')."
        if net not in ("tcp", "grpc", "splithttp", "xhttp"):
            return False, f"REALITY security in Xray-core is designed for TCP, gRPC, or XHTTP transport, not '{net}'."

    # Flow checks
    if profile.flow:
        allowed_flows = {"xtls-rprx-vision", "xtls-rprx-vision-udp443", ""}
        if profile.flow not in allowed_flows:
            return False, f"Unsupported XTLS flow '{profile.flow}'. Only 'xtls-rprx-vision' is supported."
        if proto != "vless" or net != "tcp" or sec not in ("tls", "reality"):
            return False, "XTLS flow ('xtls-rprx-vision') requires VLESS over TCP with TLS or REALITY."

    return True, "OK"


def parse_profile_uri(uri: str, subscription_id: str = "manual") -> Tuple[Optional[Profile], Optional[str]]:
    """
    Parses a single proxy share URI (vless://, vmess://, trojan://, ss://, socks://, http://, hy2://, tuic://, wg://).
    Returns (Profile, None) on success or (None, error_message) on failure.
    """
    raw = (uri or "").strip().replace("&amp;", "&")
    if not raw:
        return None, "Empty URI."

    if "://" not in raw:
        return None, "Invalid URI format: missing scheme '://'."

    scheme, _ = raw.split("://", 1)
    scheme = scheme.lower().strip()

    try:
        if scheme == "vmess":
            return _parse_vmess_uri(raw, subscription_id)
        elif scheme == "vless":
            return _parse_vless_or_trojan_uri(raw, "vless", subscription_id)
        elif scheme == "trojan":
            return _parse_vless_or_trojan_uri(raw, "trojan", subscription_id)
        elif scheme in ("hysteria2", "hy2"):
            return _parse_vless_or_trojan_uri(raw, "hysteria2", subscription_id)
        elif scheme == "tuic":
            return _parse_vless_or_trojan_uri(raw, "tuic", subscription_id)
        elif scheme in ("wireguard", "wg"):
            return _parse_vless_or_trojan_uri(raw, "wireguard", subscription_id)
        elif scheme == "ss":
            return _parse_ss_uri(raw, subscription_id)
        elif scheme in ("socks", "socks5"):
            return _parse_socks_or_http_uri(raw, "socks", subscription_id)
        elif scheme in ("http", "https"):
            return _parse_socks_or_http_uri(raw, "http", subscription_id)
        else:
            return None, f"Unsupported URI scheme '{scheme}://'."
    except Exception as exc:
        return None, f"Failed to parse {scheme}:// URI: {str(exc)}"


def _parse_vmess_uri(raw: str, subscription_id: str) -> Tuple[Optional[Profile], Optional[str]]:
    b64_part = raw[len("vmess://"):].strip()
    # Support URL-style vmess://uuid@host:port?...#name if '@' is present before '?'
    if "@" in b64_part.split("?", 1)[0]:
        return _parse_vless_or_trojan_uri("vless://" + b64_part, "vmess", subscription_id)

    frag_override = ""
    if "#" in b64_part:
        b64_part, frag_override = b64_part.split("#", 1)
        frag_override = urllib.parse.unquote(frag_override).strip()

    try:
        decoded = safe_b64decode(b64_part).decode("utf-8", errors="replace")
        data = json.loads(decoded)
    except Exception as exc:
        return None, f"Invalid VMess Base64/JSON payload: {exc}"

    if not isinstance(data, dict):
        return None, "VMess payload is not a JSON object."

    address = str(data.get("add", "")).strip()
    try:
        port = int(data.get("port", 0))
    except (ValueError, TypeError):
        return None, f"Invalid port in VMess JSON: {data.get('port')}"

    uuid_val = normalize_uuid(str(data.get("id", "")).strip())
    name = frag_override or str(data.get("ps", "")).strip() or f"VMess-{address}:{port}"
    aid = int(data.get("aid", 0) or 0)
    scy = str(data.get("scy", "auto") or "auto").strip()
    net = str(data.get("net", "tcp") or "tcp").lower().strip()
    if net == "h2":
        return None, "Unsupported transport 'h2' in VMess URI."
    header_type = str(data.get("type", "none") or "none").lower().strip()
    host = str(data.get("host", "") or "").strip()
    path = str(data.get("path", "") or "").strip()
    tls_field = str(data.get("tls", "") or "").lower().strip()
    security = "tls" if tls_field == "tls" else "none"
    sni = str(data.get("sni", "") or host or "").strip()
    alpn_raw = str(data.get("alpn", "") or "").strip()
    alpn = [x.strip() for x in alpn_raw.split(",") if x.strip()]
    fp = str(data.get("fp", "chrome") or "chrome").strip()

    prof = Profile(
        name=name,
        protocol="vmess",
        address=address,
        port=port,
        uuid_or_password=uuid_val,
        alter_id=aid,
        cipher=scy,
        network=net,
        header_type=header_type,
        host=host,
        path=path,
        security=security,
        sni=sni,
        alpn=alpn,
        fingerprint=fp,
        subscription_id=subscription_id,
    )
    ok, err = validate_profile(prof)
    if not ok:
        return None, err
    return prof, None


def _parse_vless_or_trojan_uri(
    raw: str, proto: str, subscription_id: str
) -> Tuple[Optional[Profile], Optional[str]]:
    parsed = urllib.parse.urlsplit(raw)
    uuid_or_pw = urllib.parse.unquote(parsed.username or "").strip()
    if parsed.password:
        uuid_or_pw = f"{uuid_or_pw}:{urllib.parse.unquote(parsed.password)}"
    if not uuid_or_pw and proto == "wireguard":
        qs_tmp = urllib.parse.parse_qs(parsed.query)
        uuid_or_pw = (qs_tmp.get("privateKey") or qs_tmp.get("secretKey") or ["wg-key"])[0]
    if proto in ("vless", "vmess"):
        uuid_or_pw = normalize_uuid(uuid_or_pw)

    address = (parsed.hostname or "").strip()
    try:
        port = parsed.port or 443
    except ValueError:
        return None, "Invalid port in URI."

    qs = urllib.parse.parse_qs(parsed.query)
    def qget(key: str, default: str = "") -> str:
        vals = qs.get(key)
        return vals[0].strip() if vals else default

    name = urllib.parse.unquote(parsed.fragment or "").strip() or f"{proto.upper()}-{address}:{port}"
    net = qget("type", "tcp").lower()
    if net in ("http", "h2"):
        net = "httpupgrade"
    security = qget("security", "tls" if proto in ("trojan", "hysteria2", "tuic") else "none").lower()
    sni = qget("sni", qget("peer", ""))
    host = qget("host", qget("obfsParam", ""))
    path = qget("path", qget("serviceName", ""))
    header_type = qget("headerType", "none").lower()
    flow = qget("flow", "")
    fp = qget("fp", "chrome")
    pbk = qget("pbk", "")
    sid = qget("sid", "")
    spx = qget("spx", "")
    grpc_mode = qget("mode", "gun")
    alpn_str = qget("alpn", "")
    alpn = [x.strip() for x in alpn_str.split(",") if x.strip()]
    allow_insecure = qget("allowInsecure", qget("insecure", "0")) in ("1", "true")

    prof = Profile(
        name=name,
        protocol=proto,
        address=address,
        port=port,
        uuid_or_password=uuid_or_pw,
        flow=flow,
        network=net,
        header_type=header_type,
        host=host,
        path=path,
        grpc_mode=grpc_mode,
        security=security,
        sni=sni,
        alpn=alpn,
        fingerprint=fp,
        allow_insecure=allow_insecure,
        pbk=pbk,
        sid=sid,
        spx=spx,
        subscription_id=subscription_id,
    )
    ok, err = validate_profile(prof)
    if not ok:
        return None, err
    return prof, None


def _parse_ss_uri(raw: str, subscription_id: str) -> Tuple[Optional[Profile], Optional[str]]:
    body = raw[len("ss://"):].strip()
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
        fragment = urllib.parse.unquote(fragment).strip()

    query_str = ""
    if "?" in body:
        body, query_str = body.split("?", 1)

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            try:
                userinfo = safe_b64decode(userinfo).decode("utf-8")
            except Exception as exc:
                return None, f"Invalid Base64 userinfo in ss:// URI: {exc}"
    else:
        try:
            decoded_full = safe_b64decode(body).decode("utf-8")
        except Exception as exc:
            return None, f"Invalid Base64 in ss:// URI: {exc}"
        if "@" not in decoded_full:
            return None, "Malformed ss:// URI: missing '@' separator."
        userinfo, hostport = decoded_full.rsplit("@", 1)

    if ":" not in userinfo:
        return None, "Malformed ss:// userinfo: missing 'method:password'."
    method, password = userinfo.split(":", 1)
    method = urllib.parse.unquote(method).strip()
    password = urllib.parse.unquote(password).strip()

    parsed_hp = urllib.parse.urlsplit("http://" + hostport)
    address = (parsed_hp.hostname or "").strip()
    try:
        port = parsed_hp.port or 0
    except ValueError:
        return None, "Invalid port in ss:// URI."

    name = fragment or f"SS-{address}:{port}"
    prof = Profile(
        name=name,
        protocol="shadowsocks",
        address=address,
        port=port,
        uuid_or_password=password,
        cipher=method,
        network="tcp",
        security="none",
        subscription_id=subscription_id,
    )
    ok, err = validate_profile(prof)
    if not ok:
        return None, err
    return prof, None


def _parse_socks_or_http_uri(
    raw: str, proto: str, subscription_id: str
) -> Tuple[Optional[Profile], Optional[str]]:
    parsed = urllib.parse.urlsplit(raw)
    address = (parsed.hostname or "").strip()
    try:
        port = parsed.port or (1080 if proto == "socks" else 8080)
    except ValueError:
        return None, f"Invalid port in {proto}:// URI."

    username = urllib.parse.unquote(parsed.username or "").strip()
    password = urllib.parse.unquote(parsed.password or "").strip()
    if username and not password and ":" not in username:
        try:
            dec_auth = safe_b64decode(username).decode("utf-8")
            if ":" in dec_auth:
                username, password = dec_auth.split(":", 1)
        except Exception:
            pass
    name = urllib.parse.unquote(parsed.fragment or "").strip() or f"{proto.upper()}-{address}:{port}"
    security = "tls" if raw.lower().startswith("https://") else "none"

    prof = Profile(
        name=name,
        protocol=proto,
        address=address,
        port=port,
        username=username,
        uuid_or_password=password,
        network="tcp",
        security=security,
        subscription_id=subscription_id,
    )
    ok, err = validate_profile(prof)
    if not ok:
        return None, err
    return prof, None


def export_profile_uri(profile: Profile, redact_secrets: bool = False) -> str:
    """
    Exports a Profile to a standard shareable URI.
    If redact_secrets=True, masks UUIDs/passwords for safe diagnostic sharing.
    """
    secret = "***REDACTED***" if redact_secrets else profile.uuid_or_password
    proto = profile.protocol.lower()
    tag = urllib.parse.quote(profile.name)

    if proto == "vmess":
        payload = {
            "v": "2",
            "ps": profile.name,
            "add": profile.address,
            "port": str(profile.port),
            "id": secret,
            "aid": str(profile.alter_id),
            "scy": profile.cipher,
            "net": profile.network,
            "type": profile.header_type,
            "host": profile.host,
            "path": profile.path,
            "tls": "tls" if profile.security == "tls" else "",
            "sni": profile.sni,
            "alpn": ",".join(profile.alpn),
            "fp": profile.fingerprint,
        }
        encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded}"

    elif proto in ("vless", "trojan"):
        params: Dict[str, str] = {"type": profile.network, "security": profile.security}
        if profile.header_type and profile.header_type != "none":
            params["headerType"] = profile.header_type
        if profile.sni:
            params["sni"] = profile.sni
        if profile.host:
            params["host"] = profile.host
        if profile.path:
            params["path"] = profile.path
        if profile.flow:
            params["flow"] = profile.flow
        if profile.fingerprint:
            params["fp"] = profile.fingerprint
        if profile.alpn:
            params["alpn"] = ",".join(profile.alpn)
        if profile.security == "reality":
            params["pbk"] = "***REDACTED***" if redact_secrets else profile.pbk
            if profile.sid:
                params["sid"] = profile.sid
            if profile.spx:
                params["spx"] = profile.spx
        qs = urllib.parse.urlencode(params)
        return f"{proto}://{urllib.parse.quote(secret)}@{profile.address}:{profile.port}?{qs}#{tag}"

    elif proto == "shadowsocks":
        userinfo = f"{profile.cipher}:{secret}"
        b64_user = base64.urlsafe_b64encode(userinfo.encode("utf-8")).decode("utf-8").rstrip("=")
        return f"ss://{b64_user}@{profile.address}:{profile.port}#{tag}"

    else:
        auth = ""
        if profile.username or secret:
            auth = f"{urllib.parse.quote(profile.username)}:{urllib.parse.quote(secret)}@"
        return f"{proto}://{auth}{profile.address}:{profile.port}#{tag}"


def _parse_xray_json_outbound(outbound: Dict[str, Any], remark: str, subscription_id: str) -> Optional[Profile]:
    """Extracts a Profile from a raw Xray/V2Ray JSON outbound object (used by JSON subscriptions)."""
    proto = str(outbound.get("protocol", "")).lower().strip()
    if proto not in ("vless", "vmess", "trojan", "shadowsocks", "socks", "http"):
        return None
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    net = str(stream.get("network", "tcp")).lower().strip()
    sec = str(stream.get("security", "none")).lower().strip()

    address = ""
    port = 443
    secret = ""
    cipher = "auto"
    flow = ""

    if proto in ("vless", "vmess"):
        vnext = settings.get("vnext") or []
        if not vnext:
            return None
        vn = vnext[0]
        address = str(vn.get("address", "")).strip()
        port = int(vn.get("port", 443))
        users = vn.get("users") or []
        if users:
            u0 = users[0]
            secret = str(u0.get("id", "")).strip()
            flow = str(u0.get("flow", "")).strip()
            cipher = str(u0.get("security", "auto")).strip()
    else:
        servers = settings.get("servers") or []
        if not servers:
            return None
        sv = servers[0]
        address = str(sv.get("address", "")).strip()
        port = int(sv.get("port", 443))
        secret = str(sv.get("password", "")).strip()
        cipher = str(sv.get("method", "aes-256-gcm")).strip()

    sni = ""
    pbk = ""
    sid = ""
    fp = "chrome"
    if sec == "tls":
        ts = stream.get("tlsSettings") or {}
        sni = str(ts.get("serverName", "")).strip()
        fp = str(ts.get("fingerprint", "chrome")).strip()
    elif sec == "reality":
        rs = stream.get("realitySettings") or {}
        sni = str(rs.get("serverName", "")).strip()
        pbk = str(rs.get("publicKey", "")).strip()
        sid = str(rs.get("shortId", "")).strip()
        fp = str(rs.get("fingerprint", "chrome")).strip()

    host = ""
    path = ""
    header_type = "none"
    if net == "ws":
        ws = stream.get("wsSettings") or {}
        path = str(ws.get("path", "/")).strip()
        headers = ws.get("headers") or {}
        host = str(headers.get("Host", "") or headers.get("host", "")).strip()
    elif net == "grpc":
        gr = stream.get("grpcSettings") or {}
        path = str(gr.get("serviceName", "")).strip()
    elif net == "tcp":
        tc = stream.get("tcpSettings") or {}
        hdr = tc.get("header") or {}
        header_type = str(hdr.get("type", "none")).lower().strip()

    prof = Profile(
        name=remark or f"{proto.upper()}-{address}:{port}",
        protocol=proto,
        address=address,
        port=port,
        uuid_or_password=secret,
        cipher=cipher,
        flow=flow,
        network=net,
        header_type=header_type,
        host=host,
        path=path,
        security=sec,
        sni=sni,
        fingerprint=fp,
        pbk=pbk,
        sid=sid,
        subscription_id=subscription_id,
    )
    ok, _ = validate_profile(prof)
    return prof if ok else None


def decode_subscription_content(
    raw_text: str, subscription_id: str = "sub"
) -> Tuple[List[Profile], List[str]]:
    """
    Parses a subscription response payload (supports Base64-encoded URI lists, URL-safe Base64,
    plain-text URI lists, Xray JSON outbound arrays, and HTML-embedded share links).
    Returns (valid_profiles, error_messages).
    """
    text = (raw_text or "").strip()
    if not text:
        return [], ["Empty subscription payload."]

    # 1. Check if JSON array/object (NovaLink profiles OR Xray raw configs)
    if text.startswith("{") or text.startswith("["):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if "profiles" in obj:
                    obj = obj["profiles"]
                elif "outbounds" in obj:
                    obj = [obj]
            if isinstance(obj, list):
                valid: List[Profile] = []
                errors: List[str] = []
                for idx, item in enumerate(obj):
                    if isinstance(item, dict):
                        if "outbounds" in item and isinstance(item["outbounds"], list):
                            rem = str(item.get("remarks", "") or item.get("name", f"Xray-JSON-{idx+1}"))
                            for ob in item["outbounds"]:
                                if isinstance(ob, dict):
                                    p_ob = _parse_xray_json_json_item(ob, rem, subscription_id)
                                    if p_ob:
                                        valid.append(p_ob)
                        else:
                            prof = Profile.from_dict(item)
                            prof.subscription_id = subscription_id
                            ok, err = validate_profile(prof)
                            if ok:
                                valid.append(prof)
                            else:
                                errors.append(f"JSON item #{idx + 1}: {err}")
                return valid, errors
        except Exception:
            pass

    # 2. If HTML page (e.g., Marzban/PasarGuard web template), extract embedded share URIs
    if "<html" in text.lower() or "<!doctype html" in text.lower():
        embedded_uris = re.findall(
            r"(?:vless|vmess|trojan|ss|socks5?|hy2|hysteria2|tuic|wg|wireguard)://[^\s\"'<>]+",
            text,
            flags=re.IGNORECASE,
        )
        if embedded_uris:
            text = "\n".join(embedded_uris)

    # 3. Try Base64 decoding if no scheme is directly visible
    if "://" not in text:
        try:
            decoded = safe_b64decode(text).decode("utf-8", errors="replace")
            if "://" in decoded:
                text = decoded
        except Exception as exc:
            return [], [f"Subscription content is neither valid URI list nor valid Base64 ({exc})."]

    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    valid_profiles: List[Profile] = []
    errors_list: List[str] = []

    for idx, line in enumerate(lines):
        prof, err = parse_profile_uri(line, subscription_id=subscription_id)
        if prof is not None:
            valid_profiles.append(prof)
        else:
            errors_list.append(f"Line #{idx + 1}: {err}")

    return valid_profiles, errors_list


def _parse_xray_json_json_item(ob: Dict[str, Any], rem: str, subscription_id: str) -> Optional[Profile]:
    return _parse_xray_json_outbound(ob, rem, subscription_id)
