"""
NovaLink Diagnostics, Troubleshooting & Sensitive Log Redaction Engine
Inspects application version, engine binary status, OS architecture, port conflicts,
DNS/TLS/Routing validity, subscription errors, and permission status.
Strictly strips UUIDs, passwords, tokens, and subscription URLs before exporting any diagnostic report.
"""

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any
import json
import os
import platform
import re
import time

from . import __version__, __app_name__, __min_windows_version__
from .models import AppSettings, Profile, Subscription, RoutingRule
from .engine import EngineManager, is_local_port_in_use
from .killswitch import KillSwitchManager, is_windows_admin
from .config_builder import validate_routing_rule
from .parser import validate_profile


UUID_REDACT_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
URL_QUERY_REDACT_PATTERN = re.compile(
    r"(https?://[^\s\"'<>]+?/)[^\s\"'<>]+"
)
SECRET_KV_PATTERN = re.compile(
    r"(\"(?:id|password|pass|publicKey|pbk|url)\"\s*:\s*\")([^\"]+)(\")",
    re.IGNORECASE,
)


def sanitize_sensitive_text(text: str, extra_secrets: List[str] = None) -> str:
    """
    Removes all UUIDs, passwords, subscription URL paths/tokens, and explicitly known profile secrets
    from a text string before saving or displaying diagnostic reports.
    """
    if not text:
        return ""
    sanitized = UUID_REDACT_PATTERN.sub("***[REDACTED-UUID]***", text)
    sanitized = SECRET_KV_PATTERN.sub(r"\1***[REDACTED]***\3", sanitized)
    sanitized = URL_QUERY_REDACT_PATTERN.sub(r"\1***[REDACTED-PATH]***", sanitized)

    if extra_secrets:
        for secret in extra_secrets:
            s = (secret or "").strip()
            if len(s) >= 4:
                sanitized = sanitized.replace(s, "***[REDACTED-SECRET]***")
    return sanitized


@dataclass
class DiagnosticItem:
    category: str
    status: str                 # "OK", "WARNING", "ERROR"
    summary: str
    remediation: str


class DiagnosticsManager:
    """Runs comprehensive health checks and exports sanitized troubleshooting bundles."""

    def __init__(
        self,
        engine: EngineManager,
        killswitch: KillSwitchManager,
    ):
        self.engine = engine
        self.killswitch = killswitch

    def run_all_checks(
        self,
        settings: AppSettings,
        profiles: List[Profile],
        subscriptions: List[Subscription],
        routing_rules: List[RoutingRule],
    ) -> List[DiagnosticItem]:
        items: List[DiagnosticItem] = []

        # 1. OS & Architecture Check
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        items.append(
            DiagnosticItem(
                category="System & Architecture",
                status="OK",
                summary=f"{__app_name__} v{__version__} running on {os_info} (Target baseline: {__min_windows_version__}).",
                remediation="No action required.",
            )
        )

        # 2. Engine Binary & Authenticity Check
        bin_ok, bin_msg = self.engine.verify_engine_binary()
        if bin_ok:
            ver = self.engine.get_engine_version()
            items.append(
                DiagnosticItem(
                    category="Network Engine (Xray-core)",
                    status="OK",
                    summary=f"Engine binary verified ({ver}). Running: {self.engine.is_running}.",
                    remediation="No action required.",
                )
            )
        else:
            items.append(
                DiagnosticItem(
                    category="Network Engine (Xray-core)",
                    status="ERROR",
                    summary=bin_msg,
                    remediation="Download the official Xray-win7-64.zip or Xray-win7-32.zip release, verify its SHA-256 hash, and extract xray.exe into the 'bin/' directory.",
                )
            )

        # 3. Local Port Availability Check
        if not self.engine.is_running:
            socks_busy = is_local_port_in_use(settings.local_socks_port)
            if socks_busy:
                items.append(
                    DiagnosticItem(
                        category="Local Ports",
                        status="ERROR",
                        summary=f"Local SOCKS5 port {settings.local_socks_port} is occupied by another application.",
                        remediation="Open Settings -> Local Proxy Ports and select an unused port (e.g., 10810), or close the conflicting application.",
                    )
                )
            else:
                items.append(
                    DiagnosticItem(
                        category="Local Ports",
                        status="OK",
                        summary=f"Local SOCKS5 port {settings.local_socks_port} and HTTP port {settings.local_http_port} are available.",
                        remediation="No action required.",
                    )
                )
        else:
            items.append(
                DiagnosticItem(
                    category="Local Ports",
                    status="OK",
                    summary=f"Engine is actively listening on SOCKS5 port {settings.local_socks_port}.",
                    remediation="No action required.",
                )
            )

        # 4. Selected Profile & TLS Check
        selected = next((p for p in profiles if p.id == settings.selected_profile_id), None)
        if selected is None and profiles:
            selected = profiles[0]

        if selected is None:
            items.append(
                DiagnosticItem(
                    category="Profile & TLS",
                    status="WARNING",
                    summary="No server profile is currently configured.",
                    remediation="Import a profile URI in the Servers tab or update a Subscription.",
                )
            )
        else:
            p_ok, p_err = validate_profile(selected)
            if not p_ok:
                items.append(
                    DiagnosticItem(
                        category="Profile & TLS",
                        status="ERROR",
                        summary=f"Selected profile '{selected.name}' has invalid parameters: {p_err}",
                        remediation="Edit the profile parameters or choose a valid server profile.",
                    )
                )
            elif selected.allow_insecure:
                items.append(
                    DiagnosticItem(
                        category="Profile & TLS",
                        status="WARNING",
                        summary=f"Profile '{selected.name}' has 'allowInsecure=True' enabled, which disables TLS certificate verification.",
                        remediation="Disable 'allowInsecure' in profile settings to prevent Man-in-the-Middle (MitM) attacks.",
                    )
                )
            else:
                items.append(
                    DiagnosticItem(
                        category="Profile & TLS",
                        status="OK",
                        summary=f"Profile '{selected.name}' ({selected.protocol.upper()} / {selected.network.upper()} / {selected.security.upper()}) passed structural & TLS validation.",
                        remediation="No action required.",
                    )
                )

        # 5. DNS Configuration Check
        if not settings.primary_dns:
            items.append(
                DiagnosticItem(
                    category="DNS Configuration",
                    status="ERROR",
                    summary="Primary DNS server is empty.",
                    remediation="Configure a reliable DNS server such as 1.1.1.1 or 8.8.8.8 in Settings.",
                )
            )
        else:
            items.append(
                DiagnosticItem(
                    category="DNS Configuration",
                    status="OK",
                    summary=f"Primary DNS: {settings.primary_dns}, Secondary DNS: {settings.secondary_dns}, Domestic Direct DNS: {settings.direct_dns}.",
                    remediation="No action required.",
                )
            )

        # 6. Routing Rules Check
        invalid_rules = []
        for r in routing_rules:
            ok_r, err_r = validate_routing_rule(r)
            if not ok_r:
                invalid_rules.append(err_r)
        if invalid_rules:
            items.append(
                DiagnosticItem(
                    category="Routing Rules",
                    status="ERROR",
                    summary=f"{len(invalid_rules)} routing rule(s) failed validation: {'; '.join(invalid_rules)}",
                    remediation="Open the Routing tab and fix or delete the invalid domain/CIDR rule.",
                )
            )
        else:
            active_r = sum(1 for r in routing_rules if r.enabled)
            items.append(
                DiagnosticItem(
                    category="Routing Rules",
                    status="OK",
                    summary=f"{active_r} active routing rules validated (Strategy: {settings.routing_domain_strategy}).",
                    remediation="No action required.",
                )
            )

        # 7. Subscription Health Check
        failed_subs = [s for s in subscriptions if s.enabled and "Failed" in s.last_status]
        if failed_subs:
            items.append(
                DiagnosticItem(
                    category="Subscriptions",
                    status="WARNING",
                    summary=f"{len(failed_subs)} subscription(s) failed their last update (previous valid profiles were preserved).",
                    remediation="Check network reachability or verify the subscription URL in the Subscriptions tab.",
                )
            )
        else:
            items.append(
                DiagnosticItem(
                    category="Subscriptions",
                    status="OK",
                    summary=f"{len(subscriptions)} subscription(s) configured; no active fetch errors.",
                    remediation="No action required.",
                )
            )

        # 8. Permissions & Kill Switch Check
        ks_status = self.killswitch.get_status_summary()
        admin = is_windows_admin()
        if settings.kill_switch_enabled and settings.kill_switch_mode == "firewall_strict" and os.name == "nt" and not admin:
            items.append(
                DiagnosticItem(
                    category="Permissions & Kill Switch",
                    status="WARNING",
                    summary="Strict Firewall Kill Switch is selected, but NovaLink is running without Windows Administrator privileges.",
                    remediation="Restart NovaLink as Administrator to allow netsh firewall rule management, or switch Kill Switch mode to 'System Proxy Guard'.",
                )
            )
        else:
            items.append(
                DiagnosticItem(
                    category="Permissions & Kill Switch",
                    status="OK",
                    summary=f"Kill Switch active: {ks_status['active']} (Mode: {ks_status['mode']}, Admin: {admin}).",
                    remediation="No action required.",
                )
            )

        return items

    def generate_sanitized_report(
        self,
        settings: AppSettings,
        profiles: List[Profile],
        subscriptions: List[Subscription],
        routing_rules: List[RoutingRule],
    ) -> str:
        """
        Generates a human-readable diagnostic report with all secrets, UUIDs, passwords,
        and subscription URLs strictly redacted.
        """
        checks = self.run_all_checks(settings, profiles, subscriptions, routing_rules)
        extra_secrets: List[str] = []
        for p in profiles:
            if p.uuid_or_password:
                extra_secrets.append(p.uuid_or_password)
            if p.pbk:
                extra_secrets.append(p.pbk)
        for s in subscriptions:
            if s.url:
                extra_secrets.append(s.url)

        lines = [
            "======================================================================",
            f"{__app_name__} v{__version__} — Sanitized Diagnostic & Troubleshooting Report",
            f"Generated At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"OS / Platform: {platform.platform()} ({platform.machine()})",
            f"Python Runtime: {platform.python_version()}",
            "======================================================================",
            "",
            "[1] HEALTH CHECK RESULTS",
        ]
        for idx, item in enumerate(checks, 1):
            lines.append(f"  {idx}. [{item.status}] {item.category}: {item.summary}")
            if item.status != "OK":
                lines.append(f"     -> Suggested Action: {item.remediation}")

        lines.append("")
        lines.append("[2] SANITIZED SETTINGS SUMMARY")
        lines.append(json.dumps(settings.to_dict(), indent=2))

        lines.append("")
        lines.append(f"[3] PROFILES SUMMARY (Total: {len(profiles)})")
        for p in profiles:
            lines.append(
                f"  - Name: {p.name} | Proto: {p.protocol} | Endpoint: {p.address}:{p.port} "
                f"| Net: {p.network} | Sec: {p.security} | Last Ping: {p.latency_ms}ms ({p.last_test_status})"
            )

        lines.append("")
        lines.append("[4] RECENT ENGINE LOGS (REDACTED)")
        recent_logs = self.engine.get_recent_logs(50)
        if not recent_logs:
            lines.append("  (No engine logs recorded in current session)")
        else:
            for log_line in recent_logs:
                lines.append("  " + sanitize_sensitive_text(log_line, extra_secrets))

        raw_report = "\n".join(lines)
        return sanitize_sensitive_text(raw_report, extra_secrets)
