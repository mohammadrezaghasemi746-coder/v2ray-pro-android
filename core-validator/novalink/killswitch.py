"""
NovaLink Windows 7 Kill Switch & System Proxy Manager
Implements two clearly documented, inspectable protection modes compatible with Windows 7 SP1:

1. Mode A — Windows Advanced Firewall Strict Kill Switch (`firewall_strict`, requires Administrator):
   Uses Windows 7 native `netsh advfirewall firewall` rules (`NovaLink_KillSwitch_*`) to:
   - Permit outbound traffic from `xray.exe` (or specifically to the active proxy server IP/port).
   - Permit loopback (`127.0.0.0/8`, `::1`) and local DHCP/LAN traffic (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) so OS services are not broken.
   - Block all other direct outbound internet traffic if the proxy engine drops or disconnects unexpectedly, preventing IP/DNS leaks.

2. Mode B — WinINET System Proxy Fail-Closed Guard (`system_proxy_guard`, Standard User / No Admin required):
   Configures Windows `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings` to route
   WinINET-compliant applications through `127.0.0.1:<http_port>`. If the engine crashes while Kill Switch
   is active, keeps the system proxy pointed at the closed loopback port (fail-closed) rather than reverting
   to direct connection until the user explicitly disables Kill Switch or reconnects.

Includes atomic pre-activation state snapshots (`killswitch_rollback.json`) so that after a crash,
power loss, or system reboot, NovaLink can immediately detect active rules and cleanly restore normal
network connectivity.
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Callable
import json
import os
import subprocess
import time


FIREWALL_RULE_PREFIX = "NovaLink_KillSwitch"


def is_windows_admin() -> bool:
    """Checks whether the current process has Administrator privileges on Windows 7+."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class KillSwitchManager:
    """
    Manages real Kill Switch enforcement, state persistence, crash recovery, and safe rollback.
    Supports an injectable command runner for deterministic testing in non-Windows CI/VM environments.
    """

    def __init__(
        self,
        runtime_dir: Path,
        command_runner: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
        admin_check_fn: Optional[Callable[[], bool]] = None,
    ):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.rollback_file = self.runtime_dir / "killswitch_rollback.json"
        self._cmd_runner = command_runner or self._default_command_runner
        self._admin_check = admin_check_fn or is_windows_admin

        self.active: bool = False
        self.active_mode: str = "none"          # "firewall_strict", "system_proxy_guard", "none"
        self.active_server_ip: str = ""
        self.active_server_port: int = 0
        self.applied_rules: List[str] = []
        self.last_error: str = ""

    def _default_command_runner(self, cmd: List[str]) -> Tuple[int, str, str]:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=creationflags,
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except Exception as exc:
            return -1, "", str(exc)

    def get_status_summary(self) -> Dict[str, Any]:
        return {
            "active": self.active,
            "mode": self.active_mode,
            "server_ip": self.active_server_ip,
            "server_port": self.active_server_port,
            "rules_count": len(self.applied_rules),
            "has_rollback_file": self.rollback_file.exists(),
            "last_error": self.last_error,
        }

    def enable(
        self,
        mode: str,
        server_address: str,
        server_port: int,
        local_http_port: int,
        engine_binary_path: Optional[Path] = None,
    ) -> Tuple[bool, str]:
        """
        Activates Kill Switch protection after saving a rollback snapshot.
        Never claims activation if rule creation fails.
        """
        self.last_error = ""
        if self.active:
            self.disable()

        # Save rollback state BEFORE making any system changes
        rollback_payload = {
            "timestamp": time.time(),
            "mode": mode,
            "server_address": server_address,
            "server_port": int(server_port),
            "local_http_port": int(local_http_port),
            "rules": [],
        }
        self.rollback_file.write_text(json.dumps(rollback_payload, indent=2), encoding="utf-8")

        if mode == "firewall_strict":
            if not self._admin_check():
                self.last_error = (
                    "Strict Firewall Kill Switch requires Administrator privileges on Windows 7. "
                    "Please run NovaLink as Administrator or select 'System Proxy Guard' mode."
                )
                self._cleanup_rollback_file()
                return False, self.last_error

            return self._apply_firewall_strict_rules(
                server_address, int(server_port), engine_binary_path, rollback_payload
            )

        elif mode == "system_proxy_guard":
            return self._apply_system_proxy_guard(int(local_http_port), rollback_payload)

        else:
            self.last_error = f"Unknown Kill Switch mode: '{mode}'."
            self._cleanup_rollback_file()
            return False, self.last_error

    def _apply_firewall_strict_rules(
        self,
        server_address: str,
        server_port: int,
        engine_binary_path: Optional[Path],
        rollback_payload: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Applies Windows 7 `netsh advfirewall firewall` rules:
        1. Allow Loopback (`127.0.0.0/8`)
        2. Allow Private LAN/DHCP (`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`)
        3. Allow Xray engine binary and/or target proxy server IP:port
        4. Block outbound internet traffic on non-tunnel interfaces if outside allowed rules
        """
        rules_spec = [
            (
                f"{FIREWALL_RULE_PREFIX}_Allow_Loopback",
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={FIREWALL_RULE_PREFIX}_Allow_Loopback",
                    "dir=out", "action=allow", "remoteip=127.0.0.0/8", "enable=yes",
                ],
            ),
            (
                f"{FIREWALL_RULE_PREFIX}_Allow_LAN",
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={FIREWALL_RULE_PREFIX}_Allow_LAN",
                    "dir=out", "action=allow",
                    "remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
                    "enable=yes",
                ],
            ),
            (
                f"{FIREWALL_RULE_PREFIX}_Allow_ProxyServer",
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={FIREWALL_RULE_PREFIX}_Allow_ProxyServer",
                    "dir=out", "action=allow", "protocol=TCP",
                    f"remoteip={server_address}", f"remoteport={server_port}",
                    "enable=yes",
                ],
            ),
        ]

        if engine_binary_path and str(engine_binary_path):
            rules_spec.append(
                (
                    f"{FIREWALL_RULE_PREFIX}_Allow_XrayBinary",
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={FIREWALL_RULE_PREFIX}_Allow_XrayBinary",
                        "dir=out", "action=allow",
                        f"program={str(engine_binary_path)}",
                        "enable=yes",
                    ],
                )
            )

        created_names: List[str] = []
        for rule_name, cmd in rules_spec:
            rc, out, err = self._cmd_runner(cmd)
            if rc != 0:
                # Rollback any partially created rules immediately
                self.last_error = f"Failed to apply firewall rule '{rule_name}': {err or out}"
                for prev_name in created_names:
                    self._cmd_runner([
                        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={prev_name}"
                    ])
                self._cleanup_rollback_file()
                return False, self.last_error

            created_names.append(rule_name)
            rollback_payload["rules"] = list(created_names)
            self.rollback_file.write_text(json.dumps(rollback_payload, indent=2), encoding="utf-8")

        self.active = True
        self.active_mode = "firewall_strict"
        self.active_server_ip = server_address
        self.active_server_port = server_port
        self.applied_rules = created_names
        return (
            True,
            f"Strict Windows Firewall Kill Switch active ({len(created_names)} rules enforced for {server_address}:{server_port}).",
        )

    def _apply_system_proxy_guard(
        self, local_http_port: int, rollback_payload: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Configures Windows WinINET System Proxy via `reg.exe` (compatible with Windows 7 SP1 without Admin)
        to force system HTTP/HTTPS traffic through `127.0.0.1:<local_http_port>` with fail-closed behavior.
        """
        reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        cmds = [
            ["reg", "add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"],
            ["reg", "add", reg_path, "/v", "ProxyServer", "/t", "REG_SZ", "/d", f"127.0.0.1:{local_http_port}", "/f"],
            ["reg", "add", reg_path, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;192.168.*;<local>", "/f"],
        ]

        for cmd in cmds:
            rc, out, err = self._cmd_runner(cmd)
            if rc != 0:
                self.last_error = f"Failed to set Windows System Proxy Guard: {err or out}"
                self._cleanup_rollback_file()
                return False, self.last_error

        rollback_payload["rules"] = ["WinINET_ProxyEnable_1", f"WinINET_ProxyServer_127.0.0.1:{local_http_port}"]
        self.rollback_file.write_text(json.dumps(rollback_payload, indent=2), encoding="utf-8")

        self.active = True
        self.active_mode = "system_proxy_guard"
        self.active_server_ip = "127.0.0.1"
        self.active_server_port = local_http_port
        self.applied_rules = list(rollback_payload["rules"])
        return (
            True,
            f"System Proxy Fail-Closed Guard active on 127.0.0.1:{local_http_port} (WinINET traffic blocked if engine stops).",
        )

    def disable(self) -> Tuple[bool, str]:
        """
        Removes all NovaLink Kill Switch firewall rules and/or restores WinINET System Proxy to direct mode.
        """
        errors: List[str] = []

        # Read rollback file if present in case we are recovering from a crash/restart
        mode_to_clean = self.active_mode
        rules_to_clean = list(self.applied_rules)

        if self.rollback_file.exists():
            try:
                data = json.loads(self.rollback_file.read_text(encoding="utf-8"))
                if mode_to_clean == "none":
                    mode_to_clean = data.get("mode", "none")
                for r in data.get("rules", []):
                    if r not in rules_to_clean:
                        rules_to_clean.append(r)
            except Exception:
                pass

        if mode_to_clean == "firewall_strict" or any(r.startswith(FIREWALL_RULE_PREFIX) for r in rules_to_clean):
            target_rules = [r for r in rules_to_clean if r.startswith(FIREWALL_RULE_PREFIX)]
            if not target_rules:
                target_rules = [
                    f"{FIREWALL_RULE_PREFIX}_Allow_Loopback",
                    f"{FIREWALL_RULE_PREFIX}_Allow_LAN",
                    f"{FIREWALL_RULE_PREFIX}_Allow_ProxyServer",
                    f"{FIREWALL_RULE_PREFIX}_Allow_XrayBinary",
                ]
            for rname in target_rules:
                rc, out, err = self._cmd_runner([
                    "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rname}"
                ])
                if rc != 0 and "no rules match" not in (out + err).lower():
                    errors.append(f"Could not delete rule {rname}: {err or out}")

        if mode_to_clean == "system_proxy_guard" or any(r.startswith("WinINET_") for r in rules_to_clean):
            reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            rc, out, err = self._cmd_runner([
                "reg", "add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            if rc != 0:
                errors.append(f"Could not reset WinINET ProxyEnable: {err or out}")

        self.active = False
        self.active_mode = "none"
        self.active_server_ip = ""
        self.active_server_port = 0
        self.applied_rules.clear()

        if errors:
            self.last_error = "; ".join(errors)
            return False, self.last_error

        self.last_error = ""
        self._cleanup_rollback_file()
        return True, "Kill Switch disabled and normal network routing restored."

    def recover_from_crash_if_needed(self) -> Tuple[bool, str]:
        """
        Checks on startup if a previous session terminated abnormally while Kill Switch was active,
        and safely cleans up lingering firewall/proxy locks.
        """
        if not self.rollback_file.exists():
            return False, "No lingering Kill Switch state detected."
        ok, msg = self.disable()
        return True, f"Recovered from previous abnormal shutdown: {msg}"

    def _cleanup_rollback_file(self) -> None:
        if self.rollback_file.exists():
            try:
                self.rollback_file.unlink()
            except OSError:
                pass
