"""
NovaLink Atomic Storage & State Recovery Manager
Provides crash-safe atomic file persistence, automatic pre-write backups (.bak),
corrupted entry isolation (one bad entry never breaks the entire config),
and strict separation of user data (%APPDATA%\\NovaLink on Windows) from program binaries.
"""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from .models import Profile, Subscription, RoutingRule, AppSettings
from .parser import validate_profile
from .config_builder import validate_routing_rule


def get_default_user_data_dir() -> Path:
    """
    Returns the OS-appropriate user data directory separated from installation binaries.
    On Windows 7+: %APPDATA%\\NovaLink
    On Linux/macOS: ~/.config/NovaLink
    """
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "NovaLink"
        return Path.home() / "AppData" / "Roaming" / "NovaLink"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return Path(xdg) / "NovaLink"
        return Path.home() / ".config" / "NovaLink"


def default_routing_rules() -> List[RoutingRule]:
    """Provides sensible default routing rules for a fresh installation."""
    return [
        RoutingRule(
            id="rule-lan-direct",
            name="Local & Private Networks (LAN)",
            enabled=True,
            priority=10,
            rule_type="ip",
            match_expression="127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fc00::/7",
            outbound_tag="direct",
            network_type="tcp,udp",
        ),
        RoutingRule(
            id="rule-ads-block",
            name="Block Telemetry & Ad Domains",
            enabled=True,
            priority=20,
            rule_type="domain",
            match_expression="domain:doubleclick.net, domain:googleadservices.com, domain:googlesyndication.com",
            outbound_tag="block",
            network_type="tcp,udp",
        ),
        RoutingRule(
            id="rule-domestic-direct",
            name="Domestic Domains Direct (.ir)",
            enabled=True,
            priority=30,
            rule_type="domain",
            match_expression="domain:ir",
            outbound_tag="direct",
            network_type="tcp,udp",
            dns_server_override="223.5.5.5",
        ),
    ]


class StorageManager:
    """
    Manages persistent storage of profiles, subscriptions, routing rules, test history,
    and general settings with atomic writes and automatic fallback to .bak on corruption.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir: Path = Path(data_dir) if data_dir else get_default_user_data_dir()
        self.backups_dir: Path = self.data_dir / "backups"
        self.runtime_dir: Path = self.data_dir / "runtime"
        self.logs_dir: Path = self.data_dir / "logs"

        self.state_file: Path = self.data_dir / "novalink_state.json"
        self.backup_file: Path = self.data_dir / "novalink_state.json.bak"

        self._ensure_dirs()

        self.settings: AppSettings = AppSettings()
        self.profiles: List[Profile] = []
        self.subscriptions: List[Subscription] = []
        self.routing_rules: List[RoutingRule] = default_routing_rules()
        self.test_history: List[Dict[str, Any]] = []
        self.load_warnings: List[str] = []

    def _ensure_dirs(self) -> None:
        for d in (self.data_dir, self.backups_dir, self.runtime_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)

    def save_atomic(self, create_timestamped_backup: bool = False) -> None:
        """
        Atomically writes state to disk:
        1. Serializes state to a temporary file in the same directory.
        2. Flushes and fsyncs file descriptor.
        3. Copies current valid state file to .bak.
        4. Atomically replaces target file via os.replace().
        """
        self._ensure_dirs()
        payload = {
            "schema_version": 1,
            "updated_at": time.time(),
            "settings": self.settings.to_dict(),
            "profiles": [p.to_dict() for p in self.profiles],
            "subscriptions": [s.to_dict() for s in self.subscriptions],
            "routing_rules": [r.to_dict() for r in self.routing_rules],
            "test_history": self.test_history[-200:],  # Keep last 200 test records
        }
        serialized = json.dumps(payload, indent=2, ensure_ascii=False)

        fd, tmp_path_str = tempfile.mkstemp(
            prefix=".novalink_tmp_", suffix=".json", dir=str(self.data_dir)
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass

            if self.state_file.exists():
                try:
                    shutil.copy2(str(self.state_file), str(self.backup_file))
                    if create_timestamped_backup:
                        ts_name = f"novalink_backup_{int(time.time())}.json"
                        shutil.copy2(str(self.state_file), str(self.backups_dir / ts_name))
                except OSError:
                    pass

            os.replace(str(tmp_path), str(self.state_file))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def load(self) -> Tuple[bool, List[str]]:
        """
        Loads state from disk. If the primary state file is corrupted, automatically falls back
        to novalink_state.json.bak. Individual invalid profiles or rules are skipped and logged
        without corrupting the rest of the user's configuration.
        """
        self.load_warnings.clear()
        if not self.state_file.exists() and not self.backup_file.exists():
            self.routing_rules = default_routing_rules()
            self.save_atomic()
            return True, []

        raw_data = None
        loaded_from_backup = False

        if self.state_file.exists():
            try:
                raw_data = json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                self.load_warnings.append(f"Primary state file corrupted ({exc}); attempting backup recovery.")

        if raw_data is None and self.backup_file.exists():
            try:
                raw_data = json.loads(self.backup_file.read_text(encoding="utf-8"))
                loaded_from_backup = True
                self.load_warnings.append("Successfully recovered configuration from .bak backup file.")
            except Exception as exc:
                self.load_warnings.append(f"Backup state file also unreadable ({exc}); resetting to safe defaults.")

        if not isinstance(raw_data, dict):
            self.settings = AppSettings()
            self.profiles = []
            self.subscriptions = []
            self.routing_rules = default_routing_rules()
            return False, self.load_warnings

        # 1. Settings recovery
        settings_raw = raw_data.get("settings")
        if isinstance(settings_raw, dict):
            candidate = AppSettings.from_dict(settings_raw)
            errs = candidate.validate()
            if errs:
                self.load_warnings.extend([f"Settings warning: {e}" for e in errs])
                # Sanitize invalid ports/fields individually
                if not (1024 <= candidate.local_socks_port <= 65535):
                    candidate.local_socks_port = 10808
                if not (1024 <= candidate.local_http_port <= 65535) or candidate.local_http_port == candidate.local_socks_port:
                    candidate.local_http_port = 10809
                if candidate.language not in ("fa", "en"):
                    candidate.language = "fa"
                if candidate.theme not in ("dark", "light"):
                    candidate.theme = "dark"
            self.settings = candidate

        # 2. Profiles recovery (per-item isolation)
        loaded_profiles: List[Profile] = []
        seen_ids = set()
        for idx, item in enumerate(raw_data.get("profiles", [])):
            if not isinstance(item, dict):
                self.load_warnings.append(f"Skipped non-object profile at index {idx}.")
                continue
            try:
                prof = Profile.from_dict(item)
                ok, err = validate_profile(prof)
                if not ok:
                    self.load_warnings.append(f"Skipped invalid profile '{prof.name}': {err}")
                    continue
                if prof.id in seen_ids:
                    prof.id = f"{prof.id}-{idx}"
                seen_ids.add(prof.id)
                loaded_profiles.append(prof)
            except Exception as exc:
                self.load_warnings.append(f"Skipped malformed profile at index {idx}: {exc}")
        self.profiles = loaded_profiles

        # 3. Subscriptions recovery
        loaded_subs: List[Subscription] = []
        for idx, item in enumerate(raw_data.get("subscriptions", [])):
            if not isinstance(item, dict):
                continue
            try:
                sub = Subscription.from_dict(item)
                if sub.url and (sub.url.startswith("http://") or sub.url.startswith("https://")):
                    loaded_subs.append(sub)
                else:
                    self.load_warnings.append(f"Skipped subscription '{sub.name}' with invalid URL scheme.")
            except Exception as exc:
                self.load_warnings.append(f"Skipped malformed subscription at index {idx}: {exc}")
        self.subscriptions = loaded_subs

        # 4. Routing rules recovery
        loaded_rules: List[RoutingRule] = []
        for idx, item in enumerate(raw_data.get("routing_rules", [])):
            if not isinstance(item, dict):
                continue
            try:
                rule = RoutingRule.from_dict(item)
                ok, err = validate_routing_rule(rule)
                if ok:
                    loaded_rules.append(rule)
                else:
                    self.load_warnings.append(f"Skipped invalid routing rule: {err}")
            except Exception as exc:
                self.load_warnings.append(f"Skipped malformed routing rule at index {idx}: {exc}")
        self.routing_rules = loaded_rules if loaded_rules else default_routing_rules()

        # 5. Test history
        hist = raw_data.get("test_history", [])
        if isinstance(hist, list):
            self.test_history = [h for h in hist if isinstance(h, dict)][-200:]

        if loaded_from_backup:
            self.save_atomic()

        return True, self.load_warnings

    def export_backup_bundle(self, destination_path: Path, redact_secrets: bool = False) -> None:
        """Exports settings, profiles, subscriptions, and routing rules to an external JSON file."""
        profiles_out = []
        for p in self.profiles:
            d = p.to_dict()
            if redact_secrets:
                d["uuid_or_password"] = "***REDACTED***"
                if d.get("pbk"):
                    d["pbk"] = "***REDACTED***"
            profiles_out.append(d)

        subs_out = []
        for s in self.subscriptions:
            d = s.to_dict()
            if redact_secrets:
                d["url"] = "***REDACTED_SUBSCRIPTION_URL***"
            subs_out.append(d)

        bundle = {
            "schema_version": 1,
            "exported_at": time.time(),
            "redacted": redact_secrets,
            "settings": self.settings.to_dict(),
            "profiles": profiles_out,
            "subscriptions": subs_out,
            "routing_rules": [r.to_dict() for r in self.routing_rules],
        }
        destination_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")

    def import_backup_bundle(self, source_path: Path) -> Tuple[bool, str]:
        """Imports a previously exported backup bundle after validating contents."""
        try:
            data = json.loads(source_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return False, "Backup file root must be a JSON object."
            if data.get("redacted"):
                return False, "Cannot import a redacted diagnostic export as live configuration."
            # Create safety snapshot before importing
            self.save_atomic(create_timestamped_backup=True)
            self.state_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            ok, warnings = self.load()
            return ok, ("Imported successfully." if not warnings else "; ".join(warnings))
        except Exception as exc:
            return False, f"Failed to import backup: {exc}"
