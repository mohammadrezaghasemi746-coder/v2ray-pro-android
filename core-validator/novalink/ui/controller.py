"""
NovaLink Application Controller
Coordinates StorageManager, EngineManager, SubscriptionManager, ServerTester, KillSwitchManager,
and DiagnosticsManager. Keeps UI completely decoupled from network/process execution.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable
import time

from ..models import Profile, Subscription, RoutingRule, AppSettings
from ..storage import StorageManager
from ..parser import parse_profile_uri, validate_profile, export_profile_uri
from ..config_builder import build_xray_config, validate_routing_rule
from ..engine import EngineManager
from ..subscription import SubscriptionManager, SubscriptionUpdateResult
from ..tester import ServerTester, PingResult
from ..killswitch import KillSwitchManager
from ..diagnostics import DiagnosticsManager, DiagnosticItem


class NovaLinkController:
    """
    Central application controller providing thread-safe, testable operations for all GUI views
    and CLI tools. Every button in the UI calls a method on this controller.
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        engine_binary_path: Optional[Path] = None,
        killswitch_cmd_runner: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
        killswitch_admin_check: Optional[Callable[[], bool]] = None,
    ):
        self.storage = StorageManager(data_dir=data_dir)
        self.storage.load()

        self.engine = EngineManager(
            runtime_dir=self.storage.runtime_dir,
            engine_binary_path=engine_binary_path,
        )
        self.killswitch = KillSwitchManager(
            runtime_dir=self.storage.runtime_dir,
            command_runner=killswitch_cmd_runner,
            admin_check_fn=killswitch_admin_check,
        )
        self.sub_manager = SubscriptionManager(
            timeout_sec=10.0,
            max_workers=self.storage.settings.subscription_concurrency,
        )
        self.tester = ServerTester(
            max_concurrency=self.storage.settings.ping_concurrency,
            timeout_ms=self.storage.settings.ping_timeout_ms,
        )
        self.diagnostics = DiagnosticsManager(
            engine=self.engine,
            killswitch=self.killswitch,
        )

        # Perform startup orphan & crash recovery checks
        self.startup_recovery_messages: List[str] = []
        killed_orphan, orphan_msg = self.engine.cleanup_orphan_processes()
        if killed_orphan:
            self.startup_recovery_messages.append(orphan_msg)

        ks_recovered, ks_msg = self.killswitch.recover_from_crash_if_needed()
        if ks_recovered:
            self.startup_recovery_messages.append(ks_msg)

    # --- Profile Management ---
    def add_profile_from_uri(self, uri: str, group: str = "Manual") -> Tuple[Optional[Profile], str]:
        prof, err = parse_profile_uri(uri, subscription_id="manual")
        if prof is None:
            return None, err or "Invalid URI"

        prof.group = group
        fp = prof.fingerprint_key()
        for existing in self.storage.profiles:
            if existing.fingerprint_key() == fp:
                return None, f"Duplicate profile: identical endpoint & credentials already exist as '{existing.name}'."

        self.storage.profiles.append(prof)
        if not self.storage.settings.selected_profile_id:
            self.storage.settings.selected_profile_id = prof.id
        self.storage.save_atomic()
        return prof, "Profile added successfully."

    def update_profile(self, updated_profile: Profile) -> Tuple[bool, str]:
        ok, err = validate_profile(updated_profile)
        if not ok:
            return False, err
        for idx, p in enumerate(self.storage.profiles):
            if p.id == updated_profile.id:
                self.storage.profiles[idx] = updated_profile
                self.storage.save_atomic()
                return True, "Profile updated."
        return False, "Profile ID not found."

    def delete_profile(self, profile_id: str) -> Tuple[bool, str]:
        if self.engine.is_running and self.engine.active_profile and self.engine.active_profile.id == profile_id:
            return False, "Cannot delete the currently connected profile. Disconnect first."
        before = len(self.storage.profiles)
        self.storage.profiles = [p for p in self.storage.profiles if p.id != profile_id]
        if len(self.storage.profiles) == before:
            return False, "Profile not found."
        if self.storage.settings.selected_profile_id == profile_id:
            self.storage.settings.selected_profile_id = (
                self.storage.profiles[0].id if self.storage.profiles else None
            )
        self.storage.save_atomic()
        return True, "Profile deleted."

    def query_profiles(
        self,
        search_query: str = "",
        protocol_filter: str = "all",
        group_filter: str = "all",
        sort_by: str = "latency",
    ) -> List[Profile]:
        q = (search_query or "").lower().strip()
        p_filter = (protocol_filter or "all").lower().strip()
        g_filter = (group_filter or "all").strip()

        filtered: List[Profile] = []
        for p in self.storage.profiles:
            if p_filter != "all" and p.protocol.lower() != p_filter:
                continue
            if g_filter != "all" and p.group != g_filter:
                continue
            if q and (q not in p.name.lower() and q not in p.address.lower() and q not in p.group.lower()):
                continue
            filtered.append(p)

        if sort_by == "name":
            filtered.sort(key=lambda x: x.name.lower())
        elif sort_by == "protocol":
            filtered.sort(key=lambda x: (x.protocol.lower(), x.name.lower()))
        else:
            # Sort by latency (valid lowest latency first)
            filtered.sort(
                key=lambda x: (
                    0 if (x.last_test_status == "OK" and x.latency_ms is not None) else 1,
                    x.latency_ms if (x.last_test_status == "OK" and x.latency_ms is not None) else 999999,
                    x.name.lower(),
                )
            )
        return filtered

    # --- Subscription Management ---
    def add_subscription(self, name: str, url: str) -> Tuple[Optional[Subscription], str]:
        clean_name = (name or "").strip() or "Subscription"
        clean_url = (url or "").strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            return None, "Subscription URL must start with http:// or https://."

        for s in self.storage.subscriptions:
            if s.url.strip().lower() == clean_url.lower():
                return None, f"Duplicate subscription URL already exists under '{s.name}'."

        sub = Subscription(name=clean_name, url=clean_url, enabled=True)
        self.storage.subscriptions.append(sub)
        self.storage.save_atomic()
        return sub, f"Subscription '{clean_name}' added."

    def toggle_subscription(self, sub_id: str) -> Tuple[bool, str]:
        for s in self.storage.subscriptions:
            if s.id == sub_id:
                s.enabled = not s.enabled
                self.storage.save_atomic()
                state_str = "enabled" if s.enabled else "disabled"
                return True, f"Subscription '{s.name}' is now {state_str}."
        return False, "Subscription not found."

    def delete_subscription(self, sub_id: str, delete_associated_profiles: bool = True) -> Tuple[bool, str]:
        target = next((s for s in self.storage.subscriptions if s.id == sub_id), None)
        if not target:
            return False, "Subscription not found."
        self.storage.subscriptions = [s for s in self.storage.subscriptions if s.id != sub_id]
        if delete_associated_profiles:
            self.storage.profiles = [p for p in self.storage.profiles if p.subscription_id != sub_id]
        self.storage.save_atomic()
        return True, f"Subscription '{target.name}' removed."

    def update_subscriptions(
        self,
        progress_callback: Optional[Callable[[int, int, SubscriptionUpdateResult], None]] = None,
    ) -> List[SubscriptionUpdateResult]:
        self.sub_manager.max_workers = self.storage.settings.subscription_concurrency
        updated_profiles, results = self.sub_manager.update_all_subscriptions(
            self.storage.subscriptions,
            self.storage.profiles,
            progress_callback=progress_callback,
        )
        self.storage.profiles = updated_profiles
        if not self.storage.settings.selected_profile_id and self.storage.profiles:
            self.storage.settings.selected_profile_id = self.storage.profiles[0].id
        self.storage.save_atomic()
        return results

    # --- Server Latency Testing ---
    def test_all_servers(
        self,
        method: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, PingResult], None]] = None,
    ) -> List[PingResult]:
        self.tester.max_concurrency = self.storage.settings.ping_concurrency
        self.tester.timeout_ms = self.storage.settings.ping_timeout_ms
        chosen_method = method or self.storage.settings.ping_test_method
        results = self.tester.test_all_profiles(
            self.storage.profiles,
            method=chosen_method,
            progress_callback=progress_callback,
            sort_profiles_in_place=True,
        )
        for r in results:
            self.storage.test_history.append({
                "profile_id": r.profile_id,
                "profile_name": r.profile_name,
                "method": r.method,
                "status": r.status,
                "latency_ms": r.latency_ms,
                "timestamp": r.timestamp,
            })
        self.storage.save_atomic()
        return results

    def cancel_server_tests(self) -> None:
        self.tester.cancel()

    # --- Routing Management ---
    def add_routing_rule(self, rule: RoutingRule) -> Tuple[bool, str]:
        ok, err = validate_routing_rule(rule)
        if not ok:
            return False, err
        self.storage.routing_rules.append(rule)
        self.storage.routing_rules.sort(key=lambda r: r.priority)
        self.storage.save_atomic()
        self._reload_engine_if_connected()
        return True, f"Routing rule '{rule.name}' added and applied."

    def toggle_routing_rule(self, rule_id: str) -> Tuple[bool, str]:
        for r in self.storage.routing_rules:
            if r.id == rule_id:
                r.enabled = not r.enabled
                self.storage.save_atomic()
                self._reload_engine_if_connected()
                return True, f"Rule '{r.name}' {'enabled' if r.enabled else 'disabled'}."
        return False, "Rule not found."

    def delete_routing_rule(self, rule_id: str) -> Tuple[bool, str]:
        before = len(self.storage.routing_rules)
        self.storage.routing_rules = [r for r in self.storage.routing_rules if r.id != rule_id]
        if len(self.storage.routing_rules) == before:
            return False, "Rule not found."
        self.storage.save_atomic()
        self._reload_engine_if_connected()
        return True, "Routing rule deleted."

    def _reload_engine_if_connected(self) -> None:
        if self.engine.is_running and self.engine.active_profile:
            self.engine.start(
                self.engine.active_profile,
                self.storage.settings,
                self.storage.routing_rules,
            )

    # --- Connection & Kill Switch Lifecycle ---
    def connect_selected_profile(self, profile_id: Optional[str] = None) -> Tuple[bool, str]:
        target_id = profile_id or self.storage.settings.selected_profile_id
        prof = next((p for p in self.storage.profiles if p.id == target_id), None)
        if prof is None:
            return False, "No valid server profile selected."

        self.storage.settings.selected_profile_id = prof.id
        ok, msg = self.engine.start(prof, self.storage.settings, self.storage.routing_rules)
        if not ok:
            return False, msg

        if self.storage.settings.kill_switch_enabled:
            ks_ok, ks_msg = self.killswitch.enable(
                mode=self.storage.settings.kill_switch_mode,
                server_address=prof.address,
                server_port=prof.port,
                local_http_port=self.storage.settings.local_http_port,
                engine_binary_path=self.engine.engine_binary_path,
            )
            if not ks_ok:
                # If user requested Kill Switch and it failed to engage, stop engine and report clearly
                self.engine.stop()
                return False, f"Connection aborted because Kill Switch failed to activate: {ks_msg}"
            msg = f"{msg} | {ks_msg}"

        self.storage.save_atomic()
        return True, msg

    def disconnect(self, disable_killswitch: bool = True) -> Tuple[bool, str]:
        eng_ok, eng_msg = self.engine.stop()
        ks_msg = ""
        if disable_killswitch and self.killswitch.active:
            _, ks_msg = self.killswitch.disable()
        combined = f"{eng_msg} {ks_msg}".strip()
        return eng_ok, combined

    def get_dashboard_telemetry(self) -> Dict[str, Any]:
        """
        Returns 100% honest real-time state for the Dashboard.
        Never fabricates throughput speeds or ping numbers.
        """
        selected = next(
            (p for p in self.storage.profiles if p.id == self.storage.settings.selected_profile_id),
            self.storage.profiles[0] if self.storage.profiles else None,
        )
        active_prof = self.engine.active_profile or selected
        active_rules_count = sum(1 for r in self.storage.routing_rules if r.enabled)
        enabled_subs = [s for s in self.storage.subscriptions if s.enabled]

        return {
            "connected": self.engine.is_running,
            "uptime_sec": self.engine.connected_duration_sec,
            "server_name": active_prof.name if active_prof else "None",
            "server_endpoint": f"{active_prof.address}:{active_prof.port}" if active_prof else "—",
            "server_protocol": active_prof.protocol.upper() if active_prof else "—",
            "last_latency_ms": active_prof.latency_ms if active_prof else None,
            "last_test_method": active_prof.last_test_method if active_prof else "",
            "last_test_status": active_prof.last_test_status if active_prof else "Untested",
            "throughput_measured": False,
            "throughput_status": "Not Measured (Requires Xray gRPC Stats API)",
            "dns_status": f"Primary: {self.storage.settings.primary_dns} | Direct: {self.storage.settings.direct_dns}",
            "routing_status": f"{active_rules_count} Active Rules ({self.storage.settings.routing_domain_strategy})",
            "killswitch_active": self.killswitch.active,
            "killswitch_mode": self.killswitch.active_mode if self.killswitch.active else "Disabled",
            "subscriptions_summary": f"{len(enabled_subs)} Enabled / {len(self.storage.profiles)} Total Profiles",
        }
