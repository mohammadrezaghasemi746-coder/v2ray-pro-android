"""
NovaLink Native Desktop Graphical User Interface (Tkinter / ttk)
Designed for Windows 7 SP1 (x86/x64) through Windows 11 and Linux X11.
Features:
- Modern Dark & Light Cyan themes with high-contrast typography
- Full Bilingual support: Persian (RTL layout alignment) and English (LTR layout alignment)
- High-DPI awareness on Windows 7+ (`SetProcessDPIAware`)
- 6 Complete Functional Views: Dashboard, Servers, Subscriptions, Routing, Settings, Diagnostics
- Zero dummy buttons: every action invokes `NovaLinkController` on background threads where appropriate.
"""

import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

from .controller import NovaLinkController
from .i18n import PALETTES, STRINGS
from ..models import Profile, RoutingRule
from ..parser import export_profile_uri


def enable_windows7_dpi_awareness() -> None:
    """Enables crisp High-DPI scaling on Windows 7 SP1+ via user32.SetProcessDPIAware()."""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class NovaLinkDesktopApp:
    """Main desktop GUI window powered by Tkinter/ttk and NovaLinkController."""

    def __init__(self, controller: Optional[NovaLinkController] = None):
        if not TK_AVAILABLE:
            raise RuntimeError(
                "Tkinter is not installed in this headless Linux environment. "
                "On Windows 7 SP1+, Python 3.8 installer includes Tcl/Tk natively."
            )
        enable_windows7_dpi_awareness()
        self.controller = controller or NovaLinkController()
        self.root = tk.Tk()
        self.root.geometry("1120x720")
        self.root.minsize(920, 600)

        self.lang = self.controller.storage.settings.language
        self.theme_name = self.controller.storage.settings.theme
        self.palette = PALETTES.get(self.theme_name, PALETTES["dark"])
        self.strings = STRINGS.get(self.lang, STRINGS["fa"])

        self.root.title(self.strings["app_title"])
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._active_tab = "dashboard"
        self._build_styles()
        self._build_layout()
        self._schedule_telemetry_refresh()

    def _t(self, key: str) -> str:
        return self.strings.get(key, key)

    def _build_styles(self) -> None:
        p = self.palette
        self.root.configure(bg=p["bg_main"])
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("Main.TFrame", background=p["bg_main"])
        style.configure("Sidebar.TFrame", background=p["bg_sidebar"])
        style.configure("Card.TFrame", background=p["bg_card"], relief="flat")
        style.configure(
            "Title.TLabel",
            background=p["bg_main"],
            foreground=p["fg_primary"],
            font=("Segoe UI", 15, "bold"),
        )
        style.configure(
            "CardTitle.TLabel",
            background=p["bg_card"],
            foreground=p["accent"],
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "CardValue.TLabel",
            background=p["bg_card"],
            foreground=p["fg_primary"],
            font=("Segoe UI", 12, "bold"),
        )
        style.configure(
            "Accent.TButton",
            background=p["accent"],
            foreground="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 7),
        )
        style.map("Accent.TButton", background=[("active", p["accent_hover"])])

        style.configure(
            "Treeview",
            background=p["bg_card"],
            fieldbackground=p["bg_card"],
            foreground=p["fg_primary"],
            rowheight=28,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=p["bg_sidebar"],
            foreground=p["fg_primary"],
            font=("Segoe UI", 9, "bold"),
        )

    def _build_layout(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()

        self.lang = self.controller.storage.settings.language
        self.theme_name = self.controller.storage.settings.theme
        self.palette = PALETTES.get(self.theme_name, PALETTES["dark"])
        self.strings = STRINGS.get(self.lang, STRINGS["fa"])
        self._build_styles()
        self.root.title(self._t("app_title"))

        is_rtl = self.lang == "fa"
        sidebar_side = tk.RIGHT if is_rtl else tk.LEFT
        content_side = tk.LEFT if is_rtl else tk.RIGHT

        self.sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", width=220)
        self.sidebar.pack(side=sidebar_side, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        self.content_area = ttk.Frame(self.root, style="Main.TFrame")
        self.content_area.pack(side=content_side, fill=tk.BOTH, expand=True, padx=18, pady=18)

        brand_lbl = tk.Label(
            self.sidebar,
            text="NOVALINK",
            bg=self.palette["bg_sidebar"],
            fg=self.palette["accent"],
            font=("Segoe UI", 16, "bold"),
            pady=20,
        )
        brand_lbl.pack(fill=tk.X)

        nav_items = [
            ("dashboard", self._t("nav_dashboard")),
            ("servers", self._t("nav_servers")),
            ("subscriptions", self._t("nav_subscriptions")),
            ("routing", self._t("nav_routing")),
            ("settings", self._t("nav_settings")),
            ("diagnostics", self._t("nav_diagnostics")),
        ]
        for tab_id, label_text in nav_items:
            btn = tk.Button(
                self.sidebar,
                text=label_text,
                bg=self.palette["accent"] if self._active_tab == tab_id else self.palette["bg_sidebar"],
                fg="#FFFFFF" if self._active_tab == tab_id else self.palette["fg_primary"],
                activebackground=self.palette["accent_hover"],
                activeforeground="#FFFFFF",
                bd=0,
                padx=16,
                pady=11,
                anchor="e" if is_rtl else "w",
                font=("Segoe UI", 10, "bold" if self._active_tab == tab_id else "normal"),
                command=lambda t=tab_id: self._switch_tab(t),
            )
            btn.pack(fill=tk.X, padx=10, pady=3)

        self._render_active_tab()

    def _switch_tab(self, tab_id: str) -> None:
        self._active_tab = tab_id
        self._build_layout()

    def _render_active_tab(self) -> None:
        for child in self.content_area.winfo_children():
            child.destroy()

        if self._active_tab == "dashboard":
            self._render_dashboard()
        elif self._active_tab == "servers":
            self._render_servers()
        elif self._active_tab == "subscriptions":
            self._render_subscriptions()
        elif self._active_tab == "routing":
            self._render_routing()
        elif self._active_tab == "settings":
            self._render_settings()
        elif self._active_tab == "diagnostics":
            self._render_diagnostics()

    # --- 1. Dashboard View ---
    def _render_dashboard(self) -> None:
        tel = self.controller.get_dashboard_telemetry()
        top_bar = ttk.Frame(self.content_area, style="Main.TFrame")
        top_bar.pack(fill=tk.X, pady=(0, 14))

        title = ttk.Label(top_bar, text=self._t("nav_dashboard"), style="Title.TLabel")
        title.pack(side=tk.RIGHT if self.lang == "fa" else tk.LEFT)

        conn_btn_text = self._t("btn_disconnect") if tel["connected"] else self._t("btn_connect")
        conn_btn = ttk.Button(
            top_bar,
            text=conn_btn_text,
            style="Accent.TButton",
            command=self._on_toggle_connection,
        )
        conn_btn.pack(side=tk.LEFT if self.lang == "fa" else tk.RIGHT)

        grid = ttk.Frame(self.content_area, style="Main.TFrame")
        grid.pack(fill=tk.BOTH, expand=True)
        for col in range(2):
            grid.columnconfigure(col, weight=1, uniform="cards")

        cards_data = [
            (
                "Connection Status",
                self._t("status_connected") if tel["connected"] else self._t("status_disconnected"),
            ),
            (self._t("lbl_selected_server"), f"{tel['server_name']} ({tel['server_protocol']})"),
            (self._t("lbl_target_endpoint"), tel["server_endpoint"]),
            (self._t("lbl_uptime"), f"{tel['uptime_sec']} sec"),
            (
                self._t("lbl_last_latency"),
                f"{tel['last_latency_ms']} ms [{tel['last_test_method']}]"
                if tel["last_latency_ms"] is not None
                else tel["last_test_status"],
            ),
            (self._t("lbl_dns_status"), tel["dns_status"]),
            (self._t("lbl_routing_status"), tel["routing_status"]),
            (self._t("lbl_killswitch_status"), f"{tel['killswitch_mode']} (Active: {tel['killswitch_active']})"),
            (self._t("lbl_sub_status"), tel["subscriptions_summary"]),
            ("Engine Traffic Stats", tel["throughput_status"]),
        ]

        for idx, (k, v) in enumerate(cards_data):
            r, c = divmod(idx, 2)
            card = ttk.Frame(grid, style="Card.TFrame", padding=14)
            card.grid(row=r, column=c, sticky="nsew", padx=6, pady=6)
            ttk.Label(card, text=k, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, text=str(v), style="CardValue.TLabel", wraplength=420).pack(anchor="w", pady=(6, 0))

    def _on_toggle_connection(self) -> None:
        if self.controller.engine.is_running:
            ok, msg = self.controller.disconnect()
        else:
            ok, msg = self.controller.connect_selected_profile()
        if not ok:
            messagebox.showerror("Connection Error", msg)
        self._render_active_tab()

    # --- 2. Servers View ---
    def _render_servers(self) -> None:
        bar = ttk.Frame(self.content_area, style="Main.TFrame")
        bar.pack(fill=tk.X, pady=(0, 10))

        self.search_var = tk.StringVar()
        self.proto_var = tk.StringVar(value="all")

        ttk.Entry(bar, textvariable=self.search_var, width=26).pack(side=tk.LEFT, padx=4)
        ttk.Combobox(
            bar,
            textvariable=self.proto_var,
            values=["all", "vless", "vmess", "trojan", "shadowsocks", "socks", "http"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Filter / Sort", command=self._refresh_servers_tree).pack(side=tk.LEFT, padx=4)

        ttk.Button(
            bar,
            text=self._t("btn_test_all_ping"),
            style="Accent.TButton",
            command=self._on_test_all_servers,
        ).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bar, text=self._t("btn_cancel_ping"), command=self.controller.cancel_server_tests).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_add_profile"), command=self._on_add_profile_dialog).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_delete_profile"), command=self._on_delete_selected_profile).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_export_uri"), command=self._on_copy_profile_uri).pack(
            side=tk.RIGHT, padx=4
        )

        self.ping_progress_lbl = ttk.Label(self.content_area, text="", style="CardTitle.TLabel")
        self.ping_progress_lbl.pack(fill=tk.X, pady=(0, 6))

        cols = ("name", "protocol", "address", "port", "latency", "status", "group")
        self.servers_tree = ttk.Treeview(self.content_area, columns=cols, show="headings")
        for col, heading in [
            ("name", "Server Name"),
            ("protocol", "Protocol"),
            ("address", "Destination"),
            ("port", "Port"),
            ("latency", "Latency (ms)"),
            ("status", "Status"),
            ("group", "Source / Group"),
        ]:
            self.servers_tree.heading(col, text=heading)
            self.servers_tree.column(col, width=130 if col != "name" else 220)
        self.servers_tree.pack(fill=tk.BOTH, expand=True)
        self.servers_tree.bind("<<TreeviewSelect>>", self._on_select_server_row)
        self._refresh_servers_tree()

    def _refresh_servers_tree(self) -> None:
        if not hasattr(self, "servers_tree"):
            return
        for row in self.servers_tree.get_children():
            self.servers_tree.delete(row)
        profiles = self.controller.query_profiles(
            search_query=self.search_var.get(),
            protocol_filter=self.proto_var.get(),
        )
        for p in profiles:
            lat_str = f"{p.latency_ms} ms ({p.last_test_method})" if p.latency_ms is not None else "—"
            self.servers_tree.insert(
                "",
                tk.END,
                iid=p.id,
                values=(p.name, p.protocol.upper(), p.address, p.port, lat_str, p.last_test_status, p.group),
            )

    def _on_select_server_row(self, _event: object) -> None:
        sel = self.servers_tree.selection()
        if sel:
            self.controller.storage.settings.selected_profile_id = sel[0]
            self.controller.storage.save_atomic()

    def _on_add_profile_dialog(self) -> None:
        uri = simpledialog.askstring(
            "Import Profile URI",
            "Paste VLESS / VMess / Trojan / Shadowsocks / SOCKS / HTTP URI:",
            parent=self.root,
        )
        if uri:
            prof, msg = self.controller.add_profile_from_uri(uri)
            if prof is None:
                messagebox.showerror("Invalid Profile", msg)
            else:
                self._refresh_servers_tree()

    def _on_delete_selected_profile(self) -> None:
        sel = self.servers_tree.selection()
        if not sel:
            return
        ok, msg = self.controller.delete_profile(sel[0])
        if not ok:
            messagebox.showerror("Delete Error", msg)
        self._refresh_servers_tree()

    def _on_copy_profile_uri(self) -> None:
        sel = self.servers_tree.selection()
        if not sel:
            return
        prof = next((p for p in self.controller.storage.profiles if p.id == sel[0]), None)
        if prof:
            uri = export_profile_uri(prof, redact_secrets=False)
            self.root.clipboard_clear()
            self.root.clipboard_append(uri)
            messagebox.showinfo("Exported", "Share URI copied to clipboard.")

    def _on_test_all_servers(self) -> None:
        def _progress(done: int, total: int, res: object) -> None:
            pct = int((done / max(1, total)) * 100)
            self.root.after(
                0,
                lambda: self.ping_progress_lbl.configure(
                    text=f"Testing Servers: {done}/{total} ({pct}%) — Last: {getattr(res, 'profile_name', '')}"
                ),
            )

        def _worker() -> None:
            self.controller.test_all_servers(progress_callback=_progress)
            self.root.after(0, self._refresh_servers_tree)

        threading.Thread(target=_worker, daemon=True).start()

    # --- 3. Subscriptions View ---
    def _render_subscriptions(self) -> None:
        bar = ttk.Frame(self.content_area, style="Main.TFrame")
        bar.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(
            bar,
            text=self._t("btn_update_subs"),
            style="Accent.TButton",
            command=self._on_update_all_subs,
        ).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bar, text=self._t("btn_add_sub"), command=self._on_add_sub_dialog).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bar, text=self._t("btn_toggle_sub"), command=self._on_toggle_selected_sub).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_delete_sub"), command=self._on_delete_selected_sub).pack(
            side=tk.RIGHT, padx=4
        )

        cols = ("name", "enabled", "count", "added", "duplicates", "invalid", "status")
        self.subs_tree = ttk.Treeview(self.content_area, columns=cols, show="headings")
        for col, text in [
            ("name", "Name"),
            ("enabled", "Enabled"),
            ("count", "Valid Profiles"),
            ("added", "New"),
            ("duplicates", "Duplicates"),
            ("invalid", "Rejected"),
            ("status", "Last Update Status"),
        ]:
            self.subs_tree.heading(col, text=text)
            self.subs_tree.column(col, width=125 if col != "status" else 260)
        self.subs_tree.pack(fill=tk.BOTH, expand=True)
        self._refresh_subs_tree()

    def _refresh_subs_tree(self) -> None:
        if not hasattr(self, "subs_tree"):
            return
        for r in self.subs_tree.get_children():
            self.subs_tree.delete(r)
        for s in self.controller.storage.subscriptions:
            self.subs_tree.insert(
                "",
                tk.END,
                iid=s.id,
                values=(
                    s.name,
                    "Yes" if s.enabled else "No",
                    s.profile_count,
                    s.last_added_count,
                    s.last_duplicate_count,
                    s.last_invalid_count,
                    s.last_status,
                ),
            )

    def _on_add_sub_dialog(self) -> None:
        name = simpledialog.askstring("Subscription Name", "Enter subscription name:", parent=self.root)
        if not name:
            return
        url = simpledialog.askstring("Subscription URL", "Enter https:// subscription URL:", parent=self.root)
        if not url:
            return
        sub, msg = self.controller.add_subscription(name, url)
        if sub is None:
            messagebox.showerror("Subscription Error", msg)
        self._refresh_subs_tree()

    def _on_toggle_selected_sub(self) -> None:
        sel = self.subs_tree.selection()
        if sel:
            self.controller.toggle_subscription(sel[0])
            self._refresh_subs_tree()

    def _on_delete_selected_sub(self) -> None:
        sel = self.subs_tree.selection()
        if sel:
            self.controller.delete_subscription(sel[0])
            self._refresh_subs_tree()

    def _on_update_all_subs(self) -> None:
        def _worker() -> None:
            self.controller.update_subscriptions()
            self.root.after(0, self._refresh_subs_tree)

        threading.Thread(target=_worker, daemon=True).start()

    # --- 4. Routing View ---
    def _render_routing(self) -> None:
        bar = ttk.Frame(self.content_area, style="Main.TFrame")
        bar.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(bar, text=self._t("btn_add_rule"), style="Accent.TButton", command=self._on_add_rule_dialog).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_delete_rule"), command=self._on_delete_selected_rule).pack(
            side=tk.RIGHT, padx=4
        )

        cols = ("priority", "name", "type", "expression", "outbound", "enabled")
        self.rules_tree = ttk.Treeview(self.content_area, columns=cols, show="headings")
        for col, text in [
            ("priority", "Order"),
            ("name", "Rule Name"),
            ("type", "Match Type"),
            ("expression", "Domain / CIDR / Port"),
            ("outbound", "Action (Outbound)"),
            ("enabled", "Enabled"),
        ]:
            self.rules_tree.heading(col, text=text)
            self.rules_tree.column(col, width=130 if col != "expression" else 280)
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
        for r in self.controller.storage.routing_rules:
            self.rules_tree.insert(
                "",
                tk.END,
                iid=r.id,
                values=(r.priority, r.name, r.rule_type, r.match_expression, r.outbound_tag.upper(), r.enabled),
            )

    def _on_add_rule_dialog(self) -> None:
        name = simpledialog.askstring("Rule Name", "Rule name:", parent=self.root)
        if not name:
            return
        rtype = simpledialog.askstring("Rule Type", "Type (domain / ip / port):", initialvalue="domain", parent=self.root)
        expr = simpledialog.askstring("Match Expression", "Domain or CIDR (e.g., domain:example.com or 10.0.0.0/8):", parent=self.root)
        outbound = simpledialog.askstring("Outbound", "Action (proxy / direct / block):", initialvalue="direct", parent=self.root)
        if rtype and expr and outbound:
            rule = RoutingRule(
                name=name,
                rule_type=rtype.strip().lower(),
                match_expression=expr.strip(),
                outbound_tag=outbound.strip().lower(),
            )
            ok, msg = self.controller.add_routing_rule(rule)
            if not ok:
                messagebox.showerror("Invalid Rule", msg)
            self._render_active_tab()

    def _on_delete_selected_rule(self) -> None:
        sel = self.rules_tree.selection()
        if sel:
            self.controller.delete_routing_rule(sel[0])
            self._render_active_tab()

    # --- 5. Settings View ---
    def _render_settings(self) -> None:
        s = self.controller.storage.settings
        card = ttk.Frame(self.content_area, style="Card.TFrame", padding=18)
        card.pack(fill=tk.BOTH, expand=True)

        self.set_lang_var = tk.StringVar(value=s.language)
        self.set_theme_var = tk.StringVar(value=s.theme)
        self.set_socks_var = tk.StringVar(value=str(s.local_socks_port))
        self.set_http_var = tk.StringVar(value=str(s.local_http_port))
        self.set_dns1_var = tk.StringVar(value=s.primary_dns)
        self.set_ks_enabled_var = tk.BooleanVar(value=s.kill_switch_enabled)
        self.set_ks_mode_var = tk.StringVar(value=s.kill_switch_mode)

        fields = [
            ("Language (fa / en):", ttk.Combobox(card, textvariable=self.set_lang_var, values=["fa", "en"], state="readonly")),
            ("Theme (dark / light):", ttk.Combobox(card, textvariable=self.set_theme_var, values=["dark", "light"], state="readonly")),
            ("Local SOCKS5 Port:", ttk.Entry(card, textvariable=self.set_socks_var)),
            ("Local HTTP Port:", ttk.Entry(card, textvariable=self.set_http_var)),
            ("Primary DNS:", ttk.Entry(card, textvariable=self.set_dns1_var)),
            ("Kill Switch Mode:", ttk.Combobox(card, textvariable=self.set_ks_mode_var, values=["firewall_strict", "system_proxy_guard"], state="readonly")),
        ]
        for idx, (label_text, widget) in enumerate(fields):
            ttk.Label(card, text=label_text, style="CardTitle.TLabel").grid(row=idx, column=0, sticky="w", pady=8, padx=8)
            widget.grid(row=idx, column=1, sticky="ew", pady=8, padx=8)

        ks_chk = tk.Checkbutton(
            card,
            text="Enable Kill Switch Protection on Connect",
            variable=self.set_ks_enabled_var,
            bg=self.palette["bg_card"],
            fg=self.palette["fg_primary"],
            selectcolor=self.palette["bg_input"],
        )
        ks_chk.grid(row=len(fields), column=0, columnspan=2, sticky="w", pady=8, padx=8)

        ttk.Button(
            card,
            text=self._t("btn_save_settings"),
            style="Accent.TButton",
            command=self._on_save_settings,
        ).grid(row=len(fields) + 1, column=0, columnspan=2, pady=14)

    def _on_save_settings(self) -> None:
        s = self.controller.storage.settings
        try:
            s.language = self.set_lang_var.get()
            s.theme = self.set_theme_var.get()
            s.local_socks_port = int(self.set_socks_var.get())
            s.local_http_port = int(self.set_http_var.get())
            s.primary_dns = self.set_dns1_var.get().strip()
            s.kill_switch_enabled = bool(self.set_ks_enabled_var.get())
            s.kill_switch_mode = self.set_ks_mode_var.get()
        except ValueError:
            messagebox.showerror("Settings Error", "Port numbers must be valid integers.")
            return

        errs = s.validate()
        if errs:
            messagebox.showerror("Validation Error", "\n".join(errs))
            return

        self.controller.storage.save_atomic(create_timestamped_backup=True)
        self._build_layout()

    # --- 6. Diagnostics View ---
    def _render_diagnostics(self) -> None:
        bar = ttk.Frame(self.content_area, style="Main.TFrame")
        bar.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(bar, text=self._t("btn_run_diag"), style="Accent.TButton", command=self._render_diagnostics).pack(
            side=tk.RIGHT, padx=4
        )
        ttk.Button(bar, text=self._t("btn_export_diag"), command=self._on_export_diag_report).pack(
            side=tk.RIGHT, padx=4
        )

        report_text = self.controller.diagnostics.generate_sanitized_report(
            self.controller.storage.settings,
            self.controller.storage.profiles,
            self.controller.storage.subscriptions,
            self.controller.storage.routing_rules,
        )
        txt = tk.Text(
            self.content_area,
            bg=self.palette["bg_card"],
            fg=self.palette["fg_primary"],
            font=("Consolas", 10),
            wrap="word",
        )
        txt.insert("1.0", report_text)
        txt.configure(state="disabled")
        txt.pack(fill=tk.BOTH, expand=True)

    def _on_export_diag_report(self) -> None:
        out_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="NovaLink-Diagnostic-Report.txt",
            parent=self.root,
        )
        if out_path:
            report_text = self.controller.diagnostics.generate_sanitized_report(
                self.controller.storage.settings,
                self.controller.storage.profiles,
                self.controller.storage.subscriptions,
                self.controller.storage.routing_rules,
            )
            Path(out_path).write_text(report_text, encoding="utf-8")
            messagebox.showinfo("Saved", f"Sanitized diagnostic report saved to:\n{out_path}")

    def _schedule_telemetry_refresh(self) -> None:
        if self._active_tab == "dashboard" and self.controller.engine.is_running:
            self._render_dashboard()
        self.root.after(2000, self._schedule_telemetry_refresh)

    def _on_close(self) -> None:
        self.controller.disconnect(disable_killswitch=True)
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
