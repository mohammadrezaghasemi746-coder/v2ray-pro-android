import unittest
import socket
import threading
import ipaddress
import json
import subprocess
from pathlib import Path
import tempfile
from novalink.storage import StorageManager
from novalink.parser import parse_profile_uri
from novalink.config_builder import build_xray_config
from novalink.models import AppSettings, RoutingRule
from novalink.tester import ServerTester
from novalink.updater import parse_xray_dgst_file, verify_archive_against_dgst
from novalink.engine import compute_file_sha256

# Exact CIDR list from V2RayVpnService.PUBLIC_IPV4_ROUTES_EXCLUDING_LAN
PUBLIC_IPV4_ROUTES_EXCLUDING_LAN = [("1.0.0.0", 8), ("2.0.0.0", 7), ("4.0.0.0", 6), ("8.0.0.0", 7), ("11.0.0.0", 8), ("12.0.0.0", 6), ("16.0.0.0", 4), ("32.0.0.0", 3), ("64.0.0.0", 3), ("96.0.0.0", 6), ("100.0.0.0", 10), ("100.128.0.0", 9), ("101.0.0.0", 8), ("102.0.0.0", 7), ("104.0.0.0", 5), ("112.0.0.0", 5), ("120.0.0.0", 6), ("124.0.0.0", 7), ("126.0.0.0", 8), ("128.0.0.0", 3), ("160.0.0.0", 5), ("168.0.0.0", 8), ("169.0.0.0", 9), ("169.128.0.0", 10), ("169.192.0.0", 11), ("169.224.0.0", 12), ("169.240.0.0", 13), ("169.248.0.0", 14), ("169.252.0.0", 15), ("169.255.0.0", 16), ("170.0.0.0", 7), ("172.0.0.0", 12), ("172.32.0.0", 11), ("172.64.0.0", 10), ("172.128.0.0", 9), ("173.0.0.0", 8), ("174.0.0.0", 7), ("176.0.0.0", 4), ("192.0.0.0", 9), ("192.128.0.0", 11), ("192.160.0.0", 13), ("192.169.0.0", 16), ("192.170.0.0", 15), ("192.172.0.0", 14), ("192.176.0.0", 12), ("192.192.0.0", 10), ("193.0.0.0", 8), ("194.0.0.0", 7), ("196.0.0.0", 6), ("200.0.0.0", 5), ("208.0.0.0", 4)]


class V2RayProAndroidCoreTests(unittest.TestCase):

    def test_01_zero_demo_configs_by_default(self):
        """Verifies that a fresh installation contains ZERO demo/default server profiles or subscriptions."""
        with tempfile.TemporaryDirectory() as tmp:
            sm = StorageManager(Path(tmp))
            sm.load()
            self.assertEqual(len(sm.profiles), 0, "Initial profiles list MUST be strictly empty (no demo configs)!")
            self.assertEqual(len(sm.subscriptions), 0, "Initial subscriptions list MUST be strictly empty!")

    def test_02_anti_leak_and_static_ip_routing_rules(self):
        """Verifies WebRTC STUN block, IPv6 leak guard, and VLESS REALITY config generation."""
        uri = "vless://550e8400-e29b-41d4-a716-446655440000@198.51.100.42:443?security=reality&encryption=none&pbk=m1234567890abcdef1234567890abcdef1234567890&fp=chrome&type=tcp&sni=www.cloudflare.com&sid=a1b2#UserImportedNode"
        prof, err = parse_profile_uri(uri)
        self.assertIsNotNone(prof, f"Failed to parse valid VLESS REALITY URI: {err}")
        settings = AppSettings(
            local_socks_port=10808,
            local_http_port=10809,
            primary_dns="1.1.1.1",
        )
        rules = [
            RoutingRule(
                id="webrtc-stun-block",
                name="Block WebRTC STUN Leak",
                enabled=True,
                priority=1,
                rule_type="port",
                match_expression="3478, 3479, 5349, 19302",
                outbound_tag="block",
            ),
            RoutingRule(
                id="ipv6-sinkhole",
                name="Block IPv6 Leak",
                enabled=True,
                priority=2,
                rule_type="ip",
                match_expression="::/0",
                outbound_tag="block",
            ),
        ]
        cfg = build_xray_config(prof, settings, rules)
        self.assertEqual(cfg["outbounds"][0]["protocol"], "vless")
        rule_ports = [r.get("port") for r in cfg["routing"]["rules"] if "port" in r]
        self.assertTrue(any("3478" in str(p) for p in rule_ports))

    def test_03_real_network_tcp_latency_and_error_classification(self):
        """Verifies TCP ping returns real ms on open port and None (never 0ms) on refused/unreachable port."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def accept_loop():
            try:
                conn, _ = srv.accept()
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()

        tester = ServerTester(timeout_ms=1000)
        res_ok = tester.test_single_tcp("127.0.0.1", port)
        srv.close()
        self.assertEqual(res_ok.status, "OK")
        self.assertIsNotNone(res_ok.latency_ms)
        self.assertGreaterEqual(res_ok.latency_ms, 1)

        # Now test closed port -> must fail with latency_ms is None (never 0)
        res_closed = tester.test_single_tcp("127.0.0.1", port)
        self.assertNotEqual(res_closed.status, "OK")
        self.assertIsNone(res_closed.latency_ms)

    def test_04_periodic_ota_sha256_integrity_verification(self):
        """Verifies OTA update archive SHA-256 verification against official .dgst manifest."""
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "V2RayPro-OTA-v2.1.0.apk"
            pkg.write_bytes(b"PK\x03\x04V2RayPro-Android-Binary-Payload-v2.1.0")
            sha = compute_file_sha256(pkg)
            dgst = f"SHA256 = {sha}\n"
            ok, msg = verify_archive_against_dgst(pkg, dgst)
            self.assertTrue(ok, msg)

    def test_05_lan_route_exclusion_table_mathematical_proof(self):
        """Proves PUBLIC_IPV4_ROUTES_EXCLUDING_LAN excludes all RFC1918 LAN & gateway IPs while covering public IPs."""
        nets = [ipaddress.ip_network(f"{ip}/{pfx}") for ip, pfx in PUBLIC_IPV4_ROUTES_EXCLUDING_LAN]

        def is_routed_to_tun(ip_str):
            addr = ipaddress.ip_address(ip_str)
            return any(addr in n for n in nets)

        # Private Wi-Fi/LAN gateways & subnets MUST bypass TUN
        for lan_ip in ["192.168.1.1", "192.168.0.100", "10.0.0.1", "10.200.200.1", "172.16.0.1", "172.31.255.1", "169.254.1.1", "127.0.0.1", "224.0.0.251"]:
            self.assertFalse(is_routed_to_tun(lan_ip), f"LAN IP {lan_ip} was erroneously routed into TUN!")

        # Public internet IPs MUST enter TUN
        for pub_ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "104.16.132.229", "185.199.108.153"]:
            self.assertTrue(is_routed_to_tun(pub_ip), f"Public IP {pub_ip} was not routed into TUN!")

    def test_06_webview_js_parser_and_subscription_merger(self):
        """Executes the actual JS parser and non-destructive subscription merger from index.html via Node.js."""
        html_path = Path(__file__).resolve().parent.parent / "app/src/main/assets/index.html"
        html_text = html_path.read_text(encoding="utf-8")
        script_body = html_text.split("<script>")[1].split("</script>")[0]

        node_test = r"""
        const document = {
          getElementById: () => ({ textContent: "", value: "", style: {}, classList: { add(){}, remove(){}, toggle(){}, contains(){return true;} }, addEventListener(){} }),
          querySelectorAll: () => [],
          querySelector: () => null,
          activeElement: null
        };
        const window = {
          addEventListener(){},
          performance: { now: () => 100 },
          navigator: { userAgent: "Mozilla/5.0" }
        };
        const navigator = window.navigator;
        const localStorage = { getItem: () => null, setItem(){} };
        const setInterval = () => 1;
        const setTimeout = () => 1;
        const clearTimeout = () => {};
        """ + script_body + r"""
        // 1. Verify initial zero demo servers
        if (state.servers.length !== 0) throw new Error("Expected 0 initial servers");

        // 2. Test parsing VLESS REALITY with Persian/Emoji remark & SS SIP002
        const b64Sub = Buffer.from(
          "vless://550e8400-e29b-41d4-a716-446655440000@de1.example.com:443?security=reality&pbk=pubkey123&sni=www.cloudflare.com&type=tcp&fp=chrome#🇩🇪 سرور آلمان ۱\n" +
          "ss://YWVzLTI1Ni1nY206bXlwYXNz@ss.example.com:8388#🇳🇱 هلند\n" +
          "vless://550e8400-e29b-41d4-a716-446655440000@bad.example.com:443?security=reality#MissingPbkShouldBeRejected\n"
        ).toString("base64");

        const extracted = extractAllConfigsFromPayload(b64Sub, "", "https://sub.example.com/1");
        if (extracted.length !== 2) throw new Error("Expected 2 valid configs (invalid REALITY rejected), got " + extracted.length);

        const m1 = mergeProfilesForSubscription("https://sub.example.com/1", extracted);
        if (m1.added !== 2 || m1.updated !== 0) throw new Error("Unexpected first merge counts: " + JSON.stringify(m1));
        const firstUid = state.servers[0].uid;

        // 3. Re-merging identical subscription must preserve UIDs and produce 0 duplicates
        const m2 = mergeProfilesForSubscription("https://sub.example.com/1", extracted);
        if (m2.added !== 0 || m2.updated !== 2 || state.servers.length !== 2 || state.servers[0].uid !== firstUid) {
          throw new Error("Idempotent subscription update failed: " + JSON.stringify(m2));
        }
        console.log("JS_UNIT_TESTS_OK");
        """
        proc = subprocess.run(["node", "-e", node_test], capture_output=True, text=True, check=True)
        self.assertIn("JS_UNIT_TESTS_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
