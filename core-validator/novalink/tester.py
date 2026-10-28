"""
NovaLink Server Latency & Connectivity Tester
Clearly distinguishes between:
1. TCP Connect Latency (`tcp`): Real socket handshake time (`connect()`) to server:port.
2. HTTP Proxy Round-Trip Latency (`http_proxy`): Real HTTP request routed through an active local proxy port to a test target URL.
3. ICMP Echo (`icmp`): OS ping utility (network layer reachability only, does not verify proxy port).

Features bounded concurrency (ThreadPoolExecutor), cancellation token (`threading.Event`),
progress callbacks, and automatic sorting of servers by measured result.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Callable, Dict, Any, Tuple
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error

from .models import Profile


@dataclass
class PingResult:
    profile_id: str
    profile_name: str
    method: str                 # "TCP", "HTTP-Proxy", "ICMP"
    status: str                 # "OK", "Timeout", "Failed", "Cancelled"
    latency_ms: Optional[int]
    detail: str = ""
    timestamp: float = 0.0


class ServerTester:
    """
    Executes real network latency tests across one or all profiles with bounded concurrency
    and clean mid-flight cancellation. Never generates fake/random ping numbers.
    """

    def __init__(self, max_concurrency: int = 10, timeout_ms: int = 3000):
        self.max_concurrency = max(1, min(max_concurrency, 50))
        self.timeout_ms = max(200, min(timeout_ms, 30000))
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def cancel(self) -> None:
        """Signals all pending and active test workers to abort cleanly."""
        self._cancel_event.set()

    def test_single_tcp(self, address: str, port: int, timeout_ms: Optional[int] = None) -> PingResult:
        """Measures real TCP SYN/SYN-ACK handshake time to (address, port)."""
        t_sec = (timeout_ms or self.timeout_ms) / 1000.0
        now = time.time()
        if self._cancel_event.is_set():
            return PingResult("", "", "TCP", "Cancelled", None, "Test cancelled by user", now)

        t0 = time.perf_counter()
        try:
            with socket.create_connection((address, int(port)), timeout=t_sec):
                elapsed_ms = max(1, int(round((time.perf_counter() - t0) * 1000)))
                return PingResult("", "", "TCP", "OK", elapsed_ms, f"TCP handshake to {address}:{port} succeeded", now)
        except socket.timeout:
            return PingResult("", "", "TCP", "Timeout", None, f"TCP handshake timed out after {int(t_sec*1000)}ms", now)
        except OSError as ose:
            return PingResult("", "", "TCP", "Failed", None, f"TCP connection failed: {ose}", now)

    def test_via_local_http_proxy(
        self,
        local_http_port: int,
        test_url: str = "http://cp.cloudflare.com/generate_204",
        timeout_ms: Optional[int] = None,
    ) -> PingResult:
        """
        Measures real end-to-end HTTP request latency routed through the active local HTTP proxy inbound.
        """
        t_sec = (timeout_ms or self.timeout_ms) / 1000.0
        now = time.time()
        if self._cancel_event.is_set():
            return PingResult("", "", "HTTP-Proxy", "Cancelled", None, "Cancelled", now)

        proxy_url = f"http://127.0.0.1:{int(local_http_port)}"
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(
            test_url,
            headers={"User-Agent": "NovaLink-LatencyCheck/1.2"},
            method="GET",
        )
        t0 = time.perf_counter()
        try:
            with opener.open(req, timeout=t_sec) as resp:
                code = getattr(resp, "status", resp.getcode())
                elapsed_ms = max(1, int(round((time.perf_counter() - t0) * 1000)))
                if 200 <= code < 400:
                    return PingResult("", "", "HTTP-Proxy", "OK", elapsed_ms, f"HTTP {code} via 127.0.0.1:{local_http_port}", now)
                return PingResult("", "", "HTTP-Proxy", "Failed", None, f"Unexpected HTTP status {code}", now)
        except socket.timeout:
            return PingResult("", "", "HTTP-Proxy", "Timeout", None, f"Proxy test timed out ({int(t_sec*1000)}ms)", now)
        except urllib.error.URLError as ue:
            if isinstance(ue.reason, socket.timeout):
                return PingResult("", "", "HTTP-Proxy", "Timeout", None, f"Proxy test timed out ({int(t_sec*1000)}ms)", now)
            return PingResult("", "", "HTTP-Proxy", "Failed", None, f"Proxy error: {ue.reason}", now)
        except Exception as exc:
            return PingResult("", "", "HTTP-Proxy", "Failed", None, f"Proxy test error: {exc}", now)

    def test_single_icmp(self, address: str, timeout_ms: Optional[int] = None) -> PingResult:
        """Executes a single OS ICMP echo request (Windows 7 `ping -n 1 -w <ms>` or Linux `ping -c 1 -W <sec>`)."""
        ms = timeout_ms or self.timeout_ms
        now = time.time()
        import os
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", str(ms), address]
        else:
            sec = max(1, int(ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(sec), address]

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=(ms / 1000.0) + 1.5)
            elapsed_ms = max(1, int(round((time.perf_counter() - t0) * 1000)))
            if proc.returncode == 0:
                return PingResult("", "", "ICMP", "OK", elapsed_ms, "ICMP Echo Reply received", now)
            return PingResult("", "", "ICMP", "Timeout", None, "No ICMP reply", now)
        except subprocess.TimeoutExpired:
            return PingResult("", "", "ICMP", "Timeout", None, "ICMP timed out", now)
        except Exception as exc:
            return PingResult("", "", "ICMP", "Failed", None, f"ICMP error: {exc}", now)

    def test_all_profiles(
        self,
        profiles: List[Profile],
        method: str = "tcp",
        progress_callback: Optional[Callable[[int, int, PingResult], None]] = None,
        sort_profiles_in_place: bool = True,
    ) -> List[PingResult]:
        """
        Tests all provided profiles using bounded concurrency (`self.max_concurrency`).
        Updates each Profile's `latency_ms`, `last_test_status`, `last_test_method`, and `last_test_time`.
        If `sort_profiles_in_place=True`, sorts profiles so successful lowest-latency servers appear first,
        followed by untested/failed/timeout servers.
        """
        with self._lock:
            self._cancel_event.clear()
            self._is_running = True

        total = len(profiles)
        if total == 0:
            with self._lock:
                self._is_running = False
            return []

        results: List[PingResult] = []
        completed_count = 0

        def _worker(prof: Profile) -> Tuple[Profile, PingResult]:
            if self._cancel_event.is_set():
                res = PingResult(
                    profile_id=prof.id,
                    profile_name=prof.name,
                    method=method.upper(),
                    status="Cancelled",
                    latency_ms=None,
                    detail="Cancelled by user",
                    timestamp=time.time(),
                )
                return prof, res

            if method.lower() == "icmp":
                res = self.test_single_icmp(prof.address, self.timeout_ms)
            else:
                res = self.test_single_tcp(prof.address, prof.port, self.timeout_ms)

            res.profile_id = prof.id
            res.profile_name = prof.name
            return prof, res

        try:
            with ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
                future_map = {executor.submit(_worker, p): p for p in profiles}
                for fut in as_completed(future_map):
                    prof, res = fut.result()
                    completed_count += 1
                    if res.status != "Cancelled":
                        prof.latency_ms = res.latency_ms
                        prof.last_test_status = res.status
                        prof.last_test_method = res.method
                        prof.last_test_time = res.timestamp
                    results.append(res)
                    if progress_callback:
                        progress_callback(completed_count, total, res)
        finally:
            if sort_profiles_in_place:
                profiles.sort(
                    key=lambda p: (
                        0 if (p.last_test_status == "OK" and p.latency_ms is not None) else 1,
                        p.latency_ms if (p.last_test_status == "OK" and p.latency_ms is not None) else 999999,
                        p.name.lower(),
                    )
                )
            with self._lock:
                self._is_running = False

        return results
