"""
NovaLink Xray-core Engine Lifecycle & Process Manager
Manages configuration validation, controlled process startup, stdout/stderr ring-buffer capture,
local port occupation verification, single-instance locking, and orphan process cleanup after crashes.
"""

from collections import deque
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Callable
import hashlib
import json
import os
import signal
import socket
import subprocess
import threading
import time

from .models import Profile, AppSettings, RoutingRule
from .config_builder import build_xray_config


def is_local_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a local TCP port is already bound by another process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex((host, int(port))) == 0


def compute_file_sha256(filepath: Path) -> str:
    """Computes the SHA-256 hex digest of an executable or archive for authenticity verification."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class EngineManager:
    """
    Controls the execution of the Xray-core process (`xray.exe` on Windows 7+ or `xray` on POSIX).
    Never fakes connection status: verifies both process health and local inbound port binding.
    """

    def __init__(
        self,
        runtime_dir: Path,
        engine_binary_path: Optional[Path] = None,
        expected_sha256: Optional[str] = None,
    ):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.pid_file = self.runtime_dir / "xray_engine.pid"
        self.active_config_path = self.runtime_dir / "active_config.json"

        if engine_binary_path:
            self.engine_binary_path = Path(engine_binary_path)
        else:
            default_name = "xray.exe" if os.name == "nt" else "xray"
            self.engine_binary_path = Path(__file__).resolve().parent.parent / "bin" / default_name

        self.expected_sha256 = expected_sha256
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._log_buffer: deque = deque(maxlen=500)
        self._connected_since: Optional[float] = None
        self._active_profile: Optional[Profile] = None
        self._reader_thread: Optional[threading.Thread] = None
        self.on_unexpected_exit: Optional[Callable[[int, str], None]] = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            if self._process is None:
                return False
            return self._process.poll() is None

    @property
    def connected_duration_sec(self) -> int:
        if not self.is_running or self._connected_since is None:
            return 0
        return max(0, int(time.time() - self._connected_since))

    @property
    def active_profile(self) -> Optional[Profile]:
        return self._active_profile if self.is_running else None

    def get_recent_logs(self, max_lines: int = 100) -> List[str]:
        with self._lock:
            items = list(self._log_buffer)
        return items[-max_lines:]

    def cleanup_orphan_processes(self) -> Tuple[bool, str]:
        """
        Detects if a previous NovaLink session crashed leaving an orphan `xray` process running,
        verifies the process identity, and terminates it cleanly so ports are freed.
        """
        if not self.pid_file.exists():
            return False, "No stale PID file found."

        try:
            data = json.loads(self.pid_file.read_text(encoding="utf-8"))
            stale_pid = int(data.get("pid", 0))
        except Exception:
            self._remove_pid_file()
            return False, "Removed unreadable stale PID file."

        if stale_pid <= 0:
            self._remove_pid_file()
            return False, "Invalid stale PID removed."

        killed = False
        msg = f"Checked stale PID {stale_pid}."
        try:
            if os.name == "nt":
                # Verify process name via tasklist on Windows 7+ before killing
                check = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {stale_pid}", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if "xray" in check.stdout.lower() or "python" in check.stdout.lower():
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(stale_pid)],
                        capture_output=True,
                        timeout=5,
                    )
                    killed = True
                    msg = f"Terminated orphan engine process (PID {stale_pid})."
            else:
                # POSIX check via /proc/<pid>/cmdline or os.kill(pid, 0)
                cmdline_path = Path(f"/proc/{stale_pid}/cmdline")
                if cmdline_path.exists():
                    cmdline_str = cmdline_path.read_bytes().decode("utf-8", errors="ignore")
                    if "xray" in cmdline_str.lower() or "active_config.json" in cmdline_str:
                        os.kill(stale_pid, signal.SIGTERM)
                        time.sleep(0.15)
                        try:
                            os.kill(stale_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        killed = True
                        msg = f"Terminated orphan engine process (PID {stale_pid})."
        except Exception as exc:
            msg = f"Orphan cleanup check completed ({exc})."
        finally:
            self._remove_pid_file()

        return killed, msg

    def verify_engine_binary(self) -> Tuple[bool, str]:
        """Checks if the engine binary exists, is executable, and matches expected SHA-256 if configured."""
        if not self.engine_binary_path.exists():
            return (
                False,
                f"Xray-core binary not found at '{self.engine_binary_path}'. "
                "Please place official Xray-win7-64/32 xray.exe in the bin/ folder or run scripts/fetch_xray_win7.ps1.",
            )
        if self.expected_sha256:
            actual = compute_file_sha256(self.engine_binary_path)
            if actual.lower() != self.expected_sha256.lower():
                return (
                    False,
                    f"Engine SHA-256 mismatch! Expected {self.expected_sha256}, got {actual}. Execution blocked for security.",
                )
        return True, "Engine binary verified."

    def get_engine_version(self) -> str:
        """Queries `xray version` from the engine binary."""
        ok, msg = self.verify_engine_binary()
        if not ok:
            return "Not Installed"
        try:
            cmd = self._build_command(["version"])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip().splitlines()[0]
            return f"Unknown (exit {proc.returncode})"
        except Exception as exc:
            return f"Error ({exc})"

    def validate_config_with_engine(self, config_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Writes a temporary config file and runs `xray run -test -c <file>` if the engine binary
        is available, verifying structural and protocol compatibility directly with the core.
        """
        test_cfg_path = self.runtime_dir / "test_validate_config.json"
        test_cfg_path.write_text(json.dumps(config_dict, indent=2, ensure_ascii=False), encoding="utf-8")

        ok, msg = self.verify_engine_binary()
        if not ok:
            return False, msg

        try:
            cmd = self._build_command(["run", "-test", "-c", str(test_cfg_path)])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode == 0:
                return True, "Configuration validated by engine."
            return False, f"Engine rejected configuration: {output}"
        except Exception as exc:
            return False, f"Failed to execute engine config check: {exc}"
        finally:
            if test_cfg_path.exists():
                try:
                    test_cfg_path.unlink()
                except OSError:
                    pass

    def start(
        self,
        profile: Profile,
        settings: AppSettings,
        routing_rules: List[RoutingRule],
    ) -> Tuple[bool, str]:
        """
        Starts the proxy engine in a controlled subprocess:
        1. Cleans up any stale orphan processes.
        2. Validates profile, settings, and routing rules and builds active_config.json.
        3. Verifies local SOCKS and HTTP ports are free.
        4. Validates configuration with the engine (`-test`).
        5. Spawns the engine process and captures stdout/stderr asynchronously.
        6. Verifies the process stays alive and binds the local SOCKS port.
        """
        if self.is_running:
            self.stop()

        self.cleanup_orphan_processes()

        # 1. Build & validate configuration
        try:
            config_dict = build_xray_config(profile, settings, routing_rules)
        except Exception as exc:
            return False, str(exc)

        # 2. Check port availability before launching
        if is_local_port_in_use(settings.local_socks_port):
            return (
                False,
                f"Local SOCKS port {settings.local_socks_port} is already occupied by another program. "
                "Please change the port in Settings or close the conflicting application.",
            )
        if settings.enable_http_proxy and is_local_port_in_use(settings.local_http_port):
            return (
                False,
                f"Local HTTP port {settings.local_http_port} is already occupied by another program. "
                "Please change the port in Settings or close the conflicting application.",
            )

        # 3. Verify engine binary & run `-test`
        ok_bin, bin_msg = self.verify_engine_binary()
        if not ok_bin:
            return False, bin_msg

        ok_cfg, cfg_msg = self.validate_config_with_engine(config_dict)
        if not ok_cfg:
            return False, cfg_msg

        # 4. Write active configuration
        self.active_config_path.write_text(
            json.dumps(config_dict, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # 5. Launch controlled subprocess
        cmd = self._build_command(["run", "-c", str(self.active_config_path)])
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        with self._lock:
            self._log_buffer.clear()
            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=creationflags,
                )
            except Exception as exc:
                self._process = None
                return False, f"Failed to launch engine process: {exc}"

            pid = self._process.pid
            self.pid_file.write_text(
                json.dumps({"pid": pid, "started_at": time.time(), "profile": profile.name}),
                encoding="utf-8",
            )

        # Start log reader & monitor thread
        self._reader_thread = threading.Thread(
            target=self._consume_output_and_monitor,
            args=(self._process,),
            daemon=True,
        )
        self._reader_thread.start()

        # 6. Wait up to 3.0 seconds for local SOCKS inbound port to bind and verify process hasn't exited
        deadline = time.monotonic() + 3.0
        port_bound = False
        while time.monotonic() < deadline:
            if not self.is_running:
                recent = "\n".join(self.get_recent_logs(10))
                self._remove_pid_file()
                return False, f"Engine process exited unexpectedly during startup:\n{recent}"
            if is_local_port_in_use(settings.local_socks_port):
                port_bound = True
                break
            time.sleep(0.08)

        if not port_bound:
            self.stop()
            return (
                False,
                f"Engine process started (PID {pid}) but failed to bind local SOCKS port {settings.local_socks_port} within 3s.",
            )

        self._connected_since = time.time()
        self._active_profile = profile
        return True, f"Connected via '{profile.name}' (SOCKS5 127.0.0.1:{settings.local_socks_port})."

    def stop(self) -> Tuple[bool, str]:
        """Stops the running engine process cleanly, frees local ports, and removes PID lock."""
        with self._lock:
            proc = self._process
            self._process = None
            self._connected_since = None
            self._active_profile = None

        if proc is None:
            self._remove_pid_file()
            return True, "Engine is already stopped."

        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
            if proc.stdout:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
        except Exception as exc:
            self._remove_pid_file()
            return False, f"Error while stopping engine process: {exc}"

        self._remove_pid_file()
        return True, "Disconnected and freed local proxy ports."

    def _build_command(self, args: List[str]) -> List[str]:
        if str(self.engine_binary_path).endswith(".py"):
            import sys
            return [sys.executable, str(self.engine_binary_path)] + args
        return [str(self.engine_binary_path)] + args

    def _consume_output_and_monitor(self, proc: subprocess.Popen) -> None:
        try:
            if proc.stdout:
                for line in proc.stdout:
                    clean_line = line.rstrip("\r\n")
                    if clean_line:
                        with self._lock:
                            self._log_buffer.append(f"[{time.strftime('%H:%M:%S')}] {clean_line}")
        except Exception:
            pass
        finally:
            if proc.stdout:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            rc = proc.poll()
            # If self._process is still pointing to proc, it means an unexpected crash occurred
            unexpected = False
            with self._lock:
                if self._process is proc:
                    unexpected = True
                    self._process = None
                    self._connected_since = None
                    self._active_profile = None
            if unexpected:
                self._remove_pid_file()
                if self.on_unexpected_exit:
                    self.on_unexpected_exit(rc if rc is not None else -1, "Engine process terminated unexpectedly.")

    def _remove_pid_file(self) -> None:
        if self.pid_file.exists():
            try:
                self.pid_file.unlink()
            except OSError:
                pass
