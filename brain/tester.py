"""ConnectionTester — fitness function for evaluating zapret2 lua-desync strategies.

Shadow-mode: test connections go through a separate winws2/nfqws2 instance
without affecting main traffic.

Strategies are lists of lua-desync calls, e.g.:
  ["fake:blob=fake_default_tls:ip_ttl=6:tcp_md5", "multisplit:pos=midsld"]
"""

from __future__ import annotations

import logging
import platform
import random
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.tester")


# ─── Test result data ─────────────────────────────────────────────────────────

@dataclass
class HostTestResult:
    """Result of a single curl test to one host."""
    host: str
    success: bool
    http_code: int = 0
    latency_ms: float = 0.0
    error_type: str = ""  # "" | "timeout" | "rst" | "dns" | "refused" | "error"


@dataclass
class StrategyTestReport:
    """Aggregated results for one strategy across all hosts/trials."""
    flags: list[str]
    fitness: float = 0.0
    host_results: dict = field(default_factory=dict)  # host -> {successes, total, avg_latency_ms, error_types}
    total_success: int = 0
    total_tests: int = 0
    avg_latency_ms: float = 0.0

# ─── Mock fitness: effective combo patterns ──────────────────────────────────

_EFFECTIVE_COMBOS: dict[str, float] = {
    "fake+ttl": 0.85,
    "fake+md5": 0.80,
    "fakedsplit+ttl": 0.82,
    "multisplit+midsld": 0.88,
    "multidisorder+midsld": 0.90,
    "fake+ttl+md5": 0.92,
    "fake+autottl": 0.87,
    "fake+repeats+md5": 0.85,
    "multidisorder+seqovl": 0.78,
}


def _mock_fitness(flags: list[str]) -> float:
    """Mock fitness based on known effective zapret2 combos.

    Capped at 0.95 to prevent early GA exit.
    """
    score = 0.1
    flag_str = " ".join(flags)

    if "fake" in flag_str and "ip_ttl" in flag_str and "tcp_md5" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+ttl+md5"])
    if "multidisorder" in flag_str and "midsld" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["multidisorder+midsld"])
    if "multisplit" in flag_str and "midsld" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["multisplit+midsld"])
    if "fake" in flag_str and "autottl" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+autottl"])
    if "fakedsplit" in flag_str and "ip_ttl" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fakedsplit+ttl"])
    if "fake" in flag_str and "tcp_md5" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+md5"])
    if "fake" in flag_str and "ip_ttl" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+ttl"])
    if "fake" in flag_str and "repeats" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+repeats+md5"])
    if "multidisorder" in flag_str and "seqovl" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["multidisorder+seqovl"])

    if "ip_ttl" in flag_str:
        score += 0.05
    if "tcp_md5" in flag_str:
        score += 0.03
    if "midsld" in flag_str:
        score += 0.03

    noise = random.uniform(-0.10, 0.08)
    return round(max(0.0, min(0.95, score + noise)), 3)


# Successful HTTP codes (site responded, including 403 = server reachable)
_SUCCESS_CODES = {200, 301, 302, 303, 307, 308, 403}


class ConnectionTester:
    """Connection quality tester for zapret2 lua-desync strategies."""

    def __init__(self, config: dict, mock: bool = True, hostlist_path: Optional[Path] = None):
        self.config = config
        self.mock = mock
        self.hosts: list[str] = config.get("test_hosts", ["youtube.com", "discord.com", "cdn.discordapp.com"])
        self.hosts_h2: list[str] = config.get("test_hosts_h2", ["youtube.com"])
        self.hosts_ws: list[str] = config.get("test_hosts_websocket", ["gateway.discord.gg"])
        self.trials: int = config.get("test_trials", 3)
        self.timeout: int = config.get("test_timeout", 5)
        self._evo_timeout: int = min(self.timeout, 3)  # shorter timeout during evolution
        self._evo_trials: int = 1  # 1 trial per host during evolution (fast screening)
        self._base_dir = Path(config.get("_base_dir", "."))
        self._is_windows = platform.system() == "Windows"
        self._zapret_bin = self._resolve_zapret_binary()
        self._zapret_dir = self._zapret_bin.parent if self._zapret_bin else None
        self._lua_dir = self._resolve_lua_dir()
        self._hostlist_path = hostlist_path
        self._shadow_process: Optional[subprocess.Popen] = None
        self._last_report: Optional[StrategyTestReport] = None

    def test_strategy(self, flags: list[str]) -> float:
        """Evaluate strategy. Returns fitness 0.0-1.0.

        flags is a list of lua-desync call strings, e.g.:
          ["fake:blob=fake_default_tls:ip_ttl=6:tcp_md5", "multisplit:pos=midsld"]
        """
        if self.mock:
            return self._test_mock(flags)
        return self._test_real(flags)

    # ─── Mock ──────────────────────────────────────────────────────────────

    def _test_mock(self, flags: list[str]) -> float:
        """Mock testing without real connections."""
        fitness = _mock_fitness(flags)
        logger.debug("Mock test: flags=%s fitness=%.3f", " | ".join(flags), fitness)
        return fitness

    # ─── Real testing ──────────────────────────────────────────────────────

    def _test_real(self, flags: list[str]) -> float:
        """Real testing through shadow zapret2 instance + curl.

        Fitness formula (0.0 - 1.0):
          base    = success_rate (0-1)              — weight 0.60
          latency = latency bonus (fast < 1s)       — weight 0.25
          penalty = error type penalty (RST worse)  — weight 0.15

        Uses fail-fast: if first host test fails, skips remaining
        to avoid prolonged broken connectivity.
        """
        if not self._zapret_bin:
            logger.error("zapret2 binary not found, falling back to mock")
            return self._test_mock(flags)

        successful = 0
        total_tests = 0
        all_results: list[HostTestResult] = []
        # During evolution: 1 trial, shorter timeout for fast screening
        trials = self._evo_trials
        timeout = self._evo_timeout

        try:
            # 1. Start shadow zapret2 with strategy
            self._start_shadow_zapret(flags)

            # 2. Wait for zapret2 to initialize + WinDivert driver load
            time.sleep(1.5)

            if self._shadow_process is None or self._shadow_process.poll() is not None:
                # Read stderr for crash reason
                stderr_msg = ""
                if self._shadow_process and self._shadow_process.stderr:
                    try:
                        stderr_msg = self._shadow_process.stderr.read().decode(errors="replace")[:500]
                    except Exception:
                        pass
                logger.error("Shadow zapret2 failed to start: %s", stderr_msg or "(no output)")
                return 0.0

            # 3. Test each host with fail-fast
            consecutive_fails = 0
            for host in self.hosts:
                for trial in range(trials):
                    r = self._curl_test(host, timeout_override=timeout)
                    all_results.append(r)
                    total_tests += 1
                    if r.success:
                        successful += 1
                        consecutive_fails = 0
                    else:
                        consecutive_fails += 1

                    # FAIL-FAST: if first 2 tests both fail, this strategy
                    # is likely breaking all traffic — abort immediately
                    if consecutive_fails >= 2 and successful == 0:
                        logger.debug("Fail-fast: %d consecutive failures, aborting", consecutive_fails)
                        break

                if consecutive_fails >= 2 and successful == 0:
                    break

            # 3b. Extended tests: H2 stream + WebSocket (only if basic tests passed)
            if successful > 0:
                for host in self.hosts_h2:
                    r = self._curl_test_h2_stream(host, timeout_override=timeout + 2)
                    all_results.append(r)
                    total_tests += 1
                    if r.success:
                        successful += 1

                for host in self.hosts_ws:
                    r = self._curl_test_websocket(host, timeout_override=timeout)
                    all_results.append(r)
                    total_tests += 1
                    if r.success:
                        successful += 1

        except Exception as exc:
            logger.error("Test failed: %s", exc)
            return 0.0

        finally:
            # 4. Stop shadow zapret2 IMMEDIATELY
            self._stop_shadow_zapret()

        if total_tests == 0:
            return 0.0

        # ── Compute composite fitness ──────────────────────────────────────
        fitness = self._compute_fitness(all_results, successful, total_tests)

        # ── Build per-host report for analytics ────────────────────────────
        self._last_report = self._build_report(flags, all_results, fitness)

        logger.info(
            "Real test: flags=%s fitness=%.3f (%d/%d) avg_latency=%.0fms",
            " | ".join(flags), fitness, successful, total_tests,
            self._last_report.avg_latency_ms,
        )
        return round(fitness, 3)

    def test_strategy_thorough(self, flags: list[str]) -> float:
        """Full test with all trials — use after evolution to verify winner."""
        if self.mock:
            return self._test_mock(flags)

        # Save and restore evolution settings
        saved_trials = self._evo_trials
        saved_timeout = self._evo_timeout
        self._evo_trials = self.trials  # full trials (3)
        self._evo_timeout = self.timeout  # full timeout (5s)
        try:
            return self._test_real(flags)
        finally:
            self._evo_trials = saved_trials
            self._evo_timeout = saved_timeout

    @staticmethod
    def _compute_fitness(
        results: list[HostTestResult], successful: int, total: int,
    ) -> float:
        """Composite fitness: success rate + latency bonus - error penalty.

        Components (weights sum to 1.0):
          success_rate  (0.60) — fraction of successful tests
          latency_bonus (0.25) — reward fast responses (< 1000ms ideal)
          error_penalty (0.15) — RST/refused = full penalty, timeout = partial
        """
        # 1. Base success rate
        success_rate = successful / total

        # 2. Latency bonus: only for successful requests
        ok_results = [r for r in results if r.success and r.latency_ms > 0]
        if ok_results:
            avg_latency = sum(r.latency_ms for r in ok_results) / len(ok_results)
            # 0ms → 1.0, 1000ms → 0.5, 3000ms → ~0.25, 5000ms+ → ~0.15
            latency_bonus = 1.0 / (1.0 + avg_latency / 1000.0)
        else:
            latency_bonus = 0.0

        # 3. Error penalty: classify failures
        fail_results = [r for r in results if not r.success]
        if fail_results:
            rst_count = sum(1 for r in fail_results if r.error_type == "rst")
            timeout_count = sum(1 for r in fail_results if r.error_type == "timeout")
            other_count = len(fail_results) - rst_count - timeout_count
            # RST = active blocking (full penalty), timeout = passive (partial)
            penalty_score = (rst_count * 1.0 + timeout_count * 0.6 + other_count * 0.3) / total
        else:
            penalty_score = 0.0

        fitness = (
            0.60 * success_rate
            + 0.25 * latency_bonus
            - 0.15 * penalty_score
        )

        return max(0.0, min(1.0, fitness))

    def _build_report(
        self, flags: list[str], results: list[HostTestResult], fitness: float,
    ) -> StrategyTestReport:
        """Aggregate per-host stats for logging and analytics."""
        report = StrategyTestReport(flags=flags, fitness=fitness)
        host_data: dict[str, dict] = {}

        for r in results:
            if r.host not in host_data:
                host_data[r.host] = {
                    "successes": 0, "total": 0,
                    "latencies": [], "error_types": [],
                }
            d = host_data[r.host]
            d["total"] += 1
            if r.success:
                d["successes"] += 1
            if r.latency_ms > 0:
                d["latencies"].append(r.latency_ms)
            if r.error_type:
                d["error_types"].append(r.error_type)

        for host, d in host_data.items():
            avg_lat = sum(d["latencies"]) / len(d["latencies"]) if d["latencies"] else 0
            report.host_results[host] = {
                "successes": d["successes"],
                "total": d["total"],
                "avg_latency_ms": round(avg_lat, 1),
                "error_types": list(set(d["error_types"])),
            }

        report.total_success = sum(d["successes"] for d in host_data.values())
        report.total_tests = sum(d["total"] for d in host_data.values())

        all_lats = [r.latency_ms for r in results if r.latency_ms > 0]
        report.avg_latency_ms = round(sum(all_lats) / len(all_lats), 1) if all_lats else 0
        return report

    # ─── Shadow zapret2 management ─────────────────────────────────────────

    def _start_shadow_zapret(self, flags: list[str]) -> None:
        """Start separate zapret2 instance for testing."""
        self._stop_shadow_zapret()

        # Kill any leftover winws2 (permanent or crashed shadow)
        if self._is_windows:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", "winws2.exe"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
                )
                time.sleep(0.5)
            except Exception:
                pass

        cmd = [str(self._zapret_bin)]

        if self._is_windows:
            # Windows: winws2 with WinDivert (outgoing only for testing)
            cmd.extend([
                "--wf-tcp-out=80,443",
                "--wf-udp-out=443",
            ])
        else:
            # Linux: nfqws2 with netfilter queue
            cmd.extend(["--qnum=200"])
            self._setup_linux_shadow_nfqueue()

        # Load Lua libraries (required for zapret2)
        # Use relative paths from cwd (binary dir) to avoid spaces-in-path issues
        if self._lua_dir:
            import os
            lib_path = self._lua_dir / "zapret-lib.lua"
            antidpi_path = self._lua_dir / "zapret-antidpi.lua"
            base = str(self._zapret_dir) if self._zapret_dir else "."
            if lib_path.exists():
                rel = os.path.relpath(str(lib_path), base)
                cmd.append(f"--lua-init=@{rel}")
            if antidpi_path.exists():
                rel = os.path.relpath(str(antidpi_path), base)
                cmd.append(f"--lua-init=@{rel}")

        # Hostlist: only apply desync to blocked domains (prevents breaking all traffic)
        if self._hostlist_path and self._hostlist_path.exists() and self._zapret_dir:
            import shutil
            local_hl = self._zapret_dir / "hostlist.txt"
            try:
                shutil.copy2(str(self._hostlist_path), str(local_hl))
                cmd.append("--hostlist=hostlist.txt")
            except Exception:
                pass

        # TLS filters (no --payload: process ALL packets, not just ClientHello)
        # This matches permanent mode and is critical for HTTP/2 streams
        cmd.extend([
            "--filter-tcp=80,443",
            "--filter-l7=tls,http",
        ])

        # Add strategy lua-desync calls
        for call in flags:
            cmd.append(f"--lua-desync={call}")

        logger.debug("Starting shadow zapret2: %s", " ".join(cmd))

        try:
            # For Windows, set working dir to zapret binary dir (for WinDivert.dll)
            cwd = str(self._zapret_dir) if self._is_windows and self._zapret_dir else None

            self._shadow_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=cwd,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            logger.info("Shadow zapret2 started (pid=%d)", self._shadow_process.pid)
        except FileNotFoundError:
            logger.error("zapret2 binary not found at %s", self._zapret_bin)
            self._shadow_process = None
        except OSError as exc:
            logger.error("Failed to start shadow zapret2: %s", exc)
            self._shadow_process = None

    def _stop_shadow_zapret(self) -> None:
        """Stop shadow zapret2 instance. Uses taskkill as fallback on Windows."""
        if self._shadow_process is None:
            return

        try:
            proc = self._shadow_process
            self._shadow_process = None

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

            logger.debug("Shadow zapret2 stopped (pid=%d)", proc.pid)
        except Exception as exc:
            logger.warning("Error stopping shadow zapret2: %s", exc)

        # Fallback: force-kill any remaining winws2 processes
        if self._is_windows:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", "winws2.exe"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=3,
                )
            except Exception:
                pass
        else:
            self._cleanup_linux_shadow_nfqueue()

    # ─── curl testing ──────────────────────────────────────────────────────

    # curl exit codes that indicate specific failure types
    _CURL_RST_CODES = {7, 56}        # connection refused / reset
    _CURL_TIMEOUT_CODES = {28}        # operation timed out
    _CURL_DNS_CODES = {6}             # could not resolve host
    _CURL_SSL_CODES = {35, 51, 60}    # SSL errors

    def _curl_test(self, host: str, timeout_override: int = 0) -> HostTestResult:
        """Single curl test with latency measurement and error classification."""
        t = timeout_override or self.timeout
        try:
            # -w format: "HTTP_CODE|TIME_TOTAL_MS"
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(t),
                    f"https://{host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}|%{time_total}",
                ],
                capture_output=True,
                text=True,
                timeout=t + 3,
            )

            # Parse "CODE|TIME" output
            parts = result.stdout.strip().split("|")
            http_code = 0
            latency_ms = 0.0
            try:
                http_code = int(parts[0])
            except (ValueError, IndexError):
                pass
            try:
                latency_ms = round(float(parts[1]) * 1000, 1)  # seconds → ms
            except (ValueError, IndexError):
                pass

            # Success: clean exit + success code, OR success code + timeout
            # (timeout with HTTP 200 = page loaded but body too large for timeout)
            if http_code in _SUCCESS_CODES and (result.returncode == 0 or result.returncode == 28):
                logger.debug("curl %s: HTTP %d in %.0fms (OK)", host, http_code, latency_ms)
                return HostTestResult(
                    host=host, success=True, http_code=http_code,
                    latency_ms=latency_ms, error_type="",
                )

            # Classify error by curl exit code
            error_type = self._classify_curl_error(result.returncode)
            logger.debug(
                "curl %s: HTTP %d, exit=%d, %.0fms (%s)",
                host, http_code, result.returncode, latency_ms, error_type,
            )
            return HostTestResult(
                host=host, success=False, http_code=http_code,
                latency_ms=latency_ms, error_type=error_type,
            )

        except subprocess.TimeoutExpired:
            logger.debug("curl %s: process timeout", host)
            return HostTestResult(
                host=host, success=False, http_code=0,
                latency_ms=self.timeout * 1000, error_type="timeout",
            )
        except FileNotFoundError:
            logger.error("curl not found in PATH")
            return HostTestResult(host=host, success=False, error_type="error")
        except Exception as exc:
            logger.debug("curl %s: error %s", host, exc)
            return HostTestResult(host=host, success=False, error_type="error")

    @classmethod
    def _classify_curl_error(cls, returncode: int) -> str:
        """Map curl exit code to error category."""
        if returncode == 0:
            return ""
        if returncode in cls._CURL_RST_CODES:
            return "rst"
        if returncode in cls._CURL_TIMEOUT_CODES:
            return "timeout"
        if returncode in cls._CURL_DNS_CODES:
            return "dns"
        if returncode in cls._CURL_SSL_CODES:
            return "ssl"
        return "error"

    # ─── Extended tests: HTTP/2 stream + WebSocket ──────────────────────────

    def _curl_test_h2_stream(self, host: str, timeout_override: int = 0) -> HostTestResult:
        """Test HTTP/2 stream — download 64KB to detect strategies that break after handshake."""
        timeout = timeout_override or 8
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(timeout),
                    "-r", "0-65535",
                    f"https://{host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}|%{time_total}",
                ],
                capture_output=True, text=True, timeout=timeout + 3,
            )
            parts = result.stdout.strip().split("|")
            http_code = int(parts[0]) if parts else 0
            latency_ms = round(float(parts[1]) * 1000, 1) if len(parts) > 1 else 0.0

            if http_code in _SUCCESS_CODES and (result.returncode == 0 or result.returncode == 28):
                return HostTestResult(host=f"h2:{host}", success=True, http_code=http_code, latency_ms=latency_ms)

            error_type = self._classify_curl_error(result.returncode)
            return HostTestResult(host=f"h2:{host}", success=False, http_code=http_code, latency_ms=latency_ms, error_type=error_type)
        except subprocess.TimeoutExpired:
            return HostTestResult(host=f"h2:{host}", success=False, latency_ms=timeout * 1000, error_type="timeout")
        except Exception:
            return HostTestResult(host=f"h2:{host}", success=False, error_type="error")

    def _curl_test_websocket(self, host: str, timeout_override: int = 0) -> HostTestResult:
        """Test WebSocket upgrade — verifies Discord gateway-style connections."""
        timeout = timeout_override or 5
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(timeout),
                    f"https://{host}",
                    "-H", "Upgrade: websocket",
                    "-H", "Connection: Upgrade",
                    "-H", "Sec-WebSocket-Version: 13",
                    "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}|%{time_total}",
                ],
                capture_output=True, text=True, timeout=timeout + 3,
            )
            parts = result.stdout.strip().split("|")
            http_code = int(parts[0]) if parts else 0
            latency_ms = round(float(parts[1]) * 1000, 1) if len(parts) > 1 else 0.0

            # WebSocket upgrade: 101 Switching Protocols, or 404 (gateway responds)
            ws_success = http_code in {101, 200, 301, 302, 404} and result.returncode in {0, 28}
            if ws_success:
                return HostTestResult(host=f"ws:{host}", success=True, http_code=http_code, latency_ms=latency_ms)

            error_type = self._classify_curl_error(result.returncode)
            return HostTestResult(host=f"ws:{host}", success=False, http_code=http_code, latency_ms=latency_ms, error_type=error_type)
        except subprocess.TimeoutExpired:
            return HostTestResult(host=f"ws:{host}", success=False, latency_ms=timeout * 1000, error_type="timeout")
        except Exception:
            return HostTestResult(host=f"ws:{host}", success=False, error_type="error")

    # ─── Linux shadow nfqueue ──────────────────────────────────────────────

    def _setup_linux_shadow_nfqueue(self) -> None:
        """Setup separate nfqueue for shadow testing."""
        try:
            subprocess.run(
                ["iptables", "-t", "mangle", "-A", "OUTPUT",
                 "-p", "tcp", "--dport", "443",
                 "-m", "mark", "--mark", "0x100",
                 "-j", "NFQUEUE", "--queue-num", "200"],
                capture_output=True, timeout=5,
            )
            logger.debug("Shadow nfqueue rules applied")
        except Exception as exc:
            logger.warning("Failed to setup shadow nfqueue: %s", exc)

    def _cleanup_linux_shadow_nfqueue(self) -> None:
        """Remove shadow nfqueue rules."""
        try:
            subprocess.run(
                ["iptables", "-t", "mangle", "-D", "OUTPUT",
                 "-p", "tcp", "--dport", "443",
                 "-m", "mark", "--mark", "0x100",
                 "-j", "NFQUEUE", "--queue-num", "200"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    # ─── Helpers ───────────────────────────────────────────────────────────

    def _resolve_zapret_binary(self) -> Optional[Path]:
        """Find zapret2 binary."""
        if self._is_windows:
            name = self.config.get("zapret_binary_windows", "winws2.exe")
        else:
            name = self.config.get("zapret_binary_linux", "nfqws2")

        # Check PATH
        found = shutil.which(name)
        if found:
            return Path(found)

        # Check project root
        local = self._base_dir / name
        if local.exists():
            return local

        search_paths = [
            self._base_dir / "bin" / name,
            Path("/usr/local/bin") / name,
            Path("/usr/bin") / name,
        ]

        # Search in zapret2 directory (windows x86_64 / x86)
        if self._is_windows:
            for zdir in sorted(self._base_dir.glob("zapret2-*/binaries/windows-x86_64"), reverse=True):
                search_paths.insert(0, zdir / name)
            for zdir in sorted(self._base_dir.glob("zapret2-*/binaries/windows-x86"), reverse=True):
                search_paths.append(zdir / name)
        else:
            for zdir in sorted(self._base_dir.glob("zapret2-*/binaries/linux-*"), reverse=True):
                search_paths.insert(0, zdir / "nfqws2")

        for p in search_paths:
            if p.exists():
                logger.info("Found zapret2 binary: %s", p)
                return p

        logger.warning("zapret2 binary '%s' not found", name)
        return None

    def _resolve_lua_dir(self) -> Optional[Path]:
        """Find zapret2 Lua library directory."""
        # Search in zapret2 directory
        for zdir in sorted(self._base_dir.glob("zapret2-*/lua"), reverse=True):
            if (zdir / "zapret-lib.lua").exists():
                logger.info("Found zapret2 Lua libs: %s", zdir)
                return zdir

        # Check project lua dir
        local = self._base_dir / "lua"
        if (local / "zapret-lib.lua").exists():
            return local

        logger.warning("zapret2 Lua libraries not found")
        return None
