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
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.tester")

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

    def __init__(self, config: dict, mock: bool = True):
        self.config = config
        self.mock = mock
        self.hosts: list[str] = config.get("test_hosts", ["youtube.com", "discord.com", "x.com"])
        self.trials: int = config.get("test_trials", 3)
        self.timeout: int = config.get("test_timeout", 5)
        self._base_dir = Path(config.get("_base_dir", "."))
        self._is_windows = platform.system() == "Windows"
        self._zapret_bin = self._resolve_zapret_binary()
        self._zapret_dir = self._zapret_bin.parent if self._zapret_bin else None
        self._lua_dir = self._resolve_lua_dir()
        self._shadow_process: Optional[subprocess.Popen] = None

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
        """Real testing through shadow zapret2 instance + curl."""
        if not self._zapret_bin:
            logger.error("zapret2 binary not found, falling back to mock")
            return self._test_mock(flags)

        try:
            # 1. Start shadow zapret2 with strategy
            self._start_shadow_zapret(flags)

            # 2. Wait for zapret2 to initialize
            time.sleep(2)

            if self._shadow_process is None or self._shadow_process.poll() is not None:
                logger.error("Shadow zapret2 failed to start")
                return 0.0

            # 3. Test each host
            total_tests = len(self.hosts) * self.trials
            successful = 0

            for host in self.hosts:
                for trial in range(self.trials):
                    if self._curl_test(host):
                        successful += 1

            fitness = successful / total_tests if total_tests > 0 else 0.0

        except Exception as exc:
            logger.error("Test failed: %s", exc)
            fitness = 0.0

        finally:
            # 4. Stop shadow zapret2
            self._stop_shadow_zapret()

        logger.info(
            "Real test: flags=%s fitness=%.3f (%d/%d)",
            " | ".join(flags), fitness, successful, total_tests,
        )
        return round(fitness, 3)

    # ─── Shadow zapret2 management ─────────────────────────────────────────

    def _start_shadow_zapret(self, flags: list[str]) -> None:
        """Start separate zapret2 instance for testing."""
        self._stop_shadow_zapret()

        cmd = [str(self._zapret_bin)]

        if self._is_windows:
            # Windows: winws2 with WinDivert
            cmd.extend([
                "--wf-tcp-out=80,443",
                "--wf-udp-out=443",
            ])
        else:
            # Linux: nfqws2 with netfilter queue
            cmd.extend(["--qnum=200"])
            self._setup_linux_shadow_nfqueue()

        # Load Lua libraries (required for zapret2)
        if self._lua_dir:
            lib_path = self._lua_dir / "zapret-lib.lua"
            antidpi_path = self._lua_dir / "zapret-antidpi.lua"
            if lib_path.exists():
                cmd.append(f"--lua-init=@{lib_path}")
            if antidpi_path.exists():
                cmd.append(f"--lua-init=@{antidpi_path}")

        # TLS filters
        cmd.extend([
            "--filter-tcp=80,443",
            "--filter-l7=tls,http",
            "--out-range=-d10",
        ])

        # Payload filters + strategy calls for TLS
        cmd.append("--payload=tls_client_hello,http_req")

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
        """Stop shadow zapret2 instance."""
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
                proc.wait(timeout=2)

            logger.debug("Shadow zapret2 stopped (pid=%d)", proc.pid)
        except Exception as exc:
            logger.warning("Error stopping shadow zapret2: %s", exc)

        if not self._is_windows:
            self._cleanup_linux_shadow_nfqueue()

    # ─── curl testing ──────────────────────────────────────────────────────

    def _curl_test(self, host: str) -> bool:
        """Single curl test. Returns True if successful."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(self.timeout),
                    f"https://{host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 3,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    code = int(result.stdout.strip())
                    success = code in _SUCCESS_CODES
                    logger.debug("curl %s: HTTP %d (%s)", host, code, "OK" if success else "FAIL")
                    return success
                except ValueError:
                    pass

        except subprocess.TimeoutExpired:
            logger.debug("curl %s: timeout", host)
        except FileNotFoundError:
            logger.error("curl not found in PATH")
        except Exception as exc:
            logger.debug("curl %s: error %s", host, exc)

        return False

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
