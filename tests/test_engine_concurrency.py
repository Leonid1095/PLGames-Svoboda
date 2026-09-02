"""Guards against running two winws2 instances at once.

One WinDivert driver, one instance. Every defect below was live in the tree and
produces the same symptom: two winws2 processes on the wire, which CLAUDE.md
records as breaking the user's internet.

* The GA applied a strategy permanently from its per-generation callback, while
  ga.evolve() kept starting shadow instances for the remaining generations.
* The health monitor read the ~1-4s window where _active_process still points
  at a process a deliberate stop had just terminated, called it a crash, and
  respawned on top of the shadow tester.
* Nothing stopped a second engine from starting at all: the GUI's QSharedMemory
  guard covers only the GUI, so an orphaned engine plus a fresh launch gave two.

Checked as source text where the alternative would be importing run_real, which
arms its real atexit cleanup on the machine running the tests.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

SRC = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")


def _function_source(name: str) -> str:
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(SRC, node) or ""
    raise AssertionError(f"{name} not found in run_real.py")


class TestNoInterimApplyDuringEvolution(unittest.TestCase):
    def test_on_gen_does_not_start_winws2(self):
        body = _function_source("on_gen")
        self.assertNotIn("_start_permanent_zapret", body,
                         "on_gen runs between generations while the shadow tester is "
                         "still starting winws2 — it must not start a permanent one")

    def test_reason_is_documented(self):
        body = _function_source("on_gen")
        self.assertIn("WinDivert", body)


class TestMaintenanceFlag(unittest.TestCase):
    def test_flag_exists_and_is_an_event(self):
        self.assertIn("_zapret_maintenance = threading.Event()", SRC)

    def test_deliberate_stop_sets_it(self):
        stop = _function_source("_stop_permanent_zapret")
        self.assertIn("_zapret_maintenance.set()", stop)

    def test_successful_start_clears_it(self):
        start = _function_source("_start_permanent_zapret")
        self.assertIn("_zapret_maintenance.clear()", start)

    def test_health_monitor_honours_it(self):
        mon = _function_source("_winws2_health_monitor")
        self.assertIn("_zapret_maintenance.is_set()", mon)
        # and requires more than one dead reading before respawning
        self.assertIn("dead_reads", mon)
        self.assertIn("_start_permanent_zapret", mon, "monitor should still respawn a real crash")

    def test_monitor_checks_flag_before_declaring_a_crash(self):
        mon = _function_source("_winws2_health_monitor")
        flag_at = mon.index("_zapret_maintenance.is_set()")
        respawn_at = mon.index("_start_permanent_zapret")
        self.assertLess(flag_at, respawn_at)


class TestSingleInstanceGuard(unittest.TestCase):
    def test_guard_is_checked_before_touching_the_network(self):
        main = _function_source("main")
        guard_at = main.index("_acquire_single_instance()")
        for later in ("_start_permanent_zapret", "netsh", "scrub_proxy_env"):
            if later in main:
                self.assertLess(guard_at, main.index(later),
                                f"instance guard must run before {later}")

    def test_guard_fails_open_off_windows(self):
        fn = _function_source("_acquire_single_instance")
        self.assertIn('platform.system() != "Windows"', fn)
        self.assertIn("return True", fn)

    @unittest.skipUnless(sys.platform == "win32", "named mutex is Windows-only")
    def test_second_instance_is_refused(self):
        """Hold the mutex in a child process, then try to take it here."""
        child = textwrap.dedent(f"""
            import sys, time
            sys.argv = ['run_real.py']
            sys.path.insert(0, r"{BASE_DIR}")
            import run_real
            run_real._acquire_single_instance()
            time.sleep(20)
        """)
        proc = subprocess.Popen([sys.executable, "-c", child],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Give the child time to create the mutex.
            deadline = __import__("time").monotonic() + 15
            acquired = True
            while __import__("time").monotonic() < deadline:
                probe = subprocess.run(
                    [sys.executable, "-c", textwrap.dedent(f"""
                        import sys
                        sys.argv = ['run_real.py']
                        sys.path.insert(0, r"{BASE_DIR}")
                        import run_real
                        raise SystemExit(0 if run_real._acquire_single_instance() else 3)
                    """)],
                    capture_output=True, timeout=60)
                if probe.returncode == 3:
                    acquired = False
                    break
                __import__("time").sleep(1)
            self.assertFalse(acquired, "a second engine must be refused while one holds the mutex")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()


class TestExitPathsReleaseZapret(unittest.TestCase):
    """run-real-safety.md: every return/break path must stop winws2 if one is
    running. Leaving it applied also leaves the QUIC firewall rule and
    CertificateRevocation=0 in place — while _pause_exit blocks on a console."""

    def test_ip_blocked_early_returns_stop_zapret(self):
        main = _function_source("main")
        marker = "All blocked sites are IP-blocked"
        self.assertIn(marker, main)
        # the stop must appear before the branch, not after one of the returns
        stop_at = main.rindex("_stop_permanent_zapret", 0, main.index(marker))
        self.assertGreater(stop_at, 0)
        segment = main[stop_at:main.index(marker) + 800]
        self.assertIn("_active_process = None", segment)

    def test_monitoring_mode_releases_classification_instance(self):
        """_monitoring_loop only activates recovery while _active_process is
        None, so entering it holding the classification instance made the guard
        permanently false."""
        main = _function_source("main")
        idx = main.index("All sites accessible without DPI bypass")
        segment = main[idx:idx + 700]
        self.assertIn("_stop_permanent_zapret", segment)
        self.assertIn("_active_process = None", segment)
        self.assertLess(segment.index("_stop_permanent_zapret"), segment.index("_monitoring_loop("))

    def test_failed_host_solve_keeps_existing_overrides(self):
        self.assertNotIn("_wd_extra = solver.build_extra_profiles(lua_dir) if solved else None", SRC)
        self.assertIn("else _wd_extra", SRC)


if __name__ == "__main__":
    unittest.main()
