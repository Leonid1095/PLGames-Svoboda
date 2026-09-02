"""Parity guard: the refactored cleanup must not have LOST a restore step.

`_emergency_cleanup()` used to be a long inline block in run_real.py. It now
delegates to brain/net_cleanup.py so the GUI Stop button can run the identical
steps (TerminateProcess skips the engine's atexit). The old body is kept as
`_legacy_emergency_cleanup()` and is still the import-failure fallback.

If the two diverge, a user's internet stays broken after exit — the worst
failure mode this project has.

The legacy side is checked STATICALLY (by parsing run_real.py), deliberately:
importing run_real at test time would replace sys.stdout with a TextIOWrapper
and, far worse, register its real atexit cleanup — so merely running the test
suite would kill winws2 and rewrite the user's firewall and registry on exit.
The new side is exercised dynamically with everything mocked.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import net_cleanup  # noqa: E402


def _function_source(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(path.read_text(encoding="utf-8"), node) or ""
    raise AssertionError(f"{name} not found in {path.name}")


class _Recorder:
    """Captures subprocess commands and winreg writes.

    ``proxy_server`` is what the registry reports for ProxyServer, so a test can
    play either "Svoboda's own loopback proxy" or "the user's corporate proxy".
    """

    def __init__(self, proxy_server: str = "127.0.0.1:1080"):
        self.commands: list[list[str]] = []
        self.reg_writes: list[tuple] = []
        self.reg_deletes: list[str] = []
        self.proxy_server = proxy_server

    def run(self, cmd, *a, **kw):
        self.commands.append([str(c) for c in cmd])
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        return r

    def _query(self, key, name):
        if name == "AutoConfigURL":
            return ("http://127.0.0.1/proxy.pac", 1)
        if name == "ProxyServer":
            if self.proxy_server is None:
                raise FileNotFoundError(name)
            return (self.proxy_server, 1)
        raise FileNotFoundError(name)

    def fake_winreg(self):
        wr = MagicMock()
        wr.HKEY_CURRENT_USER = 0
        wr.KEY_ALL_ACCESS = 0
        wr.REG_DWORD = 4
        wr.OpenKey.return_value = MagicMock()
        wr.QueryValueEx.side_effect = self._query
        wr.SetValueEx.side_effect = lambda key, name, r, typ, val: self.reg_writes.append((name, val))
        wr.DeleteValue.side_effect = lambda key, name: self.reg_deletes.append(name)
        return wr

    def flat(self) -> str:
        return "\n".join(" ".join(c) for c in self.commands)


def _capture_new_cleanup(proxy_server: str = "127.0.0.1:1080") -> _Recorder:
    rec = _Recorder(proxy_server)
    with patch.object(subprocess, "run", rec.run), \
         patch.object(net_cleanup.platform, "system", return_value="Windows"), \
         patch.dict(sys.modules, {"winreg": rec.fake_winreg(), "ctypes": MagicMock()}), \
         patch("brain.dns_fixer.remove_hosts_entries", return_value=True), \
         patch("brain.status_writer.write_status"):
        net_cleanup.cleanup_network(notify_gui=True)
    return rec


class TestLegacyStillDocumentsTheSteps(unittest.TestCase):
    """Sanity: the legacy body we are comparing against still exists."""

    def setUp(self):
        self.legacy = _function_source(BASE_DIR / "run_real.py", "_legacy_emergency_cleanup")

    def test_legacy_present_and_nonempty(self):
        self.assertGreater(len(self.legacy.splitlines()), 20)

    def test_legacy_steps_are_the_ones_we_check(self):
        for needle in ("Svoboda Block QUIC", "winws2.exe", "gost.exe",
                       "CertificateRevocation", "AutoConfigURL", "ProxyEnable",
                       "remove_hosts_entries"):
            self.assertIn(needle, self.legacy, f"legacy cleanup no longer does {needle}")


class TestNewCleanupCoversLegacy(unittest.TestCase):
    def setUp(self):
        self.rec = _capture_new_cleanup()

    def test_kills_engine_processes(self):
        for proc in ("winws2.exe", "gost.exe"):
            self.assertIn(proc, self.rec.flat(), f"new cleanup lost: kill {proc}")

    def test_removes_quic_firewall_rule(self):
        self.assertIn("Svoboda Block QUIC", self.rec.flat())
        self.assertIn("delete", self.rec.flat())

    def test_restores_certificate_revocation(self):
        self.assertIn(("CertificateRevocation", 1), self.rec.reg_writes)

    def test_removes_our_pac_and_our_loopback_proxy(self):
        self.assertIn("AutoConfigURL", self.rec.reg_deletes)
        self.assertIn(("ProxyEnable", 0), self.rec.reg_writes)

    def test_does_not_disable_a_proxy_that_is_not_ours(self):
        """A user whose only route out is a corporate proxy must keep it.
        Cleanup runs on every engine exit AND every GUI Stop, so blanket-
        clearing ProxyEnable would leave them with no internet."""
        rec = _capture_new_cleanup(proxy_server="proxy.corp.example.com:3128")
        self.assertNotIn(("ProxyEnable", 0), rec.reg_writes)
        # our own PAC is still removed
        self.assertIn("AutoConfigURL", rec.reg_deletes)

    def test_no_proxy_configured_is_still_cleared(self):
        rec = _capture_new_cleanup(proxy_server=None)
        self.assertIn(("ProxyEnable", 0), rec.reg_writes)

    def test_adds_ciadpi_kill_and_dns_flush(self):
        """Additions over legacy: ByeDPI is ours too, and DNS must be flushed."""
        self.assertIn("ciadpi.exe", self.rec.flat())
        self.assertIn("flushdns", self.rec.flat())

    def test_reports_every_step(self):
        rec = _Recorder()
        with patch.object(subprocess, "run", rec.run), \
             patch.object(net_cleanup.platform, "system", return_value="Windows"), \
             patch.dict(sys.modules, {"winreg": rec.fake_winreg(), "ctypes": MagicMock()}), \
             patch("brain.dns_fixer.remove_hosts_entries", return_value=True), \
             patch("brain.status_writer.write_status"):
            result = net_cleanup.cleanup_network(notify_gui=False)
        for step in ("quic_rule", "cert_revocation", "processes", "pac_proxy",
                     "hosts_file", "dns_flush"):
            self.assertIn(step, result)


class TestEngineWiring(unittest.TestCase):
    """Checked as source text — importing run_real would arm its real atexit."""

    def setUp(self):
        self.src = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")

    def test_emergency_cleanup_delegates_and_falls_back(self):
        dispatch = _function_source(BASE_DIR / "run_real.py", "_emergency_cleanup")
        self.assertIn("from brain.net_cleanup import cleanup_network", dispatch)
        self.assertIn("cleanup_network(notify_gui=True)", dispatch)
        # Two fallbacks: import failure and runtime failure.
        self.assertEqual(dispatch.count("_legacy_emergency_cleanup()"), 2, dispatch)

    def test_cleanup_registered_on_every_exit_path(self):
        self.assertIn("atexit.register(_emergency_cleanup)", self.src)
        self.assertIn("SetConsoleCtrlHandler", self.src)

    def test_gui_runs_cleanup_after_terminate(self):
        bridge = (BASE_DIR / "gui" / "engine_bridge.py").read_text(encoding="utf-8")
        self.assertIn("from brain.net_cleanup import cleanup_network", bridge)
        self.assertIn("request_stop()", bridge)
        # Cleanup must not be conditional on a graceful exit.
        stop_impl = _function_source(BASE_DIR / "gui" / "engine_bridge.py", "_stop_impl")
        self.assertIn("self._run_cleanup()", stop_impl)

    def test_stale_stop_request_cannot_kill_a_fresh_engine(self):
        """Both sides clear the request before the engine starts running."""
        bridge = (BASE_DIR / "gui" / "engine_bridge.py").read_text(encoding="utf-8")
        start = _function_source(BASE_DIR / "gui" / "engine_bridge.py", "start")
        self.assertIn("clear_stop_request()", start)
        self.assertIn("clear_stop_request()", self.src)


if __name__ == "__main__":
    unittest.main()
