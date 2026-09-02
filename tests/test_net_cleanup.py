"""Tests for brain/net_cleanup.py — the shared network-restore steps.

Everything is mocked: these tests must never touch the firewall, registry,
processes or the hosts file of the machine running the suite.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import net_cleanup as nc  # noqa: E402


class TestCleanupNetwork(unittest.TestCase):
    def test_runs_every_step_and_never_raises(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return True

        with patch.object(nc, "_run", fake_run), \
             patch.object(nc.platform, "system", return_value="Windows"), \
             patch.object(nc, "restore_certificate_revocation", return_value=True), \
             patch.object(nc, "remove_pac_proxy", return_value=True), \
             patch.object(nc, "remove_hosts_fix", return_value=True), \
             patch("brain.status_writer.write_status") as ws:
            res = nc.cleanup_network(notify_gui=True)

        self.assertTrue(all(res.values()), res)
        flat = [" ".join(c) for c in calls]
        self.assertTrue(any("Svoboda Block QUIC" in c for c in flat), "QUIC rule must be removed")
        for name in ("winws2.exe", "gost.exe", "ciadpi.exe"):
            self.assertTrue(any(name in c and "taskkill" in c for c in flat), name)
        self.assertTrue(any("flushdns" in c for c in flat))
        ws.assert_called_once()
        self.assertEqual(ws.call_args.kwargs.get("state"), "stopped")

    def test_step_failure_does_not_stop_the_rest(self):
        with patch.object(nc, "remove_quic_block", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                # individual helpers may raise only when called directly...
                nc.remove_quic_block()
        # ...but the orchestrator wraps them: simulate a failing subprocess layer
        with patch.object(nc.subprocess, "run", side_effect=OSError("no netsh")), \
             patch.object(nc, "restore_certificate_revocation", return_value=False), \
             patch.object(nc, "remove_pac_proxy", return_value=False), \
             patch.object(nc, "remove_hosts_fix", return_value=False):
            res = nc.cleanup_network(notify_gui=False)
        self.assertIn("quic_rule", res)
        self.assertIn("dns_flush", res)

    def test_engine_and_gui_share_the_implementation(self):
        engine = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")
        bridge = (BASE_DIR / "gui" / "engine_bridge.py").read_text(encoding="utf-8")
        self.assertIn("from brain.net_cleanup import cleanup_network", engine)
        self.assertIn("from brain.net_cleanup import cleanup_network", bridge)
        # legacy inline fallback must still exist in the engine
        self.assertIn("def _legacy_emergency_cleanup", engine)


if __name__ == "__main__":
    unittest.main()
