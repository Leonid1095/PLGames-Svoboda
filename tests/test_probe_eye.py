"""Tests for brain/probe_eye.py — SMART layer 1 background probing thread.

We don't want to make real network calls in unit tests, so the probe_fn
is mocked. The tests verify wiring: thread lifecycle, host iteration,
analytics logging shape, throughput-aware `usable` extraction, and the
graceful-shutdown contract.
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.analytics import Analytics
from brain.probe_eye import ProbeEye


class TestProbeEye(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.analytics = Analytics({
            "_base_dir": self.tmpdir, "analytics_db_path": "test_eye.db",
        })

    def tearDown(self):
        self.analytics.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_probe_fn(self, response: dict):
        """Build a probe_fn that returns `response` for every call and
        records call args for assertion."""
        calls = []

        def probe(host, timeout):
            calls.append((host, timeout))
            return dict(response)

        return probe, calls

    def test_thread_starts_and_stops(self):
        """Lifecycle: start launches thread, stop joins it cleanly."""
        probe_fn, _ = self._make_probe_fn({"usable": True, "throughput_kbps": 100,
                                            "ttfb_ms": 50, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["a.com"], probe_fn=probe_fn,
                       interval_sec=5)
        eye.start()
        self.assertTrue(eye._thread.is_alive())
        eye.stop()
        self.assertFalse(eye._thread.is_alive())

    def test_sweep_calls_probe_for_each_host(self):
        """One sweep_once invokes probe_fn once per host."""
        probe_fn, calls = self._make_probe_fn({"usable": True, "throughput_kbps": 80,
                                                "ttfb_ms": 30, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["a.com", "b.com", "c.com"],
                       probe_fn=probe_fn)
        eye._sweep_once()
        self.assertEqual(len(calls), 3)
        self.assertEqual({c[0] for c in calls}, {"a.com", "b.com", "c.com"})

    def test_sweep_logs_probes_to_analytics(self):
        """Each successful probe ends up in probe_history."""
        probe_fn, _ = self._make_probe_fn({"usable": True, "throughput_kbps": 200,
                                            "ttfb_ms": 25, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["foo.com"], probe_fn=probe_fn)
        eye._sweep_once()
        baseline = self.analytics.get_probe_baseline("foo.com")
        self.assertEqual(baseline["samples"], 1)
        self.assertAlmostEqual(baseline["throughput_mean_kbps"], 200.0, places=1)

    def test_uses_usable_field_not_just_success(self):
        """Throttled probe (success=True, usable=False) is logged as failure."""
        probe_fn, _ = self._make_probe_fn({
            "usable": False,         # throughput < 10 KB/s → not usable
            "success": True,         # HTTP 200 still
            "throughput_kbps": 5,
            "ttfb_ms": 8000,
            "http_code": 200,
        })
        eye = ProbeEye(self.analytics, hosts=["throttled.com"], probe_fn=probe_fn)
        eye._sweep_once()
        baseline = self.analytics.get_probe_baseline("throttled.com")
        self.assertEqual(baseline["samples"], 1)
        # success_rate counts `usable` not `success` — so 0%, not 100%
        self.assertEqual(baseline["success_rate"], 0.0)

    def test_falls_back_to_success_when_usable_missing(self):
        """Backward-compat: if probe_fn returns no `usable`, use `success`."""
        probe_fn, _ = self._make_probe_fn({
            "success": True, "throughput_kbps": 100, "ttfb_ms": 50, "http_code": 200,
        })
        eye = ProbeEye(self.analytics, hosts=["legacy.com"], probe_fn=probe_fn)
        eye._sweep_once()
        baseline = self.analytics.get_probe_baseline("legacy.com")
        self.assertEqual(baseline["success_rate"], 1.0)

    def test_probe_failure_does_not_crash_loop(self):
        """If probe_fn raises, sweep continues to next host."""
        calls = []

        def flaky_probe(host, timeout):
            calls.append(host)
            if host == "bad.com":
                raise RuntimeError("simulated network blip")
            return {"usable": True, "throughput_kbps": 50, "ttfb_ms": 100,
                    "http_code": 200, "success": True}

        eye = ProbeEye(self.analytics, hosts=["good1.com", "bad.com", "good2.com"],
                       probe_fn=flaky_probe)
        # Should not raise even though one probe throws
        eye._sweep_once()
        self.assertEqual(len(calls), 3)
        # Both good hosts logged; bad one wasn't
        self.assertEqual(self.analytics.get_probe_baseline("good1.com")["samples"], 1)
        self.assertEqual(self.analytics.get_probe_baseline("good2.com")["samples"], 1)
        self.assertEqual(self.analytics.get_probe_baseline("bad.com")["samples"], 0)

    def test_stop_responsive(self):
        """stop() returns within ~2s even if interval_sec is large."""
        probe_fn, _ = self._make_probe_fn({"usable": True, "throughput_kbps": 100,
                                            "ttfb_ms": 50, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["x.com"], probe_fn=probe_fn,
                       interval_sec=60)  # would otherwise sleep 60s
        eye.start()
        time.sleep(0.5)  # let it enter the sleep loop
        t0 = time.time()
        eye.stop(join_timeout=3.0)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 3.0)

    def test_set_hosts_changes_sweep_target(self):
        """set_hosts() swaps the host list mid-flight."""
        probe_fn, calls = self._make_probe_fn({"usable": True, "throughput_kbps": 100,
                                                "ttfb_ms": 50, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["old.com"], probe_fn=probe_fn)
        eye._sweep_once()
        self.assertEqual([c[0] for c in calls], ["old.com"])

        calls.clear()
        eye.set_hosts(["new1.com", "new2.com"])
        eye._sweep_once()
        self.assertEqual({c[0] for c in calls}, {"new1.com", "new2.com"})

    def test_strategy_id_recorded(self):
        """When strategy_id_fn is provided, its return value is logged with the probe."""
        probe_fn, _ = self._make_probe_fn({"usable": True, "throughput_kbps": 100,
                                            "ttfb_ms": 50, "http_code": 200, "success": True})
        eye = ProbeEye(self.analytics, hosts=["sid.com"], probe_fn=probe_fn,
                       strategy_id_fn=lambda: "strat-xyz")
        eye._sweep_once()
        # Read raw row to verify strategy_id field
        with self.analytics._lock:
            cursor = self.analytics._conn.execute(
                "SELECT strategy_id FROM probe_history WHERE host = ?", ("sid.com",),
            )
            row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "strat-xyz")


if __name__ == "__main__":
    unittest.main()
