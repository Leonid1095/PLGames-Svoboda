"""Tests for brain/status_writer.py — engine<->GUI IPC incl. graceful stop."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import status_writer as sw  # noqa: E402


class _TmpRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self._patches = [
            patch.object(sw, "_DIR", d),
            patch.object(sw, "STATUS_PATH", os.path.join(d, "status.json")),
            patch.object(sw, "STOP_REQUEST_PATH", os.path.join(d, "stop.request")),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self.tmp.cleanup()


class TestStatus(_TmpRuntime):
    def test_write_merges_and_stamps(self):
        sw.write_status(state=sw.STATE_STARTING, isp="er-telecom")
        sw.write_status(sites="3/4")
        st = sw.read_status()
        self.assertEqual(st["state"], sw.STATE_STARTING)
        self.assertEqual(st["isp"], "er-telecom")
        self.assertEqual(st["sites"], "3/4")
        self.assertIn("ts", st)

    def test_read_missing_or_corrupt_is_empty(self):
        self.assertEqual(sw.read_status(), {})
        Path(sw.STATUS_PATH).write_text("{not json", encoding="utf-8")
        self.assertEqual(sw.read_status(), {})

    def test_clear(self):
        sw.write_status(state=sw.STATE_ACTIVE)
        sw.clear_status()
        self.assertEqual(sw.read_status(), {})
        sw.clear_status()  # idempotent


class TestStopRequest(_TmpRuntime):
    def test_roundtrip(self):
        self.assertFalse(sw.stop_requested())
        self.assertTrue(sw.request_stop())
        self.assertTrue(sw.stop_requested())
        sw.clear_stop_request()
        self.assertFalse(sw.stop_requested())
        sw.clear_stop_request()  # idempotent

    def test_request_creates_runtime_dir(self):
        nested = os.path.join(self.tmp.name, "nested")
        with patch.object(sw, "_DIR", nested), \
             patch.object(sw, "STOP_REQUEST_PATH", os.path.join(nested, "stop.request")):
            self.assertTrue(sw.request_stop())
            self.assertTrue(os.path.exists(os.path.join(nested, "stop.request")))

    def test_engine_and_gui_agree_on_contract(self):
        """run_real.py must poll stop_requested(); the bridge must request_stop()."""
        engine = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")
        bridge = (BASE_DIR / "gui" / "engine_bridge.py").read_text(encoding="utf-8")
        self.assertIn("stop_requested()", engine)
        self.assertIn("clear_stop_request()", engine)
        self.assertIn("request_stop()", bridge)
        self.assertIn("cleanup_network", bridge)  # cleanup even after TerminateProcess


if __name__ == "__main__":
    unittest.main()
