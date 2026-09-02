"""Tests for the deep-fetch check — TSPU "16 KB freeze" detection.

Since June 2025 TSPU lets a TLS connection to suspect foreign/CDN IPs pass
~16 KB and then silently stalls it, with no RST (net4people/bbs#490,
youtubeUnblock#356, zapret discussion #2075). A >512-byte body check scores
that as a working strategy, so YouTube "works" but no video plays. These tests
pin the signature: timed out holding a partial body in the 8-32 KB window.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.tester import (  # noqa: E402
    _DEEP_FETCH_BYTES, _FREEZE_MAX_BYTES, _FREEZE_MIN_BYTES,
    ConnectionTester, HostTestResult,
)


class _FakeCurl:
    """subprocess.run stand-in returning a curl -w line."""

    def __init__(self, code, seconds, speed, size, returncode=0):
        self.stdout = f"{code}|{seconds}|{speed}|{size}"
        self.returncode = returncode
        self.stderr = ""


def _tester():
    cfg = {"test_hosts": ["youtube.com"], "throttle_threshold_ms": 3000}
    return ConnectionTester(cfg, mock=True)


class TestFreezeDetection(unittest.TestCase):
    def _run(self, **kw):
        t = _tester()
        with patch.object(subprocess, "run", return_value=_FakeCurl(**kw)):
            return t._curl_test_h2_stream("youtube.com", timeout_override=10)

    def test_16kb_freeze_is_a_failure(self):
        """206 + timeout + ~16 KB body = the documented TSPU stall."""
        r = self._run(code=206, seconds=10.0, speed=1638, size=16384, returncode=28)
        self.assertFalse(r.success)
        self.assertEqual(r.error_type, "freeze16k")

    def test_freeze_window_boundaries(self):
        for size in (_FREEZE_MIN_BYTES, 16384, _FREEZE_MAX_BYTES):
            r = self._run(code=206, seconds=10.0, speed=100, size=size, returncode=28)
            self.assertEqual(r.error_type, "freeze16k", f"size={size}")

    def test_tiny_stall_is_truncated_not_freeze(self):
        r = self._run(code=206, seconds=10.0, speed=50, size=1024, returncode=28)
        self.assertFalse(r.success)
        self.assertEqual(r.error_type, "truncated")

    def test_large_partial_is_truncated_not_freeze(self):
        r = self._run(code=206, seconds=10.0, speed=5000, size=50000, returncode=28)
        self.assertFalse(r.success)
        self.assertEqual(r.error_type, "truncated")

    def test_complete_fast_download_is_clean_success(self):
        r = self._run(code=206, seconds=0.4, speed=160000, size=_DEEP_FETCH_BYTES)
        self.assertTrue(r.success)
        self.assertEqual(r.error_type, "")

    def test_short_resource_that_completes_is_success(self):
        """A 12 KB page that ends cleanly (exit 0) must NOT be called a freeze."""
        r = self._run(code=200, seconds=0.3, speed=40000, size=12000, returncode=0)
        self.assertTrue(r.success)
        self.assertEqual(r.error_type, "")

    def test_slow_full_download_is_throttled(self):
        r = self._run(code=206, seconds=6.0, speed=4000, size=_DEEP_FETCH_BYTES)
        self.assertTrue(r.success)
        self.assertEqual(r.error_type, "throttled")

    def test_rst_is_still_rst(self):
        r = self._run(code=0, seconds=0.2, speed=0, size=0, returncode=7)
        self.assertFalse(r.success)
        self.assertEqual(r.error_type, "rst")

    def test_malformed_curl_output_does_not_raise(self):
        t = _tester()
        bad = _FakeCurl(code=0, seconds=0, speed=0, size=0)
        bad.stdout = "garbage"
        with patch.object(subprocess, "run", return_value=bad):
            r = t._curl_test_h2_stream("youtube.com")
        self.assertFalse(r.success)

    def test_requests_the_full_range(self):
        t = _tester()
        with patch.object(subprocess, "run", return_value=_FakeCurl(206, 0.3, 200000, _DEEP_FETCH_BYTES)) as run:
            t._curl_test_h2_stream("youtube.com")
        cmd = run.call_args[0][0]
        self.assertIn(f"0-{_DEEP_FETCH_BYTES - 1}", cmd)
        self.assertIn("%{http_code}|%{time_total}|%{speed_download}|%{size_download}", cmd)
        self.assertIn("--noproxy", cmd)


class TestFreezeIsPenalised(unittest.TestCase):
    def test_freeze_weighted_like_timeout(self):
        t = _tester()
        ok = [HostTestResult(host="a", success=True, http_code=200, latency_ms=300)]
        frozen = [HostTestResult(host="h2:a", success=False, error_type="freeze16k")]
        timed = [HostTestResult(host="h2:a", success=False, error_type="timeout")]
        f_freeze = t._compute_fitness(ok + frozen, 1, 2)
        f_timeout = t._compute_fitness(ok + timed, 1, 2)
        self.assertAlmostEqual(f_freeze, f_timeout, places=6)

    def test_freeze_scores_below_clean_success(self):
        t = _tester()
        ok = [HostTestResult(host="a", success=True, http_code=200, latency_ms=300)]
        clean = ok + [HostTestResult(host="h2:a", success=True, http_code=206, latency_ms=400)]
        frozen = ok + [HostTestResult(host="h2:a", success=False, error_type="freeze16k")]
        self.assertGreater(t._compute_fitness(clean, 2, 2), t._compute_fitness(frozen, 1, 2))


if __name__ == "__main__":
    unittest.main()
