"""Tests for brain/netenv.py — proxy-environment hygiene for direct-path tests.

Live incident 2026-09-01: HTTPS_PROXY=http://127.0.0.1:12334 was set on the
dev machine, so every curl check tunnelled through a foreign exit and the ISP
was detected as the proxy's AS. Strategies would have looked "working" while
the real DPI path stayed blocked. These tests pin the guard rails.
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import netenv  # noqa: E402

_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
)


class TestScrubProxyEnv(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _PROXY_VARS}
        # Start from a clean slate — the dev machine itself may have proxies set.
        for k in _PROXY_VARS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_removes_every_proxy_variable(self):
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:12334"
        os.environ["https_proxy"] = "http://127.0.0.1:12334"
        os.environ["ALL_PROXY"] = "socks5://127.0.0.1:1080"
        removed = netenv.scrub_proxy_env()
        # Windows env keys are case-insensitive (os.environ upper-cases them)
        self.assertEqual({k.upper() for k in removed}, {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"})
        for var in _PROXY_VARS:
            self.assertNotIn(var, os.environ)

    def test_noop_when_clean_and_idempotent(self):
        for var in _PROXY_VARS:
            os.environ.pop(var, None)
        self.assertEqual(netenv.scrub_proxy_env(), {})
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:12334"
        self.assertEqual(list(netenv.scrub_proxy_env()), ["HTTPS_PROXY"])
        self.assertEqual(netenv.scrub_proxy_env(), {})  # second call: nothing left

    def test_detect_reports_without_removing(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:12334"
        found = netenv.detect_proxy_env()
        self.assertEqual(found, {"HTTPS_PROXY": "http://127.0.0.1:12334"})
        self.assertIn("HTTPS_PROXY", os.environ)

    def test_curl_direct_flag(self):
        self.assertEqual(tuple(netenv.CURL_DIRECT), ("--noproxy", "*"))

    def test_direct_session_ignores_environment(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:12334"
        s = netenv.direct_session()
        self.assertFalse(s.trust_env)


class TestMeasurementCurlSitesAreDirect(unittest.TestCase):
    """Regression guard: every direct-path curl measurement must carry
    *CURL_DIRECT. Proxy tests (proxy_router, gost, naive, byedpi) pass an
    explicit --proxy and must NOT be touched."""

    MEASUREMENT_MODULES = [
        "brain/tester.py",
        "brain/block_classifier.py",
        "brain/tspu_profiler.py",
        "brain/ech.py",
        "brain/watchdog.py",
    ]

    def test_brain_measurement_modules(self):
        for rel in self.MEASUREMENT_MODULES:
            src = (BASE_DIR / rel).read_text(encoding="utf-8")
            sites = re.findall(r'"curl",\s*"-s",[^\n]*', src)
            self.assertTrue(sites, f"{rel}: expected at least one curl call")
            for site in sites:
                self.assertIn("*CURL_DIRECT", site, f"{rel}: curl call without --noproxy: {site}")
            self.assertIn("from brain.netenv import CURL_DIRECT", src, rel)

    def test_run_real_curl_check_one(self):
        src = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")
        start = src.index("def _curl_check_one(")
        end = src.index("\ndef ", start + 10)
        body = src[start:end]
        self.assertIn('"curl", "-s", *CURL_DIRECT', body)

    def test_engines_scrub_at_start(self):
        for rel in ("run_real.py", "run_shadow.py"):
            src = (BASE_DIR / rel).read_text(encoding="utf-8")
            self.assertIn("scrub_proxy_env()", src, rel)


if __name__ == "__main__":
    unittest.main()
