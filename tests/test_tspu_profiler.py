"""Tests for brain/tspu_profiler.py — Russian-network TSPU fallback.

Live run 2026-05-03 (svoboda.log): the profiler ran AFTER the cached strategy
was already applied, youtube.com answered 301 through the bypass, the probe
concluded "HTTPS not blocked" and returned dpi_type=unknown for er-telecom.
run_real.py gates the no-fake policy on dpi_type.startswith("tspu"), so the
policy silently switched off on the primary test ISP. These tests pin the fix:
a Russian network is always classified as TSPU, and a probe that runs behind
an active bypass is marked inconclusive instead of "not blocked".
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.tspu_profiler import (  # noqa: E402
    RU_ISPS, TSPUProfile, TSPUProfiler, is_russian_network,
)


class TestIsRussianNetwork(unittest.TestCase):
    def test_country_code(self):
        self.assertTrue(is_russian_network("RU"))
        self.assertTrue(is_russian_network("ru"))
        self.assertTrue(is_russian_network(" RU "))
        self.assertFalse(is_russian_network("LV"))
        self.assertFalse(is_russian_network(""))

    def test_known_isp_names(self):
        for isp in RU_ISPS:
            self.assertTrue(is_russian_network("", isp), isp)
        self.assertTrue(is_russian_network("", "ER-Telecom"))
        self.assertFalse(is_russian_network("", "unknown"))
        self.assertFalse(is_russian_network("LV", "baykov"))


class TestClassification(unittest.TestCase):
    def setUp(self):
        self.p = TSPUProfiler(timeout=1)

    def test_inconclusive_probe_on_russian_isp_assumes_tspu(self):
        prof = TSPUProfile(isp="er-telecom", country="RU", probe_inconclusive=True)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_stateful")
        self.assertTrue(prof.dpi_type.startswith("tspu"))

    def test_inconclusive_probe_outside_russia_stays_unknown(self):
        prof = TSPUProfile(isp="unknown", country="LV", probe_inconclusive=True)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "unknown")

    def test_not_blocked_on_russian_network_is_still_tspu(self):
        # Host reachable directly (e.g. not in the RKN list) — TSPU is still there.
        prof = TSPUProfile(isp="unknown", country="RU", blocks_tls_sni=False)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_stateful")

    def test_isp_name_alone_is_enough(self):
        prof = TSPUProfile(isp="rostelecom", country="", blocks_tls_sni=False)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_stateful")

    def test_not_blocked_outside_russia_is_unknown(self):
        prof = TSPUProfile(isp="unknown", country="DE", blocks_tls_sni=False)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "unknown")

    def test_behavioural_classification_unchanged(self):
        prof = TSPUProfile(blocks_tls_sni=True, blocks_http_host=False, is_stateful=True)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_stateful")

        prof = TSPUProfile(blocks_tls_sni=True, blocks_http_host=False, is_stateful=False)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_rst")

        prof = TSPUProfile(blocks_tls_sni=True, blocks_http_host=True)
        self.p._classify_dpi_type(prof)
        self.assertEqual(prof.dpi_type, "tspu_full")


class TestProbeBehindBypass(unittest.TestCase):
    def setUp(self):
        self.p = TSPUProfiler(timeout=1)
        self.ok = {"success": True, "http_code": 301, "exit": 0, "error": ""}

    def test_reachable_with_bypass_is_inconclusive(self):
        prof = TSPUProfile()
        with patch.object(self.p, "_curl_probe", return_value=self.ok):
            self.p._probe_dpi_behavior("youtube.com", prof, bypass_active=True)
        self.assertTrue(prof.probe_inconclusive)
        self.assertTrue(prof.blocks_tls_sni)  # default assumption kept

    def test_reachable_without_bypass_means_not_blocked(self):
        prof = TSPUProfile()
        with patch.object(self.p, "_curl_probe", return_value=self.ok):
            self.p._probe_dpi_behavior("youtube.com", prof, bypass_active=False)
        self.assertFalse(prof.probe_inconclusive)
        self.assertFalse(prof.blocks_tls_sni)

    def test_full_profile_on_er_telecom_behind_bypass(self):
        """Exact 2026-05-03 scenario: cached strategy active, probe succeeds."""
        with patch.object(self.p, "_measure_server_distance", return_value=25), \
             patch.object(self.p, "_curl_probe", return_value=self.ok):
            prof = self.p.profile("youtube.com", isp="er-telecom", asn="AS42116",
                                  country="RU", bypass_active=True)
        self.assertTrue(prof.dpi_type.startswith("tspu"), prof.evidence)
        self.assertEqual(prof.country, "RU")

    def test_full_profile_outside_russia_not_blocked(self):
        with patch.object(self.p, "_measure_server_distance", return_value=12), \
             patch.object(self.p, "_curl_probe", return_value=self.ok):
            prof = self.p.profile("youtube.com", isp="unknown", country="lv")
        self.assertEqual(prof.dpi_type, "unknown")
        self.assertEqual(prof.country, "LV")


if __name__ == "__main__":
    unittest.main()
