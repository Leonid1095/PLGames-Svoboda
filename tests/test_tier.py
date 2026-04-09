"""Tests for brain/tier.py — TierManager license and tier logic."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.tier import TIERS, TierManager


class TestTierDefinitions(unittest.TestCase):
    """Validate tier definitions are consistent."""

    def test_all_tiers_have_required_keys(self):
        required = {"name", "ai_model_display", "ai_interval_seconds", "ai_auto_test",
                     "priority_strategies", "vps_proxy"}
        for tier_name, cfg in TIERS.items():
            for key in required:
                self.assertIn(key, cfg, f"Tier '{tier_name}' missing key '{key}'")

    def test_free_tier_no_proxy(self):
        self.assertFalse(TIERS["free"]["vps_proxy"])
        self.assertFalse(TIERS["free"]["ai_auto_test"])

    def test_pro_tier_has_proxy(self):
        self.assertTrue(TIERS["pro"]["vps_proxy"])
        self.assertTrue(TIERS["pro"]["ai_auto_test"])

    def test_intervals_decreasing(self):
        """Higher tiers should have shorter AI intervals."""
        self.assertGreater(TIERS["free"]["ai_interval_seconds"],
                           TIERS["supporter"]["ai_interval_seconds"])
        self.assertGreater(TIERS["supporter"]["ai_interval_seconds"],
                           TIERS["pro"]["ai_interval_seconds"])


class TestTierManager(unittest.TestCase):
    """Test TierManager logic."""

    def _make_manager(self, config=None, license_data=None):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {"_base_dir": tmp}
            if config:
                cfg.update(config)

            if license_data:
                lic_path = Path(tmp) / "license.json"
                lic_path.write_text(json.dumps(license_data), encoding="utf-8")

            return TierManager(cfg)

    def test_default_tier_is_free(self):
        tm = self._make_manager()
        self.assertEqual(tm.tier, "free")

    def test_valid_pro_license(self):
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        tm = self._make_manager(license_data={"tier": "pro", "until": future})
        self.assertEqual(tm.tier, "pro")

    def test_expired_license_falls_to_free(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        tm = self._make_manager(license_data={"tier": "pro", "until": past})
        self.assertEqual(tm.tier, "free")

    def test_invalid_until_date_falls_to_free(self):
        tm = self._make_manager(license_data={"tier": "pro", "until": "not-a-date"})
        self.assertEqual(tm.tier, "free")

    def test_empty_until_falls_to_free(self):
        tm = self._make_manager(license_data={"tier": "supporter", "until": ""})
        self.assertEqual(tm.tier, "free")

    def test_owner_detection_by_install_id(self):
        tm = self._make_manager(config={
            "install_id": "owner-123",
            "_owner_ids": ["owner-123"],
        })
        self.assertTrue(tm._is_owner())
        self.assertTrue(tm.has_vps_proxy)

    def test_non_owner_no_vps_proxy_on_free(self):
        tm = self._make_manager()
        self.assertFalse(tm.has_vps_proxy)
        self.assertIsNone(tm.proxy_url)

    def test_pro_with_server_proxy_url(self):
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        tm = self._make_manager(license_data={
            "tier": "pro",
            "until": future,
            "proxy_url": "socks5://user:pass@proxy.example.com:443",
        })
        self.assertEqual(tm.proxy_url, "socks5://user:pass@proxy.example.com:443")

    def test_update_license(self):
        tm = self._make_manager()
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        tm.update_license({"tier": "supporter", "until": future})
        self.assertEqual(tm.tier, "supporter")

    def test_ai_scan_timing(self):
        tm = self._make_manager()
        # First scan should always be allowed
        self.assertTrue(tm.should_run_ai_scan())
        tm.mark_ai_scan_done()
        # Immediately after should be denied (free tier = 24h interval)
        self.assertFalse(tm.should_run_ai_scan())

    def test_status_line_free(self):
        tm = self._make_manager()
        line = tm.get_status_line()
        self.assertIn("FREE", line)
        self.assertIn("plgames-ai", line)

    def test_status_line_supporter(self):
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        tm = self._make_manager(license_data={"tier": "supporter", "until": future})
        line = tm.get_status_line()
        self.assertIn("SUPPORTER", line)

    def test_embedded_proxy_returns_empty(self):
        """Security: embedded proxy fallback must return empty string."""
        result = TierManager._decode_embedded_proxy()
        self.assertEqual(result, "")

    def test_owner_proxy_url_none_when_no_server_url(self):
        """Owner without server-delivered URL should get None (not hardcoded creds)."""
        tm = self._make_manager(config={
            "install_id": "owner-123",
            "_owner_ids": ["owner-123"],
        })
        # No license with proxy_url, and _decode_embedded_proxy returns ""
        self.assertIsNone(tm.proxy_url)

    def test_license_persistence(self):
        """License should be saved to disk and reloaded."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {"_base_dir": tmp}
            tm1 = TierManager(cfg)
            future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
            tm1.update_license({"tier": "pro", "until": future})

            # Create new manager from same directory
            tm2 = TierManager(cfg)
            self.assertEqual(tm2.tier, "pro")

    def test_corrupt_license_file(self):
        """Corrupt license file should not crash."""
        with tempfile.TemporaryDirectory() as tmp:
            lic_path = Path(tmp) / "license.json"
            lic_path.write_text("NOT VALID JSON {{{", encoding="utf-8")
            tm = TierManager({"_base_dir": tmp})
            self.assertEqual(tm.tier, "free")


if __name__ == "__main__":
    unittest.main()
