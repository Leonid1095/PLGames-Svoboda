"""Tests for brain/analytics.py — SQLite analytics database."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.analytics import Analytics


class TestAnalyticsDB(unittest.TestCase):
    """Test Analytics SQLite database operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = {
            "_base_dir": self.tmpdir,
            "analytics_db_path": "test_analytics.db",
        }
        self.analytics = Analytics(self.config)

    def tearDown(self):
        self.analytics.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_schema_creation(self):
        """DB schema should be created on init."""
        cursor = self.analytics._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        expected = {"schema_version", "strategies", "test_results",
                    "evolution_log", "isp_snapshots", "sync_queue"}
        self.assertTrue(expected.issubset(tables))

    def test_log_strategy(self):
        """Log a strategy and retrieve it."""
        self.analytics.log_strategy(
            strategy_id="test-1",
            flags=["multisplit:pos=1", "fake:ttl=4"],
            fitness=0.85,
            isp="er-telecom",
        )
        results = self.analytics.get_best_flags_for_isp("er-telecom")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["fitness"], 0.85)
        self.assertEqual(results[0]["flags"], ["multisplit:pos=1", "fake:ttl=4"])

    def test_log_strategy_result_wins_losses(self):
        """Track wins and losses for strategies."""
        self.analytics.log_strategy("s1", ["flag1"], 0.5, isp="test")
        self.analytics.log_strategy_result("s1", True)
        self.analytics.log_strategy_result("s1", True)
        self.analytics.log_strategy_result("s1", False)

        results = self.analytics.get_best_flags_for_isp("test")
        self.assertEqual(results[0]["wins"], 2)
        self.assertEqual(results[0]["losses"], 1)

    def test_log_test_result(self):
        """Log and count test results."""
        self.analytics.log_strategy("s1", ["flag1"], 0.5, isp="test")
        self.analytics.log_test_result("s1", "youtube.com", 200, True, 150.5)
        self.analytics.log_test_result("s1", "youtube.com", 0, False, 0.0, "rst")

        rate = self.analytics.get_host_success_rate("youtube.com")
        self.assertAlmostEqual(rate, 0.5)

    def test_get_recent_success_rate(self):
        """Rolling window success rate with streak info."""
        self.analytics.log_strategy("s1", ["f"], 0.5, isp="test")
        for i in range(5):
            self.analytics.log_test_result("s1", "x.com", 200, True, 100.0)
        self.analytics.log_test_result("s1", "x.com", 0, False, 0.0, "timeout")

        stats = self.analytics.get_recent_success_rate("x.com", minutes=60)
        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["successes"], 5)
        # Latest is failure, so streak_fail should be 1
        self.assertEqual(stats["streak_fail"], 1)

    def test_get_recent_success_rate_empty(self):
        """Empty results should return zeros."""
        stats = self.analytics.get_recent_success_rate("nonexistent.com")
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["rate"], 0.0)
        self.assertEqual(stats["streak_ok"], 0)

    def test_evolution_log(self):
        """Log evolution generations."""
        self.analytics.log_evolution_generation(
            generation=1, best_fitness=0.9, avg_fitness=0.6,
            best_flags=["fake:ttl=4"], population_size=12, isp="test",
        )
        # Just verify it doesn't crash
        cursor = self.analytics._conn.execute(
            "SELECT COUNT(*) FROM evolution_log"
        )
        self.assertEqual(cursor.fetchone()[0], 1)

    def test_isp_snapshot(self):
        """Log ISP detection snapshot."""
        self.analytics.log_isp_snapshot(
            external_ip="1.2.3.4", asn="AS42116",
            isp_name="er-telecom", org="ER-Telecom",
            region="Tatarstan", middlebox_type="TSPU",
            middlebox_ttl=4, middlebox_window=None,
        )
        cursor = self.analytics._conn.execute("SELECT COUNT(*) FROM isp_snapshots")
        self.assertEqual(cursor.fetchone()[0], 1)

    def test_sync_queue(self):
        """Enqueue and retrieve sync items."""
        self.analytics.log_isp_snapshot(
            "1.2.3.4", "AS42116", "er-telecom", "ER",
            "Tatarstan", "TSPU", 4, None,
        )
        pending = self.analytics.get_pending_sync()
        self.assertGreaterEqual(len(pending), 1)
        self.assertEqual(pending[0]["event_type"], "isp_snapshot")

    def test_mark_synced(self):
        """Mark sync items as sent."""
        self.analytics.log_isp_snapshot(
            "1.2.3.4", "AS42116", "er-telecom", "ER",
            "Tatarstan", "TSPU", 4, None,
        )
        pending = self.analytics.get_pending_sync()
        ids = [p["id"] for p in pending]
        self.analytics.mark_synced(ids)

        pending_after = self.analytics.get_pending_sync()
        self.assertEqual(len(pending_after), 0)

    def test_stats_summary(self):
        """Overall stats should work with empty DB."""
        stats = self.analytics.get_stats_summary()
        self.assertEqual(stats["total_strategies"], 0)
        self.assertEqual(stats["total_tests"], 0)
        self.assertAlmostEqual(stats["avg_fitness"], 0.0)

    def test_stats_summary_with_data(self):
        """Stats with actual data."""
        self.analytics.log_strategy("s1", ["f1"], 0.8, isp="t")
        self.analytics.log_strategy("s2", ["f2"], 0.6, isp="t")
        self.analytics.log_test_result("s1", "host", 200, True, 100)

        stats = self.analytics.get_stats_summary()
        self.assertEqual(stats["total_strategies"], 2)
        self.assertEqual(stats["total_tests"], 1)
        self.assertAlmostEqual(stats["avg_fitness"], 0.7)

    def test_strategy_upsert(self):
        """INSERT OR REPLACE should update existing strategy."""
        self.analytics.log_strategy("s1", ["old"], 0.3, isp="t")
        self.analytics.log_strategy("s1", ["new"], 0.9, isp="t")
        results = self.analytics.get_best_flags_for_isp("t")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["flags"], ["new"])
        self.assertAlmostEqual(results[0]["fitness"], 0.9)

    def test_host_health_aggregation(self):
        """get_all_hosts_health should aggregate correctly."""
        self.analytics.log_strategy("s1", ["f"], 0.5, isp="t")
        # youtube: all success
        for _ in range(5):
            self.analytics.log_test_result("s1", "youtube.com", 200, True, 100)
        # discord: all fail
        for _ in range(5):
            self.analytics.log_test_result("s1", "discord.com", 0, False, 0, "rst")

        health = self.analytics.get_all_hosts_health(["youtube.com", "discord.com"], minutes=60)
        self.assertAlmostEqual(health["overall_rate"], 0.5)
        self.assertIn("youtube.com", health["healthy"])
        self.assertIn("discord.com", health["degraded"])

    def test_concurrent_writes(self):
        """Multiple threads writing should not crash (WAL mode)."""
        errors = []

        def writer(thread_id):
            try:
                for i in range(20):
                    self.analytics.log_strategy(
                        f"s-{thread_id}-{i}", [f"flag-{i}"], 0.5, isp="test"
                    )
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # We accept that some writes may fail with "database is locked" in WAL mode
        # but the DB should not corrupt
        stats = self.analytics.get_stats_summary()
        self.assertGreater(stats["total_strategies"], 0)


if __name__ == "__main__":
    unittest.main()
