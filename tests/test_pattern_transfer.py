"""Tests for brain/pattern_transfer.py — SMART layer 2."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.analytics import Analytics
from brain.pattern_transfer import PatternTransfer


class TestPatternTransfer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.analytics = Analytics({
            "_base_dir": self.tmpdir, "analytics_db_path": "test_pt.db",
        })
        self.pt = PatternTransfer(self.analytics)

    def tearDown(self):
        self.analytics.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_schema_created(self):
        cursor = self.analytics._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pattern_transfer'"
        )
        self.assertIsNotNone(cursor.fetchone())

    def test_record_first_win_creates_row(self):
        self.pt.record_pattern_win(
            isp="er-telecom", block_type="TLS_INTERFERENCE",
            flags=["tls_pad:size=2048", "multisplit:pos=1:seqovl=568"],
            fitness=0.95, host="discord.com",
        )
        top = self.pt.get_top_patterns("er-telecom", "TLS_INTERFERENCE")
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["flags"],
                         ["tls_pad:size=2048", "multisplit:pos=1:seqovl=568"])
        self.assertAlmostEqual(top[0]["fitness"], 0.95, places=2)
        self.assertEqual(top[0]["wins"], 1)
        self.assertEqual(top[0]["sample_hosts"], ["discord.com"])

    def test_record_subsequent_wins_increment(self):
        """Same pattern, different hosts → wins++ and host added."""
        for host in ["discord.com", "cdn.discordapp.com", "discord.gg"]:
            self.pt.record_pattern_win(
                isp="er-telecom", block_type="TLS_INTERFERENCE",
                flags=["tls_pad:size=2048"], fitness=0.9, host=host,
            )
        top = self.pt.get_top_patterns("er-telecom", "TLS_INTERFERENCE")
        self.assertEqual(len(top), 1)  # still one row
        self.assertEqual(top[0]["wins"], 3)
        self.assertEqual(set(top[0]["sample_hosts"]),
                         {"discord.com", "cdn.discordapp.com", "discord.gg"})

    def test_duplicate_host_not_added_twice(self):
        for _ in range(5):
            self.pt.record_pattern_win(
                isp="rt", block_type="HTTP2_STREAM_KILL",
                flags=["alpn_strip:strip=h2,h2c"], fitness=0.8, host="x.com",
            )
        top = self.pt.get_top_patterns("rt", "HTTP2_STREAM_KILL")
        self.assertEqual(top[0]["wins"], 5)
        self.assertEqual(top[0]["sample_hosts"], ["x.com"])  # not duplicated

    def test_fitness_takes_max(self):
        """If second win scores higher, fitness updates to new max."""
        self.pt.record_pattern_win(isp="i", block_type="b", flags=["f"],
                                    fitness=0.5, host="h1")
        self.pt.record_pattern_win(isp="i", block_type="b", flags=["f"],
                                    fitness=0.9, host="h2")
        top = self.pt.get_top_patterns("i", "b")
        self.assertAlmostEqual(top[0]["fitness"], 0.9, places=2)

    def test_fitness_not_downgraded(self):
        """If second win scores lower, fitness stays at previous max."""
        self.pt.record_pattern_win(isp="i", block_type="b", flags=["f"],
                                    fitness=0.9, host="h1")
        self.pt.record_pattern_win(isp="i", block_type="b", flags=["f"],
                                    fitness=0.4, host="h2")
        top = self.pt.get_top_patterns("i", "b")
        self.assertAlmostEqual(top[0]["fitness"], 0.9, places=2)

    def test_top_patterns_ordered_fitness_then_wins(self):
        # Pattern A: fitness 0.95, wins 1
        self.pt.record_pattern_win(isp="i", block_type="b",
                                    flags=["A"], fitness=0.95, host="h1")
        # Pattern B: fitness 0.80, wins 5 (more proven, but lower peak)
        for h in ["h2", "h3", "h4", "h5", "h6"]:
            self.pt.record_pattern_win(isp="i", block_type="b",
                                        flags=["B"], fitness=0.80, host=h)
        # Pattern C: fitness 0.70, wins 10
        for i in range(10):
            self.pt.record_pattern_win(isp="i", block_type="b",
                                        flags=["C"], fitness=0.70,
                                        host=f"hh{i}")
        top = self.pt.get_top_patterns("i", "b", limit=3)
        # Sort: fitness DESC, then wins DESC. So A first (0.95), B (0.80), C (0.70)
        self.assertEqual(top[0]["flags"], ["A"])
        self.assertEqual(top[1]["flags"], ["B"])
        self.assertEqual(top[2]["flags"], ["C"])

    def test_lookup_scoped_by_isp_and_block_type(self):
        self.pt.record_pattern_win(isp="A", block_type="X", flags=["fa"],
                                    fitness=0.9, host="h")
        self.pt.record_pattern_win(isp="B", block_type="X", flags=["fb"],
                                    fitness=0.9, host="h")
        self.pt.record_pattern_win(isp="A", block_type="Y", flags=["fy"],
                                    fitness=0.9, host="h")
        # Each scope returns only its own pattern
        self.assertEqual(self.pt.get_top_patterns("A", "X")[0]["flags"], ["fa"])
        self.assertEqual(self.pt.get_top_patterns("B", "X")[0]["flags"], ["fb"])
        self.assertEqual(self.pt.get_top_patterns("A", "Y")[0]["flags"], ["fy"])
        # Unknown scope → empty
        self.assertEqual(self.pt.get_top_patterns("Z", "X"), [])

    def test_empty_inputs_no_op(self):
        """No isp, no block_type, or no flags → silently skipped."""
        self.pt.record_pattern_win(isp="", block_type="X", flags=["f"],
                                    fitness=1.0, host="h")
        self.pt.record_pattern_win(isp="i", block_type="", flags=["f"],
                                    fitness=1.0, host="h")
        self.pt.record_pattern_win(isp="i", block_type="X", flags=[],
                                    fitness=1.0, host="h")
        self.assertEqual(self.pt.get_top_patterns("i", "X"), [])

    def test_limit_caps_results(self):
        for i in range(10):
            self.pt.record_pattern_win(isp="i", block_type="b",
                                        flags=[f"f{i}"], fitness=0.5, host="h")
        top = self.pt.get_top_patterns("i", "b", limit=3)
        self.assertEqual(len(top), 3)

    def test_stats(self):
        self.pt.record_pattern_win(isp="A", block_type="X", flags=["f1"],
                                    fitness=0.9, host="h")
        self.pt.record_pattern_win(isp="A", block_type="Y", flags=["f2"],
                                    fitness=0.9, host="h")
        self.pt.record_pattern_win(isp="A", block_type="X", flags=["f3"],
                                    fitness=0.9, host="h")
        s = self.pt.stats()
        self.assertEqual(s["patterns"], 3)
        self.assertEqual(s["scopes"], 2)  # (A,X) and (A,Y)
        self.assertEqual(s["total_wins"], 3)


if __name__ == "__main__":
    unittest.main()
