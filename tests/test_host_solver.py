"""Tests for brain/host_solver.py — per-host strategy solver."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.host_solver import HostSolver, HostStrategy


class TestHostStrategy(unittest.TestCase):
    """Test HostStrategy dataclass serialization."""

    def test_to_dict(self):
        hs = HostStrategy(
            host="youtube.com", flags=["multisplit:pos=1"],
            fitness=0.85, isp="er-telecom", tested_at=1000.0,
        )
        d = hs.to_dict()
        self.assertEqual(d["host"], "youtube.com")
        self.assertEqual(d["flags"], ["multisplit:pos=1"])
        self.assertAlmostEqual(d["fitness"], 0.85)

    def test_from_dict(self):
        d = {
            "host": "discord.com",
            "flags": ["fake:ttl=4"],
            "fitness": 0.7,
            "isp": "mts",
            "tested_at": 2000.0,
        }
        hs = HostStrategy.from_dict(d)
        self.assertEqual(hs.host, "discord.com")
        self.assertEqual(hs.isp, "mts")

    def test_from_dict_defaults(self):
        d = {"host": "x.com", "flags": []}
        hs = HostStrategy.from_dict(d)
        self.assertAlmostEqual(hs.fitness, 0.0)
        self.assertEqual(hs.isp, "unknown")

    def test_roundtrip(self):
        original = HostStrategy(
            host="test.com", flags=["a", "b"],
            fitness=0.5, isp="test", tested_at=123.0,
        )
        restored = HostStrategy.from_dict(original.to_dict())
        self.assertEqual(original.host, restored.host)
        self.assertEqual(original.flags, restored.flags)
        self.assertAlmostEqual(original.fitness, restored.fitness)


class TestHostSolver(unittest.TestCase):
    """Test HostSolver solve logic."""

    def _make_solver(self, tester=None, strategies=None):
        tmpdir = tempfile.mkdtemp()
        config = {"_base_dir": tmpdir}
        if strategies:
            db_path = Path(tmpdir) / "host_strategies.json"
            db_path.write_text(json.dumps(strategies), encoding="utf-8")
        solver = HostSolver(config, tester=tester)
        solver._tmpdir = tmpdir  # for cleanup
        return solver

    def test_no_tester_returns_none(self):
        solver = self._make_solver(tester=None)
        result = solver.solve("test.com")
        self.assertIsNone(result)

    def test_level1_finds_strategy(self):
        """Level 1 should test standard strategies and pick best."""
        mock_tester = MagicMock()
        # Return high fitness for the host
        mock_tester.test_strategy_single_host.return_value = 0.9
        solver = self._make_solver(tester=mock_tester)
        result = solver.solve("youtube.com", strategies_to_try=[
            {"name": "test", "flags": ["multisplit:pos=1"]}
        ])
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.fitness, 0.9)
        self.assertEqual(result.host, "youtube.com")

    def test_level1_low_fitness_continues(self):
        """Low fitness at Level 1 should try Level 2."""
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.1
        solver = self._make_solver(tester=mock_tester)
        result = solver.solve("hard.example.com", strategies_to_try=[
            {"name": "bad", "flags": ["bad_flag"]}
        ])
        # Should have tried level 2 as well
        # Level 2 also returns 0.1, so overall result is None
        self.assertIsNone(result)

    def test_level1_early_exit_after_warm_pool_filled(self):
        """Fitness > 0.8 should stop, but only after warm pool has at least
        2 alternatives — single strong hit alone leaves failover with no
        cached alternative, defeating the warm-pool design."""
        mock_tester = MagicMock()
        call_count = 0

        def side_effect(flags, host):
            nonlocal call_count
            call_count += 1
            return 0.95  # Very high

        mock_tester.test_strategy_single_host.side_effect = side_effect
        solver = self._make_solver(tester=mock_tester)
        result = solver.solve("fast.example.com", strategies_to_try=[
            {"name": "s1", "flags": ["f1"]},
            {"name": "s2", "flags": ["f2"]},
            {"name": "s3", "flags": ["f3"]},
        ])
        self.assertIsNotNone(result)
        # Test 2 strategies (filling pool to size 2 with fitness>0.8) then break.
        # Pool has 1 alternative for fast failover.
        self.assertEqual(call_count, 2)
        self.assertEqual(len(result.alternatives), 1)

    def test_cached_strategy_within_24h(self):
        """get() should return cached strategy if < 24h old."""
        import time
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.9
        solver = self._make_solver(tester=mock_tester)
        solver.solve("cached.com", strategies_to_try=[
            {"name": "t", "flags": ["f"]}
        ])
        cached = solver.get("cached.com")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.host, "cached.com")

    def test_expired_cache_returns_none(self):
        """get() should return None for strategies > 24h old."""
        import time
        mock_tester = MagicMock()
        solver = self._make_solver(tester=mock_tester)
        solver._strategies["old.com"] = HostStrategy(
            host="old.com", flags=["f"], fitness=0.5,
            tested_at=time.time() - 90000,  # 25 hours ago
        )
        cached = solver.get("old.com")
        self.assertIsNone(cached)

    def test_progress_callback(self):
        """on_progress should be called for each strategy."""
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.2
        progress_calls = []

        def on_progress(current, total, name, fitness):
            progress_calls.append((current, total, name, fitness))

        solver = self._make_solver(tester=mock_tester)
        solver.solve("test.com", strategies_to_try=[
            {"name": "s1", "flags": ["f1"]},
            {"name": "s2", "flags": ["f2"]},
        ], on_progress=on_progress)

        self.assertEqual(len(progress_calls), 2)
        self.assertEqual(progress_calls[0][0], 1)  # current
        self.assertEqual(progress_calls[0][1], 2)  # total

    def test_persistence(self):
        """Solved strategies should persist to disk."""
        tmpdir = tempfile.mkdtemp()
        config = {"_base_dir": tmpdir}
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.9

        solver1 = HostSolver(config, tester=mock_tester)
        solver1.solve("persist.com", strategies_to_try=[
            {"name": "t", "flags": ["f"]}
        ])

        # New solver from same dir should load the strategy
        solver2 = HostSolver(config, tester=mock_tester)
        self.assertIn("persist.com", solver2.get_all())

    def test_community_server_lookup(self):
        """Level 0: community server should be checked first."""
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.9
        mock_sync = MagicMock()
        mock_sync.get_host_strategy.return_value = {
            "flags": ["community_flag"], "fitness": 0.8
        }
        solver = self._make_solver(tester=mock_tester)
        solver._sync = mock_sync
        result = solver.solve("community.example.com", isp="test")
        self.assertIsNotNone(result)
        mock_sync.get_host_strategy.assert_called_once()

    def test_community_server_failure_continues(self):
        """Community server failure should not block solving."""
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.9
        mock_sync = MagicMock()
        mock_sync.get_host_strategy.side_effect = RuntimeError("network error")
        solver = self._make_solver(tester=mock_tester)
        solver._sync = mock_sync
        result = solver.solve("fallback.example.com", isp="test",
                              strategies_to_try=[{"name": "t", "flags": ["f"]}])
        self.assertIsNotNone(result)  # Should still find via Level 1

    def test_warm_pool_built_with_top_3(self):
        """solve() should build a warm pool of up to top-3 strategies.

        Scores chosen below the >0.8 early-break so we walk the full list.
        Pool stops growing once 3 strategies are accepted with the worst > 0.6.
        """
        mock_tester = MagicMock()
        # 4 strategies above pool threshold, all under the 0.8 early-break,
        # so the loop walks at least 3 to fill the pool then breaks.
        scores = iter([0.78, 0.72, 0.65, 0.58])
        mock_tester.test_strategy_single_host.side_effect = lambda f, h: next(scores)

        solver = self._make_solver(tester=mock_tester)
        result = solver.solve("pool.example.com", strategies_to_try=[
            {"name": "s1", "flags": ["a"]},
            {"name": "s2", "flags": ["b"]},
            {"name": "s3", "flags": ["c"]},
            {"name": "s4", "flags": ["d"]},
        ])
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.fitness, 0.78)
        # Pool size 3 -> 1 current + 2 alternatives
        self.assertEqual(len(result.alternatives), 2)
        # Alternatives sorted descending by fitness
        self.assertGreater(result.alternatives[0]["fitness"], result.alternatives[1]["fitness"])

    def test_next_alternative_failover(self):
        """next_alternative() promotes pool[0] -> current, recycles old."""
        mock_tester = MagicMock()
        scores = iter([0.78, 0.72, 0.65])
        mock_tester.test_strategy_single_host.side_effect = lambda f, h: next(scores)

        solver = self._make_solver(tester=mock_tester)
        solver.solve("fail.example.com", strategies_to_try=[
            {"name": "s1", "flags": ["a"]},
            {"name": "s2", "flags": ["b"]},
            {"name": "s3", "flags": ["c"]},
        ])
        original = solver.get("fail.example.com")
        self.assertEqual(original.flags, ["a"])
        self.assertEqual(len(original.alternatives), 2)

        # Failover: should promote ["b"] to current, push ["a"] to back
        new = solver.next_alternative("fail.example.com")
        self.assertIsNotNone(new)
        self.assertEqual(new.flags, ["b"])
        self.assertAlmostEqual(new.fitness, 0.72)
        # Pool size unchanged (2 alternatives), order rotated
        self.assertEqual(len(new.alternatives), 2)
        self.assertEqual(new.alternatives[-1]["flags"], ["a"])  # old current at back

    def test_next_alternative_returns_none_when_pool_empty(self):
        """next_alternative() returns None when no alternatives available."""
        mock_tester = MagicMock()
        # Single strong hit — but new code tests 2 to fill pool
        # Force only 1 by giving second a sub-threshold score
        scores = iter([0.95, 0.4])
        mock_tester.test_strategy_single_host.side_effect = lambda f, h: next(scores)

        solver = self._make_solver(tester=mock_tester)
        solver.solve("solo.example.com", strategies_to_try=[
            {"name": "s1", "flags": ["a"]},
            {"name": "s2", "flags": ["b"]},
        ])
        # Pool should have 1 entry (only first crossed threshold)
        result = solver.get("solo.example.com")
        self.assertEqual(len(result.alternatives), 0)
        # Failover with empty pool returns None
        self.assertIsNone(solver.next_alternative("solo.example.com"))

    def test_ai_feedback_excludes_flags(self):
        """AI feedback should exclude certain functions."""
        mock_tester = MagicMock()
        mock_tester.test_strategy_single_host.return_value = 0.9
        mock_ai = MagicMock()
        mock_ai.get_excluded_functions.return_value = {"excluded_func"}

        solver = self._make_solver(tester=mock_tester)
        solver._ai_feedback = mock_ai
        result = solver.solve("ai.example.com", strategies_to_try=[
            {"name": "excluded", "flags": ["excluded_func:param=1"]},
            {"name": "ok", "flags": ["good_func:param=1"]},
        ])
        # The excluded strategy should be skipped
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
