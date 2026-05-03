"""Tests for brain/enumerator.py — strategy enumeration & rate-limit guard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.enumerator import StrategyEnumerator


class TestZeroStreakAbort(unittest.TestCase):
    """Live-run on 2026-05-03 showed enum wasting 50+ minutes when TSPU
    rate-limits all curls — every test returned 0/2 fitness=0.0 and the
    enum kept walking the entire 70-strategy list. Worse, the resulting
    bogus zeros polluted strategies_db and got synced to the community
    server. The zero_streak_abort guard short-circuits this."""

    def _make_strategies(self, n: int) -> list[dict]:
        return [
            {"name": f"s{i}", "flags": [f"flag{i}"], "desc": f"strategy {i}"}
            for i in range(n)
        ]

    def test_aborts_after_n_consecutive_zeros(self):
        """5+ zeros in a row → abort, return None, do not test more strategies."""
        mock_tester = MagicMock()
        mock_tester.test_strategy.return_value = 0.0  # everything fails

        enum = StrategyEnumerator(strategies=self._make_strategies(20))
        result = enum.enumerate(mock_tester, threshold=0.5, zero_streak_abort=5)
        self.assertIsNone(result)
        # Should test exactly 5 (the streak limit), not all 20
        self.assertEqual(mock_tester.test_strategy.call_count, 5)

    def test_streak_resets_on_nonzero(self):
        """Mid-list non-zero result resets the streak — we don't abort
        when there's signal somewhere."""
        scores = iter([0.0, 0.0, 0.0, 0.4, 0.0, 0.0, 0.0, 0.0, 0.0])
        mock_tester = MagicMock()
        mock_tester.test_strategy.side_effect = lambda f: next(scores)

        enum = StrategyEnumerator(strategies=self._make_strategies(10))
        result = enum.enumerate(mock_tester, threshold=0.5, zero_streak_abort=5)
        # Streak: 3 zeros, reset by 0.4, 5 more zeros → abort
        # Total tests: 3 + 1 + 5 = 9 (last skipped after streak hits 5)
        self.assertIsNone(result)
        self.assertEqual(mock_tester.test_strategy.call_count, 9)

    def test_disable_with_zero_value(self):
        """zero_streak_abort=0 disables the guard (legacy behavior)."""
        mock_tester = MagicMock()
        mock_tester.test_strategy.return_value = 0.0

        enum = StrategyEnumerator(strategies=self._make_strategies(10))
        result = enum.enumerate(mock_tester, threshold=0.5, zero_streak_abort=0)
        self.assertIsNone(result)
        # Walks all 10 since guard disabled
        self.assertEqual(mock_tester.test_strategy.call_count, 10)

    def test_no_abort_when_strategy_passes(self):
        """If a strategy passes threshold before streak abort, return it."""
        scores = iter([0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0])
        mock_tester = MagicMock()
        mock_tester.test_strategy.side_effect = lambda f: next(scores)

        enum = StrategyEnumerator(strategies=self._make_strategies(10))
        result = enum.enumerate(mock_tester, threshold=0.5, zero_streak_abort=5)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "s3")

    def test_last_result_kind_signals_outcome(self):
        """last_result_kind lets caller distinguish "exhausted" from
        "aborted_rate_limit" so backoff logic can fire only on the latter."""
        # Found case
        mock_t = MagicMock()
        mock_t.test_strategy.return_value = 0.9
        enum = StrategyEnumerator(strategies=self._make_strategies(3))
        enum.enumerate(mock_t, threshold=0.5, zero_streak_abort=5)
        self.assertEqual(enum.last_result_kind, "found")

        # Exhausted case (all under threshold but non-zero, so no abort)
        mock_t = MagicMock()
        mock_t.test_strategy.return_value = 0.3
        enum = StrategyEnumerator(strategies=self._make_strategies(3))
        enum.enumerate(mock_t, threshold=0.5, zero_streak_abort=5)
        self.assertEqual(enum.last_result_kind, "exhausted")

        # Aborted case (5 zeros in a row)
        mock_t = MagicMock()
        mock_t.test_strategy.return_value = 0.0
        enum = StrategyEnumerator(strategies=self._make_strategies(20))
        enum.enumerate(mock_t, threshold=0.5, zero_streak_abort=5)
        self.assertEqual(enum.last_result_kind, "aborted_rate_limit")

    def test_does_not_count_skipped_excluded(self):
        """Excluded-function skips don't count toward streak (no test ran)."""
        # All non-excluded fail, but we have only 3 of them
        mock_tester = MagicMock()
        mock_tester.test_strategy.return_value = 0.0
        strategies = [
            {"name": "ex1", "flags": ["forbidden:p=1"], "desc": ""},
            {"name": "s1", "flags": ["good:p=1"], "desc": ""},
            {"name": "ex2", "flags": ["forbidden:p=2"], "desc": ""},
            {"name": "s2", "flags": ["good:p=2"], "desc": ""},
            {"name": "s3", "flags": ["good:p=3"], "desc": ""},
        ]
        enum = StrategyEnumerator(
            strategies=strategies,
            excluded_functions={"forbidden"},
        )
        result = enum.enumerate(mock_tester, threshold=0.5, zero_streak_abort=5)
        self.assertIsNone(result)
        # Tested only 3 (excluded skipped). Streak reaches 3, doesn't trigger 5.
        self.assertEqual(mock_tester.test_strategy.call_count, 3)


if __name__ == "__main__":
    unittest.main()
