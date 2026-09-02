"""Tests for the 2026-09 enumerator refresh: tcp_ts gating + new no-fake entries."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import enumerator as en  # noqa: E402
from brain.enumerator import KNOWN_STRATEGIES, StrategyEnumerator  # noqa: E402

FAKE_FUNCS = {"fake", "fakedsplit", "fakeddisorder", "hostfakesplit"}


def _strats():
    return [
        {"name": "ts1", "flags": ["fake:blob=tls_google:repeats=6:tcp_ts=-600000", "multisplit:pos=1"], "desc": ""},
        {"name": "plain", "flags": ["multisplit:pos=1:seqovl=568"], "desc": ""},
        {"name": "ts2", "flags": ["hostfakesplit:host=www.google.com:tcp_ts=-600000"], "desc": ""},
    ]


class TestTcpTimestampGating(unittest.TestCase):
    def test_disabled_drops_tcp_ts_strategies(self):
        e = StrategyEnumerator(strategies=_strats(), require_tcp_timestamps=False)
        self.assertEqual([s["name"] for s in e.strategies], ["plain"])

    def test_enabled_keeps_everything(self):
        e = StrategyEnumerator(strategies=_strats(), require_tcp_timestamps=True)
        self.assertEqual(len(e.strategies), 3)

    def test_auto_detection_is_consulted(self):
        with patch.object(en, "tcp_timestamps_enabled", return_value=False):
            e = StrategyEnumerator(strategies=_strats())
        self.assertEqual([s["name"] for s in e.strategies], ["plain"])
        with patch.object(en, "tcp_timestamps_enabled", return_value=None):
            e = StrategyEnumerator(strategies=_strats())
        self.assertEqual(len(e.strategies), 3)   # unknown => do not filter

    def test_detection_failure_is_harmless(self):
        with patch.object(en, "tcp_timestamps_enabled", side_effect=RuntimeError("no powershell")):
            e = StrategyEnumerator(strategies=_strats())
        self.assertEqual(len(e.strategies), 3)


class TestRefreshEntries(unittest.TestCase):
    NEW = [
        "flowseal_1102_google_681_realpat_ipid0",
        "flowseal_1102_general_568_realpat",
        "nofake_568_ipid0_disorder",
        "flowseal_alt2_652_pos2_realpat",
        "flowseal_alt7_679_sniext",
        "klondike_rtk_multidisorder_7pos_seqovl1",
    ]

    def test_new_entries_present_and_no_fake(self):
        by_name = {s["name"]: s for s in KNOWN_STRATEGIES}
        for name in self.NEW:
            self.assertIn(name, by_name)
            for flag in by_name[name]["flags"]:
                self.assertNotIn(flag.split(":", 1)[0], FAKE_FUNCS, f"{name} must be no-fake")

    def test_proven_strategy_still_first(self):
        self.assertEqual(KNOWN_STRATEGIES[0]["name"], "nofake_disorder_568")

    def test_names_unique(self):
        names = [s["name"] for s in KNOWN_STRATEGIES]
        self.assertEqual(len(names), len(set(names)))

    def test_flag_syntax_sane(self):
        for s in KNOWN_STRATEGIES:
            for flag in s["flags"]:
                self.assertTrue(re.match(r"^[a-z_0-9]+(:[A-Za-z0-9_+,=.\-]+)*$", flag), f"{s['name']}: {flag!r}")


class TestHarvestedStrategiesAreLinted(unittest.TestCase):
    """A strategy winws2 would reject must never enter the pool: it burns a
    ~30s test slot and records a bogus zero in strategies_db."""

    def _enum_with_harvest(self, harvested):
        with patch("brain.strategy_harvester.harvest_safe", return_value=harvested):
            return StrategyEnumerator(include_harvested=True, require_tcp_timestamps=True)

    def test_invalid_harvested_strategy_is_dropped(self):
        harvested = [
            {"name": "h_bad_fool", "flags": ["fake:blob=fake_default_tls:fool=md5sig"], "desc": ""},
            {"name": "h_bad_func", "flags": ["notafunction:pos=1"], "desc": ""},
            {"name": "h_good", "flags": ["multisplit:pos=3:seqovl=99"], "desc": ""},
        ]
        names = [s["name"] for s in self._enum_with_harvest(harvested).strategies]
        self.assertIn("h_good", names)
        self.assertNotIn("h_bad_fool", names)
        self.assertNotIn("h_bad_func", names)

    def test_lint_failure_does_not_block_enumeration(self):
        harvested = [{"name": "h_good", "flags": ["multisplit:pos=3:seqovl=99"], "desc": ""}]
        with patch("brain.enumerator._lint_strategy", side_effect=RuntimeError("boom")):
            with patch("brain.strategy_harvester.harvest_safe", return_value=harvested):
                # _lint_strategy raising is caught inside itself; simulate the
                # harder case where the whole call blows up.
                try:
                    e = StrategyEnumerator(include_harvested=True, require_tcp_timestamps=True)
                except RuntimeError:
                    self.fail("a lint failure must not break enumeration")
        self.assertGreater(len(e.strategies), 0)


class TestEngineNoFakePolicyCoversHostfakesplit(unittest.TestCase):
    def test_run_real_fake_funcs(self):
        src = (BASE_DIR / "run_real.py").read_text(encoding="utf-8")
        m = re.search(r"_FAKE_FUNCS = frozenset\(\{([^}]*)\}\)", src)
        self.assertIsNotNone(m)
        funcs = {x.strip().strip('"') for x in m.group(1).split(",") if x.strip()}
        self.assertEqual(funcs, FAKE_FUNCS)
        # seed filter must use the same set, not a startswith("fake") heuristic
        self.assertIn('flag.split(":", 1)[0] in _FAKE_FUNCS', src)


if __name__ == "__main__":
    unittest.main()
