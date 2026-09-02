"""Tests for brain/strategy_lint.py — static validation of desync strategies.

winws2.exe needs elevation even to parse its arguments, so a malformed strategy
is only discovered on a live run, and a silently-skipped desync scores like a
working bypass. The linter reads the INSTALLED engine's zapret-antidpi.lua and
checks every strategy against it.

It exists because the 2026-09 audit found two real defects this would have
caught: the harvester emitting `fool=md5sig` (zapret v1 spelling; in zapret2
`fool=` names a Lua function) and a shipped `oob:pos=1` (oob takes char/byte/urp,
never pos).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.enumerator import KNOWN_STRATEGIES  # noqa: E402
from brain.strategy_lint import (  # noqa: E402
    lint, lint_call, load_vocabulary, parse_call,
)


def _vocab():
    load_vocabulary.cache_clear()
    return load_vocabulary(str(BASE_DIR))


class TestParseCall(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_call("multisplit:pos=1:seqovl=568"),
                         ("multisplit", [("pos", "1"), ("seqovl", "568")]))

    def test_flag_without_value_and_prefix(self):
        self.assertEqual(parse_call("--lua-desync=fake:blob=x:tcp_md5"),
                         ("fake", [("blob", "x"), ("tcp_md5", None)]))

    def test_commas_stay_inside_one_value(self):
        func, args = parse_call("multidisorder:pos=1,midsld:seqovl=5")
        self.assertEqual(func, "multidisorder")
        self.assertEqual(args[0], ("pos", "1,midsld"))

    def test_equals_inside_value_survives(self):
        func, args = parse_call("fake:tls_mod=rnd,dupsid,sni=www.google.com")
        self.assertEqual(args, [("tls_mod", "rnd,dupsid,sni=www.google.com")])

    def test_bare_function(self):
        self.assertEqual(parse_call("syndata"), ("syndata", []))


class TestVocabulary(unittest.TestCase):
    def setUp(self):
        self.v = _vocab()
        if self.v is None:
            self.skipTest("no zapret2 engine extracted")

    def test_core_functions_known(self):
        for f in ("multisplit", "multidisorder", "fake", "hostfakesplit",
                  "syndata", "wssize", "oob", "tcpseg", "drop", "send"):
            self.assertTrue(self.v.known_function(f), f)

    def test_project_custom_lua_functions_known(self):
        """lua/svoboda_*.lua primitives load through the same --lua-init chain."""
        for f in ("alpn_strip", "tls_pad", "tls_grease", "tls_extreorder"):
            self.assertTrue(self.v.known_function(f), f)

    def test_helpers_are_not_desync_entry_points(self):
        for f in ("pos_normalize", "pos_array_normalize", "multidisorder_send"):
            self.assertFalse(self.v.known_function(f), f)

    def test_standard_groups_resolved(self):
        args = self.v.allowed_args("multisplit")
        for a in ("pos", "seqovl", "seqovl_pattern", "blob",   # own args
                  "tcp_md5", "tcp_seq", "tcp_ts", "ip_ttl",    # standard fooling
                  "ip_id", "badsum", "repeats"):               # ipid/reconstruct/rawsend
            self.assertIn(a, args, a)

    def test_trailing_prose_does_not_truncate_group_list(self):
        """hostfakesplit's standard-args line ends with a sentence of prose;
        'reconstruct' must still be picked up so badsum stays valid."""
        self.assertIn("badsum", self.v.allowed_args("hostfakesplit"))
        self.assertIn("host", self.v.allowed_args("hostfakesplit"))


class TestLinting(unittest.TestCase):
    def setUp(self):
        self.v = _vocab()
        if self.v is None:
            self.skipTest("no zapret2 engine extracted")

    def test_valid_strategies_are_clean(self):
        for call in (
            "multisplit:pos=1:seqovl=568",
            "multidisorder:pos=1,midsld",
            "multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:ip_id=zero",
            "hostfakesplit:host=www.google.com:repeats=4:tcp_ts=-600000",
            "fake:blob=fake_default_tls:repeats=6:tcp_md5",
            "send:dir=out:delay=50",
            "syndata",
        ):
            self.assertEqual(lint_call(call, self.v), [], call)

    def test_v1_fooling_spelling_is_rejected(self):
        """The exact harvester bug: zapret v1 fooling names under fool=."""
        for name, want in (("md5sig", "tcp_md5"), ("badseq", "tcp_seq"), ("ts", "tcp_ts")):
            problems = lint_call(f"fake:blob=x:fool={name}", self.v)
            self.assertEqual(len(problems), 1, name)
            self.assertIn("zapret v1 fooling name", problems[0])
            self.assertIn(want, problems[0])

    def test_unknown_argument_rejected(self):
        self.assertTrue(lint_call("multisplit:pos=1:nosucharg=42", self.v))
        self.assertTrue(lint_call("oob:pos=1", self.v))   # oob takes char/byte/urp

    def test_unknown_function_rejected(self):
        problems = lint_call("notafunction:pos=1", self.v)
        self.assertEqual(len(problems), 1)
        self.assertIn("unknown desync function", problems[0])

    def test_enum_values_checked(self):
        self.assertTrue(lint_call("multisplit:pos=1:ip_id=bogus", self.v))
        self.assertEqual(lint_call("multisplit:pos=1:ip_id=zero", self.v), [])
        self.assertTrue(lint_call("send:dir=sideways", self.v))
        self.assertEqual(lint_call("send:dir=out", self.v), [])

    def test_custom_function_accepts_any_arguments(self):
        self.assertEqual(lint_call("alpn_strip:strip=h2,h2c", self.v), [])

    def test_missing_engine_reports_nothing(self):
        """No engine extracted must mean 'cannot check', never 'everything is broken'."""
        self.assertEqual(lint_call("anything:at=all", None), [])


class TestShippedStrategiesAreValid(unittest.TestCase):
    """Regression guard for the whole enumerator pool."""

    def test_every_known_strategy_lints_clean(self):
        if _vocab() is None:
            self.skipTest("no zapret2 engine extracted")
        problems: list[str] = []
        for s in KNOWN_STRATEGIES:
            for p in lint(s["flags"], str(BASE_DIR)):
                problems.append(f"{s['name']}: {p}")
        self.assertEqual(problems, [], "Invalid strategies:\n" + "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
