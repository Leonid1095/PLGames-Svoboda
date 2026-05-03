"""Tests for brain/strategy_harvester.py — translator and parser."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.strategy_harvester import (
    _parse_cli_args,
    parse_zapret_v1_bat,
    translate_zapret_v1,
    harvest,
)


class TestTranslateZapretV1(unittest.TestCase):
    def test_split2_with_pos(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "split2",
            "--dpi-desync-split-pos": "1",
        })
        self.assertEqual(flags, ["multisplit:pos=1"])

    def test_disorder2_with_pos(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "disorder2",
            "--dpi-desync-split-pos": "2",
        })
        self.assertEqual(flags, ["multidisorder:pos=2,midsld"])

    def test_fake_with_ttl_and_repeats(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "fake",
            "--dpi-desync-ttl": "5",
            "--dpi-desync-repeats": "6",
        })
        self.assertEqual(len(flags), 1)
        self.assertIn("blob=fake_default_tls", flags[0])
        self.assertIn("repeats=6", flags[0])
        self.assertIn("ip_ttl=5", flags[0])

    def test_chained_fake_split2(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "fake,split2",
            "--dpi-desync-split-pos": "1",
            "--dpi-desync-repeats": "4",
        })
        self.assertEqual(len(flags), 2)
        self.assertTrue(flags[0].startswith("fake:"))
        self.assertEqual(flags[1], "multisplit:pos=1")

    def test_unknown_function_returns_none(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "rstrack",  # not in our map
            "--dpi-desync-split-pos": "1",
        })
        self.assertIsNone(flags)

    def test_empty_desync_returns_none(self):
        self.assertIsNone(translate_zapret_v1({}))

    def test_fakedsplit_translates_to_seqovl_pattern(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "fakedsplit",
            "--dpi-desync-split-pos": "1",
        })
        self.assertEqual(len(flags), 1)
        self.assertIn("seqovl_pattern=fake_default_tls", flags[0])

    def test_fooling_md5sig_appended(self):
        flags = translate_zapret_v1({
            "--dpi-desync": "fake",
            "--dpi-desync-fooling": "md5sig",
            "--dpi-desync-ttl": "4",
        })
        self.assertIn("fool=md5sig", flags[0])


class TestParseCliArgs(unittest.TestCase):
    def test_equals_form(self):
        args = _parse_cli_args("--key=value --foo=bar")
        self.assertEqual(args["--key"], "value")
        self.assertEqual(args["--foo"], "bar")

    def test_quoted_value(self):
        args = _parse_cli_args('--name="John Doe" --age=42')
        self.assertEqual(args["--name"], "John Doe")
        self.assertEqual(args["--age"], "42")

    def test_flag_without_value(self):
        args = _parse_cli_args("--verbose --debug")
        self.assertEqual(args["--verbose"], "1")
        self.assertEqual(args["--debug"], "1")


class TestParseFlowsealBat(unittest.TestCase):
    """Realistic .bat sample similar to Flowseal's actual file format."""

    def test_parses_single_strategy_block(self):
        content = (
            'start "zapret: discord1" /B /min "%~dp0winws.exe" '
            '--wf-tcp=443 --filter-tcp=443 '
            '--hostlist="%~dp0lists\\list-discord.txt" '
            '--dpi-desync=fake,split2 --dpi-desync-split-pos=1 '
            '--dpi-desync-repeats=6 --dpi-desync-ttl=4\n'
        )
        strategies = parse_zapret_v1_bat(content, "test", ["harvested"])
        self.assertEqual(len(strategies), 1)
        s = strategies[0]
        self.assertTrue(s["name"].startswith("harvest_"))
        self.assertEqual(len(s["flags"]), 2)
        self.assertIn("harvested", s["tags"])
        self.assertEqual(s["source"], "test")

    def test_skips_unparseable_strategies(self):
        content = (
            'start "good" /B /min "%~dp0winws.exe" '
            '--dpi-desync=split2 --dpi-desync-split-pos=1\n'
            'start "bad" /B /min "%~dp0winws.exe" '
            '--dpi-desync=unknownfunc --dpi-desync-split-pos=1\n'
        )
        strategies = parse_zapret_v1_bat(content, "test", [])
        self.assertEqual(len(strategies), 1)
        self.assertIn("good", strategies[0]["name"])

    def test_dedupes_within_file(self):
        content = (
            'start "first" /B /min "%~dp0winws.exe" --dpi-desync=split2 --dpi-desync-split-pos=1\n'
            'start "second" /B /min "%~dp0winws.exe" --dpi-desync=split2 --dpi-desync-split-pos=1\n'
        )
        strategies = parse_zapret_v1_bat(content, "test", [])
        self.assertEqual(len(strategies), 1)


class TestHarvestCache(unittest.TestCase):
    """Cache logic — doesn't hit network."""

    def test_returns_cached_when_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            sample = [{"name": "x", "flags": ["a"], "desc": "y"}]
            cache.write_text(json.dumps(sample), encoding="utf-8")
            result = harvest(cache_path=cache)
            self.assertEqual(result, sample)


if __name__ == "__main__":
    unittest.main()
