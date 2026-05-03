"""AI Strategy Engineer — when watchdog is stuck, ask LLM to design a
new desync flag combination based on observed symptoms.

Why this is different from existing AIAdvisor:
  - AIAdvisor.suggest_strategies() picks from a pre-baked menu of known
    strategies. Good for general guidance, useless when *all* known
    strategies fail (TSPU adapted faster than our hardcoded list).
  - This module sends the LLM the RAW symptom pattern (curl exit codes,
    latency distribution, error timing, ISP) and asks it to invent a
    novel flag combination — bypassing our hardcoded enumerator.

Trigger: enumerator returns last_result_kind="exhausted" AND no community
strategy exists for this (isp, block_type) AND we've burned 5+ minutes
on enum without finding anything > 0.4 fitness.

Safety:
  - Output is validated: must be JSON {"flags": [...], "reasoning": "..."}
  - Each flag string is regex-checked against known zapret2 functions
    (multisplit, multidisorder, fake, alpn_strip, ...) before testing
  - Rate-limited via AIAdvisor (server-side has its own 429)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("svoboda.ai_engineer")


_ALLOWED_FUNCTIONS = {
    "multisplit", "multidisorder", "fake", "wssize", "oob",
    "hostfakesplit", "alpn_strip", "tls_pad", "tls_extreorder",
    "tls_grease", "tls_morph",
}

_FLAG_RE = re.compile(r"^[a-z_]+(:[a-z0-9_+\-,=.@/]+)*$", re.IGNORECASE)

_SYSTEM_PROMPT = """You are a DPI bypass engineer. Given symptoms from a
failing zapret2 client (Russian TSPU or similar middlebox), design a
single new desync flag combination that hasn't been tried yet.

Output ONLY a JSON object:
{
  "flags": ["multisplit:pos=1:seqovl=N", "fake:blob=fake_default_tls:repeats=N"],
  "reasoning": "one sentence explaining why this should work"
}

Rules:
- Use only zapret2 lua-desync functions: multisplit, multidisorder,
  fake, wssize, oob, hostfakesplit, alpn_strip, tls_pad, tls_extreorder,
  tls_grease, tls_morph
- Flag chains use " | " separator semantics; each flag is a string in the array
- For TSPU MITM (exit=60 SSL): try SNI-fragmentation (multisplit:pos=1
  with small seqovl values like 5/8/16, or huge ones like 4096), or
  combine alpn_strip with split
- For HTTP2_STREAM_KILL: alpn_strip:strip=h2,h2c is required first
- Don't propose strategies the user already tried (listed in symptoms)
- Don't include explanations outside JSON
"""


@dataclass
class EngineerOutput:
    flags: list[str]
    reasoning: str


def _validate_flag(flag: str) -> bool:
    """Cheap sanity check on a flag string."""
    if not isinstance(flag, str) or not flag:
        return False
    if not _FLAG_RE.match(flag):
        return False
    func = flag.split(":", 1)[0]
    return func in _ALLOWED_FUNCTIONS


def _parse_response(text: str) -> Optional[EngineerOutput]:
    """Extract JSON from LLM response, validate flags."""
    if not text:
        return None
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    text = re.sub(r"\n?```\s*$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Maybe model dumped extra text — extract the first JSON object
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            logger.warning("AI Engineer: no JSON in response: %s", text[:120])
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            logger.warning("AI Engineer: malformed JSON: %s", exc)
            return None

    flags = data.get("flags")
    if not isinstance(flags, list) or not flags:
        return None
    if not all(_validate_flag(f) for f in flags):
        bad = [f for f in flags if not _validate_flag(f)]
        logger.warning("AI Engineer: rejected flags %s", bad)
        return None
    return EngineerOutput(
        flags=flags,
        reasoning=str(data.get("reasoning", "")).strip()[:300],
    )


def _build_symptoms(
    isp: str,
    block_type: str,
    failing_hosts: list[str],
    tried_strategies: list[tuple[str, float]],
    error_pattern: str,
) -> str:
    """Compose a structured symptom report for the LLM."""
    tried = "\n".join(
        f"  - {name}: fitness={fit:.2f}"
        for name, fit in tried_strategies[-15:]  # last 15
    ) or "  (none)"
    return (
        f"ISP: {isp}\n"
        f"Block type: {block_type}\n"
        f"Failing hosts: {', '.join(failing_hosts) or '(none)'}\n"
        f"Error pattern: {error_pattern}\n\n"
        f"Strategies already tried (recent):\n{tried}\n\n"
        f"Propose a single NEW flag combination not in the tried list."
    )


class AIStrategyEngineer:
    """Asks the LLM to invent a new desync strategy from raw symptoms.

    Wraps an existing AIAdvisor for its server-proxy chat plumbing —
    we just override the system prompt and parse JSON output.
    """

    def __init__(self, advisor):
        """advisor: an AIAdvisor instance (we call advisor._chat)."""
        self._advisor = advisor

    def is_available(self) -> bool:
        return bool(self._advisor) and self._advisor.is_available()

    def request_strategy(
        self,
        isp: str,
        block_type: str,
        failing_hosts: list[str],
        tried_strategies: list[tuple[str, float]],
        error_pattern: str = "",
    ) -> Optional[EngineerOutput]:
        """Ask LLM for a new strategy. Returns None on any failure.

        Never raises — caller should treat None as 'try something else'.
        """
        if not self.is_available():
            return None
        symptoms = _build_symptoms(
            isp, block_type, failing_hosts, tried_strategies, error_pattern,
        )
        prompt = _SYSTEM_PROMPT + "\n\n" + symptoms
        try:
            # Reuse advisor's _chat but with our system prompt prepended
            # Note: _chat embeds its own system prompt; we send our content
            # as user message and rely on the LLM to follow our format
            response = self._advisor._chat(prompt)
        except Exception as exc:
            logger.warning("AI Engineer chat failed: %s", exc)
            return None
        result = _parse_response(response)
        if result:
            logger.info(
                "AI Engineer proposed: %s — %s",
                " | ".join(result.flags), result.reasoning,
            )
        return result
