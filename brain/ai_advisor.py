"""AI Advisor — LLM-powered strategy analysis and recommendations.

All AI requests go through the server proxy (POST /api/v1/ai/chat).
AI URLs, keys, and model selection are handled server-side.
The client never sees AI credentials.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import requests

from brain.analytics import Analytics

logger = logging.getLogger("svoboda.ai")

_SYSTEM_PROMPT = """\
You are an expert in zapret2/nfqws2 DPI desync bypass tool configuration.
You MUST ONLY use the exact flags listed below. Do NOT invent new flags.

ALLOWED FLAGS (use ONLY these):

Methods (pick exactly ONE per strategy):
  --dpi-desync=fake
  --dpi-desync=rst
  --dpi-desync=disorder
  --dpi-desync=disorder2
  --dpi-desync=multisplit
  --dpi-desync=overlap

Parameters (optional, combine with method):
  --dpi-desync-ttl=N          (N = 1 to 15)
  --dpi-desync-split-pos=N    (N = 1 to 5)
  --dpi-desync-split-seqovl=N (N = 1 to 3)
  --dpi-desync-repeats=N      (N = 2 to 6)

Boolean flags (optional):
  --dpi-desync-fooling=badseq
  --dpi-desync-fooling=badsum
  --dpi-desync-fooling=md5sig
  --dpi-desync-ipfrag=1
  --dpi-desync-fake-tls=1

RULES:
- Each strategy is an array of 2-6 flags from the list above
- Each strategy MUST have exactly one --dpi-desync= method
- Return ONLY a valid JSON array of arrays, no text

EXAMPLE OUTPUT:
[
  ["--dpi-desync=fake", "--dpi-desync-ttl=5", "--dpi-desync-split-pos=2"],
  ["--dpi-desync=disorder2", "--dpi-desync-ttl=3", "--dpi-desync-fooling=badseq"],
  ["--dpi-desync=multisplit", "--dpi-desync-ipfrag=1", "--dpi-desync-repeats=3"]
]
"""


class AIAdvisor:
    """LLM-powered strategy advisor. Routes through server proxy."""

    def __init__(self, config: dict, analytics: Analytics, tier_manager=None):
        self._server_url: str = config.get("server_api_url", "")
        self._server_key: str = config.get("server_api_key", "")
        self._enabled: bool = config.get("ai_enabled", True)
        self._analytics = analytics
        self._tier = tier_manager
        self._install_id: str = config.get("install_id", "")
        self._last_model: str = "unknown"

    @property
    def is_available(self) -> bool:
        """Check if AI advisor can work (server URL configured)."""
        return self._enabled and bool(self._server_url)

    @property
    def active_model(self) -> str:
        """Last known model (returned by server)."""
        return self._last_model

    def set_install_id(self, install_id: str) -> None:
        """Set install_id (called after registration)."""
        self._install_id = install_id

    def set_server_key(self, key: str) -> None:
        """Update server API key (after auto-registration)."""
        self._server_key = key

    def suggest_strategies(self, isp: str, middlebox_type: str = "unknown", region: str = "") -> list[list[str]]:
        """Ask AI to suggest new strategies based on collected data."""
        if not self.is_available:
            return []

        # Gather context from analytics
        context = self._build_context(isp, middlebox_type, region)

        prompt = f"""Suggest 3-5 zapret2 desync strategies for this network:

ISP: {isp}
Middlebox: {middlebox_type}
Region: {region}

{context}

Return ONLY a JSON array of flag arrays using the allowed flags. No explanation, no markdown."""

        try:
            response = self._chat(prompt)
            strategies = self._parse_strategies(response)
            if strategies:
                logger.info("AI suggested %d strategies for %s", len(strategies), isp)
            return strategies
        except Exception as exc:
            logger.warning("AI suggestion failed: %s", exc)
            return []

    def analyze_failure(self, flags: list[str], fitness: float, isp: str) -> Optional[str]:
        """Ask AI to analyze why a strategy has low fitness."""
        if not self.is_available:
            return None

        prompt = f"""This zapret2 desync strategy scored low (fitness={fitness:.2f}):
Flags: {' '.join(flags)}
ISP: {isp}

Why might it fail? Suggest one better alternative using only the allowed flags.
Return as JSON: {{"analysis": "brief reason", "improved_flags": ["--dpi-desync=...", ...]}}"""

        try:
            response = self._chat(prompt)
            return response
        except Exception as exc:
            logger.debug("AI analysis failed: %s", exc)
            return None

    def rank_strategies(self, strategies: list[list[str]], isp: str) -> list[list[str]]:
        """Ask AI to rank strategies by expected effectiveness."""
        if not self.is_available or not strategies:
            return strategies

        strategies_json = json.dumps(strategies)
        prompt = f"""Rank these TCP optimization strategies for ISP "{isp}" from most to least likely effective.
Return ONLY a JSON array of the same strategies in ranked order.

Strategies: {strategies_json}"""

        try:
            response = self._chat(prompt)
            ranked = self._parse_strategies(response)
            return ranked if ranked else strategies
        except Exception:
            return strategies

    # ─── Internal ──────────────────────────────────────────────────────────

    def _chat(self, user_message: str) -> str:
        """Send a message through the server AI proxy."""
        resp = requests.post(
            f"{self._server_url}/api/v1/ai/chat",
            headers={
                "X-API-Key": self._server_key,
                "Content-Type": "application/json",
            },
            json={
                "install_id": self._install_id,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                "temperature": 0.7,
                "max_tokens": 1024,
            },
            timeout=45,
        )

        if resp.status_code == 429:
            logger.info("AI rate limited: %s", resp.json().get("detail", ""))
            raise RuntimeError("AI rate limited")

        if resp.status_code != 200:
            raise RuntimeError(f"AI proxy error: HTTP {resp.status_code} - {resp.text[:200]}")

        data = resp.json()
        self._last_model = data.get("model", "unknown")
        return data["content"]

    def _build_context(self, isp: str, middlebox_type: str, region: str) -> str:
        """Build context string from analytics data."""
        lines = []

        # Top strategies for this ISP
        best = self._analytics.get_best_flags_for_isp(isp, limit=5)
        if best:
            lines.append("Top known strategies:")
            for s in best:
                flags_str = " ".join(s["flags"])
                lines.append(f"  fitness={s['fitness']:.2f} wins={s['wins']} losses={s['losses']} | {flags_str}")

        # Host success rates
        for host in ["youtube.com", "discord.com", "x.com"]:
            rate = self._analytics.get_host_success_rate(host, hours=48)
            if rate > 0:
                lines.append(f"  {host}: {rate:.0%} success (48h)")

        # Stats
        stats = self._analytics.get_stats_summary()
        lines.append(f"Total strategies tested: {stats['total_strategies']}")
        lines.append(f"Total connection tests: {stats['total_tests']}")

        return "\n".join(lines) if lines else "No historical data available yet."

    @staticmethod
    def _parse_strategies(response: str) -> list[list[str]]:
        """Parse AI response into list of strategy flag arrays."""
        # Try to find JSON array in response
        text = response.strip()

        # Try direct parse
        try:
            data = json.loads(text)
            if isinstance(data, list) and all(isinstance(s, list) for s in data):
                return data
            if isinstance(data, dict) and "improved_flags" in data:
                return [data["improved_flags"]]
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code block
        if "```" in text:
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

        # Try to find array anywhere
        start = text.find("[[")
        end = text.rfind("]]") + 2
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        logger.debug("Could not parse AI response: %s", text[:200])
        return []
