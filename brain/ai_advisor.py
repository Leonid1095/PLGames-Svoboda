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
zapret2 uses Lua-based strategies passed as --lua-desync= arguments.

AVAILABLE DESYNC FUNCTIONS:
  fake        — send fake packet (needs blob= parameter)
  fakedsplit  — fake + split combined
  multisplit  — split TCP into multiple segments
  multidisorder — split + reorder segments
  disorder    — reorder TCP segments
  syndata     — send data in SYN packet
  pktmod      — modify current packet (fooling)
  wssize      — modify TCP window size
  send        — send current dissect with modifiers
  drop        — drop original packet

AVAILABLE PARAMETERS (colon-separated after function name):
  blob=fake_default_tls|fake_default_http|fake_default_quic|0x00000000
  ip_ttl=N              (N = 1 to 15)
  ip6_ttl=N             (N = 1 to 15)
  ip_autottl=DELTA,MIN-MAX  (e.g. -2,3-20)
  ip6_autottl=DELTA,MIN-MAX
  tcp_md5               (boolean, no value)
  tcp_ts_up             (boolean)
  tcp_seq=N             (e.g. -10000, -66000)
  tcp_ack=N             (e.g. -66000)
  tcp_flags_unset=ack
  repeats=N             (N = 1 to 11)
  pos=MARKER            (1, 2, 5, midsld, method+2, endhost-1)
  seqovl=N              (N = 1 to 10)
  seqovl_pattern=HEX    (e.g. 0x1603030000)
  tls_mod=MODS          (rnd, rndsni, dupsid — comma-separated)
  ipfrag                (boolean, enable IP fragmentation)
  nofake1               (boolean)
  wsize=N               (TCP window size)
  scale=N               (TCP window scale)

RULES:
- Each strategy is an array of lua-desync call strings
- Format: "function:param1:param2:param3"
- Each strategy MUST have at least one primary desync function (fake, multisplit, etc.)
- 1-4 calls per strategy
- Return ONLY a valid JSON array of arrays, no text

EXAMPLE OUTPUT:
[
  ["fake:blob=fake_default_tls:ip_ttl=6:tcp_md5", "multisplit:pos=midsld"],
  ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:tcp_md5:repeats=6", "multidisorder:pos=1,midsld"],
  ["fakedsplit:blob=fake_default_tls:ip_ttl=4:tcp_seq=-10000", "pktmod:tcp_md5"]
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

    def suggest_strategies(
        self, isp: str, middlebox_type: str = "unknown", region: str = "",
        ai_feedback=None, tspu_profile=None,
    ) -> list[list[str]]:
        """Ask AI to suggest strategies using structured feedback data.

        If ai_feedback is provided, sends full test history + observations.
        Falls back to built-in expert strategies if server is unavailable.
        """
        # Try server AI with structured context
        if self.is_available:
            if ai_feedback and hasattr(ai_feedback, 'build_structured_prompt'):
                # NEW: structured prompt with full test history
                best_known = None
                best_fitness = 0.0
                best_db = self._analytics.get_best_flags_for_isp(isp, limit=1)
                if best_db:
                    best_known = best_db[0]["flags"]
                    best_fitness = best_db[0]["fitness"]

                tspu_dict = {}
                if tspu_profile:
                    tspu_dict = {
                        "dpi_hop_distance": getattr(tspu_profile, 'dpi_hop_distance', None),
                        "server_hop_distance": getattr(tspu_profile, 'server_hop_distance', None),
                        "recommended_ttl": getattr(tspu_profile, 'recommended_ttl', None),
                        "blocks_tls_sni": getattr(tspu_profile, 'blocks_tls_sni', True),
                        "dpi_type": getattr(tspu_profile, 'dpi_type', 'unknown'),
                    }

                prompt = ai_feedback.build_structured_prompt(
                    isp=isp, asn="", tspu_profile=tspu_dict,
                    best_known=best_known, best_fitness=best_fitness,
                    problem=f"Need better strategies for {isp}, middlebox={middlebox_type}",
                )
            else:
                # Legacy: simple prompt
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

        # Fallback: built-in expert strategies based on analytics
        return self._builtin_expert_strategies(isp)

    def _builtin_expert_strategies(self, isp: str) -> list[list[str]]:
        """Built-in expert strategies when AI server is unavailable.

        Based on zapret2 documentation + known TSPU behavior patterns.
        Prioritizes strategies by what works for Russian ISPs.
        """
        # Check analytics for what worked before
        best_known = self._analytics.get_best_flags_for_isp(isp, limit=3)
        strategies: list[list[str]] = []

        # Re-use top known strategies with mutations
        for s in best_known:
            if s["fitness"] > 0.3:
                strategies.append(s["flags"])

        # Expert strategies for Russian TSPU (proven patterns)
        # Key: ip_autottl auto-detects correct TTL so fake reaches DPI but not server
        expert = [
            # autottl fake + split (safest: TTL auto-calibrated)
            ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6", "multisplit:pos=midsld"],
            # multidisorder works well against TSPU sequence analysis
            ["multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"],
            # autottl fake + multidisorder (for long connections like Discord)
            ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5", "multidisorder:pos=1,midsld"],
            # multisplit at multiple positions
            ["multisplit:pos=1,midsld,endhost-1:seqovl=6:seqovl_pattern=0x1603030000"],
            # fakedsplit with autottl
            ["fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5"],
            # aggressive: autottl + high repeats + split
            ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5:repeats=8", "multidisorder:pos=1,midsld"],
        ]

        strategies.extend(expert)
        logger.info("Built-in expert: %d strategies (incl %d from analytics)", len(strategies), len(best_known))
        return strategies

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
