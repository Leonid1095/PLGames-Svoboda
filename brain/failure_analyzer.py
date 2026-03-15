"""FailureAnalyzer — structured analysis of strategy failures.

Instead of AI just suggesting random strategies, this module:
1. Analyzes per-host error patterns
2. Identifies root cause (TTL too low, wrong split pos, etc.)
3. Suggests specific parameter changes
4. Can use AI for complex cases via server proxy
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from brain.tester import StrategyTestReport, HostTestResult
from brain.tspu_profiler import TSPUProfile

logger = logging.getLogger("svoboda.analyzer")


@dataclass
class StrategyDelta:
    """A specific change to a strategy."""
    action: str          # "add" | "remove" | "modify" | "replace"
    target: str          # parameter or call to change
    old_value: str = ""
    new_value: str = ""
    reason: str = ""


@dataclass
class FailureReport:
    """Structured analysis of why a strategy failed."""
    root_cause: str         # short identifier
    confidence: float       # 0.0-1.0
    explanation: str        # human-readable
    changes: list[StrategyDelta] = field(default_factory=list)
    improved_flags: list[str] = field(default_factory=list)


class FailureAnalyzer:
    """Analyze strategy failures and suggest improvements."""

    def analyze(
        self,
        flags: list[str],
        fitness: float,
        host_results: dict,
        tspu_profile: Optional[TSPUProfile] = None,
    ) -> FailureReport:
        """Analyze why a strategy scored low fitness.

        Args:
            flags: the strategy that was tested
            host_results: per-host test results from tester
            tspu_profile: optional TSPU fingerprint

        Returns:
            FailureReport with root cause + suggested changes
        """
        flag_str = " | ".join(flags)

        # Count error types across all hosts
        errors = {"rst": 0, "timeout": 0, "ssl": 0, "dns": 0, "error": 0, "ok": 0}
        for host, data in host_results.items():
            if isinstance(data, dict):
                for et in data.get("error_types", []):
                    errors[et] = errors.get(et, 0) + 1
                errors["ok"] += data.get("successes", 0)

        total_fail = sum(v for k, v in errors.items() if k != "ok")
        total_ok = errors["ok"]

        # ── Rule-based analysis ──────────────────────────────────────

        # All timeout = strategy breaks traffic or TTL too low
        if errors["timeout"] > 0 and total_ok == 0:
            return self._analyze_all_timeout(flags, tspu_profile)

        # All RST = DPI still sees real SNI
        if errors["rst"] > 0 and total_ok == 0:
            return self._analyze_all_rst(flags, tspu_profile)

        # SSL errors = TLS handshake corrupted
        if errors["ssl"] > 0:
            return self._analyze_ssl_errors(flags, tspu_profile)

        # Partial success = some hosts work, others don't
        if total_ok > 0 and total_fail > 0:
            return self._analyze_partial(flags, host_results, tspu_profile)

        # Default: generic analysis
        return FailureReport(
            root_cause="unknown",
            confidence=0.3,
            explanation=f"Strategy scored {fitness:.3f} with mixed results. "
                       f"Errors: {errors}. Manual investigation needed.",
        )

    # ─── Specific failure patterns ───────────────────────────────────────

    def _analyze_all_timeout(
        self, flags: list[str], tspu: Optional[TSPUProfile],
    ) -> FailureReport:
        """All tests timed out — strategy is breaking traffic."""
        flag_str = " ".join(flags)
        changes: list[StrategyDelta] = []
        improved = list(flags)

        # Check if using fake with fixed TTL
        has_fixed_ttl = "ip_ttl=" in flag_str
        has_autottl = "ip_autottl" in flag_str
        has_fake = any(f.startswith("fake") or f.startswith("fakedsplit") for f in flags)

        if has_fake and has_fixed_ttl and not has_autottl:
            # Fixed TTL is likely too low or too high
            reason = "Fixed TTL may not reach DPI or may reach server"
            if tspu and tspu.recommended_ttl:
                changes.append(StrategyDelta(
                    action="modify", target="ip_ttl",
                    old_value="current", new_value=str(tspu.recommended_ttl),
                    reason=f"DPI at ~{tspu.dpi_hop_distance} hops, use TTL={tspu.recommended_ttl}",
                ))
            else:
                changes.append(StrategyDelta(
                    action="replace", target="ip_ttl",
                    new_value="ip_autottl=-1,3-20",
                    reason="Switch to autottl for automatic calibration",
                ))

            return FailureReport(
                root_cause="ttl_misconfigured",
                confidence=0.75,
                explanation=f"All connections timed out. fake with fixed ip_ttl is "
                           f"{'reaching server (too high)' if has_fixed_ttl else 'dying before DPI (too low)'}. "
                           f"{reason}.",
                changes=changes,
            )

        if has_fake and has_autottl:
            # autottl needs incoming packets to calibrate — may not work without --wf-tcp-in
            return FailureReport(
                root_cause="autottl_no_calibration",
                confidence=0.70,
                explanation="autottl cannot calibrate without incoming packets. "
                           "On Windows, --wf-tcp-in is needed but may cause issues. "
                           "Try strategy without fake (pure split/disorder).",
                changes=[StrategyDelta(
                    action="remove", target="fake call",
                    reason="Remove fake, use only multisplit/multidisorder",
                )],
            )

        # No fake — pure split/disorder causing timeout = DPI not affected
        return FailureReport(
            root_cause="strategy_ineffective",
            confidence=0.60,
            explanation="All connections timed out. Strategy doesn't bypass this DPI. "
                       "Try different approach: fake+TTL or stronger split positions.",
            changes=[StrategyDelta(
                action="add", target="seqovl",
                new_value="seqovl=5:seqovl_pattern=0x1603030000",
                reason="Add sequence overlap to confuse DPI reassembly",
            )],
        )

    def _analyze_all_rst(
        self, flags: list[str], tspu: Optional[TSPUProfile],
    ) -> FailureReport:
        """All tests got RST — DPI is actively blocking."""
        flag_str = " ".join(flags)
        changes: list[StrategyDelta] = []

        has_split = any("multisplit" in f or "multidisorder" in f for f in flags)
        has_seqovl = "seqovl" in flag_str

        if not has_split:
            changes.append(StrategyDelta(
                action="add", target="multisplit",
                new_value="multisplit:pos=1,midsld",
                reason="DPI sees complete SNI — split ClientHello",
            ))
        elif has_split and not has_seqovl:
            changes.append(StrategyDelta(
                action="modify", target="split params",
                new_value="seqovl=5:seqovl_pattern=0x1603030000",
                reason="DPI reassembles split packets — add sequence overlap",
            ))
        else:
            changes.append(StrategyDelta(
                action="add", target="fake",
                new_value="fake:blob=fake_default_tls:ip_autottl=-1,3-20:tcp_md5:repeats=6",
                reason="DPI sees through split+seqovl — need fake packet injection",
            ))

        return FailureReport(
            root_cause="dpi_active_rst",
            confidence=0.80,
            explanation="DPI actively sends RST packets. It can see the SNI despite our strategy. "
                       "Need stronger packet manipulation.",
            changes=changes,
        )

    def _analyze_ssl_errors(
        self, flags: list[str], tspu: Optional[TSPUProfile],
    ) -> FailureReport:
        """SSL/TLS errors — DPI corrupts handshake or certificate mismatch."""
        return FailureReport(
            root_cause="tls_corruption",
            confidence=0.65,
            explanation="TLS handshake fails with SSL error. DPI may be corrupting packets "
                       "or an antivirus (Kaspersky) is interfering with TLS.",
            changes=[
                StrategyDelta(
                    action="replace", target="strategy",
                    new_value="multisplit:pos=1,midsld,endhost-1:seqovl=6:seqovl_pattern=0x1603030000",
                    reason="Try multi-position split to hide ClientHello from DPI",
                ),
            ],
        )

    def _analyze_partial(
        self, flags: list[str], host_results: dict,
        tspu: Optional[TSPUProfile],
    ) -> FailureReport:
        """Some hosts work, others don't — different block methods per host."""
        working = []
        failing = []

        for host, data in host_results.items():
            if isinstance(data, dict):
                if data.get("successes", 0) > 0:
                    working.append(host)
                else:
                    failing.append(host)

        return FailureReport(
            root_cause="partial_bypass",
            confidence=0.70,
            explanation=f"Strategy works for {', '.join(working)} but fails for {', '.join(failing)}. "
                       f"Different sites may need different strategies. "
                       f"Consider per-host strategy profiles.",
            changes=[],
        )

    # ─── AI-enhanced analysis ────────────────────────────────────────────

    def build_ai_prompt(
        self,
        flags: list[str],
        fitness: float,
        host_results: dict,
        tspu_profile: Optional[TSPUProfile] = None,
        local_analysis: Optional[FailureReport] = None,
    ) -> str:
        """Build structured prompt for AI server analysis.

        Returns a prompt string to send to /api/v1/ai/chat.
        AI should return JSON with specific StrategyDelta changes.
        """
        prompt_parts = [
            "Analyze this zapret2 desync strategy failure and suggest SPECIFIC parameter changes.",
            "",
            f"Strategy tested: {' | '.join(flags)}",
            f"Fitness score: {fitness:.3f}",
        ]

        if tspu_profile:
            prompt_parts.extend([
                "",
                "TSPU Profile:",
                f"  DPI distance: ~{tspu_profile.dpi_hop_distance} hops",
                f"  Server distance: ~{tspu_profile.server_hop_distance} hops",
                f"  Recommended TTL: {tspu_profile.recommended_ttl}",
                f"  Blocks SNI: {tspu_profile.blocks_tls_sni}",
                f"  Blocks HTTP Host: {tspu_profile.blocks_http_host}",
                f"  DPI type: {tspu_profile.dpi_type}",
                f"  ISP: {tspu_profile.isp}",
            ])

        if host_results:
            prompt_parts.extend(["", "Per-host results:"])
            for host, data in host_results.items():
                if isinstance(data, dict):
                    prompt_parts.append(
                        f"  {host}: {data.get('successes', 0)}/{data.get('total', 0)} OK, "
                        f"errors={data.get('error_types', [])}, "
                        f"avg_latency={data.get('avg_latency_ms', 0):.0f}ms"
                    )

        if local_analysis:
            prompt_parts.extend([
                "",
                f"Local analysis: {local_analysis.root_cause} (confidence={local_analysis.confidence:.0%})",
                f"Explanation: {local_analysis.explanation}",
            ])

        prompt_parts.extend([
            "",
            "Return ONLY a JSON object:",
            '{"root_cause": "...", "improved_flags": [["call1", "call2"], ...], '
            '"explanation": "brief reason"}',
        ])

        return "\n".join(prompt_parts)
