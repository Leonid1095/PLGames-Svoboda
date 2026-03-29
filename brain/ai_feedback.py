"""AI Feedback Loop — structured context for AI strategy suggestions.

Instead of sending "suggest strategies for AS42116", we send the full
history of what was tested, what worked, what failed and why.
AI becomes a network engineer analyzing real data, not a text generator.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("svoboda.ai_feedback")


@dataclass
class TestRecord:
    """One strategy test result."""
    strategy: list[str]
    fitness: float
    failure_mode: str  # "ok" | "rst" | "timeout" | "ssl" | "h2_kill"
    host_results: dict = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "strategy": " | ".join(self.strategy),
            "fitness": round(self.fitness, 3),
            "failure_mode": self.failure_mode,
        }


class AIFeedbackLoop:
    """Collects test results and builds structured AI context.

    After enough tests, AI can see patterns:
    - "fake always fails on this ISP → exclude from gene pool"
    - "multisplit:pos=3 works but pos=1 doesn't → DPI at position 3"
    - "seqovl improves fitness by 0.15 → recommend adding it"
    """

    def __init__(self, max_history: int = 50):
        self.history: list[TestRecord] = []
        self.max_history = max_history
        self._excluded_functions: set[str] = set()

    def record_test(
        self,
        strategy: list[str],
        fitness: float,
        failure_mode: str = "",
        host_results: dict = None,
    ) -> None:
        """Record a test result for AI learning."""
        if not failure_mode:
            failure_mode = "ok" if fitness > 0.3 else "timeout"

        self.history.append(TestRecord(
            strategy=strategy,
            fitness=fitness,
            failure_mode=failure_mode,
            host_results=host_results or {},
            timestamp=time.time(),
        ))

        # Keep history bounded
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

        # Auto-learn: exclude function classes that consistently fail
        self._update_exclusions()

    def get_excluded_functions(self) -> set[str]:
        """Functions that should be excluded from GA gene pool on this ISP."""
        return self._excluded_functions

    def build_ai_context(
        self,
        isp: str = "unknown",
        asn: str = "",
        tspu_profile: dict = None,
        best_known: Optional[list[str]] = None,
        best_fitness: float = 0.0,
    ) -> str:
        """Build structured JSON context for AI prompt.

        This replaces the old "suggest strategies for ASN" approach.
        AI now sees what was tested and what worked/failed.
        """
        # Classify results by function type
        fake_results = []
        split_results = []
        disorder_results = []
        other_results = []

        for r in self.history[-20:]:  # last 20 tests
            strat_str = " | ".join(r.strategy)
            entry = r.to_dict()

            if any("fake" in s or "fakedsplit" in s for s in r.strategy):
                fake_results.append(entry)
            elif any("multisplit" in s for s in r.strategy):
                split_results.append(entry)
            elif any("multidisorder" in s for s in r.strategy):
                disorder_results.append(entry)
            else:
                other_results.append(entry)

        context = {
            "isp": isp,
            "asn": asn,
            "tspu_profile": tspu_profile or {},
            "best_known_strategy": " | ".join(best_known) if best_known else "none",
            "best_known_fitness": best_fitness,
            "excluded_functions": list(self._excluded_functions),
            "test_history": {
                "fake_strategies": fake_results,
                "multisplit_strategies": split_results,
                "multidisorder_strategies": disorder_results,
                "other_strategies": other_results,
            },
            "observations": self._generate_observations(),
        }

        return json.dumps(context, ensure_ascii=False, indent=2)

    def build_structured_prompt(
        self,
        isp: str = "unknown",
        asn: str = "",
        tspu_profile: dict = None,
        best_known: Optional[list[str]] = None,
        best_fitness: float = 0.0,
        problem: str = "",
    ) -> str:
        """Build the full AI prompt with structured context."""
        context_json = self.build_ai_context(
            isp, asn, tspu_profile, best_known, best_fitness,
        )

        observations = self._generate_observations()
        obs_text = "\n".join(f"- {o}" for o in observations) if observations else "No patterns detected yet."

        return f"""You are an expert network engineer specializing in DPI bypass with zapret2.

NETWORK DATA (structured):
{context_json}

OBSERVATIONS:
{obs_text}

CURRENT PROBLEM: {problem or 'Need to improve bypass fitness'}

TASK: Based on the test history above, suggest SPECIFIC parameter changes
to the best known strategy. Do NOT suggest function classes that are in
the excluded list (they consistently fail on this ISP).

Return ONLY a JSON object:
{{
  "analysis": "Brief explanation of why current strategy scores {best_fitness}",
  "changes": [
    {{"action": "modify|add|remove", "target": "parameter_name", "value": "new_value", "reason": "why"}}
  ],
  "improved_strategy": [["call1:param1:param2", "call2:param1"]],
  "confidence": 0.0-1.0
}}"""

    # ─── Internal learning ───────────────────────────────────────────

    def _update_exclusions(self) -> None:
        """Auto-exclude function classes that consistently fail.

        Analyzes test history and excludes functions that NEVER work,
        saving time for the enumerator and GA.
        """
        if len(self.history) < 5:
            return

        # Auto-exclude function classes that scored 0 in 3+ tests
        for func_name in ("syndata", "fake", "fakedsplit", "tcpseg", "hostfakesplit"):
            tests = [r for r in self.history if any(func_name in s for s in r.strategy)]
            if len(tests) >= 3:
                successes = sum(1 for r in tests if r.fitness > 0.1)
                if successes == 0:
                    self._excluded_functions.add(func_name)
                    logger.info("Auto-excluded '%s': 0/%d tests succeeded", func_name, len(tests))

    def _generate_observations(self) -> list[str]:
        """Generate deep observations from test history.

        Performs the kind of analysis a human expert would:
        1. Per-domain failure patterns (is a domain ALWAYS failing?)
        2. Strategy class effectiveness (fake=0, multisplit=good, etc.)
        3. Parameter impact analysis (seqovl, wssize, etc.)
        4. Root cause diagnosis (SNI proxy, TSPU specifics)
        """
        observations = []

        if not self.history:
            return ["No test data collected yet."]

        # ── Best strategy ──────────────────────────────────────────
        best = max(self.history, key=lambda r: r.fitness)
        if best.fitness > 0:
            observations.append(
                f"Best strategy: {' | '.join(best.strategy)} (fitness={best.fitness:.3f})"
            )

        # ── Per-domain failure analysis ────────────────────────────
        # Like a human would: "youtube.com ALWAYS fails → not a strategy issue"
        domain_stats: dict[str, dict] = {}  # domain → {total, success, errors}
        for rec in self.history:
            if not rec.host_results:
                continue
            for host, result in rec.host_results.items():
                if host not in domain_stats:
                    domain_stats[host] = {"total": 0, "success": 0, "errors": {}}
                domain_stats[host]["total"] += 1
                if isinstance(result, dict):
                    ok = result.get("success", False)
                    err = result.get("error_type", "unknown")
                elif isinstance(result, bool):
                    ok = result
                    err = "unknown"
                else:
                    ok = bool(result)
                    err = "unknown"
                if ok:
                    domain_stats[host]["success"] += 1
                else:
                    domain_stats[host]["errors"][err] = domain_stats[host]["errors"].get(err, 0) + 1

        for host, stats in domain_stats.items():
            total = stats["total"]
            if total < 3:
                continue
            success_rate = stats["success"] / total
            if success_rate == 0:
                top_err = max(stats["errors"], key=stats["errors"].get) if stats["errors"] else "unknown"
                observations.append(
                    f"CRITICAL: {host} failed ALL {total} tests (error={top_err}). "
                    f"This is NOT a strategy problem — the domain may need a proxy, "
                    f"or winws2 is interfering with SNI proxy traffic."
                )
            elif success_rate < 0.2:
                observations.append(
                    f"WARNING: {host} only passed {stats['success']}/{total} tests. "
                    f"Consider per-host solver or proxy routing."
                )
            elif success_rate > 0.8:
                observations.append(
                    f"{host} works reliably ({stats['success']}/{total} passed)."
                )

        # ── Strategy class analysis ────────────────────────────────
        # "ALL fake = 0 → TSPU detects fake packets on this ISP"
        class_stats: dict[str, list[float]] = {}
        for func_name in ("fake", "multisplit", "multidisorder", "wssize", "fakedsplit"):
            tests = [r for r in self.history if any(func_name in s for s in r.strategy)]
            if tests:
                fitnesses = [r.fitness for r in tests]
                class_stats[func_name] = fitnesses

        for func_name, fitnesses in class_stats.items():
            avg = sum(fitnesses) / len(fitnesses)
            count = len(fitnesses)
            if avg < 0.05 and count >= 3:
                observations.append(
                    f"IMPORTANT: ALL {count} '{func_name}' strategies scored avg={avg:.3f}. "
                    f"{func_name} does NOT work on this ISP — auto-excluded from search."
                )
            elif avg > 0.3 and count >= 2:
                observations.append(
                    f"'{func_name}' strategies work (avg={avg:.3f}, {count} tests). "
                    f"Focus evolution on {func_name}-based strategies."
                )

        # ── Fitness ceiling detection ──────────────────────────────
        # "Best is 0.43 after 53 strategies → one domain always fails"
        top_results = sorted(self.history, key=lambda r: r.fitness, reverse=True)[:10]
        if len(top_results) >= 5:
            ceiling = sum(r.fitness for r in top_results[:5]) / 5
            if 0.35 < ceiling < 0.50:
                observations.append(
                    f"FITNESS CEILING at ~{ceiling:.2f} — suggests 1-2 domains always fail "
                    f"regardless of strategy. These domains likely need proxy routing, "
                    f"not DPI bypass. Check per-domain stats above."
                )

        # ── seqovl impact ──────────────────────────────────────────
        with_seqovl = [r for r in self.history if any("seqovl" in s for s in r.strategy)]
        without_seqovl = [r for r in self.history
                          if any("multisplit" in s for s in r.strategy)
                          and not any("seqovl" in s for s in r.strategy)]
        if with_seqovl and without_seqovl:
            avg_with = sum(r.fitness for r in with_seqovl) / len(with_seqovl)
            avg_without = sum(r.fitness for r in without_seqovl) / len(without_seqovl)
            diff = avg_with - avg_without
            if abs(diff) > 0.03:
                better = "improves" if diff > 0 else "hurts"
                observations.append(
                    f"seqovl {better} fitness by {abs(diff):.3f} "
                    f"(with={avg_with:.3f} vs without={avg_without:.3f})"
                )

        # ── wssize impact ──────────────────────────────────────────
        with_wssize = [r for r in self.history if any("wssize" in s for s in r.strategy)]
        without_wssize = [r for r in self.history
                          if not any("wssize" in s for s in r.strategy)
                          and any("multisplit" in s or "multidisorder" in s for s in r.strategy)]
        if with_wssize and without_wssize:
            avg_ws = sum(r.fitness for r in with_wssize) / len(with_wssize)
            avg_no_ws = sum(r.fitness for r in without_wssize) / len(without_wssize)
            if abs(avg_ws - avg_no_ws) > 0.03:
                better = "helps" if avg_ws > avg_no_ws else "hurts"
                observations.append(
                    f"wssize {better}: {avg_ws:.3f} vs {avg_no_ws:.3f}"
                )

        # ── Excluded ───────────────────────────────────────────────
        if self._excluded_functions:
            observations.append(
                f"Auto-excluded (never work): {', '.join(sorted(self._excluded_functions))}"
            )

        return observations
