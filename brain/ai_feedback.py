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
        """Auto-exclude function classes that consistently fail."""
        if len(self.history) < 5:
            return

        # Count fake successes vs failures
        fake_tests = [r for r in self.history
                      if any("fake" in s or "fakedsplit" in s for s in r.strategy)]
        if len(fake_tests) >= 3:
            fake_success = sum(1 for r in fake_tests if r.fitness > 0.3)
            if fake_success == 0:
                self._excluded_functions.add("fake")
                self._excluded_functions.add("fakedsplit")
                logger.info("AI feedback: excluded 'fake' — 0/%d successes", len(fake_tests))

        # Count syndata
        syndata_tests = [r for r in self.history
                         if any("syndata" in s for s in r.strategy)]
        if len(syndata_tests) >= 3:
            syn_success = sum(1 for r in syndata_tests if r.fitness > 0.3)
            if syn_success == 0:
                self._excluded_functions.add("syndata")

    def _generate_observations(self) -> list[str]:
        """Generate human-readable observations from test history."""
        observations = []

        if not self.history:
            return ["No test data collected yet."]

        # Best strategy
        best = max(self.history, key=lambda r: r.fitness)
        if best.fitness > 0:
            observations.append(
                f"Best strategy: {' | '.join(best.strategy)} (fitness={best.fitness:.3f})"
            )

        # Fake analysis
        fake_tests = [r for r in self.history
                      if any("fake" in s for s in r.strategy)]
        if fake_tests:
            avg_fake = sum(r.fitness for r in fake_tests) / len(fake_tests)
            if avg_fake < 0.1:
                observations.append(
                    f"IMPORTANT: All {len(fake_tests)} fake strategies scored avg={avg_fake:.3f} — "
                    f"fake does NOT work on this ISP. DPI likely ignores TTL-based fakes."
                )

        # Split analysis
        split_tests = [r for r in self.history
                       if any("multisplit" in s for s in r.strategy)]
        if split_tests:
            avg_split = sum(r.fitness for r in split_tests) / len(split_tests)
            if avg_split > 0.5:
                observations.append(
                    f"multisplit strategies work well (avg={avg_split:.3f}) — "
                    f"DPI is vulnerable to ClientHello splitting."
                )

        # seqovl impact
        with_seqovl = [r for r in self.history if any("seqovl" in s for s in r.strategy)]
        without_seqovl = [r for r in self.history
                          if any("multisplit" in s for s in r.strategy)
                          and not any("seqovl" in s for s in r.strategy)]
        if with_seqovl and without_seqovl:
            avg_with = sum(r.fitness for r in with_seqovl) / len(with_seqovl)
            avg_without = sum(r.fitness for r in without_seqovl) / len(without_seqovl)
            if avg_with > avg_without + 0.05:
                observations.append(
                    f"seqovl improves fitness: +{avg_with - avg_without:.3f} "
                    f"(with={avg_with:.3f} vs without={avg_without:.3f})"
                )

        # Excluded
        if self._excluded_functions:
            observations.append(
                f"Excluded from gene pool: {', '.join(self._excluded_functions)}"
            )

        return observations
