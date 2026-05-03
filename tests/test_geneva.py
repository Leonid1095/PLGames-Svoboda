"""Tests for Geneva strategy mutation preservation invariants.

The composer's mutate_strategy used to be free to remove any operator
that wasn't a fragment, which silently destroyed the alpn_modify gene
in our h2-downgrade seeds. Lock down the structural-op preservation
and leading-op ordering contracts.
"""

from __future__ import annotations

import random
import unittest

from brain.geneva import GenevaComposer, GenevaOp, mutate_flags_geneva


class TestMutatePreservesStructuralOps(unittest.TestCase):
    """alpn_modify and fragment must survive mutate_strategy + roundtrip."""

    def setUp(self) -> None:
        # Deterministic randomness so the assertions are stable.
        random.seed(42)
        self.composer = GenevaComposer()

    def test_alpn_modify_never_dropped_by_mutate_strategy(self) -> None:
        ops = [
            GenevaOp("alpn_modify", {"strip": "h2,h2c"}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ]
        for _ in range(200):
            mutated = self.composer.mutate_strategy(list(ops))
            self.assertTrue(
                any(op.name == "alpn_modify" for op in mutated),
                "alpn_modify must survive mutation",
            )

    def test_alpn_modify_stays_leading(self) -> None:
        ops = [
            GenevaOp("alpn_modify", {"strip": "h2,h2c"}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ]
        for _ in range(200):
            mutated = self.composer.mutate_strategy(list(ops))
            self.assertTrue(mutated, "mutation must not produce empty op list")
            self.assertEqual(
                mutated[0].name, "alpn_modify",
                "alpn_modify must remain at index 0 (semantic ordering — runs "
                "before fragments which would otherwise drop the original packet)",
            )

    def test_fragment_never_dropped_by_mutate_strategy(self) -> None:
        ops = [GenevaOp("fragment", {"offset": "1,midsld", "in_order": False})]
        for _ in range(200):
            mutated = self.composer.mutate_strategy(list(ops))
            self.assertTrue(
                any(op.name == "fragment" for op in mutated),
                "fragment must survive mutation (defines what the strategy is)",
            )

    def test_alpn_strip_survives_full_flag_roundtrip(self) -> None:
        """End-to-end: flags -> ops -> mutate -> flags should keep alpn_strip
        in the chain and as the first call."""
        flags = ["alpn_strip:strip=h2,h2c", "multidisorder:pos=1,midsld"]
        for _ in range(200):
            out = mutate_flags_geneva(flags, dpi_type="tspu")
            self.assertTrue(out, "roundtrip must produce non-empty flag list")
            self.assertTrue(
                any("alpn_strip" in f for f in out),
                f"alpn_strip dropped during roundtrip: {out}",
            )
            self.assertIn(
                "alpn_strip", out[0],
                f"alpn_strip not at index 0 after roundtrip: {out}",
            )


if __name__ == "__main__":
    unittest.main()
