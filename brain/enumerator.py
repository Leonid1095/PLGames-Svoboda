"""StrategyEnumerator — blockcheck2-style deterministic strategy testing.

Instead of random GA evolution, tests a curated list of known-working
strategies in priority order. Returns the first one that passes threshold.

Modeled after zapret2 blockcheck2.sh approach:
  - Pre-defined strategy list ordered by effectiveness
  - Test each sequentially, stop at first success
  - Much faster than GA: 15-60 seconds vs 15-17 minutes
"""

from __future__ import annotations

import logging
from typing import Optional

from brain.tester import ConnectionTester

logger = logging.getLogger("svoboda.enumerator")


# ─── Known-working strategies, ordered by priority ───────────────────────────
# Each strategy is tested in order; first one passing threshold wins.
# Sorted by: anti-throttle first (Tier 0) → autottl → fixed TTL → basic split → minimalist

KNOWN_STRATEGIES: list[dict] = [
    # ── Tier 0: Anti-throttle FIRST (ER-Telecom/Dom.ru + Flowseal proven) ─
    # TSPU stateful DPI throttles connections when it recognizes bypass pattern.
    # seqovl=4096 overwhelms DPI state buffer. seqovl=681 = SNI field offset.
    # These must be tested BEFORE basic seqovl=8 strategies which get throttled.
    {
        "name": "ertel_multisplit_4096",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "ER-Telecom/Dom.ru: 4KB overlap overwhelms DPI state buffer",
    },
    {
        "name": "ertel_multisplit_4096_disorder",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "ER-Telecom: 4KB overlap + disorder (proven for Dom.ru)",
    },
    {
        "name": "ertel_hostfakesplit",
        "flags": [
            "hostfakesplit:host=ya.ru:tcp_md5:badsum",
        ],
        "desc": "ER-Telecom: send fake ya.ru SNI (bad checksum) before real ClientHello",
    },
    {
        "name": "ertel_fake_4096",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5:repeats=6:tls_mod=rnd,dupsid",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "ER-Telecom: fake Google SNI TTL=5 + split 4096",
    },
    {
        "name": "flowseal_681_disorder",
        "flags": [
            "multisplit:pos=1:seqovl=681",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Flowseal: SNI-field offset 681 + disorder (anti-throttle)",
    },
    {
        "name": "flowseal_681_fake",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=8:tls_mod=rnd,dupsid",
            "multisplit:pos=1:seqovl=681",
        ],
        "desc": "Flowseal: fake (Google SNI) + split at SNI offset 681",
    },
    {
        "name": "flowseal_568_disorder",
        "flags": [
            "multisplit:pos=1:seqovl=568",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Flowseal: split at seqovl=568 + disorder (alt position)",
    },
    {
        "name": "flowseal_fakedsplit_aggressive",
        "flags": [
            "fakedsplit:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=6",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Flowseal: fakedsplit + aggressive disorder",
    },
    # blockcheck2 canonical: split at SNI extension boundary with full blob as seqovl_pattern
    # This is what zapret2's own blockcheck2.d/standard/23-seqovl.sh tests.
    # seqovl_pattern=fake_default_tls makes the overlap data look like a TLS ClientHello.
    {
        "name": "blockcheck2_sniext1_pat",
        "flags": [
            "multisplit:pos=sniext+1:seqovl=681:seqovl_pattern=fake_default_tls",
        ],
        "desc": "blockcheck2 canonical: split at SNI ext+1 with TLS blob overlap",
    },
    {
        "name": "blockcheck2_sniext4_pat",
        "flags": [
            "multisplit:pos=sniext+4:seqovl=681:seqovl_pattern=fake_default_tls",
        ],
        "desc": "blockcheck2 canonical: split at SNI ext+4 with TLS blob overlap",
    },
    {
        "name": "tcpseg_drop",
        "flags": [
            "tcpseg:pos=0,-1:seqovl=1",
            "drop",
        ],
        "desc": "blockcheck2: whole-packet single-byte overlap + drop original (minimal)",
    },
    {
        "name": "tcpseg_blob_drop",
        "flags": [
            "tcpseg:pos=0,-1:seqovl=681:seqovl_pattern=fake_default_tls",
            "drop",
        ],
        "desc": "blockcheck2: whole-packet TLS-blob overlap + drop original",
    },

    # ── Tier 1: autottl-based (safest, auto-calibrates TTL) ──────────────
    {
        "name": "autottl_fake_md5_split",
        "flags": [
            "fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6",
            "multisplit:pos=midsld",
        ],
        "desc": "Fake with auto-TTL + split at SLD boundary",
    },
    {
        "name": "autottl_fake_multidisorder",
        "flags": [
            "fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Fake with auto-TTL + disorder at multiple positions",
    },
    {
        "name": "autottl_fake_high_repeats",
        "flags": [
            "fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5:repeats=8",
            "multisplit:pos=1,midsld",
        ],
        "desc": "Aggressive fake (8 repeats) + split",
    },
    {
        "name": "autottl_fakedsplit",
        "flags": [
            "fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5",
        ],
        "desc": "Single fakedsplit call with auto-TTL",
    },

    # ── Tier 2: fixed TTL fake (for when autottl calibration fails) ──────
    {
        "name": "fake_ttl5_md5_split",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5:repeats=6",
            "multisplit:pos=midsld",
        ],
        "desc": "Fake TTL=5 (TSPU at hop 5) + split",
    },
    {
        "name": "fake_ttl4_md5_disorder",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=4",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Fake TTL=4 + disorder",
    },
    {
        "name": "fake_ttl6_seq_disorder",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=6:ip6_ttl=6:tcp_md5:tcp_seq=-10000",
            "multidisorder:pos=midsld:seqovl=5",
        ],
        "desc": "Fake TTL=6 with seq fooling + disorder",
    },
    {
        "name": "fake_ttl3_md5_split",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=3:ip6_ttl=3:tcp_md5:repeats=6",
            "multisplit:pos=midsld",
        ],
        "desc": "Fake TTL=3 (DPI at 1-2 hops) + split",
    },

    # ── Tier 3: multisplit/multidisorder (no fake, fallback) ─────────────
    # NOTE: seqovl=8 may get THROTTLED by TSPU. Use only after Tier 0-2 fail.
    {
        "name": "multisplit_seqovl_tls",
        "flags": [
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x1603030000",
        ],
        "desc": "Split with TLS-pattern sequence overlap",
    },
    {
        "name": "multisplit_multidisorder",
        "flags": [
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Split + disorder combo (seqovl=8, may throttle on TSPU)",
    },
    {
        "name": "multidisorder_seqovl",
        "flags": [
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Disorder with TLS sequence overlap",
    },
    {
        "name": "multisplit_endhost",
        "flags": [
            "multisplit:pos=1,midsld,endhost-1:seqovl=6:seqovl_pattern=0x1603030000",
        ],
        "desc": "Split at 3 positions including endhost",
    },
    {
        "name": "multidisorder_drop",
        "flags": [
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
            "drop",
        ],
        "desc": "Split + drop original (aggressive)",
    },

    # ── Tier 4: combined strategies (heavier, for aggressive DPI) ────────
    {
        "name": "autottl_fake_split_disorder",
        "flags": [
            "fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=4",
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Triple combo: fake + split + disorder",
    },
    {
        "name": "autottl_fake_aggressive",
        "flags": [
            "fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5:repeats=11",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Max repeats + disorder (last resort)",
    },
    {
        "name": "syndata_split",
        "flags": [
            "syndata",
            "multisplit:pos=1,midsld",
        ],
        "desc": "Send data in SYN + split",
    },

    # ── Tier 5: minimalist (for very simple DPI) ────────────────────────
    {
        "name": "multisplit_simple",
        "flags": [
            "multisplit:pos=midsld",
        ],
        "desc": "Minimal: split at SLD boundary only",
    },
    {
        "name": "multidisorder_simple",
        "flags": [
            "multidisorder:pos=midsld",
        ],
        "desc": "Minimal: disorder at SLD boundary",
    },
    {
        "name": "fakedsplit_ttl5",
        "flags": [
            "fakedsplit:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5",
        ],
        "desc": "Single fakedsplit with fixed TTL",
    },

    # ── Tier 6: morphed strategies (anti-ML DPI) ────────────────────
    {
        "name": "morphed_disorder_seqovl",
        "flags": [
            "wssize:wsize=65535:scale=7",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Chrome-like window + disorder (anti-ML morphing)",
    },
    {
        "name": "morphed_split_padencap",
        "flags": [
            "wssize:wsize=65535:scale=7",
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
        ],
        "desc": "Chrome-like window + split with padding",
    },

    # ── Tier 7: HTTP/2 stream kill bypass (Telegram, Discord streams) ──
    {
        "name": "wssize1_multidisorder",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Tiny TCP window breaks H2 stream DPI + disorder",
    },
    {
        "name": "wssize1_multisplit",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
        ],
        "desc": "Tiny TCP window + split (H2 stream kill bypass)",
    },
    {
        "name": "wssize1_disorder_fake",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_ttl=4:tcp_md5:repeats=4",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Tiny window + fake + disorder (max anti-H2-kill)",
    },

    # ── Tier 8: Protocol-agnostic (for non-standard services) ─────
    {
        "name": "multidisorder_pos2",
        "flags": [
            "multidisorder:pos=2",
        ],
        "desc": "Simple disorder at position 2 (minimal, wide compat)",
    },
    {
        "name": "multisplit_pos2_seqovl",
        "flags": [
            "multisplit:pos=2:seqovl=8:seqovl_pattern=0x00000000",
        ],
        "desc": "Simple split at position 2 with overlap",
    },
]


class StrategyEnumerator:
    """Deterministic strategy enumeration (blockcheck2-style).

    Tests known-working strategies in priority order.
    Returns first strategy that passes threshold.
    """

    def __init__(self, strategies: Optional[list[dict]] = None,
                 excluded_functions: Optional[set[str]] = None):
        self.strategies = strategies or KNOWN_STRATEGIES
        self.excluded_functions = excluded_functions or set()

    def enumerate(
        self,
        tester: ConnectionTester,
        threshold: float = 0.6,
        on_progress: Optional[callable] = None,
        on_result: Optional[callable] = None,
    ) -> Optional[dict]:
        """Test strategies in order, return first passing threshold.

        Skips strategies containing excluded functions (from AI feedback).
        on_result(flags, fitness) — called after each test for AI feedback.

        Args:
            tester: ConnectionTester instance (mock=False for real testing)
            threshold: minimum fitness to accept
            on_progress: callback(index, total, name, fitness) for UI updates

        Returns:
            dict with "name", "flags", "fitness" or None if all fail
        """
        total = len(self.strategies)
        logger.info("Enumerating %d known strategies (threshold=%.2f)", total, threshold)

        for i, strat in enumerate(self.strategies):
            name = strat["name"]
            flags = strat["flags"]

            # Skip strategies with excluded functions (AI feedback)
            if self.excluded_functions:
                has_excluded = any(
                    f.split(":")[0] in self.excluded_functions for f in flags
                )
                if has_excluded:
                    logger.debug("Skipping %s (contains excluded function)", name)
                    if on_progress:
                        on_progress(i + 1, total, f"{name} [SKIP]", 0.0)
                    continue

            fitness = tester.test_strategy(flags)

            if on_progress:
                on_progress(i + 1, total, name, fitness)
            if on_result:
                on_result(flags, fitness)

            logger.info(
                "Enum [%d/%d] %s: fitness=%.3f %s",
                i + 1, total, name, fitness,
                "PASS" if fitness >= threshold else "fail",
            )

            if fitness >= threshold:
                logger.info("Found working strategy: %s (fitness=%.3f)", name, fitness)
                return {"name": name, "flags": flags, "fitness": fitness, "desc": strat.get("desc", "")}

        logger.warning("No strategy passed threshold %.2f", threshold)
        return None

    def enumerate_thorough(
        self,
        tester: ConnectionTester,
        threshold: float = 0.6,
        top_n: int = 3,
        on_progress: Optional[callable] = None,
    ) -> list[dict]:
        """Test all strategies and return top N above threshold.

        Slower but finds the BEST strategy, not just first passing.
        Use when quick enumeration finds something but want to optimize.
        """
        results = []
        total = len(self.strategies)

        for i, strat in enumerate(self.strategies):
            fitness = tester.test_strategy(strat["flags"])

            if on_progress:
                on_progress(i + 1, total, strat["name"], fitness)

            if fitness >= threshold:
                results.append({
                    "name": strat["name"],
                    "flags": strat["flags"],
                    "fitness": fitness,
                    "desc": strat.get("desc", ""),
                })

        # Sort by fitness descending
        results.sort(key=lambda x: x["fitness"], reverse=True)
        return results[:top_n]
