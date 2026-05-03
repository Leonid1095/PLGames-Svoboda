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
    # ══════════════════════════════════════════════════════════════════
    # TIER 0: NO-FAKE STRATEGIES (TSPU-resistant)
    # TSPU stateful DPI (er-telecom, 2026-04) detects and blocks ALL
    # fake packets. Pure split/disorder strategies bypass SNI filtering
    # without triggering fake detection. TESTED FIRST.
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "nofake_disorder_568",
        "flags": [
            "multisplit:pos=1:seqovl=568",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "No-fake: split@568 + disorder (proven on TSPU er-telecom Apr 2026)",
    },
    {
        "name": "nofake_disorder_seqovl5",
        "flags": [
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "No-fake: disorder with TLS record overlap (cached, proven)",
    },
    {
        "name": "nofake_disorder_681",
        "flags": [
            "multisplit:pos=1:seqovl=681",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "No-fake: split@681 + disorder (Dronatar-style without fake)",
    },
    {
        "name": "nofake_disorder_4096",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "No-fake: 4KB overlap + disorder (anti-throttle, no fake detection)",
    },
    {
        "name": "nofake_multidisorder_681",
        "flags": [
            "multidisorder:pos=1,midsld:seqovl=681",
        ],
        "desc": "No-fake: pure disorder@681 (Dronatar v4.6 core)",
    },
    {
        "name": "nofake_multisplit_4096",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "No-fake: pure split 4KB overlap (overwhelms DPI state buffer)",
    },
    {
        "name": "nofake_disorder_midsld_endhost",
        "flags": [
            "multidisorder:pos=1,midsld,endhost-1:seqovl=6:seqovl_pattern=0x1603030000",
        ],
        "desc": "No-fake: 3-pos disorder with TLS overlap (max fragmentation)",
    },
    {
        "name": "nofake_wssize1_disorder",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multidisorder:pos=1,midsld:seqovl=568",
        ],
        "desc": "No-fake: tiny window + disorder@568 (dual anti-throttle)",
    },

    # ══════════════════════════════════════════════════════════════════
    # TIER 0.5: H2 DOWNGRADE FAMILY (for HTTP2_STREAM_KILL hosts)
    # TSPU lets the TLS handshake complete, then kills the H/2 stream
    # after a few KB (Discord, YouTube watch-pages, others). Pure desync
    # cannot fix this — it's an L7 attack on h2 framing.
    # `alpn_strip` removes h2 from ALPN in ClientHello, forcing the server
    # to fall back to HTTP/1.1 which TSPU does not stream-kill.
    # Per-host: applied only to hosts the classifier marks HTTP2_STREAM_KILL.
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "h2downgrade_alpn_only",
        "flags": [
            "alpn_strip:strip=h2,h2c",
        ],
        "desc": "H2 downgrade: pure ALPN strip, forces HTTP/1.1 (Discord/YouTube h2-kill bypass)",
        "tags": ["h2_downgrade", "per_host"],
    },
    {
        "name": "h2downgrade_split568",
        "flags": [
            "alpn_strip:strip=h2,h2c",
            "multisplit:pos=1:seqovl=568",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "H2 downgrade + nofake split@568 + disorder (best-of-both for stubborn TSPU)",
        "tags": ["h2_downgrade", "per_host"],
    },
    {
        "name": "h2downgrade_split4096",
        "flags": [
            "alpn_strip:strip=h2,h2c",
            "multisplit:pos=1:seqovl=4096",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "H2 downgrade + 4KB overlap (anti-throttle for downgraded HTTP/1.1 streams)",
        "tags": ["h2_downgrade", "per_host"],
    },
    {
        "name": "h2downgrade_disorder_seqovl5",
        "flags": [
            "alpn_strip:strip=h2,h2c",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "H2 downgrade + TLS-record overlap disorder",
        "tags": ["h2_downgrade", "per_host"],
    },

    # ══════════════════════════════════════════════════════════════════
    # TIER 0.7: TLS MORPH FAMILY — TEMPORARILY DISABLED (2026-05-03)
    # Live-run on er-telecom AS42116 showed all 4 tls_morph variants
    # return fitness=0.000 (0/2 fail-fast) with both 2KB padded and
    # extension-reorder-only modes. tls_extreorder fails in 133ms (server
    # rejects immediately with TLS error) — not a TSPU rate-limit, not a
    # TSPU drop, but our lua _morph_client_hello helper producing invalid
    # TLS payload after tls_dissect → modify ext_list → tls_reconstruct
    # roundtrip. alpn_strip works (modifies dis.list inside an existing
    # extension), so the bug is specifically in inserting/reordering at
    # the OUTER ext_list level.
    # The strategies stay in code (commented) so we don't lose context;
    # they will be re-enabled once the lua bug is fixed.
    # ══════════════════════════════════════════════════════════════════
    # {
    #     "name": "tls_morph_pad2k_split",
    #     "flags": [
    #         "tls_pad:size=2048",
    #         "multisplit:pos=1:seqovl=568",
    #         "multidisorder:pos=1,midsld",
    #     ],
    #     "desc": "TLS morph: 2KB padding + split@568 + disorder (Discord TLS_INTERFERENCE)",
    #     "tags": ["tls_morph", "per_host"],
    # },
    # {
    #     "name": "tls_morph_pad4k_aggressive",
    #     "flags": [
    #         "tls_pad:size=4096:reorder=1:grease=4",
    #         "multisplit:pos=1:seqovl=4096",
    #         "multidisorder:pos=1,midsld",
    #     ],
    #     "desc": "TLS morph aggressive: 4KB pad + SNI-reorder + 4 GREASE + 4KB seqovl (heavy)",
    #     "tags": ["tls_morph", "per_host"],
    # },
    # {
    #     "name": "tls_morph_pad2k_alpn_split",
    #     "flags": [
    #         "tls_pad:size=2048:grease=2",
    #         "alpn_strip:strip=h2,h2c",
    #         "multisplit:pos=1:seqovl=568",
    #         "multidisorder:pos=1,midsld",
    #     ],
    #     "desc": "TLS morph + H2 downgrade combo (TSPU sees neither SNI nor h2 cleanly)",
    #     "tags": ["tls_morph", "h2_downgrade", "per_host"],
    # },
    # {
    #     "name": "tls_morph_extreorder_only",
    #     "flags": [
    #         "tls_extreorder:pos=end",
    #         "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
    #     ],
    #     "desc": "TLS morph minimal: only extension reorder + TLS-record overlap (low overhead)",
    #     "tags": ["tls_morph", "per_host"],
    # },

    # ══════════════════════════════════════════════════════════════════
    # TIER 1: COMMUNITY PROVEN (Flowseal ALT11, Dronatar v4.6)
    # These use fake packets — work on ISPs that don't detect fake.
    # ══════════════════════════════════════════════════════════════════

    # Flowseal ALT11: Google/YouTube profile (Feb 2026, most popular)
    {
        "name": "flowseal_alt11_google",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_ts_up:repeats=8",
            "multisplit:pos=1:seqovl=681:seqovl_pattern=fake_default_tls",
        ],
        "desc": "Flowseal ALT11: Google/YouTube (15K+ users, Feb 2026)",
    },
    # Flowseal ALT11: General profile with seqovl=664
    {
        "name": "flowseal_alt11_general",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_ts_up:repeats=8",
            "multisplit:pos=1:seqovl=664",
        ],
        "desc": "Flowseal ALT11: General TLS (seqovl=664, Feb 2026)",
    },
    # Dronatar v4.6: YouTube TLS profile (Feb 2026)
    {
        "name": "dronatar_youtube",
        "flags": [
            "multidisorder:pos=1,midsld:seqovl=681",
        ],
        "desc": "Dronatar v4.6: YouTube TLS (multidisorder, Feb 2026)",
    },
    # Dronatar v4.6: YouTube HTTP (port 80)
    # Original: --dpi-desync=fake --fooling=badseq
    {
        "name": "dronatar_http",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_seq=-10000",
        ],
        "desc": "Dronatar v4.6: HTTP with badseq fooling (Feb 2026)",
    },
    # Flowseal ALT: simpler fake+fakedsplit with ts fooling
    # Original: --dpi-desync=fake,fakedsplit --fooling=ts --fakedsplit-pattern=0x00
    {
        "name": "flowseal_alt_fakedsplit",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_ts_up:repeats=6",
            "fakedsplit:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_ts_up",
        ],
        "desc": "Flowseal ALT: fake+fakedsplit with ts fooling",
    },
    # Community: syndata (game servers, Feb 2026)
    {
        "name": "flowseal_syndata",
        "flags": [
            "syndata",
        ],
        "desc": "Flowseal ALT11: syndata for game/generic TCP (Feb 2026)",
    },

    # ══════════════════════════════════════════════════════════════════
    # ER-Telecom/Dom.ru proven (our own testing)
    # ══════════════════════════════════════════════════════════════════
    {
        "name": "ertel_multisplit_4096",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "ER-Telecom/Dom.ru: 4KB overlap overwhelms DPI state buffer (anti-throttle)",
    },
    {
        "name": "ertel_multisplit_4096_disorder",
        "flags": [
            "multisplit:pos=1:seqovl=4096",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "ER-Telecom: 4KB overlap + disorder (proven for Dom.ru, anti-throttle)",
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
    # ── Tier 0b: wssize=1 anti-throttle (HTTP/2 stream kill bypass) ──────
    # Tiny TCP window forces server to send 1-byte segments → TSPU cannot
    # reconstruct HTTP/2 multiplexed streams → cannot classify as bypass.
    # Works differently from seqovl — good fallback when seqovl=4096 fails.
    {
        "name": "wssize1_disorder_4096",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny TCP window + 4KB seqovl: dual anti-throttle mechanism",
    },
    {
        "name": "wssize1_multidisorder",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Tiny TCP window + disorder: breaks H2 stream DPI tracking",
    },
    {
        "name": "wssize1_disorder_681",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multisplit:pos=1:seqovl=681",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Tiny window + SNI-offset split + disorder (triple anti-throttle)",
    },
    {
        "name": "wssize1_multisplit",
        "flags": [
            "wssize:wsize=1:scale=0",
            "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000",
        ],
        "desc": "Tiny TCP window + split (H2 stream kill bypass)",
    },
    # ── Tier 0c: remaining seqovl anti-throttle variants ─────────────────
    {
        "name": "ertel_fake_4096",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5:repeats=6:tls_mod=rnd,dupsid",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "ER-Telecom: fake Google SNI TTL=5 + split 4096",
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
        "name": "ertel_hostfakesplit",
        "flags": [
            "hostfakesplit:host=ya.ru:tcp_md5:badsum",
        ],
        "desc": "ER-Telecom: send fake ya.ru SNI (bad checksum) before real ClientHello",
    },
    {
        "name": "flowseal_fakedsplit_aggressive",
        "flags": [
            "fakedsplit:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=6",
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
        ],
        "desc": "Flowseal: fakedsplit + aggressive disorder",
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

    # ── Tier 7: wssize variants with fake (when seqovl alone fails) ──────
    {
        "name": "wssize1_fake_ttl3_split",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_ttl=3:ip6_ttl=3:tcp_md5:repeats=6",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny window + fake TTL=3 (exact DPI hop) + 4KB overlap",
    },
    {
        "name": "wssize1_fake_ttl4_disorder",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_ttl=4:tcp_md5:repeats=4",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Tiny window + fake TTL=4 + disorder (max anti-H2-kill)",
    },
    {
        "name": "wssize1_fake_ttl2_split",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_ttl=2:ip6_ttl=2:tcp_md5:repeats=8",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny window + fake TTL=2 (below DPI) + 4KB overlap",
    },
    {
        "name": "wssize1_oob_split",
        "flags": [
            "wssize:wsize=1:scale=0",
            "oob:pos=1",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny window + TCP OOB byte + 4KB overlap (confuses DPI parser)",
    },
    {
        "name": "wssize1_fake_badsum_split",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:badsum:repeats=6",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny window + fake with bad checksum + 4KB overlap",
    },
    {
        "name": "wssize1_fake_autottl_split",
        "flags": [
            "wssize:wsize=1:scale=0",
            "fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Tiny window + fake auto-TTL + 4KB overlap",
    },
    {
        "name": "ipfrag_fake_split",
        "flags": [
            "fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=6:ipfrag",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "IP-fragmented fake + 4KB overlap (TSPU may not reassemble IP frags)",
    },
    {
        "name": "wssize8_disorder",
        "flags": [
            "wssize:wsize=8:scale=0",
            "multidisorder:pos=1,midsld",
        ],
        "desc": "Very small TCP window (8 bytes) + disorder",
    },
    {
        "name": "wssize16_split_4096",
        "flags": [
            "wssize:wsize=16:scale=0",
            "multisplit:pos=1:seqovl=4096",
        ],
        "desc": "Small window (16 bytes) + 4KB seqovl anti-throttle",
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
        # Outcome of the last enumerate() call. Lets the caller distinguish
        # genuine "no strategy works" (proceed to GA) from "TSPU rate-limit
        # — every test was 0, back off and don't waste more cycles".
        # Values: "found" | "exhausted" | "aborted_rate_limit" | "not_run"
        self.last_result_kind: str = "not_run"

    def enumerate(
        self,
        tester: ConnectionTester,
        threshold: float = 0.6,
        on_progress: Optional[callable] = None,
        on_result: Optional[callable] = None,
        zero_streak_abort: int = 5,
    ) -> Optional[dict]:
        """Test strategies in order, return first passing threshold.

        Skips strategies containing excluded functions (from AI feedback).
        on_result(flags, fitness) — called after each test for AI feedback.

        Args:
            tester: ConnectionTester instance (mock=False for real testing)
            threshold: minimum fitness to accept
            on_progress: callback(index, total, name, fitness) for UI updates
            zero_streak_abort: stop enum after N consecutive 0-fitness results
                (signals TSPU rate-limit / WinDivert wedged — continuing
                wastes 30s/strategy and pollutes strategies_db with bogus
                zeros). Default 5. Set 0 to disable.

        Returns:
            dict with "name", "flags", "fitness" or None if all fail
        """
        total = len(self.strategies)
        logger.info("Enumerating %d known strategies (threshold=%.2f)", total, threshold)
        zero_streak = 0
        self.last_result_kind = "not_run"

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
                self.last_result_kind = "found"
                return {"name": name, "flags": flags, "fitness": fitness, "desc": strat.get("desc", "")}

            # Rate-limit / wedge guard: if N strategies in a row return
            # exactly 0.0, the network or WinDivert is wedged — every
            # subsequent test will also be 0 and pollute strategies_db.
            # Caller (watchdog/recovery) should back off rather than try GA.
            if fitness == 0.0:
                zero_streak += 1
                if zero_streak_abort > 0 and zero_streak >= zero_streak_abort:
                    logger.warning(
                        "Enum aborted: %d consecutive 0-fitness results — "
                        "TSPU rate-limit or WinDivert wedge suspected. "
                        "Backing off; recovery should retry later.",
                        zero_streak,
                    )
                    self.last_result_kind = "aborted_rate_limit"
                    return None
            else:
                zero_streak = 0

        logger.warning("No strategy passed threshold %.2f", threshold)
        self.last_result_kind = "exhausted"
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
