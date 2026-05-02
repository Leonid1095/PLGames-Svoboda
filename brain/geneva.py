"""Geneva Strategy Engine — academic-grade censorship evasion via genetic evolution.

Based on "Geneva: Evolving Censorship Evasion Strategies" (Bock et al., 2019)
from University of Maryland. Geneva discovers packet-manipulation strategies
that defeat nation-state censors.

Geneva operators (mapped to zapret2 lua-desync equivalents):
  fragment(ip/tcp, offset, inOrder)  → multisplit / multidisorder
  tamper(field, value)               → pktmod (ip_ttl, tcp_seq, tcp_md5, etc.)
  duplicate(action1, action2)        → send + original (send modified copy)
  drop                               → drop
  sleep(ms)                          → repeats (flood with fakes = time delay)
  inject(oob)                        → oob (out-of-band TCP data)

This module provides:
  1. Known-working Geneva strategies from academic papers (China, Iran, KZ, Russia)
  2. Strategy composition engine (combine operators into compound strategies)
  3. Smart seed generation for GA (country/DPI-type specific)
  4. Geneva-aware mutation operators (finer-grained than random)
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("svoboda.geneva")


# ═══════════════════════════════════════════════════════════════════════════════
# Geneva Operator Definitions
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GenevaOp:
    """Single Geneva operator."""
    name: str           # fragment, tamper, duplicate, drop, sleep, inject
    params: dict = field(default_factory=dict)
    children: list = field(default_factory=list)  # nested ops (for duplicate)

    def to_zapret2(self) -> list[str]:
        """Translate to zapret2 lua-desync call(s)."""
        return _TRANSLATORS.get(self.name, _noop)(self)


def _translate_fragment(op: GenevaOp) -> list[str]:
    """fragment(proto, offset, inOrder) → multisplit/multidisorder."""
    proto = op.params.get("proto", "tcp")
    offset = op.params.get("offset", "midsld")
    in_order = op.params.get("in_order", False)
    seqovl = op.params.get("seqovl", 0)

    func = "multisplit" if in_order else "multidisorder"
    call = f"{func}:pos={offset}"
    if seqovl:
        call += f":seqovl={seqovl}"
        pattern = op.params.get("seqovl_pattern", "")
        if pattern:
            call += f":seqovl_pattern={pattern}"

    if proto == "ip":
        return ["send:ipfrag", call]
    return [call]


def _translate_tamper(op: GenevaOp) -> list[str]:
    """tamper(field, action, value) → pktmod parameters."""
    target = op.params.get("field", "")
    value = op.params.get("value", "")

    parts = ["pktmod"]
    if target == "ip_ttl":
        parts.append(f"ip_ttl={value}")
        parts.append(f"ip6_ttl={value}")
    elif target == "tcp_seq":
        parts.append(f"tcp_seq={value}")
    elif target == "tcp_checksum":
        parts.append("tcp_md5")
    elif target == "tcp_window":
        parts.append(f"wsize={value}")
    elif target == "tcp_dataofs":
        parts.append("tcp_md5")  # closest: corrupt options
    elif target == "tcp_timestamp":
        parts.append("tcp_ts_up")
    elif target == "tcp_flags":
        parts.append(f"tcp_flags_unset={value}")

    return [":".join(parts)] if len(parts) > 1 else []


def _translate_duplicate(op: GenevaOp) -> list[str]:
    """duplicate(modified_copy, original) → send(modified) + original desync."""
    calls = []
    # First child: modified copy (sent before original)
    if op.children:
        child_calls = op.children[0].to_zapret2()
        for c in child_calls:
            # Wrap in send with TTL to make it a "dying" copy
            ttl = op.params.get("ttl", random.randint(1, 4))
            if c.startswith("pktmod"):
                calls.append(c)
            else:
                calls.append(f"send:ip_ttl={ttl}")
    else:
        ttl = op.params.get("ttl", random.randint(1, 4))
        calls.append(f"send:ip_ttl={ttl}")

    # Second child or original
    if len(op.children) > 1:
        calls.extend(op.children[1].to_zapret2())

    return calls


def _translate_drop(op: GenevaOp) -> list[str]:
    return ["drop"]


def _translate_sleep(op: GenevaOp) -> list[str]:
    """sleep(ms) → approximate with fake repeats (each repeat ~1ms network RTT)."""
    ms = op.params.get("ms", 100)
    repeats = max(1, min(20, ms // 10))
    return [f"fake:blob=0x00000000:ip_ttl=1:repeats={repeats}"]


def _translate_inject(op: GenevaOp) -> list[str]:
    """inject(oob) → oob (out-of-band TCP data)."""
    ttl = op.params.get("ttl", 0)
    if ttl:
        return [f"oob:ip_ttl={ttl}"]
    return ["oob"]


def _translate_alpn_modify(op: GenevaOp) -> list[str]:
    """alpn_modify(strip) → alpn_strip (TLS-layer h2 downgrade primitive).

    Distinct category from `tamper` because it operates on the TLS handshake
    payload (not IP/TCP fields). Effective against HTTP2_STREAM_KILL — TSPU
    can't kill an HTTP/2 stream that the negotiation never establishes.
    """
    strip = op.params.get("strip", "h2,h2c")
    keep_min = op.params.get("keep_min", 1)
    parts = ["alpn_strip", f"strip={strip}"]
    if keep_min != 1:
        parts.append(f"keep_min={keep_min}")
    return [":".join(parts)]


def _noop(op: GenevaOp) -> list[str]:
    return []


_TRANSLATORS = {
    "fragment": _translate_fragment,
    "tamper": _translate_tamper,
    "duplicate": _translate_duplicate,
    "drop": _translate_drop,
    "sleep": _translate_sleep,
    "inject": _translate_inject,
    "alpn_modify": _translate_alpn_modify,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Known Geneva Strategies (from academic papers + community)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GenevaStrategy:
    """Named Geneva strategy with metadata."""
    name: str
    desc: str
    country: str            # "ru", "cn", "ir", "kz", "in", "universal"
    dpi_type: str           # "tspu", "gfw", "generic", "any"
    ops: list[GenevaOp]
    effectiveness: float    # 0-1 estimated effectiveness
    anti_throttle: bool = False

    def to_zapret2_flags(self) -> list[str]:
        """Convert to zapret2 lua-desync flags list."""
        flags = []
        for op in self.ops:
            flags.extend(op.to_zapret2())
        return flags


# ── Russia (TSPU) strategies ────────────────────────────────────────────────

_RU_STRATEGIES = [
    GenevaStrategy(
        name="ru_disorder_midsld",
        desc="Out-of-order fragments at SLD boundary (TSPU can't reassemble)",
        country="ru", dpi_type="tspu",
        ops=[GenevaOp("fragment", {"offset": "1,midsld", "in_order": False})],
        effectiveness=0.7,
    ),
    GenevaStrategy(
        name="ru_flood_4096",
        desc="4KB sequence overlap overwhelms TSPU state buffer",
        country="ru", dpi_type="tspu",
        ops=[GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 4096})],
        effectiveness=0.7, anti_throttle=True,
    ),
    GenevaStrategy(
        name="ru_flood_disorder",
        desc="4KB overlap + out-of-order (dual anti-throttle)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 4096}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.75, anti_throttle=True,
    ),
    # ── HTTP2_STREAM_KILL family — alpn_strip + fragmentation ───────────
    # TSPU's HTTP2_STREAM_KILL fires only when ALPN negotiates h2. Stripping
    # h2/h2c at the TLS layer forces HTTP/1.1, which TSPU does not stream-
    # kill. Combined with a fragmentation pass for SNI hiding.
    GenevaStrategy(
        name="ru_h2downgrade_disorder",
        desc="ALPN strip h2 -> HTTP/1.1 + out-of-order fragments (Discord, YouTube watch)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("alpn_modify", {"strip": "h2,h2c"}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.8,
    ),
    GenevaStrategy(
        name="ru_h2downgrade_split568",
        desc="ALPN strip h2 + multisplit @568 + disorder (per-host warm-pool default)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("alpn_modify", {"strip": "h2,h2c"}),
            GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 568}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.82,
    ),
    GenevaStrategy(
        name="ru_h2downgrade_flood",
        desc="ALPN strip h2 + 4KB overlap (anti-throttle for HTTP/1.1 long downloads)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("alpn_modify", {"strip": "h2,h2c"}),
            GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 4096}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.78, anti_throttle=True,
    ),
    GenevaStrategy(
        name="ru_inject_fragment",
        desc="OOB injection confuses TSPU state + fragment to bypass SNI",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("inject", {"ttl": 3}),
            GenevaOp("fragment", {"offset": "midsld", "in_order": False, "seqovl": 5,
                                  "seqovl_pattern": "0x1603030000"}),
        ],
        effectiveness=0.6,
    ),
    GenevaStrategy(
        name="ru_duplicate_tamper",
        desc="Send tampered copy (low TTL, bad checksum) then fragment real",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("duplicate", {"ttl": 2}, children=[
                GenevaOp("tamper", {"field": "tcp_checksum"}),
            ]),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.55,
    ),
    GenevaStrategy(
        name="ru_ipfrag_disorder",
        desc="IP-level fragmentation + TCP disorder (double-layer confusion)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("fragment", {"proto": "ip", "offset": "midsld", "in_order": False}),
        ],
        effectiveness=0.5,
    ),
    GenevaStrategy(
        name="ru_sni_offset_681",
        desc="Flowseal: split at SNI field offset 681 (precise SNI disruption)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 681}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.7, anti_throttle=True,
    ),
    GenevaStrategy(
        name="ru_wssize1_disorder",
        desc="Tiny TCP window kills H2 mux tracking + disorder",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("tamper", {"field": "tcp_window", "value": "1"}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False,
                                  "seqovl": 5, "seqovl_pattern": "0x1603030000"}),
        ],
        effectiveness=0.6,
    ),
    GenevaStrategy(
        name="ru_sleep_fragment",
        desc="Flood with garbage (DPI timeout) then fragment real ClientHello",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("sleep", {"ms": 50}),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.45,
    ),
    GenevaStrategy(
        name="ru_triple_compound",
        desc="OOB + duplicate(tamper) + disorder (maximum DPI confusion)",
        country="ru", dpi_type="tspu",
        ops=[
            GenevaOp("inject"),
            GenevaOp("duplicate", {"ttl": 1}, children=[
                GenevaOp("tamper", {"field": "tcp_timestamp"}),
            ]),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False, "seqovl": 4096}),
        ],
        effectiveness=0.5,
    ),
]

# ── China (GFW) strategies ──────────────────────────────────────────────────

_CN_STRATEGIES = [
    GenevaStrategy(
        name="cn_fragment_8_disorder",
        desc="GFW: TCP fragment at 8 bytes, out-of-order",
        country="cn", dpi_type="gfw",
        ops=[GenevaOp("fragment", {"offset": "8", "in_order": False})],
        effectiveness=0.6,
    ),
    GenevaStrategy(
        name="cn_duplicate_ttl1",
        desc="GFW: duplicate with TTL=1 (dying copy confuses DPI)",
        country="cn", dpi_type="gfw",
        ops=[GenevaOp("duplicate", {"ttl": 1})],
        effectiveness=0.55,
    ),
    GenevaStrategy(
        name="cn_tamper_dataofs",
        desc="GFW: corrupt TCP data offset field (DPI misparses payload)",
        country="cn", dpi_type="gfw",
        ops=[
            GenevaOp("tamper", {"field": "tcp_dataofs", "value": "10"}),
            GenevaOp("fragment", {"offset": "2", "in_order": True}),
        ],
        effectiveness=0.5,
    ),
]

# ── Iran strategies ─────────────────────────────────────────────────────────

_IR_STRATEGIES = [
    GenevaStrategy(
        name="ir_fragment_4_disorder",
        desc="Iran: fragment at offset 4, reversed",
        country="ir", dpi_type="generic",
        ops=[GenevaOp("fragment", {"offset": "4", "in_order": False})],
        effectiveness=0.6,
    ),
    GenevaStrategy(
        name="ir_duplicate_corrupt",
        desc="Iran: send corrupted copy + fragment original",
        country="ir", dpi_type="generic",
        ops=[
            GenevaOp("duplicate", {"ttl": 2}, children=[
                GenevaOp("tamper", {"field": "tcp_checksum"}),
            ]),
            GenevaOp("fragment", {"offset": "midsld", "in_order": False}),
        ],
        effectiveness=0.55,
    ),
]

# ── Kazakhstan strategies ───────────────────────────────────────────────────

_KZ_STRATEGIES = [
    GenevaStrategy(
        name="kz_duplicate_dying",
        desc="Kazakhstan: dying duplicate (TTL=1) + split",
        country="kz", dpi_type="generic",
        ops=[
            GenevaOp("duplicate", {"ttl": 1}),
            GenevaOp("fragment", {"offset": "midsld", "in_order": True}),
        ],
        effectiveness=0.6,
    ),
]

# ── Universal (cross-country) ──────────────────────────────────────────────

_UNIVERSAL_STRATEGIES = [
    GenevaStrategy(
        name="uni_disorder_seqovl",
        desc="Universal: disorder + sequence overlap (works on most DPIs)",
        country="universal", dpi_type="any",
        ops=[GenevaOp("fragment", {"offset": "1,midsld", "in_order": False,
                                    "seqovl": 5, "seqovl_pattern": "0x1603030000"})],
        effectiveness=0.6,
    ),
    GenevaStrategy(
        name="uni_oob_disorder",
        desc="Universal: OOB injection + disorder (broad spectrum)",
        country="universal", dpi_type="any",
        ops=[
            GenevaOp("inject"),
            GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        ],
        effectiveness=0.5,
    ),
    GenevaStrategy(
        name="uni_multi_layer",
        desc="Universal: IP frag + TCP disorder + tamper (triple-layer)",
        country="universal", dpi_type="any",
        ops=[
            GenevaOp("fragment", {"proto": "ip", "offset": "1", "in_order": True}),
            GenevaOp("fragment", {"offset": "midsld", "in_order": False}),
            GenevaOp("tamper", {"field": "tcp_timestamp"}),
        ],
        effectiveness=0.45,
    ),
]

# All strategies indexed
ALL_STRATEGIES = _RU_STRATEGIES + _CN_STRATEGIES + _IR_STRATEGIES + _KZ_STRATEGIES + _UNIVERSAL_STRATEGIES


# ═══════════════════════════════════════════════════════════════════════════════
# Strategy Composer — creates new strategies from building blocks
# ═══════════════════════════════════════════════════════════════════════════════

class GenevaComposer:
    """Compose Geneva strategies from operator building blocks.

    Unlike random GA generation, the composer understands operator semantics:
    - fragment after inject (inject confuses state, fragment bypasses reassembly)
    - duplicate before fragment (DPI processes fake, real gets fragmented)
    - tamper + fragment (modify fields that DPI uses for tracking)
    """

    # Operator compatibility: which ops can follow which
    _COMPAT = {
        "inject":    ["fragment", "duplicate", "tamper"],
        "duplicate": ["fragment", "tamper"],
        "tamper":    ["fragment", "duplicate"],
        "fragment":  ["fragment", "tamper"],  # second fragment = different layer
        "sleep":     ["fragment", "duplicate", "inject"],
        "drop":      [],  # terminal
    }

    # Anti-throttle building blocks (TSPU-specific)
    _ANTI_THROTTLE_BLOCKS = [
        GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 4096}),
        GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 681}),
        GenevaOp("fragment", {"offset": "1", "in_order": True, "seqovl": 568}),
        GenevaOp("tamper", {"field": "tcp_window", "value": "1"}),
    ]

    # DPI confusion building blocks
    _CONFUSION_BLOCKS = [
        GenevaOp("inject"),
        GenevaOp("inject", {"ttl": 3}),
        GenevaOp("duplicate", {"ttl": 1}),
        GenevaOp("duplicate", {"ttl": 2}, children=[GenevaOp("tamper", {"field": "tcp_checksum"})]),
        GenevaOp("sleep", {"ms": 30}),
        GenevaOp("tamper", {"field": "tcp_timestamp"}),
        GenevaOp("tamper", {"field": "tcp_seq", "value": "-10000"}),
    ]

    # Fragment building blocks
    _FRAGMENT_BLOCKS = [
        GenevaOp("fragment", {"offset": "midsld", "in_order": False}),
        GenevaOp("fragment", {"offset": "1,midsld", "in_order": False}),
        GenevaOp("fragment", {"offset": "1,midsld", "in_order": False,
                              "seqovl": 5, "seqovl_pattern": "0x1603030000"}),
        GenevaOp("fragment", {"offset": "2,midsld", "in_order": False}),
        GenevaOp("fragment", {"offset": "3,midsld", "in_order": True, "seqovl": 8}),
        GenevaOp("fragment", {"proto": "ip", "offset": "midsld", "in_order": False}),
    ]

    def compose_random(self, max_depth: int = 3) -> list[GenevaOp]:
        """Generate a random compound strategy using compatible operators."""
        ops = []
        depth = random.randint(1, max_depth)

        # Start with confusion or anti-throttle
        if random.random() < 0.3:
            ops.append(random.choice(self._ANTI_THROTTLE_BLOCKS))
        if random.random() < 0.25:
            ops.append(random.choice(self._CONFUSION_BLOCKS))

        # Always end with fragment (core bypass mechanism)
        ops.append(random.choice(self._FRAGMENT_BLOCKS))

        # Trim to max depth
        return ops[:max_depth]

    def compose_for_dpi(self, dpi_type: str, anti_throttle: bool = False) -> list[GenevaOp]:
        """Generate strategy tuned for specific DPI type."""
        ops = []

        if anti_throttle:
            ops.append(random.choice(self._ANTI_THROTTLE_BLOCKS))

        if dpi_type in ("tspu", "tspu_stateful"):
            # TSPU: disorder works, fake doesn't → focus on fragment + inject
            if random.random() < 0.3:
                ops.append(random.choice([
                    GenevaOp("inject"),
                    GenevaOp("inject", {"ttl": 3}),
                    GenevaOp("duplicate", {"ttl": 1}),
                ]))
            ops.append(GenevaOp("fragment", {
                "offset": random.choice(["midsld", "1,midsld", "1,midsld,endhost-1"]),
                "in_order": False,
                "seqovl": random.choice([0, 5, 8]) if not anti_throttle else 0,
                "seqovl_pattern": "0x1603030000" if random.random() < 0.5 else "",
            }))

        elif dpi_type == "gfw":
            # GFW: fragment at small offsets + duplicate
            ops.append(GenevaOp("duplicate", {"ttl": random.randint(1, 3)}))
            ops.append(GenevaOp("fragment", {
                "offset": str(random.choice([2, 4, 8])),
                "in_order": random.choice([True, False]),
            }))

        else:
            # Generic: disorder + seqovl
            ops.append(GenevaOp("fragment", {
                "offset": "1,midsld",
                "in_order": False,
                "seqovl": random.choice([0, 5, 8, 681]),
            }))

        return ops

    def mutate_strategy(self, ops: list[GenevaOp]) -> list[GenevaOp]:
        """Mutate an existing Geneva strategy (smarter than random GA mutation)."""
        ops = list(ops)
        if not ops:
            return self.compose_random()

        action = random.choice([
            "swap_fragment_params",
            "add_confusion",
            "remove_op",
            "add_anti_throttle",
            "swap_order",
        ])

        if action == "swap_fragment_params":
            # Change fragment parameters (offset, order, seqovl)
            for i, op in enumerate(ops):
                if op.name == "fragment":
                    new_params = dict(op.params)
                    what = random.choice(["offset", "in_order", "seqovl"])
                    if what == "offset":
                        new_params["offset"] = random.choice([
                            "1", "2", "3", "midsld", "1,midsld",
                            "1,midsld,endhost-1", "2,midsld",
                        ])
                    elif what == "in_order":
                        new_params["in_order"] = not new_params.get("in_order", True)
                    elif what == "seqovl":
                        new_params["seqovl"] = random.choice([0, 1, 5, 8, 568, 681, 4096])
                    ops[i] = GenevaOp("fragment", new_params)
                    break

        elif action == "add_confusion" and len(ops) < 4:
            ops.insert(0, random.choice(self._CONFUSION_BLOCKS))

        elif action == "remove_op" and len(ops) > 1:
            # Don't remove the last fragment
            candidates = [i for i, op in enumerate(ops) if op.name != "fragment"]
            if candidates:
                ops.pop(random.choice(candidates))

        elif action == "add_anti_throttle":
            # Ensure anti-throttle is present
            has_at = any(
                op.name == "fragment" and op.params.get("seqovl", 0) >= 500
                for op in ops
            )
            if not has_at and len(ops) < 4:
                ops.insert(0, random.choice(self._ANTI_THROTTLE_BLOCKS))

        elif action == "swap_order" and len(ops) > 1:
            i, j = random.sample(range(len(ops)), 2)
            ops[i], ops[j] = ops[j], ops[i]

        return ops


# ═══════════════════════════════════════════════════════════════════════════════
# Public API — integration with GA
# ═══════════════════════════════════════════════════════════════════════════════

def get_strategies_for_country(country: str = "ru") -> list[GenevaStrategy]:
    """Get known Geneva strategies for a country/DPI type."""
    result = [s for s in ALL_STRATEGIES if s.country in (country, "universal")]
    return sorted(result, key=lambda s: s.effectiveness, reverse=True)


def get_anti_throttle_strategies() -> list[GenevaStrategy]:
    """Get strategies specifically designed to counter DPI throttling."""
    return [s for s in ALL_STRATEGIES if s.anti_throttle]


def generate_seeds(
    dpi_type: str = "tspu",
    country: str = "ru",
    count: int = 6,
    anti_throttle: bool = True,
) -> list[list[str]]:
    """Generate seed strategies for GA in zapret2 flag format.

    Combines known strategies + composer-generated variants.
    """
    seeds: list[list[str]] = []

    # 1. Known strategies for this country/DPI
    known = get_strategies_for_country(country)
    if anti_throttle:
        # Prioritize anti-throttle strategies
        known.sort(key=lambda s: (s.anti_throttle, s.effectiveness), reverse=True)

    for s in known[:count // 2]:
        flags = s.to_zapret2_flags()
        if flags:
            seeds.append(flags)
            logger.debug("Geneva seed: %s → %s", s.name, " | ".join(flags))

    # 2. Composer-generated variants
    composer = GenevaComposer()
    attempts = 0
    while len(seeds) < count and attempts < count * 3:
        attempts += 1
        ops = composer.compose_for_dpi(dpi_type, anti_throttle=anti_throttle)
        flags = []
        for op in ops:
            flags.extend(op.to_zapret2())
        if flags and flags not in seeds:
            seeds.append(flags)

    logger.info("Geneva: generated %d seed strategies for %s/%s", len(seeds), country, dpi_type)
    return seeds


def mutate_flags_geneva(flags: list[str], dpi_type: str = "tspu") -> list[str]:
    """Geneva-aware mutation: parse flags → operators → mutate → back to flags.

    Smarter than random parameter mutation — understands operator semantics.
    """
    composer = GenevaComposer()

    # Parse flags back to approximate Geneva ops
    ops = _flags_to_ops(flags)
    if not ops:
        # Can't parse — generate fresh
        ops = composer.compose_for_dpi(dpi_type)
    else:
        ops = composer.mutate_strategy(ops)

    # Convert back to flags
    new_flags = []
    for op in ops:
        new_flags.extend(op.to_zapret2())

    return new_flags if new_flags else flags


def _flags_to_ops(flags: list[str]) -> list[GenevaOp]:
    """Best-effort reverse translation: zapret2 flags → Geneva ops."""
    ops = []
    for flag in flags:
        parts = flag.split(":")
        func = parts[0]

        if func in ("multisplit", "multidisorder"):
            params = {"in_order": func == "multisplit"}
            for p in parts[1:]:
                if p.startswith("pos="):
                    params["offset"] = p[4:]
                elif p.startswith("seqovl="):
                    params["seqovl"] = int(p[7:])
                elif p.startswith("seqovl_pattern="):
                    params["seqovl_pattern"] = p[15:]
            ops.append(GenevaOp("fragment", params))

        elif func == "oob":
            params = {}
            for p in parts[1:]:
                if p.startswith("ip_ttl="):
                    params["ttl"] = int(p[7:])
            ops.append(GenevaOp("inject", params))

        elif func == "send":
            params = {}
            for p in parts[1:]:
                if p.startswith("ip_ttl="):
                    params["ttl"] = int(p[7:])
                if p == "ipfrag":
                    params["ipfrag"] = True
            ops.append(GenevaOp("duplicate", params))

        elif func == "pktmod":
            ops.append(GenevaOp("tamper", {"raw": ":".join(parts[1:])}))

        elif func == "drop":
            ops.append(GenevaOp("drop"))

        elif func == "fake":
            # Approximate as sleep (flood to create delay)
            for p in parts[1:]:
                if p.startswith("repeats="):
                    ops.append(GenevaOp("sleep", {"ms": int(p[8:]) * 10}))
                    break

        elif func == "wssize":
            for p in parts[1:]:
                if p.startswith("wsize="):
                    ops.append(GenevaOp("tamper", {"field": "tcp_window", "value": p[6:]}))
                    break

        elif func == "alpn_strip":
            params = {"strip": "h2,h2c"}
            for p in parts[1:]:
                if p.startswith("strip="):
                    params["strip"] = p[6:]
                elif p.startswith("keep_min="):
                    try:
                        params["keep_min"] = int(p[9:])
                    except ValueError:
                        pass
            ops.append(GenevaOp("alpn_modify", params))

    return ops
