"""Host Solver — find working strategy per individual host.

When the main strategy works for YouTube but not Telegram,
this module tries to find a separate strategy for Telegram
without breaking the working hosts.

Architecture:
  1. Test the failed host with each known strategy
  2. Record results (AI feedback)
  3. Save per-host strategy: {host: strategy, isp: X}
  4. Send to server for community
  5. Build multi-profile winws2 with per-host strategies
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.host_solver")


# Map block_type from BlockageClassifier to strategy tag in enumerator.
# When a host is classified, matching-tag strategies are hoisted to the
# top of the candidate list so we try the targeted fix first.
# Empty/unknown block_type → no hoisting, default priority order applies.
BLOCK_TYPE_TAGS: dict[str, str] = {
    "HTTP2_STREAM_KILL": "h2_downgrade",
    # TLS_INTERFERENCE → tls_morph: pure-local TLS payload obfuscation
    # (RFC 7685 padding + extension reorder + GREASE) overflows TSPU's
    # stateful parser when desync alone fails. No tunnel needed.
    "TLS_INTERFERENCE": "tls_morph",
    # Future: SNI_FILTER → "fake_hello_inject", THROTTLING → "anti_throttle"
}


@dataclass
class HostStrategy:
    """Working strategy for a specific host.

    `alternatives` is a warm pool of fallback strategies (top-2 after the
    current best). On per-host degradation, watchdog calls
    `HostSolver.next_alternative(host)` to promote pool[0] to current
    instantly — a winws2 restart with the swapped flags is ~5-10s vs
    a full re-enumeration which is 5-30 minutes.
    """
    host: str
    flags: list[str]
    fitness: float
    isp: str = "unknown"
    tested_at: float = 0.0
    # Top-N-1 alternatives, highest fitness first. Each: {flags, fitness}
    alternatives: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "flags": self.flags,
            "fitness": self.fitness,
            "isp": self.isp,
            "tested_at": self.tested_at,
            "alternatives": self.alternatives,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HostStrategy:
        return cls(
            host=d["host"], flags=d["flags"],
            fitness=d.get("fitness", 0.0), isp=d.get("isp", "unknown"),
            tested_at=d.get("tested_at", 0.0),
            alternatives=d.get("alternatives", []),
        )


class HostSolver:
    """Find and store per-host strategies.

    Usage:
        solver = HostSolver(config, tester, ai_feedback)
        result = solver.solve("web.telegram.org")
        if result:
            # result.flags = working strategy for telegram
            solver.save()
    """

    def __init__(self, config: dict, tester=None, ai_feedback=None,
                 server_sync=None, pattern_transfer=None):
        self._config = config
        self._base_dir = Path(config.get("_base_dir", "."))
        self._db_path = self._base_dir / "host_strategies.json"
        self._tester = tester
        self._ai_feedback = ai_feedback
        self._sync = server_sync
        # SMART layer 2: cross-host strategy generalization. Optional —
        # when present, solver records winning patterns and tries known-good
        # patterns BEFORE the 70-strategy enumeration. Caller wires
        # PatternTransfer(analytics) and passes it in.
        self._pattern_transfer = pattern_transfer
        self._strategies: dict[str, HostStrategy] = {}
        self._byedpi = None  # Track running ByeDPI instance for cleanup
        self._load()

    def shutdown(self) -> None:
        """Stop running ByeDPI process if any."""
        if self._byedpi:
            try:
                self._byedpi.stop()
            except Exception:
                pass
            self._byedpi = None

    def next_alternative(self, host: str) -> Optional[HostStrategy]:
        """Fast failover: promote next warm-pool alternative to current.

        When the current per-host strategy degrades (TSPU re-blocked it,
        or it just stopped working), call this to swap to the next-best
        cached alternative without a full re-enumeration. Demotes the
        current strategy to the end of the alternatives list so we cycle
        through all warm-pool entries before truly giving up.

        Returns the new current HostStrategy, or None if the pool is
        exhausted (caller should then run solve() to rebuild).
        """
        hs = self._strategies.get(host)
        if not hs or not hs.alternatives:
            return None

        # Promote alternatives[0] -> current, push old current to end.
        promoted = hs.alternatives.pop(0)
        old = {"flags": hs.flags, "fitness": hs.fitness, "name": "previous"}
        hs.flags = promoted["flags"]
        hs.fitness = float(promoted.get("fitness", 0.0))
        hs.tested_at = time.time()
        # Park the old current at the back of the pool so we round-robin
        # through alternatives instead of dropping them after one cycle.
        hs.alternatives.append(old)

        self._strategies[host] = hs
        self._save()
        logger.info(
            "Failover %s: promoted alt -> current (fitness=%.3f, %d alts left in pool)",
            host, hs.fitness, len(hs.alternatives),
        )
        return hs

    def get(self, host: str) -> Optional[HostStrategy]:
        """Get cached per-host strategy."""
        hs = self._strategies.get(host)
        if hs and time.time() - hs.tested_at < 86400:  # valid for 24h
            return hs
        return None

    def get_all(self) -> dict[str, HostStrategy]:
        """Get all per-host strategies."""
        return dict(self._strategies)

    def solve(
        self,
        host: str,
        isp: str = "unknown",
        strategies_to_try: Optional[list[dict]] = None,
        on_progress: Optional[callable] = None,
        block_type: str = "",
    ) -> Optional[HostStrategy]:
        """Escalation ladder: try increasingly aggressive methods per host.

        Level 1: Known strategies (multisplit, multidisorder, etc.)
        Level 2: Anti-H2 strategies (wssize=1 breaks HTTP/2 mux)
        Level 3: ByeDPI SOCKS proxy for this host
        Level 4: Report to user — needs VPN

        Args:
            block_type: optional classification from BlockageClassifier
                (HTTP2_STREAM_KILL, SNI_FILTER, ...). When set, strategies
                tagged for this block type are tried first — much faster
                recovery for known patterns. Empty → default priority order.

        Returns HostStrategy with method="zapret"|"byedpi"|None
        """
        if not self._tester:
            return None

        from brain.enumerator import KNOWN_STRATEGIES

        # ── Level 0: Check community server for known solution ─────────
        if self._sync and not strategies_to_try:
            try:
                community = self._sync.get_host_strategy(host, isp)
                if community and community.get("flags"):
                    fitness = self._tester.test_strategy_single_host(community["flags"], host)
                    if fitness > 0.5:
                        logger.info("Solved %s: Level 0 (community) — fitness=%.3f", host, fitness)
                        hs = HostStrategy(
                            host=host, flags=community["flags"], fitness=fitness,
                            isp=isp, tested_at=time.time(),
                        )
                        self._strategies[host] = hs
                        self._save()
                        return hs
            except Exception as exc:
                logger.debug("Level 0 community check failed: %s", exc)

        # ── Level 0.5: Pattern transfer (SMART layer 2) ───────────────
        # If we've seen (isp, block_type) before, try the top known pattern
        # FIRST instead of walking 70 strategies. Saves minutes per host on
        # the second-and-subsequent host of any block type — e.g. once we
        # solve discord.com TLS_INTERFERENCE, cdn.discordapp.com gets the
        # same strategy in 1 test instead of 1-3 dozen.
        if (self._pattern_transfer and not strategies_to_try
                and isp and block_type):
            try:
                patterns = self._pattern_transfer.get_top_patterns(
                    isp=isp, block_type=block_type, limit=2,
                )
                for pat in patterns:
                    pat_flags = pat.get("flags", [])
                    if not pat_flags:
                        continue
                    fitness = self._tester.test_strategy_single_host(pat_flags, host)
                    if fitness > 0.5:
                        logger.info(
                            "Solved %s: Level 0.5 (pattern transfer from %s) — "
                            "fitness=%.3f, pattern wins=%d",
                            host, ",".join(pat.get("sample_hosts", [])[:2]),
                            fitness, pat.get("wins", 0),
                        )
                        hs = HostStrategy(
                            host=host, flags=pat_flags, fitness=fitness,
                            isp=isp, tested_at=time.time(),
                        )
                        self._strategies[host] = hs
                        self._save()
                        # Record the new win to bump pattern stats and
                        # extend sample_hosts list
                        self._pattern_transfer.record_pattern_win(
                            isp=isp, block_type=block_type,
                            flags=pat_flags, fitness=fitness, host=host,
                        )
                        if self._sync and fitness > 0.5:
                            try:
                                self._sync.report_host_strategy(
                                    host, pat_flags, fitness, isp,
                                )
                            except Exception:
                                pass
                        return hs
                # Patterns existed but none worked → fall through to enum
                if patterns:
                    logger.debug(
                        "Pattern transfer: %d known patterns for (%s, %s) all "
                        "failed for %s — falling through to enum",
                        len(patterns), isp, block_type, host,
                    )
            except Exception as exc:
                logger.debug("Pattern transfer lookup failed: %s", exc)

        # ── Level 1: Standard zapret2 strategies ──────────────────────
        candidates = strategies_to_try or KNOWN_STRATEGIES

        # Block-type-aware reordering: hoist strategies tagged for the
        # detected block type to the front so we try the targeted fix
        # first. Falls back to default order if nothing matches.
        if block_type and block_type in BLOCK_TYPE_TAGS:
            tag = BLOCK_TYPE_TAGS[block_type]
            tagged, untagged = [], []
            for strat in candidates:
                if tag in strat.get("tags", []):
                    tagged.append(strat)
                else:
                    untagged.append(strat)
            if tagged:
                logger.info(
                    "Solving %s: block_type=%s, hoisting %d %s-tagged strategies",
                    host, block_type, len(tagged), tag,
                )
                candidates = tagged + untagged

        logger.info("Solving %s: Level 1 — %d strategies", host, len(candidates))

        # Track top-3 strategies above acceptance threshold to build a warm
        # pool. After loop, [0] is current; [1:] become alternatives so a
        # later degradation triggers a fast failover instead of full re-enum.
        # Each entry: (fitness, flags, name)
        top: list[tuple[float, list[str], str]] = []
        # Single best regardless of pool threshold — used as fallback so we
        # still accept a weak (0.3..0.5) strategy when nothing strong exists,
        # matching the prior behavior.
        best_fitness = 0.0
        best_flags: list[str] = []
        best_name = ""
        POOL_THRESHOLD = 0.5
        POOL_MAX = 3

        for i, strat in enumerate(candidates):
            name = strat.get("name", f"strategy_{i}")
            flags = strat["flags"]

            if self._ai_feedback:
                excluded = self._ai_feedback.get_excluded_functions()
                if any(f.split(":")[0] in excluded for f in flags):
                    continue

            fitness = self._tester.test_strategy_single_host(flags, host)

            if on_progress:
                on_progress(i + 1, len(candidates), name, fitness)

            if self._ai_feedback:
                self._ai_feedback.record_test(
                    flags, fitness,
                    failure_mode="ok" if fitness > 0.3 else "timeout",
                )

            if fitness > best_fitness:
                best_fitness, best_flags, best_name = fitness, flags, name
            if fitness >= POOL_THRESHOLD:
                top.append((fitness, flags, name))
                top.sort(key=lambda x: x[0], reverse=True)
                del top[POOL_MAX:]

            # Early-break: don't break on a single strong hit — wait for at
            # least 2 alternatives so the warm pool isn't starving.
            # Without a populated pool, fast-failover degrades to full re-enum
            # which defeats the entire warm-pool design.
            if len(top) >= POOL_MAX and top[-1][0] > 0.6:
                break
            if fitness > 0.8 and len(top) >= 2:
                break

        if top:
            best_fitness, best_flags, best_name = top[0]
            alternatives = [
                {"flags": flags, "fitness": fit, "name": name}
                for fit, flags, name in top[1:]
            ]
            hs = HostStrategy(
                host=host, flags=best_flags, fitness=best_fitness,
                isp=isp, tested_at=time.time(),
                alternatives=alternatives,
            )
            self._strategies[host] = hs
            self._save()
            logger.info(
                "Solved %s: Level 1 — %s (fitness=%.3f, +%d alt in warm pool)",
                host, best_name, best_fitness, len(alternatives),
            )
            if self._sync and best_fitness > 0.5:
                try:
                    self._sync.report_host_strategy(host, best_flags, best_fitness, isp)
                except Exception:
                    pass
            # Pattern transfer (SMART layer 2): record this win so the
            # NEXT host of the same (isp, block_type) goes through Level 0.5
            # fast path instead of re-enumerating 70 strategies.
            if self._pattern_transfer and isp and block_type and best_fitness > 0.5:
                try:
                    self._pattern_transfer.record_pattern_win(
                        isp=isp, block_type=block_type,
                        flags=best_flags, fitness=best_fitness, host=host,
                    )
                except Exception:
                    pass
            return hs

        # Weak-but-positive fallback: nothing crossed POOL_THRESHOLD but we
        # found something better than nothing. Preserves prior behavior of
        # accepting fitness > 0.3 strategies, just without a warm pool.
        if best_fitness > 0.3:
            hs = HostStrategy(
                host=host, flags=best_flags, fitness=best_fitness,
                isp=isp, tested_at=time.time(),
            )
            self._strategies[host] = hs
            self._save()
            logger.info(
                "Solved %s: Level 1 (weak) — %s (fitness=%.3f, no warm pool)",
                host, best_name, best_fitness,
            )
            return hs

        # ── Level 2: Anti-H2 strategies (wssize=1) ───────────────────
        logger.info("Solving %s: Level 2 — Anti-HTTP/2 strategies", host)
        h2_strategies = [
            {"name": "wssize1_disorder", "flags": ["wssize:wsize=1:scale=0", "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"]},
            {"name": "wssize1_split", "flags": ["wssize:wsize=1:scale=0", "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000"]},
            {"name": "wssize1_simple", "flags": ["wssize:wsize=1:scale=0", "multidisorder:pos=midsld"]},
            {"name": "wssize8_disorder", "flags": ["wssize:wsize=8:scale=0", "multidisorder:pos=1,midsld"]},
            {"name": "wssize16_split", "flags": ["wssize:wsize=16:scale=0", "multisplit:pos=midsld"]},
        ]

        for strat in h2_strategies:
            fitness = self._tester.test_strategy_single_host(strat["flags"], host)
            logger.info("  Level 2: %s → fitness=%.3f", strat["name"], fitness)
            if fitness > 0.3:
                hs = HostStrategy(
                    host=host, flags=strat["flags"], fitness=fitness,
                    isp=isp, tested_at=time.time(),
                )
                self._strategies[host] = hs
                self._save()
                logger.info("Solved %s: Level 2 — %s (fitness=%.3f)", host, strat["name"], fitness)
                if self._sync and fitness > 0.5:
                    try:
                        self._sync.report_host_strategy(host, strat["flags"], fitness, isp)
                    except Exception:
                        pass
                return hs

        # ── Level 3: ByeDPI SOCKS proxy ──────────────────────────────
        logger.info("Solving %s: Level 3 — ByeDPI SOCKS proxy", host)
        try:
            from brain.byedpi import ByeDPIFallback
            base_dir = str(self._config.get("_base_dir", "."))
            bdpi = ByeDPIFallback(self._config, base_dir=base_dir)
            if bdpi.find_binary():
                if bdpi.start(block_type="sni_filtering"):
                    if bdpi.test_proxy(host, timeout=10):
                        logger.info("Solved %s: Level 3 — ByeDPI SOCKS works!", host)
                        hs = HostStrategy(
                            host=host, flags=["__byedpi__"],
                            fitness=0.7, isp=isp, tested_at=time.time(),
                        )
                        self._strategies[host] = hs
                        self._save()
                        # Stop previous ByeDPI if any, keep reference for cleanup
                        if self._byedpi:
                            try:
                                self._byedpi.stop()
                            except Exception:
                                pass
                        self._byedpi = bdpi
                        return hs
                    bdpi.stop()
        except Exception as exc:
            logger.debug("Level 3 ByeDPI failed: %s", exc)

        # ── Level 4: Cannot solve ─────────────────────────────────────
        logger.warning("Could not solve %s after all levels", host)
        return None

    # Known domain variants — when solving "youtube.com", also apply
    # the solution to www.youtube.com, m.youtube.com etc.
    _DOMAIN_VARIANTS = {
        "youtube.com": "youtube.com,www.youtube.com,m.youtube.com,music.youtube.com",
        "discord.com": "discord.com,discordapp.com,cdn.discordapp.com",
    }

    def build_extra_profiles(self, lua_dir=None) -> list[str]:
        """Build extra winws2 --new profiles for per-host strategies.

        Returns list of command-line arguments to append to winws2.
        Each solved host gets its own profile with --hostlist-domains.
        """
        extra = []
        for host, hs in self._strategies.items():
            if time.time() - hs.tested_at > 86400:
                continue  # expired
            domains = self._DOMAIN_VARIANTS.get(host, host)
            extra.append("--new")
            extra.append("--filter-tcp=443")
            extra.append("--filter-l7=tls")
            extra.append(f"--hostlist-domains={domains}")
            for call in hs.flags:
                extra.append(f"--lua-desync={call}")
        return extra

    # ─── Persistence ──────────────────────────────────────────────────

    def _load(self) -> None:
        """Load per-host strategies from disk."""
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for d in data:
                hs = HostStrategy.from_dict(d)
                self._strategies[hs.host] = hs
            logger.info("Loaded %d per-host strategies", len(self._strategies))
        except Exception as exc:
            logger.warning("Failed to load host strategies: %s", exc)

    def _save(self) -> None:
        """Save per-host strategies to disk."""
        data = [hs.to_dict() for hs in self._strategies.values()]
        self._db_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8",
        )

    def save(self) -> None:
        """Public save."""
        self._save()
