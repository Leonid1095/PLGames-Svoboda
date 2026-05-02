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
    # Future: SNI_FILTER → "fake_hello_inject", THROTTLING → "anti_throttle"
}


@dataclass
class HostStrategy:
    """Working strategy for a specific host."""
    host: str
    flags: list[str]
    fitness: float
    isp: str = "unknown"
    tested_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "flags": self.flags,
            "fitness": self.fitness,
            "isp": self.isp,
            "tested_at": self.tested_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HostStrategy:
        return cls(
            host=d["host"], flags=d["flags"],
            fitness=d.get("fitness", 0.0), isp=d.get("isp", "unknown"),
            tested_at=d.get("tested_at", 0.0),
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

    def __init__(self, config: dict, tester=None, ai_feedback=None, server_sync=None):
        self._config = config
        self._base_dir = Path(config.get("_base_dir", "."))
        self._db_path = self._base_dir / "host_strategies.json"
        self._tester = tester
        self._ai_feedback = ai_feedback
        self._sync = server_sync
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

        best_fitness = 0.0
        best_flags = []
        best_name = ""

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
                best_fitness = fitness
                best_flags = flags
                best_name = name

            if fitness > 0.8:  # Fast response — great, use it
                break

        if best_fitness > 0.3:
            hs = HostStrategy(
                host=host, flags=best_flags, fitness=best_fitness,
                isp=isp, tested_at=time.time(),
            )
            self._strategies[host] = hs
            self._save()
            logger.info("Solved %s: Level 1 — %s (fitness=%.3f)", host, best_name, best_fitness)
            if self._sync and best_fitness > 0.5:
                try:
                    self._sync.report_host_strategy(host, best_flags, best_fitness, isp)
                except Exception:
                    pass
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
