"""DiscoveryPipeline — autonomous detection and solving of newly blocked domains.

When zapret2 detects a new blocked domain via hostlist-auto (user visited a
blocked site not in our list), this pipeline:

  1. Confirms block via BlockageClassifier (what type: SNI, IP, RST, throttle?)
  2. Routes: SNI/RST → HostSolver (find zapret2 strategy), IP → ProxyRouter
  3. Saves per-host strategy locally
  4. Reports to community server (other users get instant fix)
  5. Adds to active monitoring

The user doesn't need to do anything — visit any blocked site, we detect and fix.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.discovery")

# Don't process these (internal / not real domains)
_IGNORE_DOMAINS = {
    "localhost", "127.0.0.1", "::1",
    "wpad", "isatap", "_tcp", "_udp",
}

# Minimum time between processing same domain (seconds)
_COOLDOWN_SECONDS = 3600  # 1 hour


@dataclass
class DiscoveryResult:
    """Result of processing a newly discovered blocked domain."""
    domain: str
    block_type: str = ""          # SNI_FILTERING, IP_BLOCK, etc.
    solved: bool = False
    strategy_flags: list[str] = field(default_factory=list)
    fitness: float = 0.0
    route: str = ""               # "zapret2" | "proxy" | "unsolved"
    reported_to_server: bool = False


class DiscoveryPipeline:
    """Process newly blocked domains found by zapret2's hostlist-auto.

    Usage:
        pipeline = DiscoveryPipeline(config, tester, classifier, solver, router, sync)
        # Called from monitoring loop when hostlist-auto has new entries:
        results = pipeline.process_new_domains(["web.telegram.org", "newsite.com"])
    """

    def __init__(
        self,
        config: dict,
        tester=None,           # ConnectionTester
        classifier=None,       # BlockageClassifier
        host_solver=None,      # HostSolver
        proxy_router=None,     # ProxyRouter
        server_sync=None,      # ServerSync
        isp: str = "unknown",
    ):
        self._config = config
        self._tester = tester
        self._classifier = classifier
        self._solver = host_solver
        self._router = proxy_router
        self._sync = server_sync
        self._isp = isp

        # Track processed domains with timestamps (avoid re-processing)
        self._processed: dict[str, float] = {}
        # Domains added to monitoring
        self._monitored_domains: set[str] = set()
        # All discovered results
        self._results: dict[str, DiscoveryResult] = {}

    @property
    def monitored_domains(self) -> set[str]:
        """Domains that were discovered and added to monitoring."""
        return set(self._monitored_domains)

    @property
    def solved_count(self) -> int:
        return sum(1 for r in self._results.values() if r.solved)

    def process_new_domains(self, domains: list[str]) -> list[DiscoveryResult]:
        """Process newly detected blocked domains through the full pipeline.

        For each domain:
        1. Skip if recently processed or invalid
        2. Classify block type
        3. Route to appropriate solver
        4. Report to server
        5. Add to monitoring

        Returns list of results (only newly processed).
        """
        results = []

        for domain in domains:
            domain = domain.strip().lower()

            # Skip invalid
            if not domain or domain in _IGNORE_DOMAINS:
                continue
            if len(domain) < 4 or "." not in domain:
                continue

            # Skip if recently processed (cooldown)
            last = self._processed.get(domain, 0)
            if time.time() - last < _COOLDOWN_SECONDS:
                continue

            # Process
            result = self._process_single(domain)
            if result:
                results.append(result)
                self._processed[domain] = time.time()
                self._results[domain] = result

        return results

    def _process_single(self, domain: str) -> Optional[DiscoveryResult]:
        """Process a single newly discovered domain."""
        result = DiscoveryResult(domain=domain)

        logger.info("Discovery: processing new domain %s", domain)

        # ── Step 1: Classify block type ───────────────────────────────
        if self._classifier:
            try:
                analysis = self._classifier.classify(domain)
                result.block_type = analysis.block_type

                if analysis.block_type == "NOT_BLOCKED":
                    logger.debug("Discovery: %s is not blocked, skipping", domain)
                    return None  # false alarm or already unblocked

                logger.info("Discovery: %s → %s (confidence=%.0f%%)",
                            domain, analysis.block_type, analysis.confidence * 100)

            except Exception as exc:
                logger.debug("Discovery: classify %s failed: %s", domain, exc)
                # Assume SNI filtering if classifier fails (most common in RU)
                result.block_type = "SNI_FILTERING"

        # ── Step 2: Route based on block type ─────────────────────────
        if result.block_type in ("IP_BLOCK", "TLS_IP_BLOCK"):
            # IP blocked → needs proxy, not zapret2
            result.route = "proxy"
            logger.info("Discovery: %s is %s → proxy needed", domain, result.block_type)

            # Add to proxy router if available
            if self._router:
                from brain.proxy_router import IP_BLOCKED_DOMAINS
                IP_BLOCKED_DOMAINS.add(domain)

            self._monitored_domains.add(domain)
            return result

        # ── Step 3: Try HostSolver for DPI-bypassable domains ─────────
        if result.block_type in ("SNI_FILTERING", "RST_INJECTION", "TLS_INTERFERENCE",
                                  "HTTP2_STREAM_KILL", "TIMEOUT_SILENT", "THROTTLING"):
            result.route = "zapret2"

            if self._solver:
                try:
                    host_result = self._solver.solve(domain, isp=self._isp)
                    if host_result:
                        result.solved = True
                        result.strategy_flags = host_result.flags
                        result.fitness = host_result.fitness
                        logger.info("Discovery: SOLVED %s → fitness=%.3f, flags=%s",
                                    domain, host_result.fitness, " | ".join(host_result.flags))

                        # ── Step 4: Report to community server ────────
                        if self._sync and host_result.fitness > 0.5:
                            try:
                                self._sync.report_host_strategy(
                                    domain, host_result.flags,
                                    host_result.fitness, self._isp,
                                )
                                result.reported_to_server = True
                                logger.info("Discovery: reported %s strategy to server", domain)
                            except Exception as exc:
                                logger.debug("Discovery: server report failed for %s: %s", domain, exc)
                    else:
                        logger.info("Discovery: could not solve %s", domain)
                except Exception as exc:
                    logger.debug("Discovery: solver error for %s: %s", domain, exc)

        # ── Step 5: Add to monitoring ─────────────────────────────────
        self._monitored_domains.add(domain)

        return result

    def get_extra_profiles(self) -> list[str]:
        """Get extra winws2 profiles for all solved discovered domains.

        Returns command-line args to append to permanent winws2 instance.
        """
        if not self._solver:
            return []
        return self._solver.build_extra_profiles()

    def get_summary(self) -> str:
        """Human-readable summary of all discoveries."""
        if not self._results:
            return ""

        lines = []
        solved = [r for r in self._results.values() if r.solved]
        proxy = [r for r in self._results.values() if r.route == "proxy"]
        unsolved = [r for r in self._results.values() if not r.solved and r.route != "proxy"]

        if solved:
            lines.append(f"  Solved: {', '.join(r.domain for r in solved)}")
        if proxy:
            lines.append(f"  IP-blocked (proxy): {', '.join(r.domain for r in proxy)}")
        if unsolved:
            lines.append(f"  Unsolved: {', '.join(r.domain for r in unsolved)}")

        return "\n".join(lines)
