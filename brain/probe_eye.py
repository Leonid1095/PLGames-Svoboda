"""ProbeEye — continuous active probing for the SMART layer 1.

The watchdog runs deep health checks every 5 minutes — too coarse to
notice TSPU shaping mid-cycle or to build a statistical baseline. ProbeEye
runs a lightweight background loop that samples each test_host roughly
every 30 seconds, measuring throughput/TTFB, and persists each sample
into `probe_history` (SQLite) for the Anomaly Detector (layer 4) to read.

Key properties:
- Read-only effect on the network: small HTTPS request per host, max 4s.
- Cheap: 5 hosts × 30s ≈ 1 probe per 6s averaged. Near-zero CPU.
- Resilient: any probe error is logged but never crashes the loop.
- Cooperative shutdown: respects the same _running flag as the watchdog
  by polling a stop_event; idle sleep is broken in 1s slices so Ctrl+C
  feels responsive.
- Auto-purge: every PURGE_EVERY_SEC seconds, drops probe rows older than
  KEEP_HOURS so the DB doesn't grow forever.

Design note: ProbeEye intentionally does NOT trigger recovery itself.
It only feeds raw samples to analytics. Recovery decisions live in the
watchdog and the Anomaly Detector (layer 4, separate module). This
separation keeps each layer testable in isolation.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("svoboda.probe_eye")


# Defaults (overridable via constructor / config)
PROBE_INTERVAL_SEC = 30        # one full sweep of all hosts every 30s
PROBE_TIMEOUT_SEC = 4          # per-host curl timeout (small, won't stall sweep)
PURGE_EVERY_SEC = 1800         # 30 min — drop rows older than KEEP_HOURS
KEEP_HOURS = 24                # rolling window of historical probe data


class ProbeEye:
    """Continuous lightweight per-host probing.

    Usage:
        eye = ProbeEye(analytics, hosts=[...], probe_fn=_curl_check_one,
                       strategy_id_fn=lambda: current_sid)
        eye.start()
        ...
        eye.stop()
    """

    def __init__(
        self,
        analytics,
        hosts: list[str],
        probe_fn: Callable[[str, int], dict],
        strategy_id_fn: Optional[Callable[[], str]] = None,
        interval_sec: int = PROBE_INTERVAL_SEC,
        timeout_sec: int = PROBE_TIMEOUT_SEC,
        purge_every_sec: int = PURGE_EVERY_SEC,
        keep_hours: int = KEEP_HOURS,
    ):
        self._analytics = analytics
        # Defensive copy so external mutation doesn't drift our sweep set;
        # the caller can rotate hosts mid-flight via set_hosts().
        self._hosts: list[str] = list(hosts)
        self._probe_fn = probe_fn
        self._strategy_id_fn = strategy_id_fn or (lambda: "")
        self._interval_sec = max(5, int(interval_sec))
        self._timeout_sec = max(1, int(timeout_sec))
        self._purge_every_sec = max(60, int(purge_every_sec))
        self._keep_hours = max(1, int(keep_hours))

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()  # guards _hosts updates
        self._last_purge: float = 0.0

    # ─── Public control ──────────────────────────────────────────────────

    def start(self) -> None:
        """Launch the probe loop in a daemon thread (idempotent)."""
        if self._thread and self._thread.is_alive():
            logger.debug("ProbeEye already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="probe-eye",
        )
        self._thread.start()
        logger.info(
            "ProbeEye started: %d hosts, %ds interval, %ds timeout",
            len(self._hosts), self._interval_sec, self._timeout_sec,
        )

    def stop(self, join_timeout: float = 5.0) -> None:
        """Signal stop and wait briefly for the thread to exit."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        logger.info("ProbeEye stopped")

    def set_hosts(self, hosts: list[str]) -> None:
        """Replace the host list (e.g. when test_hosts are updated)."""
        with self._lock:
            self._hosts = list(hosts)
        logger.debug("ProbeEye hosts updated: %d", len(self._hosts))

    # ─── Internals ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Main background loop — one sweep per interval_sec."""
        # Stagger the first sweep slightly so we don't collide with startup
        # health-check; the watchdog usually does its baseline first.
        self._sleep_responsive(2.0)

        while not self._stop_event.is_set():
            sweep_start = time.time()
            self._sweep_once()

            # Periodic purge (cheap; bounded by index lookup)
            if time.time() - self._last_purge >= self._purge_every_sec:
                self._purge()
                self._last_purge = time.time()

            elapsed = time.time() - sweep_start
            sleep_for = max(1.0, self._interval_sec - elapsed)
            self._sleep_responsive(sleep_for)

    def _sweep_once(self) -> None:
        """Probe each host once; log to analytics; never raise."""
        with self._lock:
            current_hosts = list(self._hosts)
        sid = ""
        try:
            sid = self._strategy_id_fn() or ""
        except Exception:
            pass

        for host in current_hosts:
            if self._stop_event.is_set():
                return
            try:
                r = self._probe_fn(host, self._timeout_sec)
                # `usable` field is throughput-aware; falls back to `success`
                # for backward-compat with probe_fns that don't expose it.
                usable = bool(r.get("usable", r.get("success", False)))
                self._analytics.log_probe(
                    host=host,
                    success=usable,
                    throughput_kbps=float(r.get("throughput_kbps", 0.0) or 0.0),
                    ttfb_ms=float(r.get("ttfb_ms", 0.0) or 0.0),
                    http_code=int(r.get("http_code", 0) or 0),
                    strategy_id=sid,
                )
            except Exception as exc:
                # Probing must be best-effort — never crash the loop.
                logger.debug("probe %s: %s", host, exc)

    def _purge(self) -> None:
        try:
            n = self._analytics.purge_old_probes(keep_hours=self._keep_hours)
            if n > 0:
                logger.debug("ProbeEye purged %d old probe rows", n)
        except Exception as exc:
            logger.debug("ProbeEye purge failed: %s", exc)

    def _sleep_responsive(self, total_sec: float) -> None:
        """Sleep in 1-second slices so stop() returns within ~1s."""
        end = time.time() + total_sec
        while time.time() < end:
            if self._stop_event.is_set():
                return
            time.sleep(min(1.0, end - time.time()))
