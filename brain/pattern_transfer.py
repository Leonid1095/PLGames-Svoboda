"""PatternTransfer — SMART layer 2: cross-host strategy generalization.

Insight: when solver finds that `tls_morph_pad2k_split` works for
discord.com (TLS_INTERFERENCE), the same strategy is almost certainly
the right starting point for cdn.discordapp.com, cdn.discord.gg, and
ANY future host classified as TLS_INTERFERENCE on the same ISP. Re-
running 70 strategies for each host wastes minutes per host and adds
no information.

This module records (ISP, block_type) → top strategies as solver finds
them, and exposes a `get_top_patterns()` lookup that the solver consults
BEFORE its 70-strategy enumeration. If a pattern exists for the host's
(isp, block_type), the solver tests just the top 1-3 patterns first;
if any works, return immediately. Falls back to full enum only when
patterns either don't exist or all fail.

Persistence is in the existing analytics SQLite DB (avoids spinning up
a second connection / schema). Schema is migration-safe (CREATE IF NOT
EXISTS), so existing analytics DBs upgrade silently.

Cheap intelligence multiplier: the cost is one extra SQLite write per
successful solve and one extra SELECT per host classification. The
benefit is potentially 10x faster recovery for the second-and-subsequent
host of any block type.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("svoboda.pattern_transfer")


# Schema is registered into analytics on first call to ensure_schema().
# Idempotent; runs every time PatternTransfer is constructed (cheap, no-op
# on existing DBs after the first call).
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pattern_transfer (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    isp TEXT NOT NULL,
    block_type TEXT NOT NULL,
    flags_json TEXT NOT NULL,           -- JSON array of lua-desync flags
    fitness REAL NOT NULL,
    wins INTEGER DEFAULT 1,             -- N times this exact pattern won
    sample_hosts TEXT NOT NULL,         -- JSON array of hosts where it won
    first_seen REAL NOT NULL,           -- unix ts
    last_used REAL NOT NULL,            -- unix ts
    UNIQUE(isp, block_type, flags_json)
);

CREATE INDEX IF NOT EXISTS idx_pattern_lookup
    ON pattern_transfer(isp, block_type, fitness DESC, wins DESC);
"""


class PatternTransfer:
    """Cross-host generalization of solved strategies.

    Usage:
        pt = PatternTransfer(analytics)
        # When solver finds a winner:
        pt.record_pattern_win(
            isp="er-telecom", block_type="TLS_INTERFERENCE",
            flags=["tls_pad:size=2048", "multisplit:pos=1:seqovl=568"],
            fitness=0.95, host="discord.com",
        )
        # When solver starts on a new host:
        top = pt.get_top_patterns(isp="er-telecom", block_type="TLS_INTERFERENCE", limit=3)
        # → returns [{flags, fitness, wins, sample_hosts}, ...]
    """

    def __init__(self, analytics):
        self._analytics = analytics
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create pattern_transfer table if missing (idempotent)."""
        try:
            with self._analytics._lock:
                self._analytics._conn.executescript(_SCHEMA_SQL)
                self._analytics._conn.commit()
        except Exception as exc:
            logger.warning("PatternTransfer schema init failed: %s", exc)

    # ─── Recording ───────────────────────────────────────────────────────

    def record_pattern_win(
        self,
        isp: str,
        block_type: str,
        flags: list[str],
        fitness: float,
        host: str,
    ) -> None:
        """Record that `flags` solved `host` on (isp, block_type).

        - First time: insert row with wins=1, sample_hosts=[host].
        - Subsequent times: increment wins, add host to sample_hosts (deduped),
          update fitness to max(old, new), bump last_used.

        No-op for empty flags or empty isp / block_type — patterns must be
        meaningfully scoped to be useful for transfer.
        """
        if not flags or not isp or not block_type:
            return
        flags_json = json.dumps(flags, ensure_ascii=False)
        now = datetime.now(timezone.utc).timestamp()
        try:
            with self._analytics._lock:
                # Try to find existing row for this (isp, block_type, flags) tuple
                cur = self._analytics._conn.execute(
                    """SELECT id, fitness, wins, sample_hosts
                       FROM pattern_transfer
                       WHERE isp = ? AND block_type = ? AND flags_json = ?""",
                    (isp, block_type, flags_json),
                )
                row = cur.fetchone()
                if row:
                    pat_id, old_fitness, old_wins, hosts_json = row
                    try:
                        hosts = json.loads(hosts_json or "[]")
                    except Exception:
                        hosts = []
                    if host not in hosts:
                        hosts.append(host)
                        # Cap sample list to avoid unbounded growth
                        hosts = hosts[-20:]
                    self._analytics._conn.execute(
                        """UPDATE pattern_transfer
                           SET fitness = MAX(fitness, ?), wins = wins + 1,
                               sample_hosts = ?, last_used = ?
                           WHERE id = ?""",
                        (float(fitness), json.dumps(hosts, ensure_ascii=False),
                         now, pat_id),
                    )
                else:
                    self._analytics._conn.execute(
                        """INSERT INTO pattern_transfer
                           (isp, block_type, flags_json, fitness, wins,
                            sample_hosts, first_seen, last_used)
                           VALUES (?, ?, ?, ?, 1, ?, ?, ?)""",
                        (isp, block_type, flags_json, float(fitness),
                         json.dumps([host], ensure_ascii=False), now, now),
                    )
                self._analytics._conn.commit()
        except Exception as exc:
            logger.debug("record_pattern_win failed: %s", exc)

    # ─── Lookup ──────────────────────────────────────────────────────────

    def get_top_patterns(
        self, isp: str, block_type: str, limit: int = 3,
    ) -> list[dict]:
        """Return top N patterns for this (isp, block_type), best first.

        Ranking: fitness DESC, then wins DESC. Returns a list of dicts:
            [{flags: [...], fitness: float, wins: int, sample_hosts: [...]}, ...]
        Empty list when no patterns exist yet — solver should fall back to
        full enumeration in that case.
        """
        if not isp or not block_type:
            return []
        try:
            with self._analytics._lock:
                cur = self._analytics._conn.execute(
                    """SELECT flags_json, fitness, wins, sample_hosts
                       FROM pattern_transfer
                       WHERE isp = ? AND block_type = ?
                       ORDER BY fitness DESC, wins DESC
                       LIMIT ?""",
                    (isp, block_type, max(1, int(limit))),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.debug("get_top_patterns failed: %s", exc)
            return []

        out = []
        for flags_json, fitness, wins, hosts_json in rows:
            try:
                flags = json.loads(flags_json)
            except Exception:
                continue
            try:
                hosts = json.loads(hosts_json or "[]")
            except Exception:
                hosts = []
            out.append({
                "flags": flags,
                "fitness": float(fitness),
                "wins": int(wins),
                "sample_hosts": hosts,
            })
        return out

    def stats(self) -> dict:
        """Diagnostic snapshot for /status output."""
        try:
            with self._analytics._lock:
                cur = self._analytics._conn.execute(
                    "SELECT COUNT(*), COUNT(DISTINCT isp || '|' || block_type), "
                    "COALESCE(SUM(wins), 0) FROM pattern_transfer"
                )
                row = cur.fetchone()
        except Exception:
            return {"patterns": 0, "scopes": 0, "total_wins": 0}
        if not row:
            return {"patterns": 0, "scopes": 0, "total_wins": 0}
        return {
            "patterns": int(row[0] or 0),
            "scopes": int(row[1] or 0),
            "total_wins": int(row[2] or 0),
        }
