"""Analytics — local SQLite database for strategy and connection telemetry."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.analytics")

SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS strategies (
    id TEXT PRIMARY KEY,
    flags TEXT NOT NULL,           -- JSON array of flags
    fitness REAL NOT NULL DEFAULT 0.0,
    isp TEXT NOT NULL DEFAULT 'unknown',
    middlebox_type TEXT DEFAULT 'unknown',
    region TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    source TEXT DEFAULT 'local',   -- local | telegram | server
    wins INTEGER DEFAULT 0,
    losses INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy_id TEXT NOT NULL,
    host TEXT NOT NULL,
    http_code INTEGER,
    success INTEGER NOT NULL,      -- 0 or 1
    latency_ms REAL,
    tested_at TEXT NOT NULL,
    FOREIGN KEY (strategy_id) REFERENCES strategies(id)
);

CREATE TABLE IF NOT EXISTS evolution_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    best_fitness REAL NOT NULL,
    avg_fitness REAL NOT NULL,
    best_flags TEXT NOT NULL,       -- JSON array
    population_size INTEGER,
    isp TEXT,
    logged_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS isp_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_ip TEXT,
    asn TEXT,
    isp_name TEXT,
    org TEXT,
    region TEXT,
    middlebox_type TEXT,
    middlebox_ttl INTEGER,
    middlebox_window INTEGER,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,          -- JSON to send to server
    event_type TEXT NOT NULL,       -- strategy_result | evolution_complete | isp_snapshot
    created_at TEXT NOT NULL,
    synced INTEGER DEFAULT 0,      -- 0 = pending, 1 = sent
    synced_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_test_results_strategy ON test_results(strategy_id);
CREATE INDEX IF NOT EXISTS idx_test_results_host ON test_results(host);
CREATE INDEX IF NOT EXISTS idx_sync_queue_pending ON sync_queue(synced) WHERE synced = 0;
CREATE INDEX IF NOT EXISTS idx_strategies_isp ON strategies(isp);
"""


class Analytics:
    """Local SQLite analytics for strategy telemetry and server sync."""

    def __init__(self, config: dict):
        base_dir = Path(config.get("_base_dir", "."))
        db_path = base_dir / config.get("analytics_db_path", "svoboda_analytics.db")
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        logger.info("Analytics DB initialized: %s", db_path)

    def close(self) -> None:
        """Close DB connection."""
        self._conn.close()

    # ─── Strategy events ───────────────────────────────────────────────────

    def log_strategy(
        self,
        strategy_id: str,
        flags: list[str],
        fitness: float,
        isp: str = "unknown",
        middlebox_type: str = "unknown",
        region: str = "",
        source: str = "local",
    ) -> None:
        """Record a strategy (new or updated)."""
        self._conn.execute(
            """INSERT OR REPLACE INTO strategies
               (id, flags, fitness, isp, middlebox_type, region, created_at, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (strategy_id, json.dumps(flags), fitness, isp, middlebox_type, region,
             datetime.now(timezone.utc).isoformat(), source),
        )
        self._conn.commit()

    def log_strategy_result(self, strategy_id: str, success: bool) -> None:
        """Record a win or loss for a strategy."""
        col = "wins" if success else "losses"
        self._conn.execute(
            f"UPDATE strategies SET {col} = {col} + 1 WHERE id = ?",
            (strategy_id,),
        )
        self._conn.commit()

    # ─── Test result events ────────────────────────────────────────────────

    def log_test_result(
        self,
        strategy_id: str,
        host: str,
        http_code: Optional[int],
        success: bool,
        latency_ms: Optional[float] = None,
    ) -> None:
        """Record a single connection test result."""
        self._conn.execute(
            """INSERT INTO test_results
               (strategy_id, host, http_code, success, latency_ms, tested_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (strategy_id, host, http_code, int(success), latency_ms,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    # ─── Evolution events ──────────────────────────────────────────────────

    def log_evolution_generation(
        self,
        generation: int,
        best_fitness: float,
        avg_fitness: float,
        best_flags: list[str],
        population_size: int,
        isp: str = "unknown",
    ) -> None:
        """Record one generation of evolution."""
        self._conn.execute(
            """INSERT INTO evolution_log
               (generation, best_fitness, avg_fitness, best_flags, population_size, isp, logged_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (generation, best_fitness, avg_fitness, json.dumps(best_flags),
             population_size, isp, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    # ─── ISP snapshot events ───────────────────────────────────────────────

    def log_isp_snapshot(
        self,
        external_ip: str,
        asn: str,
        isp_name: str,
        org: str,
        region: str,
        middlebox_type: str,
        middlebox_ttl: Optional[int],
        middlebox_window: Optional[int],
    ) -> None:
        """Record an ISP/middlebox detection snapshot."""
        self._conn.execute(
            """INSERT INTO isp_snapshots
               (external_ip, asn, isp_name, org, region,
                middlebox_type, middlebox_ttl, middlebox_window, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (external_ip, asn, isp_name, org, region,
             middlebox_type, middlebox_ttl, middlebox_window,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

        # Queue for server sync
        self._enqueue_sync("isp_snapshot", {
            "asn": asn, "isp_name": isp_name, "region": region,
            "middlebox_type": middlebox_type,
            "middlebox_ttl": middlebox_ttl,
        })

    # ─── Sync queue ────────────────────────────────────────────────────────

    def enqueue_strategy_result(
        self, flags: list[str], fitness: float, isp: str,
        middlebox_type: str, region: str, host_results: dict,
    ) -> None:
        """Queue an anonymous strategy result for server sync."""
        self._enqueue_sync("strategy_result", {
            "flags": flags,
            "fitness": fitness,
            "isp": isp,
            "middlebox_type": middlebox_type,
            "region": region,
            "host_results": host_results,
        })

    def get_pending_sync(self, limit: int = 50) -> list[dict]:
        """Get pending sync items."""
        cursor = self._conn.execute(
            "SELECT id, payload, event_type, created_at FROM sync_queue WHERE synced = 0 ORDER BY id LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        return [
            {"id": r[0], "payload": json.loads(r[1]), "event_type": r[2], "created_at": r[3]}
            for r in rows
        ]

    def mark_synced(self, sync_ids: list[int]) -> None:
        """Mark sync items as sent."""
        if not sync_ids:
            return
        placeholders = ",".join("?" * len(sync_ids))
        self._conn.execute(
            f"UPDATE sync_queue SET synced = 1, synced_at = ? WHERE id IN ({placeholders})",
            [datetime.now(timezone.utc).isoformat()] + sync_ids,
        )
        self._conn.commit()

    # ─── Aggregation queries ───────────────────────────────────────────────

    def get_best_flags_for_isp(self, isp: str, limit: int = 5) -> list[dict]:
        """Get top strategies for a given ISP."""
        cursor = self._conn.execute(
            """SELECT flags, fitness, wins, losses FROM strategies
               WHERE isp = ? ORDER BY fitness DESC LIMIT ?""",
            (isp, limit),
        )
        return [
            {"flags": json.loads(r[0]), "fitness": r[1], "wins": r[2], "losses": r[3]}
            for r in cursor.fetchall()
        ]

    def get_host_success_rate(self, host: str, hours: int = 24) -> float:
        """Get success rate for a host over last N hours."""
        cursor = self._conn.execute(
            """SELECT COUNT(*) as total,
                      SUM(success) as ok
               FROM test_results
               WHERE host = ?
                 AND tested_at >= datetime('now', ?)""",
            (host, f"-{hours} hours"),
        )
        row = cursor.fetchone()
        if not row or row[0] == 0:
            return 0.0
        return row[1] / row[0]

    def get_stats_summary(self) -> dict:
        """Overall statistics summary."""
        cur = self._conn.cursor()

        cur.execute("SELECT COUNT(*) FROM strategies")
        total_strategies = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM test_results")
        total_tests = cur.fetchone()[0]

        cur.execute("SELECT AVG(fitness) FROM strategies WHERE fitness > 0")
        row = cur.fetchone()
        avg_fitness = row[0] if row[0] else 0.0

        cur.execute("SELECT COUNT(*) FROM sync_queue WHERE synced = 0")
        pending_sync = cur.fetchone()[0]

        return {
            "total_strategies": total_strategies,
            "total_tests": total_tests,
            "avg_fitness": round(avg_fitness, 3),
            "pending_sync": pending_sync,
        }

    # ─── Internal ──────────────────────────────────────────────────────────

    def _enqueue_sync(self, event_type: str, data: dict) -> None:
        """Add item to sync queue."""
        self._conn.execute(
            "INSERT INTO sync_queue (payload, event_type, created_at) VALUES (?, ?, ?)",
            (json.dumps(data, ensure_ascii=False), event_type,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def _init_schema(self) -> None:
        """Initialize DB schema."""
        self._conn.executescript(_SCHEMA_SQL)
        # Check version
        cursor = self._conn.execute("SELECT MAX(version) FROM schema_version")
        row = cursor.fetchone()
        current = row[0] if row and row[0] else 0
        if current < SCHEMA_VERSION:
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()
