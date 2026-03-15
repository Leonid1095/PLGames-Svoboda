"""PLGames Svoboda — Backend API for analytics aggregation + tier licensing.

Deploy on VPS alongside 3x-ui. Receives anonymous telemetry,
aggregates strategy effectiveness, serves recommended strategies,
manages tier licenses via DonatePay.

Run:
    pip install fastapi uvicorn requests
    uvicorn server.api:app --host 0.0.0.0 --port 8443
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests as http_client
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

# ─── Config ────────────────────────────────────────────────────────────────────

DB_PATH = Path(os.environ.get("SVOBODA_DB_PATH", str(Path(__file__).parent / "svoboda_server.db")))
API_KEY = os.environ.get("SVOBODA_API_KEY", "CHANGE_ME_TO_RANDOM_SECRET")
DONATEPAY_API_KEY = os.environ.get("DONATEPAY_API_KEY", "")
DONATEPAY_API_BASE = "https://donatepay.ru/api/v1"

# Tier thresholds (RUB)
TIER_SUPPORTER_MIN = 300
TIER_PRO_MIN = 600
LICENSE_DAYS = 30

# ─── Schema ────────────────────────────────────────────────────────────────────

_SERVER_SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    install_id TEXT NOT NULL,
    app_version TEXT,
    os TEXT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS strategy_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flags TEXT NOT NULL,
    fitness REAL NOT NULL,
    isp TEXT NOT NULL DEFAULT 'unknown',
    middlebox_type TEXT DEFAULT 'unknown',
    region TEXT DEFAULT '',
    report_count INTEGER DEFAULT 1,
    avg_fitness REAL NOT NULL,
    last_reported TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS installs (
    install_id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    os TEXT,
    app_version TEXT,
    isp TEXT DEFAULT 'unknown',
    event_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS licenses (
    install_id TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'free',
    donor_name TEXT,
    donation_amount REAL DEFAULT 0,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_install ON telemetry_events(install_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_events(event_type);
CREATE INDEX IF NOT EXISTS idx_scores_isp ON strategy_scores(isp);
CREATE INDEX IF NOT EXISTS idx_scores_fitness ON strategy_scores(avg_fitness DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scores_unique
    ON strategy_scores(flags, isp);
"""


# ─── Models ────────────────────────────────────────────────────────────────────

class TelemetryEvent(BaseModel):
    type: str
    data: dict
    timestamp: str


class TelemetryPayload(BaseModel):
    install_id: str
    app_version: str = "1.0.0"
    os: str = "unknown"
    events: list[TelemetryEvent]


class ActivateLicenseRequest(BaseModel):
    install_id: str
    donor_name: str  # DonatePay nickname


# ─── DB helper ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    conn = get_db()
    conn.executescript(_SERVER_SCHEMA)
    conn.close()


# ─── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Svoboda Analytics API",
    description="Anonymous telemetry aggregation + tier licensing",
    version="1.1.0",
    lifespan=lifespan,
)


def _verify_api_key(x_api_key: Optional[str]) -> None:
    if API_KEY and API_KEY != "CHANGE_ME_TO_RANDOM_SECRET":
        if x_api_key != API_KEY:
            raise HTTPException(status_code=403, detail="Invalid API key")


# ─── Telemetry ─────────────────────────────────────────────────────────────────

@app.post("/api/v1/telemetry")
async def receive_telemetry(
    payload: TelemetryPayload,
    x_api_key: Optional[str] = Header(None),
):
    """Receive anonymous telemetry from clients."""
    _verify_api_key(x_api_key)
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()

    try:
        conn.execute(
            """INSERT INTO installs (install_id, first_seen, last_seen, os, app_version, event_count)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(install_id) DO UPDATE SET
                 last_seen = excluded.last_seen, os = excluded.os,
                 app_version = excluded.app_version,
                 event_count = event_count + excluded.event_count""",
            (payload.install_id, now, now, payload.os, payload.app_version, len(payload.events)),
        )

        for event in payload.events:
            conn.execute(
                """INSERT INTO telemetry_events
                   (install_id, app_version, os, event_type, payload, timestamp, received_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (payload.install_id, payload.app_version, payload.os,
                 event.type, json.dumps(event.data, ensure_ascii=False),
                 event.timestamp, now),
            )
            if event.type == "strategy_result":
                _update_strategy_score(conn, event.data)
            if event.type == "isp_snapshot":
                conn.execute(
                    "UPDATE installs SET isp = ? WHERE install_id = ?",
                    (event.data.get("isp_name", "unknown"), payload.install_id),
                )

        conn.commit()
        return {"status": "ok", "accepted": len(payload.events)}
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        conn.close()


# ─── Strategies ────────────────────────────────────────────────────────────────

@app.get("/api/v1/strategies/recommended")
async def get_recommended_strategies(
    install_id: str = Query(...),
    isp: Optional[str] = Query(None),
    limit: int = Query(10, le=50),
    x_api_key: Optional[str] = Header(None),
):
    """Get recommended strategies based on aggregated data."""
    _verify_api_key(x_api_key)
    conn = get_db()
    try:
        if not isp:
            cursor = conn.execute("SELECT isp FROM installs WHERE install_id = ?", (install_id,))
            row = cursor.fetchone()
            isp = row[0] if row else "unknown"

        if isp and isp != "unknown":
            cursor = conn.execute(
                """SELECT flags, avg_fitness, isp, report_count FROM strategy_scores
                   WHERE isp = ? AND report_count >= 2
                   ORDER BY avg_fitness DESC LIMIT ?""", (isp, limit))
        else:
            cursor = conn.execute(
                """SELECT flags, avg_fitness, isp, report_count FROM strategy_scores
                   WHERE report_count >= 3
                   ORDER BY avg_fitness DESC LIMIT ?""", (limit,))

        strategies = [
            {"flags": json.loads(r[0]), "fitness": round(r[1], 3), "isp": r[2], "report_count": r[3]}
            for r in cursor.fetchall()
        ]
        return {"strategies": strategies, "isp": isp}
    finally:
        conn.close()


# ─── License / Tier ────────────────────────────────────────────────────────────

@app.post("/api/v1/license/activate")
async def activate_license(req: ActivateLicenseRequest):
    """Activate a license by checking DonatePay for matching donation."""
    if not DONATEPAY_API_KEY:
        raise HTTPException(status_code=503, detail="DonatePay not configured on server")

    # Check DonatePay for recent donations from this name
    donation = _find_donation(req.donor_name)
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found. Make sure name matches your DonatePay nickname.")

    amount = donation["amount"]
    if amount < TIER_SUPPORTER_MIN:
        raise HTTPException(status_code=400, detail=f"Minimum donation is {TIER_SUPPORTER_MIN} RUB. Found: {amount} RUB.")

    # Determine tier
    tier = "pro" if amount >= TIER_PRO_MIN else "supporter"

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=LICENSE_DAYS)

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO licenses (install_id, tier, donor_name, donation_amount, issued_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(install_id) DO UPDATE SET
                 tier = excluded.tier, donor_name = excluded.donor_name,
                 donation_amount = excluded.donation_amount,
                 issued_at = excluded.issued_at, expires_at = excluded.expires_at""",
            (req.install_id, tier, req.donor_name, amount, now.isoformat(), expires.isoformat()),
        )
        conn.commit()

        return {
            "status": "ok",
            "tier": tier,
            "until": expires.isoformat(),
            "donor_name": req.donor_name,
            "amount": amount,
        }
    finally:
        conn.close()


@app.get("/api/v1/license/check")
async def check_license(
    install_id: str = Query(...),
    x_api_key: Optional[str] = Header(None),
):
    """Check current license status for an install."""
    _verify_api_key(x_api_key)
    conn = get_db()
    try:
        cursor = conn.execute(
            "SELECT tier, donor_name, donation_amount, issued_at, expires_at FROM licenses WHERE install_id = ?",
            (install_id,),
        )
        row = cursor.fetchone()
        if not row:
            return {"tier": "free", "until": None}

        tier, donor_name, amount, issued_at, expires_at = row
        # Check if expired
        try:
            expires = datetime.fromisoformat(expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expires:
                return {"tier": "free", "until": None, "expired": True}
        except (ValueError, TypeError):
            return {"tier": "free", "until": None}

        return {
            "tier": tier,
            "until": expires_at,
            "donor_name": donor_name,
            "amount": amount,
        }
    finally:
        conn.close()


# ─── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/stats")
async def get_server_stats(x_api_key: Optional[str] = Header(None)):
    """Server-side aggregated statistics."""
    _verify_api_key(x_api_key)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT install_id) FROM installs")
        total_installs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM telemetry_events")
        total_events = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM strategy_scores")
        total_strategies = cur.fetchone()[0]

        # License stats
        cur.execute("SELECT tier, COUNT(*) FROM licenses WHERE expires_at > ? GROUP BY tier",
                    (datetime.now(timezone.utc).isoformat(),))
        license_stats = {r[0]: r[1] for r in cur.fetchall()}

        cur.execute(
            """SELECT isp, COUNT(*) as cnt, AVG(avg_fitness) as avg_fit
               FROM strategy_scores WHERE report_count >= 2
               GROUP BY isp ORDER BY cnt DESC LIMIT 20""")
        isp_breakdown = [
            {"isp": r[0], "strategies": r[1], "avg_fitness": round(r[2], 3)}
            for r in cur.fetchall()
        ]

        return {
            "total_installs": total_installs,
            "total_events": total_events,
            "total_strategies": total_strategies,
            "licenses": license_stats,
            "isp_breakdown": isp_breakdown,
        }
    finally:
        conn.close()


@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ─── Internal ──────────────────────────────────────────────────────────────────

def _update_strategy_score(conn: sqlite3.Connection, data: dict) -> None:
    flags = data.get("flags", [])
    fitness = data.get("fitness", 0.0)
    isp = data.get("isp", "unknown")
    middlebox_type = data.get("middlebox_type", "unknown")
    region = data.get("region", "")
    flags_json = json.dumps(flags, ensure_ascii=False)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO strategy_scores (flags, fitness, isp, middlebox_type, region, report_count, avg_fitness, last_reported)
           VALUES (?, ?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(flags, isp) DO UPDATE SET
             report_count = report_count + 1,
             avg_fitness = (avg_fitness * report_count + excluded.fitness) / (report_count + 1),
             last_reported = excluded.last_reported,
             middlebox_type = CASE WHEN excluded.middlebox_type != 'unknown'
                                   THEN excluded.middlebox_type ELSE middlebox_type END""",
        (flags_json, fitness, isp, middlebox_type, region, fitness, now),
    )


def _find_donation(donor_name: str) -> Optional[dict]:
    """Check DonatePay API for recent donation from given name."""
    try:
        resp = http_client.get(
            f"{DONATEPAY_API_BASE}/transactions",
            params={
                "access_token": DONATEPAY_API_KEY,
                "limit": 50,
                "type": "donation",
                "status": "success",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        donations = data.get("data", [])

        # Find matching donation (case-insensitive name match)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=LICENSE_DAYS + 5)).isoformat()
        for d in donations:
            name = d.get("what", "").strip()
            if name.lower() == donor_name.lower():
                created = d.get("created_at", "")
                if created >= cutoff:
                    return {
                        "name": name,
                        "amount": float(d.get("sum", 0)),
                        "date": created,
                    }

        return None
    except Exception:
        return None
