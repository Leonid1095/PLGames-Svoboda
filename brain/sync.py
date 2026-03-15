"""ServerSync — anonymous telemetry sync with backend API.

Sends anonymous strategy results and ISP profiles to the central server.
Receives improved seed strategies back.
All data is anonymous: no IP, no MAC, no hostname, no accounts.
"""

from __future__ import annotations

import hashlib
import logging
import platform
import threading
import time
import uuid
from typing import Optional

import requests

from brain.analytics import Analytics

logger = logging.getLogger("svoboda.sync")


def _generate_install_id() -> str:
    """Generate a stable anonymous install ID (not tied to hardware)."""
    # Use a random UUID generated once and persisted
    return str(uuid.uuid4())


class ServerSync:
    """Background sync of anonymous analytics with the central server."""

    def __init__(self, config: dict, analytics: Analytics):
        self._api_url: str = config.get("server_api_url", "")
        self._api_key: str = config.get("server_api_key", "")
        self._sync_enabled: bool = config.get("sync_enabled", False)
        self._sync_interval: int = config.get("sync_interval_minutes", 30) * 60
        self._analytics = analytics
        self._install_id: str = config.get("install_id", _generate_install_id())
        self._app_version: str = config.get("app_version", "1.0.0")

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def is_configured(self) -> bool:
        """Check if server sync is configured and enabled."""
        return bool(self._api_url) and self._sync_enabled

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start background sync thread."""
        if not self.is_configured:
            logger.info("Server sync disabled or not configured")
            return
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sync_loop, daemon=True, name="svoboda-sync")
        self._thread.start()
        logger.info("Server sync started (interval=%ds)", self._sync_interval)

    def stop(self) -> None:
        """Stop background sync."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("Server sync stopped")

    def sync_now(self) -> bool:
        """Trigger immediate sync. Returns True if successful."""
        if not self.is_configured:
            return False
        return self._do_sync()

    # ─── Push: send local data to server ───────────────────────────────────

    def set_tier_manager(self, tier_manager) -> None:
        """Attach tier manager for license sync."""
        self._tier_manager = tier_manager

    def _do_sync(self) -> bool:
        """Push pending analytics, pull strategies, check license."""
        success = True

        # 1. Push pending events
        try:
            pending = self._analytics.get_pending_sync(limit=100)
            if pending:
                success = self._push_events(pending)
        except Exception as exc:
            logger.warning("Push sync failed: %s", exc)
            success = False

        # 2. Pull updated seed strategies
        try:
            self._pull_strategies()
        except Exception as exc:
            logger.warning("Pull sync failed: %s", exc)

        # 3. Check license status
        try:
            self._check_license()
        except Exception as exc:
            logger.debug("License check failed: %s", exc)

        return success

    def _push_events(self, events: list[dict]) -> bool:
        """Send anonymous events to server."""
        payload = {
            "install_id": self._install_id,
            "app_version": self._app_version,
            "os": platform.system(),
            "events": [
                {
                    "type": e["event_type"],
                    "data": e["payload"],
                    "timestamp": e["created_at"],
                }
                for e in events
            ],
        }

        try:
            resp = requests.post(
                f"{self._api_url}/api/v1/telemetry",
                json=payload,
                headers=self._headers(),
                timeout=15,
            )

            if resp.status_code == 200:
                sync_ids = [e["id"] for e in events]
                self._analytics.mark_synced(sync_ids)
                logger.info("Pushed %d events to server", len(events))
                return True
            else:
                logger.warning("Server push failed: HTTP %d", resp.status_code)
                return False

        except requests.RequestException as exc:
            logger.warning("Server push error: %s", exc)
            return False

    # ─── Pull: get updated strategies from server ──────────────────────────

    def _pull_strategies(self) -> list[dict]:
        """Pull recommended strategies for our ISP from server."""
        try:
            resp = requests.get(
                f"{self._api_url}/api/v1/strategies/recommended",
                params={"install_id": self._install_id},
                headers=self._headers(),
                timeout=10,
            )

            if resp.status_code == 200:
                data = resp.json()
                strategies = data.get("strategies", [])
                if strategies:
                    logger.info("Pulled %d strategies from server", len(strategies))
                return strategies
            else:
                logger.debug("Server pull: HTTP %d", resp.status_code)
                return []

        except requests.RequestException as exc:
            logger.debug("Server pull error: %s", exc)
            return []

    # ─── Background loop ───────────────────────────────────────────────────

    def _sync_loop(self) -> None:
        """Background sync loop."""
        # Initial delay to let the app settle
        self._stop_event.wait(timeout=30)

        while self._running:
            try:
                self._do_sync()
            except Exception as exc:
                logger.error("Sync loop error: %s", exc)

            self._stop_event.wait(timeout=self._sync_interval)

    def _check_license(self) -> None:
        """Check license status from server and update tier manager."""
        if not hasattr(self, "_tier_manager") or not self._tier_manager:
            return

        try:
            resp = requests.get(
                f"{self._api_url}/api/v1/license/check",
                params={"install_id": self._install_id},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("tier") and data["tier"] != "free":
                    self._tier_manager.update_license(data)
                    logger.info("License: %s until %s", data["tier"], data.get("until", "?"))
        except requests.RequestException:
            pass

    @property
    def install_id(self) -> str:
        """Public access to install_id (for license activation)."""
        return self._install_id

    def _headers(self) -> dict:
        """Build request headers."""
        h = {"Content-Type": "application/json", "User-Agent": f"Svoboda/{self._app_version}"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h
