"""ServerSync — anonymous telemetry sync with backend API.

Sends anonymous strategy results and ISP profiles to the central server.
Receives improved seed strategies back.
Auto-registers on first run to obtain a per-install API token.
All data is anonymous: no IP, no MAC, no hostname, no accounts.
"""

from __future__ import annotations

import json
import logging
import platform
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

import requests

from brain.analytics import Analytics

logger = logging.getLogger("svoboda.sync")


def _generate_install_id() -> str:
    """Generate a stable anonymous install ID (not tied to hardware)."""
    return str(uuid.uuid4())


class ServerSync:
    """Background sync of anonymous analytics with the central server."""

    def __init__(self, config: dict, analytics: Analytics):
        self._api_url: str = config.get("server_api_url", "")
        self._api_key: str = config.get("server_api_key", "")
        self._sync_enabled: bool = config.get("sync_enabled", True)
        self._sync_interval: int = config.get("sync_interval_minutes", 30) * 60
        self._analytics = analytics
        self._install_id: str = config.get("install_id", "")
        self._app_version: str = config.get("app_version", "1.0.0")
        self._config = config
        self._base_dir = Path(config.get("_base_dir", "."))

        # Load or generate install_id
        if not self._install_id:
            self._install_id = self._load_or_create_install_id()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Components that need server key updates after registration
        self._dependents: list = []

    @property
    def is_configured(self) -> bool:
        """Check if server sync is configured and enabled."""
        return bool(self._api_url) and self._sync_enabled

    @property
    def install_id(self) -> str:
        """Public access to install_id."""
        return self._install_id

    @property
    def api_key(self) -> str:
        """Current API key (master or per-install token)."""
        return self._api_key

    def register_dependent(self, obj) -> None:
        """Register an object that needs server key updates.
        Object must have set_server_key(key) method."""
        self._dependents.append(obj)

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

    # ─── Auto-registration ────────────────────────────────────────────────

    def register_if_needed(self) -> bool:
        """Auto-register with server to get a per-install token.
        Returns True if registered successfully or already has a key."""
        if self._api_key:
            return True
        if not self._api_url:
            return False

        try:
            resp = requests.post(
                f"{self._api_url}/api/v1/register",
                json={
                    "install_id": self._install_id,
                    "app_version": self._app_version,
                    "os": platform.system(),
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._api_key = data["api_token"]
                self._save_api_key(data["api_token"])
                # Update all dependents
                for dep in self._dependents:
                    if hasattr(dep, "set_server_key"):
                        dep.set_server_key(self._api_key)
                logger.info("Registered with server, got per-install token")
                return True
            else:
                logger.warning("Registration failed: HTTP %d", resp.status_code)
                return False
        except requests.RequestException as exc:
            logger.warning("Registration error: %s", exc)
            return False

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

    # ─── Collective Intelligence (Phase 3) ──────────────────────────────

    def get_instant_strategy(self, isp: str, dpi_type: str = "unknown") -> Optional[dict]:
        """Get the best community strategy for this ISP from server.

        Returns {"flags": [...], "fitness": 0.8, "report_count": 12} or None.
        """
        if not self.is_configured or not self._api_key:
            return None
        try:
            resp = requests.get(
                f"{self._api_url}/api/v1/strategies/instant",
                params={"isp": isp, "dpi_type": dpi_type},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                strategy = data.get("strategy")
                if strategy and strategy.get("flags"):
                    logger.info(
                        "Got instant strategy from community: fitness=%.3f, %d reports",
                        strategy["fitness"], strategy["report_count"],
                    )
                    return strategy
        except requests.RequestException as exc:
            logger.debug("Instant strategy fetch failed: %s", exc)
        return None

    def vote_strategy(
        self, flags: list[str], success: bool, fitness: float = 0.0,
        isp: str = "unknown", dpi_type: str = "unknown",
    ) -> bool:
        """Vote for/against a strategy (community feedback)."""
        if not self.is_configured or not self._api_key:
            return False
        try:
            resp = requests.post(
                f"{self._api_url}/api/v1/strategies/vote",
                json={
                    "install_id": self._install_id,
                    "flags": flags,
                    "success": success,
                    "fitness": fitness,
                    "isp": isp,
                    "dpi_type": dpi_type,
                },
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("Voted %s for strategy (fitness=%.3f)", "success" if success else "failure", fitness)
                return True
        except requests.RequestException:
            pass
        return False

    def check_tspu_status(self, isp: str) -> Optional[dict]:
        """Check if TSPU firmware was updated for this ISP."""
        if not self.is_configured or not self._api_key:
            return None
        try:
            resp = requests.get(
                f"{self._api_url}/api/v1/tspu/status",
                params={"isp": isp},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("tspu_updated"):
                    logger.warning("TSPU update detected for %s!", isp)
                return data
        except requests.RequestException:
            pass
        return None

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

    def _headers(self) -> dict:
        """Build request headers."""
        h = {"Content-Type": "application/json", "User-Agent": f"Svoboda/{self._app_version}"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    # ─── Install ID persistence ────────────────────────────────────────────

    def _load_or_create_install_id(self) -> str:
        """Load install_id from disk or generate a new one."""
        id_path = self._base_dir / ".install_id"
        if id_path.exists():
            try:
                return id_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        new_id = _generate_install_id()
        try:
            id_path.write_text(new_id, encoding="utf-8")
        except OSError:
            pass
        return new_id

    def _save_api_key(self, token: str) -> None:
        """Save per-install API token to config.json."""
        config_path = self._base_dir / "config.json"
        if not config_path.exists():
            return
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            data["server_api_key"] = token
            data["install_id"] = self._install_id
            config_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            logger.info("Saved API token to config.json")
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to save API token: %s", exc)
