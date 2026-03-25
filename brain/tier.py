"""Tier system — license management via DonatePay donations.

Tiers:
  FREE:      plgames-ai (own model), 1 scan/day
  SUPPORTER: plgames-ai, 12 scans/day (every 2h), auto-test
  PRO:       DeepSeek V3 (paid API), 48 scans/day (every 30min), auto-test

AI model routing is handled server-side. The client only knows tier name.

License flow:
  1. User donates on DonatePay
  2. User enters their DonatePay nickname in the app
  3. Server checks DonatePay API for matching donation
  4. Server issues license: {tier, until, install_id}
  5. Client fetches license on every sync
"""

from __future__ import annotations

import base64
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.tier")

# ─── Tier definitions (display-only on client) ─────────────────────────────

TIERS = {
    "free": {
        "name": "Free",
        "ai_model_display": "plgames-ai",
        "ai_interval_seconds": 86400,       # 24 hours
        "ai_auto_test": False,
        "priority_strategies": False,
        "vps_proxy": False,
    },
    "supporter": {
        "name": "Supporter",
        "min_donation": 300,
        "ai_model_display": "plgames-ai",
        "ai_interval_seconds": 7200,         # 2 hours
        "ai_auto_test": True,
        "priority_strategies": True,
        "vps_proxy": False,
    },
    "pro": {
        "name": "Pro",
        "min_donation": 600,
        "ai_model_display": "DeepSeek V3",
        "ai_interval_seconds": 1800,         # 30 minutes
        "ai_auto_test": True,
        "priority_strategies": True,
        "vps_proxy": True,              # PLGames VPS proxy for IP-blocked sites
    },
}

# Duration of license per donation (30 days)
LICENSE_DURATION_DAYS = 30


class TierManager:
    """Manages user tier based on DonatePay donations and server license."""

    def __init__(self, config: dict):
        self._config = config
        base_dir = Path(config.get("_base_dir", "."))
        self._license_path = base_dir / "license.json"
        self._tier: str = "free"
        self._license: Optional[dict] = None
        self._last_ai_scan: float = 0

        # Load cached license
        self._load_license()

    @property
    def tier(self) -> str:
        """Current tier name."""
        if self._license and self._is_license_valid():
            return self._license.get("tier", "free")
        return "free"

    @property
    def tier_config(self) -> dict:
        """Current tier configuration."""
        return TIERS.get(self.tier, TIERS["free"])

    @property
    def ai_model(self) -> str:
        """AI model display name for current tier."""
        return self.tier_config["ai_model_display"]

    @property
    def ai_interval(self) -> int:
        """Seconds between AI scans for current tier."""
        return self.tier_config["ai_interval_seconds"]

    @property
    def has_auto_test(self) -> bool:
        """Whether current tier has AI auto-test."""
        return self.tier_config["ai_auto_test"]

    @property
    def has_priority_strategies(self) -> bool:
        """Whether current tier gets priority strategies."""
        return self.tier_config["priority_strategies"]

    @property
    def has_vps_proxy(self) -> bool:
        """Whether current tier has PLGames VPS proxy for IP-blocked sites."""
        if self._is_owner():
            return True
        return self.tier_config.get("vps_proxy", False)

    @property
    def proxy_url(self) -> Optional[str]:
        """VPS proxy URL — only available for PRO/owner tier.

        Sources (priority):
          1. Server-delivered in license response (rotatable, secure)
          2. Embedded fallback for owner (obfuscated, pre-sync bootstrap)

        Returns None if not authorized or unavailable.
        """
        if not self.has_vps_proxy:
            return None

        # 1. Server-delivered credentials (preferred — rotatable)
        if self._license:
            server_url = self._license.get("proxy_url")
            if server_url:
                return server_url

        # 2. Owner fallback (before first sync delivers fresh creds)
        if self._is_owner():
            return self._decode_embedded_proxy()

        return None

    @staticmethod
    def _decode_embedded_proxy() -> str:
        """Decode embedded proxy URL (owner bootstrap fallback)."""
        _d = "ABlTCUNRW1xZQA5XBQwWBQpTBzADARldK0cuLT4VQCRSJBEBGUgbHhcXEhRfBlFJEhsBVUxfCg0aGFVYBFBS"
        _k = b"sv0b0da"
        raw = base64.b64decode(_d)
        return bytes(b ^ _k[i % len(_k)] for i, b in enumerate(raw)).decode()

    def _is_owner(self) -> bool:
        """Check if this is the product owner's install (always PRO features)."""
        if not self._license:
            # Check install_id from config for owner bypass
            owner_ids = self._config.get("_owner_ids", [])
            install_id = self._config.get("install_id", "")
            return install_id in owner_ids
        return self._license.get("tier") == "owner"

    def should_run_ai_scan(self) -> bool:
        """Check if enough time has passed for next AI scan."""
        now = time.time()
        elapsed = now - self._last_ai_scan
        return elapsed >= self.ai_interval

    def mark_ai_scan_done(self) -> None:
        """Record that an AI scan was performed."""
        self._last_ai_scan = time.time()

    def update_license(self, license_data: dict) -> None:
        """Update license from server response."""
        self._license = license_data
        self._save_license()
        tier = license_data.get("tier", "free")
        until = license_data.get("until", "")
        logger.info("License updated: tier=%s until=%s", tier, until)

    def get_status_line(self) -> str:
        """Human-readable status string."""
        t = self.tier
        cfg = self.tier_config
        if t == "free":
            return f"[FREE] AI: {cfg['ai_model_display']} (1x/day)"
        elif t == "supporter":
            return f"[SUPPORTER] AI: {cfg['ai_model_display']} (every 2h) + auto-test"
        elif t == "pro" or self._is_owner():
            until = self._license.get("until", "~") if self._license else "owner"
            return f"[PRO] AI: {cfg['ai_model_display']} + VPS proxy + auto-test | {until}"
        return f"[{t.upper()}]"

    # ─── Internal ──────────────────────────────────────────────────────────

    def _is_license_valid(self) -> bool:
        """Check if cached license is still valid."""
        if not self._license:
            return False
        until = self._license.get("until", "")
        if not until:
            return False
        try:
            expires = datetime.fromisoformat(until)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < expires
        except (ValueError, TypeError):
            return False

    def _load_license(self) -> None:
        """Load cached license from disk."""
        if not self._license_path.exists():
            return
        try:
            data = json.loads(self._license_path.read_text(encoding="utf-8"))
            self._license = data
            if self._is_license_valid():
                logger.info("Loaded license: tier=%s", data.get("tier", "free"))
            else:
                logger.info("Cached license expired")
                self._license = None
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Failed to load license: %s", exc)

    def _save_license(self) -> None:
        """Save license to disk."""
        if not self._license:
            return
        try:
            self._license_path.write_text(
                json.dumps(self._license, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("Failed to save license: %s", exc)
