"""Tier system — license management via DonatePay donations.

Tiers:
  FREE:      plgames-ai (own model), 1 scan/day
  SUPPORTER: plgames-ai, 12 scans/day (every 2h), auto-test
  PRO:       DeepSeek V3 (paid API), 48 scans/day (every 30min), auto-test

License flow:
  1. User donates on DonatePay
  2. User enters their DonatePay nickname in the app
  3. Server checks DonatePay API for matching donation
  4. Server issues license: {tier, until, install_id}
  5. Client fetches license on every sync
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.tier")

# ─── Tier definitions ───────────────────────────────────────────────────────

TIERS = {
    "free": {
        "name": "Free",
        "ai_model": "plgames-ai",
        "ai_interval_seconds": 86400,       # 24 hours
        "ai_auto_test": False,
        "priority_strategies": False,
    },
    "supporter": {
        "name": "Supporter",
        "min_donation": 300,
        "ai_model": "plgames-ai",
        "ai_interval_seconds": 7200,         # 2 hours
        "ai_auto_test": True,
        "priority_strategies": True,
    },
    "pro": {
        "name": "Pro",
        "min_donation": 600,
        "ai_model": "deepseek-chat",         # DeepSeek V3
        "ai_api_url": "https://api.deepseek.com/v1",
        "ai_interval_seconds": 1800,         # 30 minutes
        "ai_auto_test": True,
        "priority_strategies": True,
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
        """AI model for current tier."""
        return self.tier_config["ai_model"]

    @property
    def ai_api_url(self) -> Optional[str]:
        """AI API URL override for current tier (None = use default)."""
        return self.tier_config.get("ai_api_url")

    @property
    def ai_api_key(self) -> Optional[str]:
        """AI API key for current tier."""
        if self.tier == "pro":
            return self._config.get("deepseek_api_key", "")
        return self._config.get("ai_api_key", "")

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
            return f"[FREE] AI: {cfg['ai_model']} (1x/day)"
        elif t == "supporter":
            return f"[SUPPORTER] AI: {cfg['ai_model']} (every 2h) + auto-test"
        elif t == "pro":
            until = self._license.get("until", "?") if self._license else "?"
            return f"[PRO] AI: DeepSeek V3 (every 30min) + auto-test | until {until}"
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
