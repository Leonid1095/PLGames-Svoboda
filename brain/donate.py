"""Donate — DonatePay integration for user support.

Provides donation page URL. Recent donations are fetched through server proxy
(DonatePay API key never leaves the server).
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

logger = logging.getLogger("svoboda.donate")


class DonateManager:
    """DonatePay donation integration via server proxy."""

    def __init__(self, config: dict):
        self._page_url: str = config.get("donatepay_page_url", "")
        self._server_url: str = config.get("server_api_url", "")
        self._server_key: str = config.get("server_api_key", "")

    @property
    def page_url(self) -> str:
        """Public donation page URL."""
        return self._page_url

    @property
    def is_configured(self) -> bool:
        """Check if donate page is set."""
        return bool(self._page_url)

    def set_server_key(self, key: str) -> None:
        """Update server API key (after auto-registration)."""
        self._server_key = key

    def get_recent_donations(self, limit: int = 10) -> list[dict]:
        """Fetch recent donations through server proxy."""
        if not self._server_url:
            return []

        try:
            resp = requests.get(
                f"{self._server_url}/api/v1/donate/recent",
                params={"limit": limit},
                headers={"X-API-Key": self._server_key},
                timeout=10,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("donations", [])
            else:
                logger.debug("Donate proxy error: HTTP %d", resp.status_code)

        except requests.RequestException as exc:
            logger.debug("Donate proxy error: %s", exc)

        return []

    def get_donation_stats(self) -> Optional[dict]:
        """Get aggregated donation statistics."""
        donations = self.get_recent_donations(limit=100)
        if not donations:
            return None

        total = sum(d.get("amount", 0) for d in donations)
        return {
            "total_amount": total,
            "donation_count": len(donations),
            "page_url": self._page_url,
        }
