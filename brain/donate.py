"""Donate — DonatePay integration for user support.

Provides donation page URL and optionally checks recent donations
via DonatePay API for in-app thank-you messages.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

logger = logging.getLogger("svoboda.donate")


class DonateManager:
    """DonatePay donation integration."""

    def __init__(self, config: dict):
        self._api_key: str = config.get("donatepay_api_key", "")
        self._page_url: str = config.get("donatepay_page_url", "")
        self._api_base: str = config.get("donatepay_api_base_url", "https://donatepay.ru/api/v1")

    @property
    def page_url(self) -> str:
        """Public donation page URL."""
        return self._page_url

    @property
    def is_configured(self) -> bool:
        """Check if DonatePay API is configured."""
        return bool(self._api_key) and bool(self._page_url)

    def get_recent_donations(self, limit: int = 10) -> list[dict]:
        """Fetch recent donations from DonatePay API."""
        if not self._api_key:
            return []

        try:
            resp = requests.get(
                f"{self._api_base}/transactions",
                params={
                    "access_token": self._api_key,
                    "limit": limit,
                    "type": "donation",
                    "status": "success",
                },
                timeout=10,
            )

            if resp.status_code == 200:
                data = resp.json()
                donations = data.get("data", [])
                return [
                    {
                        "name": d.get("what", "Anonymous"),
                        "amount": d.get("sum", 0),
                        "currency": d.get("currency", "RUB"),
                        "message": d.get("comment", ""),
                        "date": d.get("created_at", ""),
                    }
                    for d in donations
                ]
            else:
                logger.debug("DonatePay API error: HTTP %d", resp.status_code)

        except requests.RequestException as exc:
            logger.debug("DonatePay API error: %s", exc)

        return []

    def get_donation_stats(self) -> Optional[dict]:
        """Get aggregated donation statistics."""
        donations = self.get_recent_donations(limit=100)
        if not donations:
            return None

        total = sum(d["amount"] for d in donations)
        return {
            "total_amount": total,
            "donation_count": len(donations),
            "page_url": self._page_url,
        }
