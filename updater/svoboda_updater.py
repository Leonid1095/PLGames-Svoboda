"""Svoboda Updater — получение/отправка стратегий через Telegram-канал."""

from __future__ import annotations

import json
import logging
from typing import Optional

import requests

logger = logging.getLogger("svoboda.updater")

# Telegram Bot API base URL
_TG_API = "https://api.telegram.org/bot{token}"


class SvobodaUpdater:
    """Обмен стратегиями через Telegram-канал."""

    def __init__(self, config: dict):
        self._token: str = config.get("bot_token", "")
        self._channel: str = config.get("channel_id", "")
        self._share_enabled: bool = config.get("share", False)
        self._min_share_fitness: float = 0.9

    @property
    def is_configured(self) -> bool:
        """Проверить, настроен ли Telegram бот."""
        return bool(self._token) and bool(self._channel)

    # ─── Получение обновлений ──────────────────────────────────────────────

    def check_updates(self) -> list[dict]:
        """Загрузить последние стратегии из канала."""
        if not self.is_configured:
            logger.debug("Telegram not configured, skipping update check")
            return []

        try:
            # Получаем последние 10 сообщений из канала
            url = _TG_API.format(token=self._token) + "/getUpdates"
            resp = requests.get(url, params={"limit": 10, "timeout": 5}, timeout=10)

            if resp.status_code != 200:
                logger.warning("Telegram API error: %d", resp.status_code)
                return []

            data = resp.json()
            if not data.get("ok"):
                logger.warning("Telegram API returned error: %s", data.get("description"))
                return []

            strategies = []
            for update in data.get("result", []):
                msg = update.get("channel_post") or update.get("message")
                if not msg:
                    continue

                text = msg.get("text", "")
                strategy = self._parse_strategy_message(text)
                if strategy:
                    strategies.append(strategy)

            logger.info("Found %d strategies from Telegram", len(strategies))
            return strategies

        except requests.RequestException as exc:
            logger.warning("Failed to check Telegram updates: %s", exc)
            return []

    def apply_update(self, strategy_data: dict, manager) -> Optional[object]:
        """Применить стратегию из Telegram к локальной базе."""
        if "flags" not in strategy_data:
            logger.warning("Invalid strategy data: missing 'flags'")
            return None

        record = manager.import_strategy(strategy_data)
        logger.info(
            "Applied Telegram strategy: %s (fitness=%.3f)",
            record.id[:8], record.fitness,
        )
        return record

    # ─── Отправка стратегий ────────────────────────────────────────────────

    def share_strategy(self, flags: list[str], fitness: float, isp: str = "all") -> bool:
        """Отправить рабочую стратегию в канал."""
        if not self.is_configured:
            logger.debug("Telegram not configured, cannot share")
            return False

        if not self._share_enabled:
            logger.debug("Strategy sharing disabled in config")
            return False

        if fitness < self._min_share_fitness:
            logger.debug("Fitness %.3f below sharing threshold %.3f", fitness, self._min_share_fitness)
            return False

        strategy_json = json.dumps({
            "flags": flags,
            "isp": isp,
            "fitness": fitness,
            "version": "1.0",
        }, ensure_ascii=False)

        message = f"🛡 Svoboda Strategy\n```json\n{strategy_json}\n```"

        try:
            url = _TG_API.format(token=self._token) + "/sendMessage"
            resp = requests.post(url, json={
                "chat_id": self._channel,
                "text": message,
                "parse_mode": "Markdown",
            }, timeout=10)

            if resp.status_code == 200 and resp.json().get("ok"):
                logger.info("Shared strategy to Telegram (fitness=%.3f)", fitness)
                return True
            else:
                logger.warning("Failed to share: %s", resp.text)
                return False

        except requests.RequestException as exc:
            logger.warning("Failed to share strategy: %s", exc)
            return False

    # ─── Parsing ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse_strategy_message(text: str) -> Optional[dict]:
        """Извлечь JSON стратегии из текста сообщения."""
        # Ищем JSON в тексте (между ```json и ``` или просто {})
        text = text.strip()

        # Формат: ```json\n{...}\n```
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start) if "```" in text[start:] else len(text)
            json_str = text[start:end].strip()
        elif text.startswith("{"):
            json_str = text
        else:
            # Попробуем найти JSON в любом месте
            brace_start = text.find("{")
            if brace_start == -1:
                return None
            brace_end = text.rfind("}") + 1
            json_str = text[brace_start:brace_end]

        try:
            data = json.loads(json_str)
            if "flags" in data and isinstance(data["flags"], list):
                return data
        except (json.JSONDecodeError, ValueError):
            pass

        return None
