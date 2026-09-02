"""WatchDog — мониторинг соединения и триггер переэволюции."""

from __future__ import annotations

import logging
import subprocess
import platform
import threading
import time
from typing import Callable, Optional

from brain.netenv import CURL_DIRECT
logger = logging.getLogger("svoboda.watchdog")


class WatchDog:
    """Периодическая проверка доступности и триггер эволюции."""

    def __init__(self, config: dict):
        self._hosts: list[str] = config.get("test_hosts", ["youtube.com", "discord.com"])
        self._interval: int = config.get("watchdog_interval_minutes", 5) * 60
        self._fail_threshold: int = config.get("watchdog_fail_threshold", 2)
        self._min_fitness: float = config.get("watchdog_min_fitness", 0.6)
        self._timeout: int = config.get("test_timeout", 5)
        self._is_windows = platform.system() == "Windows"

        self._consecutive_failures: int = 0
        self._running: bool = False
        self._evolution_in_progress: bool = False
        self._thread: Optional[threading.Thread] = None
        self._on_trigger: Optional[Callable[[], None]] = None
        self._stop_event = threading.Event()

    def set_evolution_trigger(self, callback: Callable[[], None]) -> None:
        """Установить callback, вызываемый при необходимости переэволюции."""
        self._on_trigger = callback

    def set_evolution_status(self, in_progress: bool) -> None:
        """Обновить статус эволюции (вызывается из brain)."""
        self._evolution_in_progress = in_progress

    def start(self) -> None:
        """Запустить watchdog в фоновом потоке."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="svoboda-watchdog")
        self._thread.start()
        logger.info("WatchDog started (interval=%ds, threshold=%d)", self._interval, self._fail_threshold)

    def stop(self) -> None:
        """Остановить watchdog."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("WatchDog stopped")

    def check_now(self) -> float:
        """Ручная проверка. Возвращает fitness 0.0-1.0."""
        return self._check_connectivity()

    # ─── Main loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Основной цикл мониторинга."""
        while self._running:
            try:
                fitness = self._check_connectivity()
                self._evaluate_fitness(fitness)
            except Exception as exc:
                logger.error("WatchDog check error: %s", exc)

            # Ждём интервал или сигнал остановки
            self._stop_event.wait(timeout=self._interval)

    def _check_connectivity(self) -> float:
        """Проверить доступность хостов через curl."""
        total = len(self._hosts)
        successful = 0

        for host in self._hosts:
            if self._curl_check(host):
                successful += 1

        fitness = successful / total if total > 0 else 0.0
        logger.debug("Connectivity check: %d/%d hosts reachable (fitness=%.2f)", successful, total, fitness)
        return fitness

    def _curl_check(self, host: str) -> bool:
        """Одиночная проверка хоста через curl."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s", *CURL_DIRECT,
                    "--max-time", str(self._timeout),
                    f"https://{host}",
                    "-o", "/dev/null" if not self._is_windows else "NUL",
                    "-w", "%{http_code}",
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout + 3,
            )
            if result.returncode == 0 and result.stdout.strip():
                code = int(result.stdout.strip())
                return code in {200, 301, 302, 303, 307, 308, 403}
        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
            pass
        except Exception as exc:
            logger.debug("curl check %s failed: %s", host, exc)
        return False

    def _evaluate_fitness(self, fitness: float) -> None:
        """Оценить результат и решить нужна ли переэволюция."""
        if fitness >= self._min_fitness:
            # Всё хорошо — сбросить счётчик
            if self._consecutive_failures > 0:
                logger.info("Connectivity restored (fitness=%.2f)", fitness)
            self._consecutive_failures = 0
            return

        self._consecutive_failures += 1
        logger.warning(
            "Connectivity degraded: fitness=%.2f, failures=%d/%d",
            fitness, self._consecutive_failures, self._fail_threshold,
        )

        if self._consecutive_failures >= self._fail_threshold:
            self._trigger_evolution()

    def _trigger_evolution(self) -> None:
        """Запустить переэволюцию."""
        if self._evolution_in_progress:
            logger.info("Evolution already in progress, skipping trigger")
            return

        logger.warning("Triggering re-evolution (consecutive failures: %d)", self._consecutive_failures)
        self._consecutive_failures = 0

        if self._on_trigger:
            self._on_trigger()
        else:
            logger.warning("No evolution trigger callback set")
