"""PLGames Svoboda Brain — main daemon process.

Orchestrates all modules: genetic algorithm, connection tester, ISP profiler,
watchdog, AI advisor, analytics and server sync into a unified operation cycle.
"""

from __future__ import annotations

import json
import logging
import platform
import signal
import subprocess
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from brain.ai_advisor import AIAdvisor
from brain.analytics import Analytics
from brain.donate import DonateManager
from brain.genetic import GAConfig, StrategyGene
from brain.manager import StrategyManager
from brain.profiler import ISPProfiler
from brain.sync import ServerSync
from brain.tester import ConnectionTester
from brain.watchdog import WatchDog
from updater.svoboda_updater import SvobodaUpdater

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    """Load config from config.json."""
    config_path = BASE_DIR / "config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["_base_dir"] = str(BASE_DIR)
    return config


def setup_logging(config: dict) -> None:
    """Setup file logging with rotation."""
    log_path = BASE_DIR / config.get("log_file", "svoboda.log")
    handler = RotatingFileHandler(
        log_path,
        maxBytes=config.get("log_max_bytes", 10 * 1024 * 1024),
        backupCount=config.get("log_backup_count", 7),
        encoding="utf-8",
    )
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    root = logging.getLogger("svoboda")
    root.setLevel(getattr(logging, config.get("log_level", "INFO")))
    root.addHandler(handler)


class SvobodaBrain:
    """Main controller daemon — binds all modules together."""

    def __init__(self, config: dict):
        self.config = config
        self.analytics = Analytics(config)
        self.manager = StrategyManager(config)
        self.profiler = ISPProfiler(config)
        self.tester = ConnectionTester(config, mock=False)
        self.watchdog = WatchDog(config)
        self.updater = SvobodaUpdater(config)
        self.sync = ServerSync(config, self.analytics)
        self.ai = AIAdvisor(config, self.analytics)
        self.donate = DonateManager(config)
        self.ga_config = GAConfig.from_config(config)

        self._running = False
        self._evolution_lock = threading.Lock()
        self._zapret_process: Optional[subprocess.Popen] = None
        self._logger = logging.getLogger("svoboda.brain")

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start daemon process."""
        self._running = True
        self._setup_signals()
        self._logger.info("=== PLGames Svoboda Brain v%s starting ===", self.config.get("app_version", "1.0.0"))

        # 1. Detect ISP and network profile
        profile = self.profiler.detect()
        isp = profile.isp_name
        self._logger.info("ISP: %s | middlebox: %s | region: %s", isp, profile.middlebox_type, profile.region)

        # Log ISP snapshot to analytics
        self.analytics.log_isp_snapshot(
            external_ip=profile.external_ip, asn=profile.asn,
            isp_name=profile.isp_name, org=profile.org,
            region=profile.region, middlebox_type=profile.middlebox_type,
            middlebox_ttl=profile.middlebox_ttl, middlebox_window=profile.middlebox_window,
        )

        # 2. Check Telegram updates
        self._check_telegram_updates()

        # 3. Try to pull strategies from server
        self._pull_server_strategies(isp)

        # 4. Load best strategy or start evolution
        best = self.manager.load_on_startup(isp)
        if best:
            self._logger.info("Active strategy: %s (fitness=%.3f)", best.id[:8], best.fitness)
            self._start_zapret(best.flags)
        else:
            self._logger.info("No known strategy, starting initial evolution...")
            self.run_evolution(isp)

        # 5. Start watchdog
        self.watchdog.set_evolution_trigger(lambda: self._on_watchdog_trigger(isp))
        self.watchdog.start()

        # 6. Start server sync
        self.sync.start()

        # 7. Log donate info
        if self.donate.is_configured:
            self._logger.info("Support the project: %s", self.donate.page_url)

        # 8. Log AI status
        if self.ai.is_available:
            self._logger.info("AI advisor active (model: %s)", self.config.get("ai_model", "unknown"))

        self._logger.info("Svoboda Brain running. Collecting data in background.")
        self._main_loop()

    def shutdown(self) -> None:
        """Graceful shutdown."""
        self._logger.info("Shutting down...")
        self._running = False

        self.watchdog.stop()
        self.sync.stop()
        self._stop_zapret()

        # Save current strategy
        best = self.manager.get_best_strategy()
        if best:
            self.manager.export_lua(best)
            self._logger.info("Saved current strategy before exit")

        # Final sync attempt
        self.sync.sync_now()

        # Log stats
        stats = self.analytics.get_stats_summary()
        self._logger.info(
            "Session stats: strategies=%d tests=%d avg_fitness=%.3f pending_sync=%d",
            stats["total_strategies"], stats["total_tests"],
            stats["avg_fitness"], stats["pending_sync"],
        )

        self.analytics.close()
        self._logger.info("=== Svoboda Brain stopped ===")

    def _main_loop(self) -> None:
        """Main daemon loop."""
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    # ─── Evolution ─────────────────────────────────────────────────────────

    def run_evolution(self, isp: Optional[str] = None) -> None:
        """Run genetic algorithm to find optimal strategy."""
        if not self._evolution_lock.acquire(blocking=False):
            self._logger.info("Evolution already in progress, skipping")
            return

        try:
            self.watchdog.set_evolution_status(True)
            self._logger.info("Starting evolution for ISP: %s", isp or "unknown")

            # Collect seeds from multiple sources
            seeds = self.profiler.get_seed_strategies()

            # Ask AI for additional seed suggestions
            if self.ai.is_available and self.profiler.profile:
                ai_seeds = self.ai.suggest_strategies(
                    isp=isp or "unknown",
                    middlebox_type=self.profiler.profile.middlebox_type,
                    region=self.profiler.profile.region,
                )
                if ai_seeds:
                    self._logger.info("AI provided %d seed strategies", len(ai_seeds))
                    seeds.extend(ai_seeds)

            ga = StrategyGene(self.ga_config, seed_strategies=seeds)

            def on_gen(gen: int, best):
                avg = sum(i.fitness for i in ga.population) / len(ga.population) if ga.population else 0
                self._logger.info("Gen %02d: fitness=%.3f flags=%s", gen, best.fitness, " ".join(best.flags))
                self.analytics.log_evolution_generation(
                    generation=gen, best_fitness=best.fitness, avg_fitness=avg,
                    best_flags=best.flags, population_size=len(ga.population), isp=isp or "unknown",
                )

            ga.set_generation_callback(on_gen)

            # Run GA
            best = ga.evolve(self.tester.test_strategy)

            # Save result
            record = self.manager.save_strategy(best.flags, best.fitness, isp or "unknown")
            self.manager.export_lua(record)

            # Log to analytics + queue for server sync
            self.analytics.log_strategy(
                strategy_id=record.id, flags=best.flags, fitness=best.fitness,
                isp=isp or "unknown", source="local",
            )
            self.analytics.enqueue_strategy_result(
                flags=best.flags, fitness=best.fitness, isp=isp or "unknown",
                middlebox_type=self.profiler.profile.middlebox_type if self.profiler.profile else "unknown",
                region=self.profiler.profile.region if self.profiler.profile else "",
                host_results={},
            )

            # Apply new strategy
            self._stop_zapret()
            self._start_zapret(best.flags)

            self._logger.info("Evolution complete: fitness=%.3f, flags=%s", best.fitness, " ".join(best.flags))

            # Share if fitness is high
            if best.fitness >= 0.9:
                self.updater.share_strategy(best.flags, best.fitness, isp or "all")

            # If fitness is low, ask AI for analysis
            if best.fitness < 0.6 and self.ai.is_available:
                analysis = self.ai.analyze_failure(best.flags, best.fitness, isp or "unknown")
                if analysis:
                    self._logger.info("AI analysis: %s", analysis[:200])

        except Exception as exc:
            self._logger.error("Evolution failed: %s", exc)
            fallback = self.manager.get_best_strategy(isp)
            if fallback:
                self._stop_zapret()
                self._start_zapret(fallback.flags)
                self._logger.info("Rolled back to previous strategy %s", fallback.id[:8])
        finally:
            self.watchdog.set_evolution_status(False)
            self._evolution_lock.release()

    def _on_watchdog_trigger(self, isp: Optional[str]) -> None:
        """Watchdog callback — start re-evolution in separate thread."""
        thread = threading.Thread(
            target=self.run_evolution,
            args=(isp,),
            daemon=True,
            name="svoboda-evolution",
        )
        thread.start()

    # ─── Server strategies pull ────────────────────────────────────────────

    def _pull_server_strategies(self, isp: str) -> None:
        """Pull recommended strategies from server."""
        if not self.sync.is_configured:
            return
        try:
            strategies = self.sync._pull_strategies()
            for s in strategies:
                flags = s.get("flags", [])
                fitness = s.get("fitness", 0.0)
                if flags:
                    self.manager.import_strategy({"flags": flags, "fitness": fitness, "isp": isp})
                    self._logger.info("Imported server strategy (fitness=%.3f)", fitness)
        except Exception as exc:
            self._logger.debug("Server strategy pull failed: %s", exc)

    # ─── zapret2 process management ────────────────────────────────────────

    def _start_zapret(self, flags: list[str]) -> None:
        """Start main zapret2 process."""
        self._stop_zapret()

        is_windows = platform.system() == "Windows"
        base = Path(self.config.get("_base_dir", "."))

        if is_windows:
            binary = self.config.get("zapret_binary_windows", "winws2.exe")
        else:
            binary = self.config.get("zapret_binary_linux", "nfqws2")

        lua_path = base / self.config.get("lua_strategy_path", "lua/svoboda_strategy.lua")

        cmd = [binary]
        if not is_windows:
            cmd.extend(["--qnum=0"])
        cmd.extend(["--wf-tcp=443", "--wf-udp=443"])
        cmd.append(f"--lua-desync={lua_path}")
        cmd.extend(flags)

        self._logger.info("Starting optimizer: %s", " ".join(cmd))

        try:
            self._zapret_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if is_windows else 0,
            )
            self._logger.info("Optimizer started (pid=%d)", self._zapret_process.pid)
        except FileNotFoundError:
            self._logger.warning("Optimizer binary not found: %s (running in data collection mode)", binary)
        except OSError as exc:
            self._logger.error("Failed to start optimizer: %s", exc)

    def _stop_zapret(self) -> None:
        """Stop main zapret2 process."""
        if self._zapret_process is None:
            return
        try:
            pid = self._zapret_process.pid
            self._zapret_process.terminate()
            try:
                self._zapret_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._zapret_process.kill()
                self._zapret_process.wait(timeout=3)
            self._logger.info("Optimizer stopped (pid=%d)", pid)
        except Exception as exc:
            self._logger.warning("Error stopping optimizer: %s", exc)
        finally:
            self._zapret_process = None

    # ─── Telegram ──────────────────────────────────────────────────────────

    def _check_telegram_updates(self) -> None:
        """Check Telegram channel for strategy updates."""
        if not self.updater.is_configured:
            return
        try:
            updates = self.updater.check_updates()
            for strategy_data in updates:
                self.updater.apply_update(strategy_data, self.manager)
        except Exception as exc:
            self._logger.warning("Telegram update check failed: %s", exc)

    # ─── Signals ───────────────────────────────────────────────────────────

    def _setup_signals(self) -> None:
        """Setup SIGTERM/SIGINT for graceful shutdown."""
        def handler(signum, frame):
            self._running = False

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)


def main() -> None:
    """Entry point."""
    config = load_config()
    setup_logging(config)
    brain = SvobodaBrain(config)
    brain.start()


if __name__ == "__main__":
    main()
