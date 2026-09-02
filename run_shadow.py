"""
Shadow run — запуск Svoboda Brain в фоновом режиме сбора данных.
На Windows без zapret2 работает в mock-режиме: эволюционирует стратегии,
собирает аналитику в SQLite, синхронизирует с сервером.

Работает непрерывно — новый цикл эволюции каждые N минут.
Ctrl+C для остановки.

Запуск:
    python run_shadow.py
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time
import io
from datetime import datetime
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from brain.analytics import Analytics
from brain.ai_advisor import AIAdvisor
from brain.donate import DonateManager
from brain.genetic import GAConfig, StrategyGene
from brain.manager import StrategyManager
from brain.sync import ServerSync
from brain.tester import ConnectionTester
from brain.tier import TierManager
from brain.watchdog import WatchDog

# ─── Global stop flag ───────────────────────────────────────────────────────

_running = True


def _signal_handler(signum, frame):
    global _running
    _running = False
    print("\n  [!] Stopping... (please wait)")


def run_one_cycle(
    config, analytics, manager, tester, ai, sync, ga_config, cycle_num
):
    """Run one evolution cycle and log results."""
    now = datetime.now().strftime("%H:%M:%S")
    print()
    print(f"  --- Cycle #{cycle_num} started at {now} ---")
    print()

    seeds = [
        # zapret2 lua-desync strategies
        ["fake:blob=fake_default_tls:ip_ttl=6:ip6_ttl=6:tcp_md5", "multisplit:pos=midsld"],
        ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5", "multidisorder:pos=1,midsld"],
        ["fake:blob=fake_default_tls:ip_ttl=4:tcp_seq=-10000:repeats=6", "multidisorder:pos=midsld"],
        ["fakedsplit:blob=fake_default_tls:ip_ttl=5:tcp_md5"],
        ["fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid", "multisplit:pos=midsld,endhost-1"],
    ]

    # Ask AI for extra seeds if available
    if ai.is_available:
        print("  Asking AI for strategy suggestions...")
        ai_seeds = ai.suggest_strategies(isp="unknown", middlebox_type="unknown")
        if ai_seeds:
            print(f"  AI suggested {len(ai_seeds)} strategies")
            seeds.extend(ai_seeds)

    ga = StrategyGene(ga_config, seed_strategies=seeds)

    def on_gen(gen, best):
        if not _running:
            return
        avg = sum(i.fitness for i in ga.population) / len(ga.population)
        bar_len = int(best.fitness * 25)
        bar = "#" * bar_len + "." * (25 - bar_len)
        print(f"  Gen {gen:02d} [{bar}] best={best.fitness:.3f} avg={avg:.3f}")

        analytics.log_evolution_generation(
            generation=gen, best_fitness=best.fitness, avg_fitness=avg,
            best_flags=best.flags, population_size=len(ga.population),
            isp="shadow_test",
        )

    ga.set_generation_callback(on_gen)
    best = ga.evolve(tester.test_strategy)

    print()
    print(f"  [OK] Best: fitness={best.fitness:.3f}  flags={' '.join(best.flags)}")

    # Save
    record = manager.save_strategy(best.flags, best.fitness, "shadow_test")
    analytics.log_strategy(
        strategy_id=record.id, flags=best.flags, fitness=best.fitness,
        isp="shadow_test", source="local",
    )
    analytics.enqueue_strategy_result(
        flags=best.flags, fitness=best.fitness, isp="shadow_test",
        middlebox_type="unknown", region="", host_results={},
    )

    # Stats
    stats = analytics.get_stats_summary()
    print(f"  DB: {stats['total_strategies']} strategies | pending sync: {stats['pending_sync']}")

    # Try server sync
    if sync.is_configured:
        ok = sync.sync_now()
        status = "OK" if ok else "server unreachable"
        print(f"  Sync: {status}")

    return best


def main():
    global _running

    # Graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Direct-path measurements only (see brain/netenv.py)
    from brain.netenv import scrub_proxy_env
    scrub_proxy_env()

    # Load config
    config = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
    config["_base_dir"] = str(BASE_DIR)

    # Cycle interval (minutes)
    cycle_minutes = config.get("shadow_cycle_minutes", 10)

    # Setup logging to both file and console
    log = logging.getLogger("svoboda")
    log.setLevel(logging.DEBUG)

    from logging.handlers import RotatingFileHandler
    fh = RotatingFileHandler(
        BASE_DIR / config.get("log_file", "svoboda.log"),
        maxBytes=10 * 1024 * 1024, backupCount=7, encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    log.addHandler(ch)

    print()
    print("=" * 60)
    print("  PLGames Svoboda -- Shadow Mode (continuous)")
    print("=" * 60)
    print()

    # Init modules
    analytics = Analytics(config)
    manager = StrategyManager(config)
    tester = ConnectionTester(config, mock=True)
    tier = TierManager(config)
    donate = DonateManager(config)
    sync = ServerSync(config, analytics)
    sync.set_tier_manager(tier)

    # AI advisor — uses server proxy, no direct AI access
    ai = AIAdvisor(config, analytics, tier_manager=tier)
    ai.set_install_id(sync.install_id)

    # Register dependents for server key updates
    sync.register_dependent(ai)
    sync.register_dependent(donate)

    # Auto-register with server
    if sync.is_configured:
        print("  Registering with server...")
        if sync.register_if_needed():
            print(f"  [OK] Registered (install: {sync.install_id[:8]}...)")
            # Update AI with the obtained key
            ai.set_server_key(sync.api_key)
        else:
            print("  [!] Registration failed (will retry on sync)")

    ga_config = GAConfig.from_config(config)

    # Status
    print(f"  Analytics DB:  {config.get('analytics_db_path')}")
    print(f"  Tier:          {tier.get_status_line()}")
    print(f"  AI advisor:    {'ACTIVE' if ai.is_available else 'disabled'} (via server proxy)")
    print(f"  Server sync:   {'ACTIVE' if sync.is_configured else 'disabled'}")
    print(f"  Donate page:   {donate.page_url}")
    print(f"  Cycle every:   {cycle_minutes} min")
    print()
    print(f"  Press Ctrl+C to stop gracefully.")
    print(f"  Window stays open, data accumulates in the background.")
    print()

    cycle_num = 0
    try:
        while _running:
            cycle_num += 1
            run_one_cycle(
                config, analytics, manager, tester, ai, sync, ga_config, cycle_num
            )

            if not _running:
                break

            # Wait for next cycle
            next_time = datetime.now().strftime("%H:%M:%S")
            print()
            print(f"  Sleeping {cycle_minutes} min until next cycle... (Ctrl+C to stop)")
            print(f"  " + "-" * 55)

            # Sleep in small chunks so Ctrl+C is responsive
            for _ in range(cycle_minutes * 60):
                if not _running:
                    break
                time.sleep(1)

    except KeyboardInterrupt:
        pass

    # Shutdown
    print()
    print("  Shutting down...")
    stats = analytics.get_stats_summary()
    print(f"  Final stats:")
    print(f"    Strategies:   {stats['total_strategies']}")
    print(f"    Avg fitness:  {stats['avg_fitness']:.3f}")
    print(f"    Pending sync: {stats['pending_sync']}")
    analytics.close()

    print()
    print("  Shadow mode stopped. Data saved to:")
    print(f"    - {config.get('analytics_db_path')} (SQLite analytics)")
    print(f"    - {config.get('strategies_db_path')} (strategies)")
    print(f"    - {config.get('log_file')} (logs)")
    print()
    print("  Review collected data: python review_data.py")
    print()


if __name__ == "__main__":
    main()
