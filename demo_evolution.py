"""
Demo: genetic algorithm on mock data.

Run:
    cd PLGames_Svoboda
    python demo_evolution.py
"""

from __future__ import annotations

import json
import sys
import io
from pathlib import Path

# Добавляем корень проекта в путь
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from brain.genetic import GAConfig, StrategyGene
from brain.manager import StrategyManager
from brain.tester import ConnectionTester


def main() -> None:
    # Загрузить конфиг
    config_path = Path(__file__).resolve().parent / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["_base_dir"] = str(Path(__file__).resolve().parent)

    print("=" * 65)
    print("  PLGames Svoboda -- GA Evolution Demo")
    print("=" * 65)
    print()

    # Инициализация
    ga_config = GAConfig.from_config(config)
    tester = ConnectionTester(config, mock=True)
    manager = StrategyManager(config)

    # Seed-стратегии (Ростелеком)
    seeds = [
        ["--dpi-desync=disorder2", "--dpi-desync-ttl=5", "--dpi-desync-split-pos=3"],
        ["--dpi-desync=fake", "--dpi-desync-ttl=6", "--dpi-desync-ipfrag=1"],
    ]

    ga = StrategyGene(ga_config, seed_strategies=seeds)

    # Callback для красивого вывода
    def on_generation(gen: int, best):
        bar_len = int(best.fitness * 30)
        bar = "#" * bar_len + "." * (30 - bar_len)
        print(f"  Gen {gen:02d}  [{bar}] {best.fitness:.3f}  {' '.join(best.flags)}")

    ga.set_generation_callback(on_generation)

    print(f"  Population: {ga_config.population_size}")
    print(f"  Generations: {ga_config.generations}")
    print(f"  Mutation rate: {ga_config.mutation_rate}")
    print(f"  Elite size: {ga_config.elite_size}")
    print()
    print("  Evolution:")
    print("  " + "-" * 60)

    # Запуск эволюции
    best = ga.evolve(tester.test_strategy)

    print("  " + "-" * 60)
    print()
    print(f"  [OK] Best strategy found!")
    print(f"    Fitness: {best.fitness:.3f}")
    print(f"    Flags:   {' '.join(best.flags)}")
    print()

    # Сохранение
    record = manager.save_strategy(best.flags, best.fitness, "rostelecom")
    lua_path = manager.export_lua(record)

    print(f"  [OK] Saved to strategies_db.json (id: {record.id[:8]})")
    print(f"  [OK] Lua file: {lua_path}")
    print()

    # Показать сгенерированный Lua
    print("  Generated Lua:")
    print("  " + "-" * 60)
    lua_content = lua_path.read_text(encoding="utf-8")
    for line in lua_content.splitlines():
        print(f"  {line}")
    print("  " + "-" * 60)
    print()
    print("  Done!")


if __name__ == "__main__":
    main()
