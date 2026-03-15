"""StrategyGene — genetic algorithm for TCP optimization strategy evolution."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger("svoboda.genetic")

# ─── Gene pool: all valid optimization flags ───────────────────────────────────

GENE_POOL: list[str] = [
    "--dpi-desync=fake",
    "--dpi-desync=rst",
    "--dpi-desync=disorder",
    "--dpi-desync=disorder2",
    "--dpi-desync=multisplit",
    "--dpi-desync=overlap",
]

GENE_POOL_PARAMS: list[tuple[str, int, int]] = [
    ("--dpi-desync-ttl=", 1, 15),
    ("--dpi-desync-split-pos=", 1, 5),
    ("--dpi-desync-split-seqovl=", 1, 3),
    ("--dpi-desync-repeats=", 2, 6),
]

GENE_POOL_BOOL: list[str] = [
    "--dpi-desync-fooling=badseq",
    "--dpi-desync-fooling=badsum",
    "--dpi-desync-fooling=md5sig",
    "--dpi-desync-ipfrag=1",
    "--dpi-desync-fake-tls=1",
]

# Тип fitness-функции: принимает list[str] (флаги), возвращает float 0.0-1.0
FitnessFunc = Callable[[list[str]], float]


@dataclass
class Individual:
    """Одна особь — набор флагов zapret2."""

    flags: list[str]
    fitness: float = 0.0


@dataclass
class GAConfig:
    """Параметры генетического алгоритма."""

    population_size: int = 12
    generations: int = 30
    mutation_rate: float = 0.3
    elite_size: int = 3
    strategy_min_flags: int = 2
    strategy_max_flags: int = 6

    @classmethod
    def from_config(cls, config: dict) -> GAConfig:
        """Создать из общего config.json."""
        return cls(
            population_size=config.get("ga_population_size", 12),
            generations=config.get("ga_generations", 30),
            mutation_rate=config.get("ga_mutation_rate", 0.3),
            elite_size=config.get("ga_elite_size", 3),
            strategy_min_flags=config.get("ga_strategy_min_flags", 2),
            strategy_max_flags=config.get("ga_strategy_max_flags", 6),
        )


class StrategyGene:
    """Genetic algorithm for evolving TCP connection optimization strategies."""

    def __init__(self, config: GAConfig, seed_strategies: Optional[list[list[str]]] = None):
        self.config = config
        self.seed_strategies = seed_strategies or []
        self.population: list[Individual] = []
        self.generation: int = 0
        self.best_ever: Optional[Individual] = None
        self._on_generation: Optional[Callable[[int, Individual], None]] = None

    def set_generation_callback(self, callback: Callable[[int, Individual], None]) -> None:
        """Установить callback вызываемый после каждого поколения."""
        self._on_generation = callback

    # ─── Главный цикл эволюции ─────────────────────────────────────────────

    def evolve(self, fitness_func: FitnessFunc) -> Individual:
        """Запустить полный цикл эволюции, вернуть лучшую особь."""
        self._init_population()
        logger.info(
            "Starting evolution: pop=%d, gens=%d, mut_rate=%.2f",
            self.config.population_size,
            self.config.generations,
            self.config.mutation_rate,
        )

        for gen in range(self.config.generations):
            self.generation = gen

            # Оценка fitness
            for ind in self.population:
                if ind.fitness == 0.0:
                    ind.fitness = fitness_func(ind.flags)

            # Сортировка по fitness (лучшие первые)
            self.population.sort(key=lambda x: x.fitness, reverse=True)

            best = self.population[0]
            avg_fitness = sum(i.fitness for i in self.population) / len(self.population)

            # Обновить лучшую за всё время
            if self.best_ever is None or best.fitness > self.best_ever.fitness:
                self.best_ever = Individual(flags=list(best.flags), fitness=best.fitness)

            logger.info(
                "Gen %02d: best=%.3f avg=%.3f flags=%s",
                gen, best.fitness, avg_fitness, " ".join(best.flags),
            )

            if self._on_generation:
                self._on_generation(gen, best)

            # Ранний выход при идеальном fitness
            if best.fitness >= 1.0:
                logger.info("Perfect fitness reached at generation %d", gen)
                break

            # Создание нового поколения
            self.population = self._next_generation()

        return self.best_ever  # type: ignore[return-value]

    # ─── Инициализация популяции ───────────────────────────────────────────

    def _init_population(self) -> None:
        """Создать начальную популяцию."""
        self.population = []

        # Сначала добавляем seed-стратегии
        for seed in self.seed_strategies[: self.config.population_size]:
            self.population.append(Individual(flags=list(seed)))

        # Остальные — случайные
        while len(self.population) < self.config.population_size:
            self.population.append(Individual(flags=self._random_strategy()))

    def _random_strategy(self) -> list[str]:
        """Сгенерировать случайный набор флагов."""
        num_flags = random.randint(self.config.strategy_min_flags, self.config.strategy_max_flags)
        flags: list[str] = []

        # Обязательно один основной desync-метод
        flags.append(random.choice(GENE_POOL))

        # Набираем остальные
        all_possible = self._all_possible_flags()
        random.shuffle(all_possible)
        for flag in all_possible:
            if len(flags) >= num_flags:
                break
            if not self._conflicts(flags, flag):
                flags.append(flag)

        return flags

    # ─── Генетические операторы ────────────────────────────────────────────

    def _next_generation(self) -> list[Individual]:
        """Создать следующее поколение."""
        new_pop: list[Individual] = []

        # 1. Элитизм — лучшие переходят без изменений
        elites = self.population[: self.config.elite_size]
        for e in elites:
            new_pop.append(Individual(flags=list(e.flags), fitness=e.fitness))

        # 2. Отбор родителей из топ-50%
        half = max(2, len(self.population) // 2)
        parents_pool = self.population[:half]

        # 3. Скрещивание + мутация для заполнения популяции
        while len(new_pop) < self.config.population_size:
            parent_a = random.choice(parents_pool)
            parent_b = random.choice(parents_pool)
            child_flags = self._crossover(parent_a.flags, parent_b.flags)
            child_flags = self._mutate(child_flags)
            child_flags = self._ensure_valid(child_flags)
            new_pop.append(Individual(flags=child_flags))

        return new_pop

    def _crossover(self, parent_a: list[str], parent_b: list[str]) -> list[str]:
        """Двухточечный crossover."""
        # Объединяем в один пул, берём уникальные
        combined = list(parent_a) + [f for f in parent_b if f not in parent_a]
        if len(combined) < 2:
            return list(combined)

        # Двухточечный: выбираем 2 точки разреза
        pt1 = random.randint(0, len(combined) - 1)
        pt2 = random.randint(pt1, len(combined) - 1)

        # Берём сегмент от parent_a и остаток от parent_b
        child: list[str] = []
        for i, flag in enumerate(combined):
            if pt1 <= i <= pt2:
                # Из первого родителя (если есть)
                if flag in parent_a:
                    child.append(flag)
            else:
                # Из второго родителя (если есть)
                if flag in parent_b:
                    child.append(flag)

        # Гарантируем минимум
        if not child:
            child = list(parent_a[:2]) if len(parent_a) >= 2 else list(parent_a)

        return child

    def _mutate(self, flags: list[str]) -> list[str]:
        """Мутация: заменить/добавить/удалить случайный флаг."""
        if random.random() > self.config.mutation_rate:
            return flags

        flags = list(flags)
        action = random.choice(["replace", "add", "remove"])

        if action == "replace" and flags:
            idx = random.randint(0, len(flags) - 1)
            new_flag = self._random_flag()
            if not self._conflicts([f for i, f in enumerate(flags) if i != idx], new_flag):
                flags[idx] = new_flag

        elif action == "add" and len(flags) < self.config.strategy_max_flags:
            new_flag = self._random_flag()
            if not self._conflicts(flags, new_flag):
                flags.append(new_flag)

        elif action == "remove" and len(flags) > self.config.strategy_min_flags:
            idx = random.randint(0, len(flags) - 1)
            flags.pop(idx)

        return flags

    def _ensure_valid(self, flags: list[str]) -> list[str]:
        """Гарантировать что стратегия валидна."""
        # Должен быть хотя бы один основной desync-метод
        has_desync = any(f.startswith("--dpi-desync=") for f in flags)
        if not has_desync:
            flags.insert(0, random.choice(GENE_POOL))

        # Ограничить размер
        if len(flags) > self.config.strategy_max_flags:
            flags = flags[: self.config.strategy_max_flags]
        while len(flags) < self.config.strategy_min_flags:
            new_flag = self._random_flag()
            if not self._conflicts(flags, new_flag):
                flags.append(new_flag)

        # Убрать дубликаты по префиксу
        flags = self._deduplicate(flags)
        return flags

    # ─── Вспомогательные ───────────────────────────────────────────────────

    def _random_flag(self) -> str:
        """Вернуть случайный допустимый флаг."""
        kind = random.choice(["method", "param", "bool"])
        if kind == "method":
            return random.choice(GENE_POOL)
        elif kind == "param":
            prefix, lo, hi = random.choice(GENE_POOL_PARAMS)
            return f"{prefix}{random.randint(lo, hi)}"
        else:
            return random.choice(GENE_POOL_BOOL)

    def _all_possible_flags(self) -> list[str]:
        """Все возможные флаги (с конкретными значениями параметров)."""
        flags = list(GENE_POOL) + list(GENE_POOL_BOOL)
        for prefix, lo, hi in GENE_POOL_PARAMS:
            flags.append(f"{prefix}{random.randint(lo, hi)}")
        return flags

    @staticmethod
    def _flag_prefix(flag: str) -> str:
        """Извлечь префикс флага (до '=' или весь флаг)."""
        if "=" in flag:
            return flag.split("=")[0] + "="
        return flag

    def _conflicts(self, existing: list[str], new_flag: str) -> bool:
        """Проверить конфликт нового флага с существующими."""
        new_prefix = self._flag_prefix(new_flag)
        # Нельзя два desync-метода одновременно
        if new_prefix == "--dpi-desync=":
            return any(f.startswith("--dpi-desync=") for f in existing)
        # Нельзя дублировать одинаковые параметры
        return any(self._flag_prefix(f) == new_prefix for f in existing)

    def _deduplicate(self, flags: list[str]) -> list[str]:
        """Убрать дубликаты по префиксу, оставив последний."""
        seen: dict[str, str] = {}
        for f in flags:
            prefix = self._flag_prefix(f)
            seen[prefix] = f
        return list(seen.values())
