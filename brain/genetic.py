"""StrategyGene — genetic algorithm for zapret2 lua-desync strategy evolution.

Strategies are built as zapret2 --lua-desync command-line arguments.
Each strategy is a list of desync function calls, e.g.:
  ["fake:blob=fake_default_tls:ip_ttl=6:tcp_md5", "multisplit:pos=midsld"]

These get passed to winws2/nfqws2 as:
  --lua-desync=fake:blob=fake_default_tls:ip_ttl=6:tcp_md5 --lua-desync=multisplit:pos=midsld
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger("svoboda.genetic")

# ─── Gene pool: zapret2 lua-desync functions and parameters ───────────────────

# Primary desync functions (at least one required per strategy)
DESYNC_FUNCTIONS = [
    "fake",
    "fakedsplit",
    "multisplit",
    "multidisorder",
    "syndata",
]

# Secondary functions (can be combined with primary)
SECONDARY_FUNCTIONS = [
    "pktmod",       # apply fooling to current dissect
    "wssize",       # modify window size
    "drop",         # drop original (used after send)
    "send",         # send current dissect with modifiers
]

# Parameters for desync functions (key, possible values or range)
DESYNC_PARAMS = {
    # Fake parameters
    "blob": ["fake_default_tls", "fake_default_http", "fake_default_quic", "0x00000000"],
    "ip_ttl": (1, 15),
    "ip6_ttl": (1, 15),
    "ip_autottl": ["-1,3-20", "-2,3-20", "2,3-20"],
    "ip6_autottl": ["-1,3-20", "-2,3-20", "2,3-20"],
    "repeats": (1, 11),

    # Split/disorder parameters
    "pos": ["1", "2", "3", "5", "midsld", "method+2", "endhost-1",
            "1,midsld", "midsld,endhost-1"],

    # Sequence manipulation (fooling)
    "tcp_seq": [-66000, -10000, -5000, 10000],
    "tcp_ack": [-66000, -10000],

    # TCP fooling flags (boolean-style)
    "tcp_md5": None,       # no value needed
    "tcp_ts_up": None,
    "tcp_flags_unset": ["ack"],

    # TLS modification
    "tls_mod": ["rnd", "rndsni", "dupsid", "rnd,rndsni", "rnd,dupsid",
                "rnd,rndsni,dupsid", "rnd,dupsid,sni=www.google.com"],

    # IP fragmentation
    "ipfrag": None,
    "ipfrag_pos_udp": [8, 16, 24],

    # Sequence overlap
    "seqovl": (1, 10),
    "seqovl_pattern": ["0x1603030000", "0x00000000"],

    # Other
    "nofake1": None,
}

# Boolean params (no value, just present or absent)
BOOL_PARAMS = {"tcp_md5", "tcp_ts_up", "ipfrag", "nofake1"}

# Fitness function type
FitnessFunc = Callable[[list[str]], float]


@dataclass
class Individual:
    """One individual — a set of lua-desync function calls."""

    flags: list[str]
    fitness: float = 0.0


@dataclass
class GAConfig:
    """Genetic algorithm parameters."""

    population_size: int = 12
    generations: int = 30
    mutation_rate: float = 0.3
    elite_size: int = 3
    strategy_min_flags: int = 1  # min lua-desync calls
    strategy_max_flags: int = 4  # max lua-desync calls

    @classmethod
    def from_config(cls, config: dict) -> GAConfig:
        """Create from config.json."""
        return cls(
            population_size=config.get("ga_population_size", 12),
            generations=config.get("ga_generations", 30),
            mutation_rate=config.get("ga_mutation_rate", 0.3),
            elite_size=config.get("ga_elite_size", 3),
            strategy_min_flags=config.get("ga_strategy_min_flags", 1),
            strategy_max_flags=config.get("ga_strategy_max_flags", 4),
        )


class StrategyGene:
    """Genetic algorithm for evolving zapret2 lua-desync strategies."""

    def __init__(self, config: GAConfig, seed_strategies: Optional[list[list[str]]] = None,
                 excluded_functions: Optional[set[str]] = None):
        self.config = config
        self.seed_strategies = seed_strategies or []
        self.excluded_functions = excluded_functions or set()
        self.population: list[Individual] = []
        self.generation: int = 0
        self.best_ever: Optional[Individual] = None
        self._on_generation: Optional[Callable[[int, Individual], None]] = None
        self._stagnation_count: int = 0
        self._last_best_fitness: float = 0.0
        self._base_mutation_rate: float = config.mutation_rate

        # Filter DESYNC_FUNCTIONS based on AI feedback exclusions
        self._active_functions = [f for f in DESYNC_FUNCTIONS if f not in self.excluded_functions]
        if not self._active_functions:
            self._active_functions = ["multisplit", "multidisorder"]  # always keep these
        if self.excluded_functions:
            logger.info("GA: excluded functions from AI feedback: %s", self.excluded_functions)

    def set_generation_callback(self, callback: Callable[[int, Individual], None]) -> None:
        """Set callback called after each generation."""
        self._on_generation = callback

    # ─── Main evolution loop ─────────────────────────────────────────────

    def evolve(self, fitness_func: FitnessFunc) -> Individual:
        """Run full evolution cycle, return best individual."""
        self._init_population()
        logger.info(
            "Starting evolution: pop=%d, gens=%d, mut_rate=%.2f",
            self.config.population_size,
            self.config.generations,
            self.config.mutation_rate,
        )

        for gen in range(self.config.generations):
            self.generation = gen

            # Evaluate fitness
            for ind in self.population:
                if ind.fitness == 0.0:
                    ind.fitness = fitness_func(ind.flags)

            # Sort by fitness (best first)
            self.population.sort(key=lambda x: x.fitness, reverse=True)

            best = self.population[0]
            avg_fitness = sum(i.fitness for i in self.population) / len(self.population)

            # Track all-time best
            if self.best_ever is None or best.fitness > self.best_ever.fitness:
                self.best_ever = Individual(flags=list(best.flags), fitness=best.fitness)

            logger.info(
                "Gen %02d: best=%.3f avg=%.3f flags=%s",
                gen, best.fitness, avg_fitness, " | ".join(best.flags),
            )

            if self._on_generation:
                self._on_generation(gen, best)

            # Early exit at perfect fitness
            if best.fitness >= 1.0:
                logger.info("Perfect fitness reached at generation %d", gen)
                break

            # Stagnation detection: if best unchanged for 5 gens, shake things up
            if abs(best.fitness - self._last_best_fitness) < 0.01:
                self._stagnation_count += 1
            else:
                self._stagnation_count = 0
                self.config.mutation_rate = self._base_mutation_rate
            self._last_best_fitness = best.fitness

            if self._stagnation_count >= 5:
                self.config.mutation_rate = min(0.7, self._base_mutation_rate * 2)
                logger.info("Stagnation detected, boosting mutation to %.2f", self.config.mutation_rate)
                self._stagnation_count = 0

            # Create next generation
            self.population = self._next_generation()

        return self.best_ever  # type: ignore[return-value]

    # ─── Population initialization ───────────────────────────────────────

    def _init_population(self) -> None:
        """Create initial population."""
        self.population = []

        # Seed strategies first
        for seed in self.seed_strategies[: self.config.population_size]:
            self.population.append(Individual(flags=list(seed)))

        # Fill remaining with random strategies
        while len(self.population) < self.config.population_size:
            self.population.append(Individual(flags=self._random_strategy()))

    def _random_strategy(self) -> list[str]:
        """Generate random zapret2 lua-desync strategy."""
        num_calls = random.randint(self.config.strategy_min_flags, self.config.strategy_max_flags)
        calls: list[str] = []

        # First call must be a primary desync function
        calls.append(self._random_desync_call())

        # Additional calls
        for _ in range(num_calls - 1):
            if random.random() < 0.6:
                calls.append(self._random_desync_call())
            else:
                calls.append(self._random_secondary_call())

        return calls

    def _random_desync_call(self) -> str:
        """Generate a random primary desync function call (respects AI exclusions)."""
        func = random.choice(self._active_functions)
        params = self._random_params_for(func)
        if params:
            return f"{func}:{':'.join(params)}"
        return func

    def _random_secondary_call(self) -> str:
        """Generate a random secondary function call."""
        func = random.choice(SECONDARY_FUNCTIONS)
        params = self._random_params_for(func)
        if params:
            return f"{func}:{':'.join(params)}"
        return func

    def _random_params_for(self, func: str) -> list[str]:
        """Generate random parameters appropriate for a function."""
        params: list[str] = []

        if func in ("fake", "fakedsplit"):
            # fake needs blob
            blob = random.choice(DESYNC_PARAMS["blob"])
            params.append(f"blob={blob}")
            # ttl: prefer autottl (70%) — safer and auto-calibrates
            if random.random() < 0.7:
                autottl = random.choice(DESYNC_PARAMS["ip_autottl"])
                params.append(f"ip_autottl={autottl}")
                params.append(f"ip6_autottl={autottl}")
            else:
                ttl = random.randint(3, DESYNC_PARAMS["ip_ttl"][1])  # floor at 3
                params.append(f"ip_ttl={ttl}")
                params.append(f"ip6_ttl={ttl}")
            # fooling
            if random.random() < 0.5:
                params.append("tcp_md5")
            if random.random() < 0.3:
                seq = random.choice(DESYNC_PARAMS["tcp_seq"])
                params.append(f"tcp_seq={seq}")
            # repeats
            if random.random() < 0.3:
                reps = random.randint(*DESYNC_PARAMS["repeats"])
                params.append(f"repeats={reps}")
            # tls mod
            if func == "fake" and random.random() < 0.4:
                mod = random.choice(DESYNC_PARAMS["tls_mod"])
                params.append(f"tls_mod={mod}")

        elif func in ("multisplit", "multidisorder"):
            pos = random.choice(DESYNC_PARAMS["pos"])
            params.append(f"pos={pos}")
            if random.random() < 0.3:
                seqovl = random.randint(*DESYNC_PARAMS["seqovl"])
                params.append(f"seqovl={seqovl}")
                if random.random() < 0.5:
                    pat = random.choice(DESYNC_PARAMS["seqovl_pattern"])
                    params.append(f"seqovl_pattern={pat}")

        elif func == "pktmod":
            if random.random() < 0.5:
                ttl = random.randint(1, 3)
                params.append(f"ip_ttl={ttl}")
                params.append(f"ip6_ttl={ttl}")
            if random.random() < 0.5:
                params.append("tcp_md5")
            if random.random() < 0.3:
                seq = random.choice(DESYNC_PARAMS["tcp_seq"])
                params.append(f"tcp_seq={seq}")

        elif func == "wssize":
            wsize = random.choice([1, 2, 4, 8, 16])
            scale = random.choice([0, 2, 4, 6, 8])
            params.append(f"wsize={wsize}")
            params.append(f"scale={scale}")

        elif func == "send":
            if random.random() < 0.4:
                params.append("ipfrag")

        return params

    # ─── Genetic operators ───────────────────────────────────────────────

    def _next_generation(self) -> list[Individual]:
        """Create next generation."""
        new_pop: list[Individual] = []

        # 1. Elitism
        elites = self.population[: self.config.elite_size]
        for e in elites:
            new_pop.append(Individual(flags=list(e.flags), fitness=e.fitness))

        # 2. Select parents from top 50%
        half = max(2, len(self.population) // 2)
        parents_pool = self.population[:half]

        # 3. Crossover + mutation
        while len(new_pop) < self.config.population_size:
            parent_a = random.choice(parents_pool)
            parent_b = random.choice(parents_pool)
            child_flags = self._crossover(parent_a.flags, parent_b.flags)
            child_flags = self._mutate(child_flags)
            child_flags = self._ensure_valid(child_flags)
            new_pop.append(Individual(flags=child_flags))

        return new_pop

    def _crossover(self, parent_a: list[str], parent_b: list[str]) -> list[str]:
        """Crossover: take some calls from each parent."""
        if not parent_a or not parent_b:
            return list(parent_a or parent_b)

        child: list[str] = []
        max_len = max(len(parent_a), len(parent_b))

        for i in range(max_len):
            if random.random() < 0.5:
                if i < len(parent_a):
                    child.append(parent_a[i])
            else:
                if i < len(parent_b):
                    child.append(parent_b[i])

        if not child:
            child = [random.choice(parent_a if parent_a else parent_b)]

        return child

    def _mutate(self, flags: list[str]) -> list[str]:
        """Mutate: modify params, add/remove calls."""
        if random.random() > self.config.mutation_rate:
            return flags

        flags = list(flags)
        action = random.choice(["mutate_params", "replace_call", "add_call", "remove_call"])

        if action == "mutate_params" and flags:
            # Mutate parameters of a random call
            idx = random.randint(0, len(flags) - 1)
            flags[idx] = self._mutate_call(flags[idx])

        elif action == "replace_call" and flags:
            idx = random.randint(0, len(flags) - 1)
            flags[idx] = self._random_desync_call()

        elif action == "add_call" and len(flags) < self.config.strategy_max_flags:
            if random.random() < 0.6:
                flags.append(self._random_desync_call())
            else:
                flags.append(self._random_secondary_call())

        elif action == "remove_call" and len(flags) > self.config.strategy_min_flags:
            idx = random.randint(0, len(flags) - 1)
            flags.pop(idx)

        return flags

    def _mutate_call(self, call: str) -> str:
        """Mutate parameters within a single lua-desync call."""
        parts = call.split(":")
        func = parts[0]
        params = parts[1:] if len(parts) > 1 else []

        mutation = random.choice(["change_param", "add_param", "remove_param"])

        if mutation == "change_param" and params:
            idx = random.randint(0, len(params) - 1)
            param = params[idx]
            if "=" in param:
                key = param.split("=")[0]
                if key == "ip_ttl" or key == "ip6_ttl":
                    params[idx] = f"{key}={random.randint(1, 15)}"
                elif key == "repeats":
                    params[idx] = f"{key}={random.randint(1, 11)}"
                elif key == "seqovl":
                    params[idx] = f"{key}={random.randint(1, 10)}"
                elif key == "pos":
                    params[idx] = f"pos={random.choice(DESYNC_PARAMS['pos'])}"
                elif key == "tcp_seq":
                    params[idx] = f"tcp_seq={random.choice(DESYNC_PARAMS['tcp_seq'])}"

        elif mutation == "add_param":
            if random.random() < 0.5 and "tcp_md5" not in params:
                params.append("tcp_md5")
            elif random.random() < 0.5:
                ttl = random.randint(1, 15)
                # Replace existing ttl or add new
                params = [p for p in params if not p.startswith("ip_ttl=")]
                params.append(f"ip_ttl={ttl}")

        elif mutation == "remove_param" and params:
            idx = random.randint(0, len(params) - 1)
            params.pop(idx)

        if params:
            return f"{func}:{':'.join(params)}"
        return func

    def _ensure_valid(self, flags: list[str]) -> list[str]:
        """Ensure strategy is valid."""
        if not flags:
            flags = [self._random_desync_call()]

        # Remove excluded functions from flags
        if self.excluded_functions:
            flags = [f for f in flags if f.split(":")[0] not in self.excluded_functions]

        # Must have at least one primary desync function
        has_primary = any(f.split(":")[0] in self._active_functions for f in flags)
        if not has_primary:
            flags.insert(0, self._random_desync_call())

        # Limit size
        if len(flags) > self.config.strategy_max_flags:
            flags = flags[: self.config.strategy_max_flags]
        while len(flags) < self.config.strategy_min_flags:
            flags.append(self._random_desync_call())

        return flags
