"""StrategyManager — storage, loading and export of TCP optimization strategies."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.manager")

# ─── Lua template for strategy generation ──────────────────────────────────────

LUA_TEMPLATE = """\
-- PLGames Svoboda — auto-generated strategy
-- Generated: {timestamp}
-- Fitness: {fitness}
-- ISP Profile: {isp}

function sv_desync(conn)
    -- flags: {flags_comment}
    return {{
{flags_lua}
    }}
end
"""


class StrategyRecord:
    """Одна запись стратегии в базе."""

    def __init__(
        self,
        flags: list[str],
        fitness: float = 0.0,
        isp_profile: str = "unknown",
        strategy_id: Optional[str] = None,
        created_at: Optional[str] = None,
        wins: int = 0,
        losses: int = 0,
    ):
        self.id = strategy_id or str(uuid.uuid4())
        self.flags = list(flags)
        self.fitness = fitness
        self.isp_profile = isp_profile
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.wins = wins
        self.losses = losses

    def to_dict(self) -> dict:
        """Сериализация в словарь."""
        return {
            "id": self.id,
            "flags": self.flags,
            "fitness": self.fitness,
            "isp_profile": self.isp_profile,
            "created_at": self.created_at,
            "wins": self.wins,
            "losses": self.losses,
        }

    @classmethod
    def from_dict(cls, data: dict) -> StrategyRecord:
        """Десериализация из словаря."""
        return cls(
            flags=data["flags"],
            fitness=data.get("fitness", 0.0),
            isp_profile=data.get("isp_profile", "unknown"),
            strategy_id=data.get("id"),
            created_at=data.get("created_at"),
            wins=data.get("wins", 0),
            losses=data.get("losses", 0),
        )


class StrategyManager:
    """Менеджер стратегий: CRUD + экспорт в Lua + загрузка при старте."""

    def __init__(self, config: dict):
        base_dir = Path(config.get("_base_dir", "."))
        self.db_path = base_dir / config.get("strategies_db_path", "strategies_db.json")
        self.lua_path = base_dir / config.get("lua_strategy_path", "lua/svoboda_strategy.lua")
        self.strategies: list[StrategyRecord] = []
        self._load_db()

    # ─── Публичные методы ──────────────────────────────────────────────────

    def save_strategy(self, flags: list[str], fitness: float, isp: str = "unknown") -> StrategyRecord:
        """Сохранить новую стратегию в базу."""
        record = StrategyRecord(flags=flags, fitness=fitness, isp_profile=isp)
        self.strategies.append(record)
        self._save_db()
        logger.info("Saved strategy %s (fitness=%.3f, isp=%s)", record.id[:8], fitness, isp)
        return record

    def get_best_strategy(self, isp: Optional[str] = None) -> Optional[StrategyRecord]:
        """Вернуть стратегию с лучшим fitness (опционально по ISP)."""
        candidates = self.strategies
        if isp and isp != "unknown":
            isp_candidates = [s for s in candidates if s.isp_profile == isp]
            if isp_candidates:
                candidates = isp_candidates
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.fitness)

    def record_result(self, strategy_id: str, success: bool) -> None:
        """Записать результат применения стратегии (win/loss)."""
        for s in self.strategies:
            if s.id == strategy_id:
                if success:
                    s.wins += 1
                else:
                    s.losses += 1
                self._save_db()
                return

    def load_on_startup(self, isp: Optional[str] = None) -> Optional[StrategyRecord]:
        """Применить лучшую известную стратегию при старте."""
        best = self.get_best_strategy(isp)
        if best:
            self.export_lua(best)
            logger.info("Startup: applied strategy %s (fitness=%.3f)", best.id[:8], best.fitness)
        else:
            logger.warning("Startup: no strategies in database")
        return best

    def export_lua(self, strategy: StrategyRecord) -> Path:
        """Генерировать Lua-файл из стратегии."""
        self.lua_path.parent.mkdir(parents=True, exist_ok=True)

        flags_lua_lines = []
        for flag in strategy.flags:
            flags_lua_lines.append(f'        "{flag}",')

        lua_content = LUA_TEMPLATE.format(
            timestamp=datetime.now(timezone.utc).isoformat(),
            fitness=f"{strategy.fitness:.3f}",
            isp=strategy.isp_profile,
            flags_comment=" ".join(strategy.flags),
            flags_lua="\n".join(flags_lua_lines),
        )

        self.lua_path.write_text(lua_content, encoding="utf-8")
        logger.info("Exported Lua strategy to %s", self.lua_path)
        return self.lua_path

    def get_all_strategies(self, isp: Optional[str] = None) -> list[StrategyRecord]:
        """Все стратегии, опционально фильтрованные по ISP."""
        if isp and isp != "unknown":
            return [s for s in self.strategies if s.isp_profile == isp]
        return list(self.strategies)

    def import_strategy(self, data: dict) -> StrategyRecord:
        """Импорт стратегии из внешнего источника (Telegram и т.д.)."""
        record = StrategyRecord(
            flags=data["flags"],
            fitness=data.get("fitness", 0.0),
            isp_profile=data.get("isp", "unknown"),
        )
        self.strategies.append(record)
        self._save_db()
        logger.info("Imported strategy %s (fitness=%.3f)", record.id[:8], record.fitness)
        return record

    # ─── Внутренние методы ─────────────────────────────────────────────────

    def _load_db(self) -> None:
        """Загрузить базу стратегий с диска."""
        if not self.db_path.exists():
            self.strategies = []
            logger.info("No strategies DB found at %s, starting fresh", self.db_path)
            return
        try:
            raw = json.loads(self.db_path.read_text(encoding="utf-8"))
            self.strategies = [StrategyRecord.from_dict(r) for r in raw]
            logger.info("Loaded %d strategies from %s", len(self.strategies), self.db_path)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Failed to load strategies DB: %s", exc)
            self.strategies = []

    def _save_db(self) -> None:
        """Сохранить базу стратегий на диск."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [s.to_dict() for s in self.strategies]
        self.db_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
