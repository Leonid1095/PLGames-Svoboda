"""StrategyManager — storage, loading and export of TCP optimization strategies."""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.manager")

# ─── Valid zapret2 lua-desync functions ──────────────────────────────────────

VALID_FUNCTIONS = {
    "fake", "fakedsplit", "multisplit", "multidisorder", "syndata",
    "pktmod", "wssize", "drop", "send",
}

# ─── Migration: old --dpi-desync format → new lua-desync format ──────────────

_OLD_DESYNC_MAP = {
    "fake": "fake:blob=fake_default_tls",
    "disorder": "multidisorder",
    "disorder2": "multidisorder",
    "split": "multisplit",
    "split2": "multisplit",
    "overlap": "multisplit",
}


def _migrate_old_flag(flag: str) -> Optional[str]:
    """Convert old --dpi-desync=X format to new lua-desync format.

    Returns None if flag is invalid/unrecoverable.
    """
    # Already new format (no -- prefix)
    if not flag.startswith("--"):
        return flag

    # Parse --key=value
    if "=" not in flag:
        return None
    key, value = flag.split("=", 1)
    key = key.lstrip("-")

    if key == "dpi-desync":
        return _OLD_DESYNC_MAP.get(value, value)
    if key == "dpi-desync-ttl":
        return f"ip_ttl={value}"
    if key == "dpi-desync-fooling":
        parts = []
        if "badseq" in value:
            parts.append("tcp_seq=-10000")
        if "md5sig" in value:
            parts.append("tcp_md5")
        if "badsum" in value:
            parts.append("tcp_md5")  # closest equivalent
        return ":".join(parts) if parts else None
    if key == "dpi-desync-split-pos":
        return f"pos={value}"
    if key == "dpi-desync-repeats":
        return f"repeats={value}"

    return None


def _migrate_strategy_flags(flags: list[str]) -> list[str]:
    """Migrate a full strategy from old to new format."""
    if not flags:
        return flags

    # Check if any flag uses old format
    has_old = any(f.startswith("--") for f in flags)
    if not has_old:
        return flags

    # Group old flags into one lua-desync call
    base_func = None
    params: list[str] = []
    new_flags: list[str] = []

    for flag in flags:
        if not flag.startswith("--"):
            new_flags.append(flag)
            continue

        migrated = _migrate_old_flag(flag)
        if migrated is None:
            continue

        # Check if it's a function name or parameter
        func_name = migrated.split(":")[0]
        if func_name in VALID_FUNCTIONS or func_name in _OLD_DESYNC_MAP.values():
            if base_func:
                # Save previous function
                call = base_func + (":" + ":".join(params) if params else "")
                new_flags.append(call)
                params = []
            base_func = migrated
        else:
            params.append(migrated)

    # Flush last function
    if base_func:
        call = base_func + (":" + ":".join(params) if params else "")
        new_flags.append(call)

    return new_flags if new_flags else flags


def validate_flags(flags: list[str]) -> bool:
    """Check if flags are valid zapret2 lua-desync format."""
    if not flags:
        return False
    for flag in flags:
        if flag.startswith("--"):
            return False  # old format
        func = flag.split(":")[0]
        if func not in VALID_FUNCTIONS:
            return False
    return True

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
        """Загрузить базу стратегий с диска, мигрировать старый формат."""
        if not self.db_path.exists():
            self.strategies = []
            logger.info("No strategies DB found at %s, starting fresh", self.db_path)
            return
        try:
            raw = json.loads(self.db_path.read_text(encoding="utf-8"))
            migrated_count = 0
            valid = []
            for r in raw:
                record = StrategyRecord.from_dict(r)
                # Migrate old --dpi-desync format
                new_flags = _migrate_strategy_flags(record.flags)
                if new_flags != record.flags:
                    record.flags = new_flags
                    migrated_count += 1
                # Only keep valid strategies
                if validate_flags(record.flags):
                    valid.append(record)
            self.strategies = valid
            if migrated_count:
                logger.info("Migrated %d strategies from old format", migrated_count)
                self._save_db()
            logger.info("Loaded %d valid strategies from %s", len(self.strategies), self.db_path)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Failed to load strategies DB: %s", exc)
            self.strategies = []

    def _save_db(self) -> None:
        """Сохранить базу стратегий на диск."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [s.to_dict() for s in self.strategies]
        self.db_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
