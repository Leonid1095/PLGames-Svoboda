"""ConnectionTester — fitness function for evaluating TCP optimization strategies.

Shadow-mode: test connections go through a separate optimizer instance
(separate WinDivert filter / network namespace) without affecting main traffic.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import random
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.tester")

# ─── Карта «хороших» комбинаций для mock-тестирования ──────────────────────────

_EFFECTIVE_COMBOS: dict[str, float] = {
    "disorder2+ttl": 0.85,
    "fake+ipfrag": 0.80,
    "multisplit+badseq": 0.75,
    "overlap+badsum": 0.70,
    "disorder2+split-pos": 0.90,
    "fake+ttl+split-pos": 0.95,
    "disorder2+ttl+badseq": 0.92,
}


def _mock_fitness(flags: list[str]) -> float:
    """Имитация фитнес-функции на основе известных эффективных комбинаций.

    Capped at 0.95 to prevent early exit in GA, ensuring full evolution
    runs for better data collection.
    """
    score = 0.1
    flag_str = " ".join(flags)

    if "disorder2" in flag_str and "ttl" in flag_str and "badseq" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["disorder2+ttl+badseq"])
    if "fake" in flag_str and "ttl" in flag_str and "split-pos" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+ttl+split-pos"])
    if "disorder2" in flag_str and "split-pos" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["disorder2+split-pos"])
    if "disorder2" in flag_str and "ttl" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["disorder2+ttl"])
    if "fake" in flag_str and "ipfrag" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["fake+ipfrag"])
    if "multisplit" in flag_str and "badseq" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["multisplit+badseq"])
    if "overlap" in flag_str and "badsum" in flag_str:
        score = max(score, _EFFECTIVE_COMBOS["overlap+badsum"])

    if "ttl" in flag_str:
        score += 0.05
    if "split-pos" in flag_str:
        score += 0.03

    # Wider noise + cap at 0.95 so GA runs full generations
    noise = random.uniform(-0.10, 0.08)
    return round(max(0.0, min(0.95, score + noise)), 3)


# ─── Lua-шаблон для тестовой стратегии ─────────────────────────────────────────

_TEST_LUA_TEMPLATE = """\
-- PLGames Svoboda — test strategy (temporary)
function sv_desync(conn)
    return {{
{flags_lua}
    }}
end
"""

# Successful HTTP codes (site responded, including 403 = server reachable)
_SUCCESS_CODES = {200, 301, 302, 303, 307, 308, 403}


class ConnectionTester:
    """Connection quality tester for optimization strategies."""

    def __init__(self, config: dict, mock: bool = True):
        self.config = config
        self.mock = mock
        self.hosts: list[str] = config.get("test_hosts", ["youtube.com", "discord.com", "x.com"])
        self.trials: int = config.get("test_trials", 3)
        self.timeout: int = config.get("test_timeout", 5)
        self._base_dir = Path(config.get("_base_dir", "."))
        self._is_windows = platform.system() == "Windows"
        self._zapret_bin = self._resolve_zapret_binary()
        self._shadow_process: Optional[subprocess.Popen] = None

    def test_strategy(self, flags: list[str]) -> float:
        """Оценить стратегию. Возвращает fitness 0.0-1.0."""
        if self.mock:
            return self._test_mock(flags)
        return self._test_real(flags)

    def test_strategy_async(self, flags: list[str]) -> float:
        """Async-обёртка для test_strategy."""
        return asyncio.get_event_loop().run_in_executor(None, self.test_strategy, flags)

    # ─── Mock ──────────────────────────────────────────────────────────────

    def _test_mock(self, flags: list[str]) -> float:
        """Mock-тестирование без реальных соединений."""
        fitness = _mock_fitness(flags)
        logger.debug("Mock test: flags=%s fitness=%.3f", " ".join(flags), fitness)
        return fitness

    # ─── Real testing ──────────────────────────────────────────────────────

    def _test_real(self, flags: list[str]) -> float:
        """Реальное тестирование через shadow-режим zapret2 + curl."""
        if not self._zapret_bin:
            logger.error("zapret2 binary not found, falling back to mock")
            return self._test_mock(flags)

        # 1. Записать временный lua-файл
        tmp_lua = self._write_test_lua(flags)

        try:
            # 2. Запустить shadow-экземпляр zapret2
            self._start_shadow_zapret(tmp_lua, flags)

            # 3. Подождать пока zapret2 поднимется
            time.sleep(2)

            # 4. Тестировать каждый хост
            total_tests = len(self.hosts) * self.trials
            successful = 0

            for host in self.hosts:
                for trial in range(self.trials):
                    if self._curl_test(host):
                        successful += 1

            fitness = successful / total_tests if total_tests > 0 else 0.0

        except Exception as exc:
            logger.error("Test failed: %s", exc)
            fitness = 0.0

        finally:
            # 5. Остановить shadow zapret2
            self._stop_shadow_zapret()
            # Удалить временный lua
            try:
                tmp_lua.unlink()
            except OSError:
                pass

        logger.info(
            "Real test: flags=%s fitness=%.3f (%d/%d)",
            " ".join(flags), fitness, successful, total_tests,
        )
        return round(fitness, 3)

    # ─── Shadow zapret2 management ─────────────────────────────────────────

    def _start_shadow_zapret(self, lua_path: Path, flags: list[str]) -> None:
        """Запустить отдельный экземпляр zapret2 для тестирования."""
        self._stop_shadow_zapret()

        cmd = [str(self._zapret_bin)]

        if self._is_windows:
            # Windows: winws2 с WinDivert
            # Используем отдельный filter для shadow-режима (порт 44344)
            cmd.extend([
                "--wf-tcp=443",
                "--wf-udp=443",
                "--lua-desync=" + str(lua_path),
            ])
            # Добавляем флаги стратегии напрямую
            cmd.extend(flags)
        else:
            # Linux: nfqws2 с netfilter queue
            # Shadow-режим: используем отдельную nfqueue (номер 200)
            cmd.extend([
                "--qnum=200",
                "--lua-desync=" + str(lua_path),
            ])
            cmd.extend(flags)

            # Настроить iptables для shadow queue
            self._setup_linux_shadow_nfqueue()

        logger.debug("Starting shadow zapret2: %s", " ".join(cmd))

        try:
            self._shadow_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
        except FileNotFoundError:
            logger.error("zapret2 binary not found at %s", self._zapret_bin)
            self._shadow_process = None
        except OSError as exc:
            logger.error("Failed to start shadow zapret2: %s", exc)
            self._shadow_process = None

    def _stop_shadow_zapret(self) -> None:
        """Остановить shadow-экземпляр zapret2."""
        if self._shadow_process is None:
            return

        try:
            proc = self._shadow_process
            self._shadow_process = None

            # Мягкое завершение
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Принудительное завершение
                proc.kill()
                proc.wait(timeout=2)

            logger.debug("Shadow zapret2 stopped (pid=%d)", proc.pid)
        except Exception as exc:
            logger.warning("Error stopping shadow zapret2: %s", exc)

        if not self._is_windows:
            self._cleanup_linux_shadow_nfqueue()

    # ─── curl testing ──────────────────────────────────────────────────────

    def _curl_test(self, host: str) -> bool:
        """Один curl-тест к хосту. Возвращает True если успешно."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(self.timeout),
                    f"https://{host}",
                    "-o", "/dev/null" if not self._is_windows else "NUL",
                    "-w", "%{http_code}",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 3,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    code = int(result.stdout.strip())
                    success = code in _SUCCESS_CODES
                    logger.debug("curl %s: HTTP %d (%s)", host, code, "OK" if success else "FAIL")
                    return success
                except ValueError:
                    pass

        except subprocess.TimeoutExpired:
            logger.debug("curl %s: timeout", host)
        except FileNotFoundError:
            logger.error("curl not found in PATH")
        except Exception as exc:
            logger.debug("curl %s: error %s", host, exc)

        return False

    # ─── Linux shadow nfqueue ──────────────────────────────────────────────

    def _setup_linux_shadow_nfqueue(self) -> None:
        """Настроить отдельную nfqueue для shadow-тестирования."""
        try:
            # Добавляем правила iptables для shadow queue 200
            # Маркируем тестовый трафик через cgroup или mark
            subprocess.run(
                ["iptables", "-t", "mangle", "-A", "OUTPUT",
                 "-p", "tcp", "--dport", "443",
                 "-m", "mark", "--mark", "0x100",
                 "-j", "NFQUEUE", "--queue-num", "200"],
                capture_output=True, timeout=5,
            )
            logger.debug("Shadow nfqueue rules applied")
        except Exception as exc:
            logger.warning("Failed to setup shadow nfqueue: %s", exc)

    def _cleanup_linux_shadow_nfqueue(self) -> None:
        """Удалить правила shadow nfqueue."""
        try:
            subprocess.run(
                ["iptables", "-t", "mangle", "-D", "OUTPUT",
                 "-p", "tcp", "--dport", "443",
                 "-m", "mark", "--mark", "0x100",
                 "-j", "NFQUEUE", "--queue-num", "200"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    # ─── Helpers ───────────────────────────────────────────────────────────

    def _write_test_lua(self, flags: list[str]) -> Path:
        """Записать временный Lua-файл со стратегией."""
        flags_lua = "\n".join(f'        "{f}",' for f in flags)
        content = _TEST_LUA_TEMPLATE.format(flags_lua=flags_lua)

        tmp_dir = self._base_dir / "lua"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = tmp_dir / f"_test_{id(flags):x}.lua"
        tmp_file.write_text(content, encoding="utf-8")
        return tmp_file

    def _resolve_zapret_binary(self) -> Optional[Path]:
        """Найти бинарник zapret2."""
        if self._is_windows:
            name = self.config.get("zapret_binary_windows", "winws2.exe")
        else:
            name = self.config.get("zapret_binary_linux", "nfqws2")

        # Проверяем в PATH
        found = shutil.which(name)
        if found:
            return Path(found)

        # Проверяем рядом с проектом
        local = self._base_dir / name
        if local.exists():
            return local

        # Проверяем стандартные пути
        standard_paths = [
            Path("/usr/local/bin") / name,
            Path("/usr/bin") / name,
            self._base_dir / "bin" / name,
        ]
        for p in standard_paths:
            if p.exists():
                return p

        logger.warning("zapret2 binary '%s' not found", name)
        return None
