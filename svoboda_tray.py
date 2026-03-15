"""
PLGames Svoboda — System Tray Application

Runs DPI bypass engine in background with system tray icon.
Shows status, notifications, and tier/donate info.
"""

from __future__ import annotations

import io
import logging
import platform
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Only runs on Windows (tray icon)
if platform.system() != "Windows":
    print("Tray mode is Windows-only. Use run_real.py directly on Linux.")
    sys.exit(1)

import pystray
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

logger = logging.getLogger("svoboda.tray")

# ─── State ────────────────────────────────────────────────────────────────────

class AppState:
    """Shared state between tray and engine."""
    def __init__(self):
        self.status: str = "Starting..."
        self.active: bool = False
        self.fitness: float = 0.0
        self.strategy: str = ""
        self.sites_ok: int = 0
        self.sites_total: int = 0
        self.tier: str = "FREE"
        self.donate_url: str = ""
        self.last_check: str = ""
        self.engine_thread: Optional[threading.Thread] = None
        self.should_stop: bool = False
        self.hostlist_count: int = 0

state = AppState()

# ─── Notifications ────────────────────────────────────────────────────────────

def _notify(title: str, message: str, duration: str = "short"):
    """Send Windows toast notification."""
    try:
        from winotify import Notification, audio
        toast = Notification(
            app_id="PLGames Svoboda",
            title=title,
            msg=message,
            duration=duration,
        )
        toast.set_audio(audio.Default, loop=False)
        toast.show()
    except Exception as exc:
        logger.debug("Notification failed: %s", exc)


# ─── Tray Icon ────────────────────────────────────────────────────────────────

def _create_icon_image(color: str = "green") -> Image.Image:
    """Create simple colored circle icon."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    colors = {
        "green": (76, 175, 80),      # active, working
        "yellow": (255, 193, 7),     # evolving / partial
        "red": (244, 67, 54),        # blocked / error
        "gray": (158, 158, 158),     # stopped
    }
    rgb = colors.get(color, colors["gray"])

    # Circle
    draw.ellipse([4, 4, size - 4, size - 4], fill=rgb)
    # "S" letter
    try:
        font = ImageFont.truetype("arial.ttf", 32)
    except Exception:
        font = ImageFont.load_default()
    draw.text((size // 2, size // 2), "S", fill="white", anchor="mm", font=font)

    return img


def _build_menu() -> pystray.Menu:
    """Build tray context menu."""
    return pystray.Menu(
        pystray.MenuItem(
            lambda _: f"Status: {state.status}",
            None, enabled=False,
        ),
        pystray.MenuItem(
            lambda _: f"Sites: {state.sites_ok}/{state.sites_total}" if state.sites_total > 0 else "Sites: checking...",
            None, enabled=False,
        ),
        pystray.MenuItem(
            lambda _: f"Fitness: {state.fitness:.2f}" if state.fitness > 0 else "Fitness: ---",
            None, enabled=False,
        ),
        pystray.MenuItem(
            lambda _: f"Last check: {state.last_check}" if state.last_check else "Last check: ---",
            None, enabled=False,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            lambda _: f"Tier: {state.tier}",
            None, enabled=False,
        ),
        pystray.MenuItem(
            "Support Project (Donate)",
            lambda icon, item: _open_donate(),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Show Log",
            lambda icon, item: _open_log(),
        ),
        pystray.MenuItem(
            "Restart Engine",
            lambda icon, item: _restart_engine(),
        ),
        pystray.MenuItem(
            "Exit",
            lambda icon, item: _quit(icon),
        ),
    )


def _open_donate():
    """Open donate page in browser."""
    import webbrowser
    url = state.donate_url or "https://new.donatepay.ru/@lenya"
    webbrowser.open(url)


def _open_log():
    """Open log file."""
    log_path = BASE_DIR / "svoboda.log"
    if log_path.exists():
        import os
        os.startfile(str(log_path))


def _restart_engine():
    """Restart the bypass engine."""
    state.should_stop = True
    time.sleep(2)
    state.should_stop = False
    _start_engine_thread()


def _quit(icon: pystray.Icon):
    """Quit application."""
    state.should_stop = True
    # Kill winws2
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "winws2.exe"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        pass
    icon.stop()


def _update_icon(icon: pystray.Icon, color: str):
    """Update tray icon color."""
    try:
        icon.icon = _create_icon_image(color)
    except Exception:
        pass


# ─── Engine Bridge ────────────────────────────────────────────────────────────

def _engine_worker(icon: pystray.Icon):
    """Run the DPI bypass engine in a thread, updating tray state."""
    import json
    from brain.analytics import Analytics
    from brain.ai_advisor import AIAdvisor
    from brain.donate import DonateManager
    from brain.genetic import GAConfig
    from brain.manager import StrategyManager
    from brain.profiler import ISPProfiler, ISP_SEED_STRATEGIES
    from brain.sync import ServerSync
    from brain.tester import ConnectionTester
    from brain.tier import TierManager
    from run_real import (
        _find_zapret_binary, _find_lua_dir, _download_hostlist,
        _start_permanent_zapret, _stop_permanent_zapret,
        _quick_connectivity_check, _curl_check_one,
        _get_seeds, _run_evolution, _emergency_cleanup,
    )

    active_process = None

    try:
        # Load config
        config = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
        config["_base_dir"] = str(BASE_DIR)

        # Setup logging
        log = logging.getLogger("svoboda")
        log.setLevel(logging.DEBUG)
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(
            BASE_DIR / config.get("log_file", "svoboda.log"),
            maxBytes=10 * 1024 * 1024, backupCount=7, encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"))
        log.addHandler(fh)

        # Find zapret2
        zapret_bin = _find_zapret_binary(BASE_DIR)
        lua_dir = _find_lua_dir(BASE_DIR)
        if not zapret_bin:
            state.status = "ERROR: winws2 not found"
            _update_icon(icon, "red")
            _notify("Svoboda Error", "winws2.exe not found. Download zapret2.")
            return

        # Init modules
        analytics = Analytics(config)
        manager = StrategyManager(config)
        tier = TierManager(config)
        donate = DonateManager(config)
        sync = ServerSync(config, analytics)
        sync.set_tier_manager(tier)
        ai = AIAdvisor(config, analytics, tier_manager=tier)
        ai.set_install_id(sync.install_id)
        sync.register_dependent(ai)
        sync.register_dependent(donate)

        state.tier = tier.current_tier_name if hasattr(tier, 'current_tier_name') else "FREE"
        state.donate_url = config.get("donatepay_page_url", "")

        # Register with server
        if sync.is_configured:
            sync.register_if_needed()
            if sync.api_key:
                ai.set_server_key(sync.api_key)

        # ISP detection
        state.status = "Detecting ISP..."
        profiler = ISPProfiler(config)
        isp_name = "unknown"
        try:
            profile = profiler.detect()
            if profile:
                isp_name = profile.isp_name or "unknown"
        except Exception:
            pass

        # Download hostlist
        state.status = "Downloading blocklist..."
        hostlist = _download_hostlist(BASE_DIR)

        # Baseline check
        hosts = config.get("test_hosts", ["youtube.com", "discord.com", "cdn.discordapp.com"])
        state.sites_total = len(hosts)
        state.status = "Checking connectivity..."
        baseline = _quick_connectivity_check(hosts)
        blocked = [h for h, ok in baseline.items() if not ok]
        accessible = [h for h, ok in baseline.items() if ok]
        state.sites_ok = len(accessible)

        if not blocked:
            state.status = "All sites accessible - monitoring"
            state.active = True
            _update_icon(icon, "green")
            _notify("Svoboda", "All sites accessible. Monitoring for blocks...")
        else:
            state.status = f"{len(blocked)} site(s) blocked - evolving..."
            _update_icon(icon, "yellow")
            _notify("Svoboda", f"Blocked: {', '.join(blocked)}. Finding bypass...")

            # Evolution
            tester = ConnectionTester(config, mock=False)
            ga_config = GAConfig.from_config(config)
            ga_config.generations = min(ga_config.generations, 15)
            ga_config.population_size = min(ga_config.population_size, 10)

            seeds = _get_seeds(isp_name, ai)
            best = _run_evolution(tester, ga_config, seeds, analytics, isp_name)

            if best and best.fitness > 0.1:
                # Verify
                verified = tester.test_strategy_thorough(best.flags)
                if verified > 0.1:
                    best.fitness = verified
                    state.fitness = verified
                    state.strategy = " | ".join(best.flags)

                    # Save
                    record = manager.save_strategy(best.flags, best.fitness, isp_name)
                    analytics.log_strategy(
                        strategy_id=record.id, flags=best.flags, fitness=best.fitness,
                        isp=isp_name, source="local",
                    )

                    # Apply
                    active_process = _start_permanent_zapret(zapret_bin, lua_dir, best.flags, hostlist)
                    if active_process:
                        state.status = "DPI bypass ACTIVE"
                        state.active = True
                        _update_icon(icon, "green")
                        _notify(
                            "Svoboda - Bypass Active!",
                            f"Strategy applied (fitness={best.fitness:.2f}). Sites should be accessible now.",
                        )
                    else:
                        state.status = "Failed to start winws2"
                        _update_icon(icon, "red")
            else:
                state.status = "No working strategy found"
                _update_icon(icon, "red")
                _notify("Svoboda", "Could not find working bypass strategy. Will retry.")

        # ─── Watchdog loop ─────────────────────────────────────────────
        watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
        tester = ConnectionTester(config, mock=False)
        ga_config = GAConfig.from_config(config)
        ga_config.generations = min(ga_config.generations, 15)
        ga_config.population_size = min(ga_config.population_size, 10)

        while not state.should_stop:
            for _ in range(watchdog_interval):
                if state.should_stop:
                    break
                time.sleep(1)

            if state.should_stop:
                break

            # Check connectivity
            now = datetime.now().strftime("%H:%M")
            state.last_check = now
            ok_count = 0

            for host in hosts:
                r = _curl_check_one(host, timeout=5)
                if r["success"]:
                    ok_count += 1

            state.sites_ok = ok_count

            if ok_count == len(hosts):
                state.status = "DPI bypass ACTIVE"
                _update_icon(icon, "green")
            elif ok_count > 0:
                state.status = f"Partial: {ok_count}/{len(hosts)} sites"
                _update_icon(icon, "yellow")
            else:
                state.status = "All blocked - re-evolving..."
                _update_icon(icon, "red")
                _notify("Svoboda", "Connection degraded. Re-evolving strategy...")

                _stop_permanent_zapret(active_process)
                active_process = None

                seeds = _get_seeds(isp_name, ai)
                best = _run_evolution(tester, ga_config, seeds, analytics, isp_name)
                if best and best.fitness > 0.1:
                    active_process = _start_permanent_zapret(zapret_bin, lua_dir, best.flags, hostlist)
                    if active_process:
                        state.fitness = best.fitness
                        state.status = "DPI bypass ACTIVE (re-evolved)"
                        _update_icon(icon, "green")
                        _notify("Svoboda", f"New strategy applied (fitness={best.fitness:.2f})")

    except Exception as exc:
        state.status = f"Error: {exc}"
        _update_icon(icon, "red")
        logger.error("Engine error: %s", exc, exc_info=True)
    finally:
        _stop_permanent_zapret(active_process)
        _emergency_cleanup()


def _start_engine_thread(icon: Optional[pystray.Icon] = None):
    """Start engine in background thread."""
    if state.engine_thread and state.engine_thread.is_alive():
        return

    def worker():
        _engine_worker(_tray_icon)

    state.engine_thread = threading.Thread(target=worker, daemon=True, name="svoboda-engine")
    state.engine_thread.start()


# ─── Main ─────────────────────────────────────────────────────────────────────

_tray_icon: Optional[pystray.Icon] = None


def main():
    global _tray_icon

    _tray_icon = pystray.Icon(
        "svoboda",
        _create_icon_image("gray"),
        "PLGames Svoboda",
        menu=_build_menu(),
    )

    # Start engine when icon is ready
    def on_setup(icon):
        icon.visible = True
        _start_engine_thread(icon)

    _tray_icon.run(setup=on_setup)


if __name__ == "__main__":
    main()
