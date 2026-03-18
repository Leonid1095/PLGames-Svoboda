"""PLGames Svoboda — ByeDPI SOCKS Proxy Mode (no admin rights).

Runs ByeDPI as a local SOCKS5 proxy for DPI bypass.
No WinDivert driver needed, no administrator privileges.
User must configure browser to use SOCKS5 proxy.

Usage:
    python run_byedpi.py
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("svoboda.byedpi_mode")


def main():
    base_dir = Path(__file__).parent

    # Load config
    config_path = base_dir / "config.json"
    config = {}
    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))

    # Detect language
    import locale
    lang = "ru" if locale.getdefaultlocale()[0] and "ru" in locale.getdefaultlocale()[0] else "en"

    from brain.byedpi import ByeDPIFallback

    bdpi = ByeDPIFallback(config, base_dir=str(base_dir))

    if lang == "ru":
        print()
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║   PLGames Svoboda — Режим SOCKS прокси          ║")
        print("  ║   Без прав администратора                       ║")
        print("  ╚══════════════════════════════════════════════════╝")
    else:
        print()
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║   PLGames Svoboda — SOCKS Proxy Mode            ║")
        print("  ║   No administrator rights needed                ║")
        print("  ╚══════════════════════════════════════════════════╝")

    # Find or download ByeDPI
    print()
    if not bdpi.find_binary():
        if lang == "ru":
            print("  Скачивание ByeDPI...")
        else:
            print("  Downloading ByeDPI...")

        if not bdpi.download_binary():
            if lang == "ru":
                print("  [ERROR] Не удалось скачать ByeDPI")
                print("  Скачайте вручную: https://github.com/hufrea/byedpi/releases")
            else:
                print("  [ERROR] Failed to download ByeDPI")
                print("  Download manually: https://github.com/hufrea/byedpi/releases")
            input()
            return

    print(f"  [OK] ByeDPI: {bdpi._binary}")

    # Detect block type (simple check)
    block_type = "sni_filtering"  # Most common in Russia

    # Try presets
    if lang == "ru":
        print(f"\n  Поиск рабочей стратегии для обхода DPI...")
    else:
        print(f"\n  Finding working bypass strategy...")

    working_preset = bdpi.try_presets(block_type=block_type, test_host="youtube.com")

    if not working_preset:
        # Try default
        working_preset = bdpi.try_presets(block_type="default", test_host="youtube.com")

    if not working_preset:
        if lang == "ru":
            print("  [!] Ни одна стратегия не сработала через SOCKS")
            print("  Попробуйте запустить от администратора (режим WinDivert)")
        else:
            print("  [!] No strategy worked through SOCKS proxy")
            print("  Try running as administrator (WinDivert mode)")
        input()
        return

    # Success
    print(f"  [OK] {working_preset}")
    print(bdpi.get_browser_instructions(lang))

    # Create PAC file
    bdpi.configure_system_proxy()

    if lang == "ru":
        print("  === SOCKS ПРОКСИ АКТИВЕН ===")
        print(f"  Адрес: {bdpi.proxy_url}")
        print(f"  Стратегия: {working_preset}")
        print()
        print("  Настройте браузер и пользуйтесь!")
        print("  Ctrl+C для остановки")
    else:
        print("  === SOCKS PROXY ACTIVE ===")
        print(f"  Address: {bdpi.proxy_url}")
        print(f"  Strategy: {working_preset}")
        print()
        print("  Configure your browser and enjoy!")
        print("  Ctrl+C to stop")

    # Keep running
    try:
        while True:
            if not bdpi.is_running():
                logger.warning("ByeDPI process died, restarting...")
                bdpi.start(block_type=block_type)
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n  Stopping...")
    finally:
        bdpi.stop()


if __name__ == "__main__":
    main()
