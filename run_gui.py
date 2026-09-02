"""PLGames Svoboda — desktop GUI entry point.

Launches the friendly shell over the run_real.py engine. Requires admin (the
engine needs it for WinDivert): on Windows we self-elevate via UAC, then spawn
run_real.py as a child that inherits the elevated token.

Usage:
    python run_gui.py            # normal launch
    python run_gui.py --minimized   # start hidden in the tray (autostart)
"""

from __future__ import annotations

import ctypes
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    """Re-run this script elevated, then exit the current (non-admin) instance."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, BASE_DIR, 1
        )
    except Exception as exc:
        print(f"Elevation failed: {exc}")
    sys.exit(0)


def main() -> None:
    if os.name == "nt" and not _is_admin():
        _relaunch_as_admin()
        return

    from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMessageBox
    from PySide6.QtCore import QSharedMemory

    app = QApplication(sys.argv)
    app.setApplicationName("PLGames Svoboda")
    app.setQuitOnLastWindowClosed(False)  # live in tray

    # Single-instance guard — two engines = WinDivert conflict (breaks internet).
    lock = QSharedMemory("PLGamesSvoboda_singleton")
    if not lock.create(1):
        QMessageBox.information(None, "PLGames Svoboda",
                                "Приложение уже запущено.")
        sys.exit(0)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.warning(None, "PLGames Svoboda",
                            "Системный трей недоступен.")

    from gui.main_window import MainWindow
    win = MainWindow(BASE_DIR)
    if "--minimized" not in sys.argv and not win.config.get("gui_start_minimized"):
        win.show()
    else:
        win.hide()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
