"""Windows autostart via Task Scheduler.

A plain HKCU\\Run entry launches non-elevated, but the engine needs admin for
WinDivert — so we register a scheduled task with /RL HIGHEST that starts the GUI
elevated at logon. No-op on non-Windows.
"""

from __future__ import annotations

import os
import subprocess
import sys

TASK_NAME = "PLGamesSvobodaAutostart"
_CREATE_NO_WINDOW = 0x08000000


def _launch_target(root: str) -> str:
    """Command that the task runs: pythonw run_gui.py (or the frozen exe)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pyw if os.path.exists(pyw) else sys.executable
    return f'"{exe}" "{os.path.join(root, "run_gui.py")}" --minimized'


def set_autostart(enabled: bool, root: str) -> None:
    if os.name != "nt":
        return
    if enabled:
        subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", TASK_NAME,
             "/SC", "ONLOGON", "/RL", "HIGHEST",
             "/TR", _launch_target(root)],
            check=True, creationflags=_CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            # Called synchronously from the Qt UI thread: a wedged Task
            # Scheduler service must not freeze the window forever.
            timeout=30,
        )
    else:
        subprocess.run(
            ["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
            creationflags=_CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30,
        )
