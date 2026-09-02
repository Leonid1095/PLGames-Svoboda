"""Status writer — engine <-> GUI IPC via an atomically-written JSON file.

run_real.py calls write_status() at lifecycle points; the GUI (run_gui.py)
polls read_status() to render live state without parsing svoboda.log.

Design constraints:
- Dependency-free (stdlib only) so the engine never gains a GUI dependency.
- Best-effort: every call is wrapped — a status-write failure must NEVER
  propagate into the safety-critical engine (zapret start/stop) path.
- Atomic write (tmp + os.replace) so the GUI never reads a half-written file.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

# Single source of truth for the path, shared by engine and GUI. Anchored to the
# project root (this file lives in brain/), NOT cwd — so it resolves the same
# whether launched from the GUI, run.bat, or an elevated child process.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DIR = os.path.join(_ROOT, "runtime")
STATUS_PATH = os.path.join(_DIR, "status.json")
# GUI -> engine: "please exit cleanly". The engine polls this file and runs
# its normal shutdown (atexit cleanup) instead of being TerminateProcess'd.
STOP_REQUEST_PATH = os.path.join(_DIR, "stop.request")

# Lifecycle states the GUI knows how to render.
STATE_STOPPED = "stopped"
STATE_STARTING = "starting"
STATE_SEARCHING = "searching"   # GA / enumerator hunting for a strategy
STATE_ACTIVE = "active"         # bypass running with a working strategy
STATE_ERROR = "error"


def read_status() -> dict:
    """Return the current status dict, or {} on any error (missing/corrupt)."""
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def write_status(**fields: Any) -> None:
    """Merge ``fields`` into the status file and stamp ``ts``. Never raises.

    Merge semantics let callers update one aspect (e.g. just the strategy)
    without clobbering site counts written elsewhere.
    """
    try:
        os.makedirs(_DIR, exist_ok=True)
        data = read_status()
        data.update(fields)
        data["ts"] = time.time()
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, STATUS_PATH)
    except Exception:
        pass


def clear_status() -> None:
    """Remove the status file (engine exit). Never raises."""
    try:
        os.remove(STATUS_PATH)
    except Exception:
        pass


# ─── stop request (GUI -> engine) ────────────────────────────────────────────

def request_stop() -> bool:
    """Ask a running engine to shut down gracefully. Never raises."""
    try:
        os.makedirs(_DIR, exist_ok=True)
        with open(STOP_REQUEST_PATH, "w", encoding="utf-8") as fh:
            fh.write(str(time.time()))
        return True
    except Exception:
        return False


def stop_requested() -> bool:
    """True if a stop request file exists (engine side, polled)."""
    try:
        return os.path.exists(STOP_REQUEST_PATH)
    except Exception:
        return False


def clear_stop_request() -> None:
    """Remove a stale/consumed stop request. Never raises."""
    try:
        os.remove(STOP_REQUEST_PATH)
    except Exception:
        pass
