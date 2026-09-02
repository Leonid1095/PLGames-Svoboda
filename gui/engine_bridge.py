"""EngineBridge — launches and supervises the run_real.py backend.

The GUI must never desync packets itself. It spawns run_real.py as a child
(inheriting the GUI's admin token, which WinDivert requires) and reads live
state from runtime/status.json.

Stopping (the safety-critical part, see CLAUDE.md CRITICAL RULES):
  1. Ask nicely: write runtime/stop.request. The engine polls it, sets
     _running=False and exits through its normal path, so its own atexit
     _emergency_cleanup runs (winws2 killed, QUIC rule + PAC removed, hosts
     file cleaned, CRL check restored).
  2. If it does not exit within STOP_GRACE_SEC (busy in a long enumeration),
     TerminateProcess it. TerminateProcess skips atexit, so:
  3. ALWAYS run brain.net_cleanup.cleanup_network() in-process afterwards.
     It is idempotent, so running it after a clean exit costs ~1s and hurts
     nothing. fix_internet.bat stays the manual last resort (its winsock/IP
     stack reset and WinDivert service deletion are too heavy for every Stop).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from collections import deque

from PySide6.QtCore import QObject, Signal

from brain.status_writer import (
    read_status, clear_status, STATE_STOPPED,
    request_stop, clear_stop_request,
)

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
STOP_GRACE_SEC = 12      # engine loops poll every 0.5-1s; enumeration steps are longer
TERMINATE_WAIT_SEC = 5


class EngineBridge(QObject):
    log_line = Signal(str)
    stopped = Signal()       # emitted (from a worker thread) when stop_async finishes

    def __init__(self, root_dir: str, parent=None):
        super().__init__(parent)
        self.root = root_dir
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stopping = False
        self._lock = threading.Lock()
        self.log_buffer: deque[str] = deque(maxlen=500)

    # ─── lifecycle ──────────────────────────────────────────────────────
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def is_stopping(self) -> bool:
        return self._stopping

    def start(self, streamer: bool = False) -> None:
        if self.is_running() or self._stopping:
            return
        clear_status()
        clear_stop_request()   # a stale request must not kill the fresh engine
        args = [sys.executable, os.path.join(self.root, "run_real.py")]
        if streamer:
            args.append("--streamer")
        try:
            self._proc = subprocess.Popen(
                args,
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            self._emit(f"[GUI] Failed to launch engine: {exc}")
            self._proc = None
            return
        self._emit(f"[GUI] Engine started (pid={self._proc.pid})")
        self._reader = threading.Thread(target=self._pump_output, daemon=True)
        self._reader.start()

    def stop(self) -> None:
        """Synchronous stop + cleanup (used on Quit). Always leaves the net clean."""
        with self._lock:
            self._stopping = True
            try:
                self._stop_impl()
            finally:
                self._stopping = False

    def stop_async(self) -> None:
        """Non-blocking stop for the power button; emits ``stopped`` when done."""
        if self._stopping:
            return
        self._stopping = True
        threading.Thread(target=self._stop_worker, name="engine-stop", daemon=True).start()

    def _stop_worker(self) -> None:
        try:
            with self._lock:
                self._stop_impl()
        finally:
            self._stopping = False
            self.stopped.emit()

    # ─── internals ──────────────────────────────────────────────────────
    def _stop_impl(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            if request_stop():
                self._emit("[GUI] Asking engine to stop cleanly...")
                try:
                    proc.wait(timeout=STOP_GRACE_SEC)
                    self._emit("[GUI] Engine exited cleanly")
                except subprocess.TimeoutExpired:
                    self._emit("[GUI] Engine busy - terminating")
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=TERMINATE_WAIT_SEC)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        clear_stop_request()
        self._run_cleanup()
        clear_status()
        self._emit("[GUI] Engine stopped, network restored")

    def _run_cleanup(self) -> None:
        """In-process network restore (idempotent). Falls back to fix_internet.bat."""
        try:
            from brain.net_cleanup import cleanup_network
            results = cleanup_network(notify_gui=False)
            failed = [k for k, ok in results.items() if not ok]
            if failed:
                self._emit(f"[GUI] Cleanup warnings: {', '.join(failed)}")
            return
        except Exception as exc:
            self._emit(f"[GUI] In-process cleanup failed ({exc}); running fix_internet.bat")
        self._run_fix_internet_bat()

    def _run_fix_internet_bat(self) -> None:
        bat = os.path.join(self.root, "fix_internet.bat")
        if not os.path.exists(bat):
            return
        try:
            subprocess.run(
                ["cmd", "/c", bat],
                cwd=self.root,
                creationflags=_CREATE_NO_WINDOW,
                stdin=subprocess.DEVNULL,     # the script ends with `pause`
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        except Exception as exc:
            self._emit(f"[GUI] Cleanup warning: {exc}")

    def _pump_output(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for raw in proc.stdout:
                self._emit(raw.rstrip("\n"))
        except Exception:
            pass

    def _emit(self, line: str) -> None:
        self.log_buffer.append(line)
        self.log_line.emit(line)

    # ─── status passthrough ─────────────────────────────────────────────
    def status(self) -> dict:
        st = read_status()
        # If the engine process died without writing "stopped", reflect reality.
        if not self.is_running() and st.get("state") not in (None, STATE_STOPPED):
            st = {**st, "state": STATE_STOPPED}
        return st
