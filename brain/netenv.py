"""Network environment hygiene for direct-path measurements.

Svoboda measures the DIRECT path through the ISP's DPI. If the machine has
HTTP(S)_PROXY / ALL_PROXY environment variables set (VPN clients, Clash,
v2rayN, corporate setups), every ``curl`` and ``requests`` call would silently
go through that proxy instead — strategies would look "working" while the
real path is still blocked, and the ISP would be detected as the proxy's exit.

Found live on 2026-09-01: HTTPS_PROXY=http://127.0.0.1:12334 made all curl
checks tunnel via a Riga exit while the real ISP was er-telecom.

Usage:
    from brain.netenv import scrub_proxy_env, CURL_DIRECT, direct_session
    scrub_proxy_env()                       # once, at process start
    subprocess.run(["curl", *CURL_DIRECT, ...])
    direct_session().get(url)               # requests without env proxies
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from typing import Optional

logger = logging.getLogger("svoboda.netenv")

# Extra curl flags that force a direct connection regardless of env / .curlrc
CURL_DIRECT: tuple[str, ...] = ("--noproxy", "*")

_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
)

_scrubbed: dict[str, str] = {}


def detect_proxy_env() -> dict[str, str]:
    """Return proxy-related environment variables currently set (masked-free)."""
    return {k: v for k, v in os.environ.items() if k in _PROXY_VARS and v}


def scrub_proxy_env() -> dict[str, str]:
    """Remove proxy env vars from this process so children (curl, winws2,
    python-requests) connect directly. Returns what was removed.

    Idempotent. Logs once when something was actually removed.
    """
    removed: dict[str, str] = {}
    for var in _PROXY_VARS:
        val = os.environ.pop(var, None)
        if val:
            removed[var] = val
    if removed:
        _scrubbed.update(removed)
        logger.warning(
            "Ignoring proxy environment for direct-path measurements: %s",
            ", ".join(sorted(removed)),
        )
    return removed


def scrubbed_proxy_env() -> dict[str, str]:
    """Proxy vars removed earlier in this process (for diagnostics/UI)."""
    return dict(_scrubbed)


def direct_session():
    """A ``requests.Session`` that ignores environment proxies and .netrc.

    Imported lazily so this module stays importable without requests.
    """
    import requests  # noqa: WPS433 (lazy import by design)

    s = requests.Session()
    s.trust_env = False
    return s


# ─── TCP timestamps (needed by tcp_ts fooling) ──────────────────────────────

_tcp_ts_cache: Optional[bool] = None
_tcp_ts_checked = False


def tcp_timestamps_enabled() -> Optional[bool]:
    """Whether the TCP Timestamp option is on (Windows "Internet" TCP template).

    Windows 11 ships with timestamps DISABLED, which turns every ``tcp_ts=``
    fooling (Flowseal ``--dpi-desync-fooling=ts``, 17 of 22 profiles in 1.10.2)
    into a no-op: zapret2 "only functions if the Timestamp option is already
    present". Returns None when unknown (non-Windows / PowerShell unavailable).
    Cached for the process lifetime.
    """
    global _tcp_ts_cache, _tcp_ts_checked
    if _tcp_ts_checked:
        return _tcp_ts_cache
    _tcp_ts_checked = True
    if platform.system() != "Windows":
        return None
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-NetTCPSetting -SettingName Internet).Timestamps"],
            capture_output=True, text=True, timeout=20, creationflags=0x08000000,
        )
        out = (r.stdout or "").strip().lower()
        if out.startswith("enabled"):
            _tcp_ts_cache = True
        elif out.startswith("disabled"):
            _tcp_ts_cache = False
            logger.info("TCP timestamps disabled on this host - tcp_ts fooling strategies will be skipped")
    except Exception as exc:
        logger.debug("TCP timestamps probe failed: %s", exc)
    return _tcp_ts_cache
