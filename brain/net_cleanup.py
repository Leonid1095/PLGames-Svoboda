"""Single implementation of the "restore the network" steps.

Used by:
  - run_real.py  _emergency_cleanup()  (atexit + console handler)
  - gui/engine_bridge.py Stop button   (TerminateProcess skips the engine's atexit)
  - run_byedpi.py / tray quit paths

Everything here is idempotent, best-effort and never raises: a cleanup step
failing must not prevent the remaining steps from running.

Deliberately NOT done here (unlike fix_internet.bat): winsock reset, IP stack
reset, WinDivert service deletion. Those are last-resort manual actions —
running them on every GUI Stop can break other software (VPN clients, tools
that also use WinDivert) and require a reboot to settle.
"""

from __future__ import annotations

import logging
import platform
import subprocess

logger = logging.getLogger("svoboda.cleanup")

QUIC_RULE_NAME = "Svoboda Block QUIC"
_KILL_WINDOWS = ("winws2.exe", "gost.exe", "ciadpi.exe")
_KILL_POSIX = ("nfqws2", "ciadpi")
_REG_INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_CREATE_NO_WINDOW = 0x08000000


def _is_local_proxy(server: str) -> bool:
    """True if every entry in a WinINet ProxyServer string points at this machine.

    Accepts both plain "127.0.0.1:1080" and the per-scheme
    "http=127.0.0.1:1080;https=127.0.0.1:1080" form.
    """
    entries = [e.strip() for e in str(server).replace(",", ";").split(";") if e.strip()]
    if not entries:
        return False
    for entry in entries:
        hostport = entry.split("=", 1)[1] if "=" in entry else entry
        host = hostport.rsplit(":", 1)[0].strip().strip("[]").lower()
        if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            return False
    return True


def _run(cmd: list[str], timeout: int = 5) -> bool:
    try:
        kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": timeout}
        if platform.system() == "Windows":
            kw["creationflags"] = _CREATE_NO_WINDOW
        subprocess.run(cmd, **kw)
        return True
    except Exception as exc:
        logger.debug("cleanup cmd failed %s: %s", cmd[:3], exc)
        return False


def remove_quic_block() -> bool:
    if platform.system() != "Windows":
        return True
    return _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={QUIC_RULE_NAME}"])


def restore_certificate_revocation() -> bool:
    """Undo the CertificateRevocation=0 the engine sets for blocked CRL servers."""
    if platform.system() != "Windows":
        return True
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INET, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(key, "CertificateRevocation", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        return True
    except Exception as exc:
        logger.debug("CertificateRevocation restore failed: %s", exc)
        return False


def kill_engine_processes() -> list[str]:
    """Kill every desync/tunnel process we may have started. Returns names attempted."""
    names = _KILL_WINDOWS if platform.system() == "Windows" else _KILL_POSIX
    for name in names:
        if platform.system() == "Windows":
            _run(["taskkill", "/F", "/IM", name])
        else:
            _run(["pkill", "-f", name])
    return list(names)


def remove_pac_proxy() -> bool:
    """Drop OUR PAC (AutoConfigURL pointing at proxy.pac), then notify WinINet.

    Only Svoboda's own settings are touched. A PAC URL that is not ours is left
    alone, and ``ProxyEnable`` is cleared ONLY if we can see that the proxy in
    use is one of ours (a loopback address, which is what ProxyRouter/ByeDPI
    configure). Blanket-clearing it — which this used to do on every exit and
    every GUI Stop — cuts off any user whose only route out is a corporate or
    manual proxy, and they would have to reconfigure Windows by hand.
    """
    if platform.system() != "Windows":
        return True
    ok = True
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INET, 0, winreg.KEY_ALL_ACCESS)
        try:
            pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            if pac_url and "proxy.pac" in str(pac_url):
                winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
        # Manual proxy: clear only when it points at localhost (ours).
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            server = str(server or "")
        except FileNotFoundError:
            server = ""
        if not server or _is_local_proxy(server):
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        else:
            logger.info("Leaving the user's proxy %s enabled (not ours)", server)
        winreg.CloseKey(key)
    except Exception as exc:
        logger.debug("PAC removal failed: %s", exc)
        ok = False
    try:
        import ctypes
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass
    return ok


def remove_hosts_fix() -> bool:
    try:
        from brain.dns_fixer import remove_hosts_entries
        return bool(remove_hosts_entries())
    except Exception as exc:
        logger.debug("hosts cleanup failed: %s", exc)
        return False


def flush_dns() -> bool:
    if platform.system() == "Windows":
        return _run(["ipconfig", "/flushdns"])
    return True


def cleanup_network(notify_gui: bool = True) -> dict[str, bool]:
    """Run every restore step. Returns {step: ok} for logging/UI."""
    results: dict[str, bool] = {}
    results["quic_rule"] = remove_quic_block()
    results["cert_revocation"] = restore_certificate_revocation()
    kill_engine_processes()
    results["processes"] = True
    results["pac_proxy"] = remove_pac_proxy()
    results["hosts_file"] = remove_hosts_fix()
    results["dns_flush"] = flush_dns()
    if notify_gui:
        try:
            from brain.status_writer import write_status, STATE_STOPPED
            write_status(state=STATE_STOPPED, strategy="", pid=0)
        except Exception:
            pass
    logger.info("Network cleanup done: %s", results)
    return results
