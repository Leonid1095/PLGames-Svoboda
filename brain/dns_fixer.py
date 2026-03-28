"""Smart DNS diagnosis and auto-fix.

Detects DNS poisoning (ISP or user's DNS redirecting blocked domains)
and fixes it by writing real IPs to Windows hosts file.

Flow:
  1. Resolve domain via system DNS (socket.gethostbyname)
  2. Resolve domain via DoH (Cloudflare/Google)
  3. If IPs differ → DNS is poisoned → write real IP to hosts file
  4. Flush DNS cache so apps pick up new resolution
  5. Clean up hosts file on exit

Safety:
  - Only writes entries between marker comments (never touches user entries)
  - Cleans up on exit via _emergency_cleanup / atexit
  - Requires admin (already required for WinDivert)
"""

from __future__ import annotations

import logging
import platform
import socket
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.dns")

_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
_MARKER_START = "# PLGames Svoboda DNS fix - START"
_MARKER_END = "# PLGames Svoboda DNS fix - END"


def detect_sni_proxy(test_domains: list[str]) -> Optional[str]:
    """Detect if blocked domains are redirected to an SNI proxy.

    If 2+ unrelated domains resolve to the same IP, that IP is an SNI proxy.
    Returns the proxy IP or None.
    """
    ips: dict[str, str] = {}
    for domain in test_domains:
        try:
            ips[domain] = socket.gethostbyname(domain)
        except Exception:
            pass

    if len(ips) < 2:
        return None

    by_ip: dict[str, list[str]] = {}
    for domain, ip in ips.items():
        by_ip.setdefault(ip, []).append(domain)

    for ip, domains in by_ip.items():
        if len(domains) >= 2:
            logger.info("SNI proxy detected: %s (handles %s)", ip, ", ".join(domains))
            return ip

    return None


def diagnose_and_fix_dns(
    hosts: list[str],
    doh_resolver,
    sni_proxy_ip: Optional[str] = None,
) -> dict[str, dict]:
    """Diagnose DNS issues for each host and fix via hosts file.

    Returns dict of {host: {status, system_ip, real_ip, fixed}}.
    """
    results = {}
    fixes: dict[str, str] = {}  # domain → real_ip (to write to hosts file)

    for host in hosts:
        entry = {"status": "unknown", "system_ip": None, "real_ip": None, "fixed": False}

        # Step 1: System DNS resolution
        try:
            sys_ip = socket.gethostbyname(host)
            entry["system_ip"] = sys_ip
        except Exception:
            entry["status"] = "dns_fail"
            results[host] = entry
            continue

        # Step 2: If system IP matches SNI proxy → DNS redirect
        if sni_proxy_ip and sys_ip == sni_proxy_ip:
            # Resolve real IP via DoH
            try:
                doh_result = doh_resolver.resolve(host, rtype="A")
                if doh_result.success and doh_result.answers:
                    real_ip = None
                    for ans in doh_result.answers:
                        if ans.get("type") == 1:  # A record
                            real_ip = ans.get("data")
                            break
                    if real_ip and real_ip != sys_ip:
                        entry["real_ip"] = real_ip
                        entry["status"] = "dns_poisoned"
                        fixes[host] = real_ip
                        logger.info("DNS fix: %s → %s (was %s via SNI proxy)",
                                    host, real_ip, sys_ip)
                    else:
                        entry["status"] = "ok"
                else:
                    entry["status"] = "doh_fail"
            except Exception as exc:
                logger.debug("DoH failed for %s: %s", host, exc)
                entry["status"] = "doh_fail"
        else:
            entry["status"] = "ok"

        results[host] = entry

    # Step 3: Write fixes to hosts file
    if fixes:
        written = write_hosts_entries(fixes)
        if written:
            flush_dns()
            for host in fixes:
                results[host]["fixed"] = True
            logger.info("Fixed DNS for %d domains via hosts file", len(fixes))

    return results


def write_hosts_entries(domain_ip_map: dict[str, str]) -> bool:
    """Write domain→IP entries to Windows hosts file between markers."""
    if platform.system() != "Windows":
        return False

    try:
        content = _HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Cannot read hosts file: %s", exc)
        return False

    # Remove old Svoboda entries
    content = _remove_marker_block(content)

    # Build new block
    lines = [_MARKER_START]
    for domain, ip in sorted(domain_ip_map.items()):
        lines.append(f"{ip}\t{domain}")
        # Also add www. variant
        if not domain.startswith("www."):
            lines.append(f"{ip}\twww.{domain}")
    lines.append(_MARKER_END)

    new_content = content.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"

    try:
        _HOSTS_PATH.write_text(new_content, encoding="utf-8")
        logger.info("Wrote %d DNS entries to hosts file", len(domain_ip_map))
        return True
    except PermissionError:
        logger.warning("No permission to write hosts file (need admin)")
        return False
    except Exception as exc:
        logger.warning("Failed to write hosts file: %s", exc)
        return False


def remove_hosts_entries() -> bool:
    """Remove all PLGames Svoboda entries from hosts file."""
    if platform.system() != "Windows":
        return False

    try:
        content = _HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False

    cleaned = _remove_marker_block(content)
    if cleaned == content:
        return True  # Nothing to remove

    try:
        _HOSTS_PATH.write_text(cleaned, encoding="utf-8")
        logger.info("Removed DNS fix entries from hosts file")
        return True
    except Exception as exc:
        logger.debug("Failed to clean hosts file: %s", exc)
        return False


def flush_dns() -> None:
    """Flush system DNS cache."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
        else:
            subprocess.run(["resolvectl", "flush-caches"],
                           capture_output=True, timeout=5)
    except Exception:
        pass


def _remove_marker_block(content: str) -> str:
    """Remove everything between START and END markers (inclusive)."""
    lines = content.split("\n")
    result = []
    inside = False
    for line in lines:
        if _MARKER_START in line:
            inside = True
            continue
        if _MARKER_END in line:
            inside = False
            continue
        if not inside:
            result.append(line)
    # Remove trailing empty lines from cleanup
    while result and result[-1].strip() == "":
        result.pop()
    return "\n".join(result) + "\n" if result else ""
