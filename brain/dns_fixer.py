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


def _test_tls_through_proxy(host: str, timeout: float = 5.0) -> bool:
    """Test if a domain is accessible via its current DNS (SNI proxy or direct).

    Returns True if TLS handshake succeeds — meaning the SNI proxy works for this domain.
    """
    import ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                logger.debug("TLS OK for %s via current DNS (%s)", host, ssock.version())
                return True
    except Exception as exc:
        logger.debug("TLS failed for %s: %s", host, exc)
        return False


def diagnose_and_fix_dns(
    hosts: list[str],
    doh_resolver,
    sni_proxy_ip: Optional[str] = None,
) -> dict[str, dict]:
    """Diagnose DNS issues for each host and fix via hosts file.

    Smart logic: if a domain works through SNI proxy, DON'T override it.
    Only write real IPs for domains that are broken through the proxy.

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

        # Step 2: If system IP matches SNI proxy → check if it actually works
        if sni_proxy_ip and sys_ip == sni_proxy_ip:
            # First: test if domain works through SNI proxy as-is
            if _test_tls_through_proxy(host, timeout=5.0):
                entry["status"] = "ok_via_proxy"
                logger.info("DNS: %s works via SNI proxy %s — keeping as-is", host, sni_proxy_ip)
                results[host] = entry
                continue

            # SNI proxy doesn't work for this domain → resolve real IP via DoH
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
                        entry["status"] = "proxy_broken"
                        fixes[host] = real_ip
                        logger.info("DNS fix: %s → %s (SNI proxy broken, using real IP)",
                                    host, real_ip, )
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

    # Step 3: Write fixes to hosts file (only for domains where proxy is broken)
    if fixes:
        written = write_hosts_entries(fixes)
        if written:
            flush_dns()
            for host in fixes:
                results[host]["fixed"] = True
            logger.info("Fixed DNS for %d domains via hosts file", len(fixes))

    return results


def write_hosts_entries(domain_ip_map: dict[str, str]) -> bool:
    """Write domain→IP entries to Windows hosts file between markers.

    For wildcard-sensitive domains (like *.googlevideo.com), also writes
    common CDN subdomains so video streaming works.
    """
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


# ─── System DNS override ─────────────────────────────────────────────

_original_dns: Optional[dict] = None  # {interface: [dns_servers]}


def override_system_dns(dns_servers: list[str] = None) -> bool:
    """Replace system DNS with clean DoH-capable servers (e.g. 1.1.1.1).

    This is needed when user has an SNI proxy DNS (like 93.183.70.55)
    that doesn't work for video/CDN domains (googlevideo, discord CDN).
    By switching to Cloudflare DNS, all domains resolve to real IPs,
    and winws2 desync can work on them directly.

    Saves original DNS for restore_system_dns().
    Requires admin (already required for WinDivert).
    """
    global _original_dns
    if platform.system() != "Windows":
        return False

    if dns_servers is None:
        dns_servers = ["1.1.1.1", "1.0.0.1"]

    try:
        # Find active interface and save its DNS
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "dns"],
            capture_output=True, text=True, timeout=5,
        )

        _original_dns = {}
        current_iface = None
        for line in result.stdout.split("\n"):
            line = line.strip()
            # Match interface name
            if line.startswith("Настройка интерфейса") or line.startswith("Configuration for interface"):
                # Extract name between quotes
                if '"' in line:
                    current_iface = line.split('"')[1]
            # Match static DNS
            if current_iface and ("Статически настроенные" in line or "Statically Configured" in line or "DNS-серверы со статической" in line):
                ip_part = line.split(":")[-1].strip()
                if ip_part and ip_part[0].isdigit():
                    _original_dns[current_iface] = [ip_part]

        if not _original_dns:
            logger.debug("No static DNS found to override")
            return False

        # Override DNS on each interface that had static DNS
        for iface, old_dns in _original_dns.items():
            # Skip if already using clean DNS
            if old_dns and old_dns[0] in dns_servers:
                continue

            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns",
                 f"name={iface}", "static", dns_servers[0]],
                capture_output=True, timeout=5,
            )
            if len(dns_servers) > 1:
                subprocess.run(
                    ["netsh", "interface", "ip", "add", "dns",
                     f"name={iface}", dns_servers[1], "index=2"],
                    capture_output=True, timeout=5,
                )
            logger.info("DNS override: %s → %s (was %s)", iface, dns_servers, old_dns)

        flush_dns()
        return True

    except Exception as exc:
        logger.warning("Failed to override DNS: %s", exc)
        return False


def restore_system_dns() -> bool:
    """Restore original DNS settings saved by override_system_dns()."""
    global _original_dns
    if not _original_dns or platform.system() != "Windows":
        return False

    try:
        for iface, old_dns in _original_dns.items():
            if old_dns:
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns",
                     f"name={iface}", "static", old_dns[0]],
                    capture_output=True, timeout=5,
                )
                logger.info("DNS restored: %s → %s", iface, old_dns)
            else:
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns",
                     f"name={iface}", "dhcp"],
                    capture_output=True, timeout=5,
                )
                logger.info("DNS restored to DHCP: %s", iface)

        flush_dns()
        _original_dns = None
        return True

    except Exception as exc:
        logger.warning("Failed to restore DNS: %s", exc)
        return False


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
