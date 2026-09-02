"""Smart DNS diagnosis and auto-fix.

Detects DNS poisoning (ISP or user's DNS redirecting blocked domains)
and fixes it by writing real IPs to Windows hosts file.

Flow:
  1. Resolve domain via system DNS (socket.gethostbyname)
  2. TLS-probe the answer; certificate mismatch / shared stub IP => bogus
  3. Resolve via trusted chain (DoH -> DoT -> plain DNS) and write the real IP
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
import re
import socket
import subprocess
from pathlib import Path
from typing import Optional

from brain.dns_resolver import is_usable_ipv4

logger = logging.getLogger("svoboda.dns")

_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
_MARKER_START = "# PLGames Svoboda DNS fix - START"
_MARKER_END = "# PLGames Svoboda DNS fix - END"
_VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$")


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


# Multi-label public suffixes we actually meet in the hostlists. Not a full PSL:
# it only has to stop "co.uk"-style names collapsing to the suffix itself.
_MULTI_LABEL_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "com.au", "com.br", "com.tr", "com.ua",
    "co.jp", "co.kr", "com.cn", "co.in", "com.mx", "co.za",
})


def _registrable(host: str) -> str:
    """Registrable domain of ``host`` (www.youtube.com -> youtube.com).

    Used to tell "two names of the same site" apart from "two unrelated sites
    pointed at one IP", which is what makes a shared address suspicious.
    """
    parts = str(host).strip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _MULTI_LABEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _tls_probe(host: str, ip: Optional[str] = None, timeout: float = 5.0) -> str:
    """TLS handshake to ``ip`` (or the system-resolved address) with SNI=host.

    Returns:
      "ok"            - handshake completed, certificate valid for host
      "cert_mismatch" - handshake completed but the certificate is NOT for host
                        (ISP stub page, dead SNI proxy, MITM) => the IP is bogus
      "fail"          - reset / timeout / TLS alert (typical DPI block)
    """
    import ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip or host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                logger.debug("TLS OK for %s via %s (%s)", host, ip or "system DNS", ssock.version())
                return "ok"
    except ssl.SSLCertVerificationError as exc:
        logger.debug("TLS cert mismatch for %s via %s: %s", host, ip, exc)
        return "cert_mismatch"
    except Exception as exc:
        logger.debug("TLS failed for %s via %s: %s", host, ip, exc)
        return "fail"


def _test_tls_through_proxy(host: str, timeout: float = 5.0) -> bool:
    """Backward-compatible wrapper: True if the current DNS answer serves host."""
    return _tls_probe(host, None, timeout) == "ok"


def diagnose_and_fix_dns(
    hosts: list[str],
    doh_resolver=None,
    sni_proxy_ip: Optional[str] = None,
    resolver=None,
) -> dict[str, dict]:
    """Diagnose DNS poisoning per host and fix it via the hosts file.

    Decision per host (only bogus answers are overridden — a DPI block with a
    correct IP is left to the desync engine):
      1. sys_ip  = system resolver answer
      2. If TLS to sys_ip with the real SNI succeeds -> keep (direct, CDN edge
         or a working SNI proxy — all fine).
      3. Otherwise the answer is considered BOGUS when
           - TLS completed but the certificate is for another name
             (ISP stub / dead SNI proxy — the discord.com exit=60 case), or
           - sys_ip is the shared SNI-proxy address (sni_proxy_ip), or
           - sys_ip is returned for 2+ unrelated hosts in this run.
         A bogus answer is replaced by a trusted resolution
         (DoH -> DoT -> plain DNS to public resolvers; see brain.dns_resolver).
      4. Fixes are written between marker lines in the hosts file and removed
         on exit.

    Returns {host: {status, system_ip, real_ip, fixed, source}}.
    status: ok | ok_via_proxy | dns_fail | blocked_not_dns | poisoned_fixed |
            poisoned_unresolved
    """
    from brain.dns_resolver import resolve_trusted

    resolver = resolver or (lambda h: resolve_trusted(h, doh_resolver=doh_resolver))
    results: dict[str, dict] = {}
    fixes: dict[str, str] = {}

    # Pass 1: system answers (to spot one IP shared by unrelated hosts)
    sys_ips: dict[str, Optional[str]] = {}
    for host in hosts:
        try:
            sys_ips[host] = socket.gethostbyname(host)
        except Exception:
            sys_ips[host] = None
    # Count how many UNRELATED sites share each IP. youtube.com and
    # www.youtube.com legitimately resolve to the same address, and on a
    # blocking ISP both TLS probes fail — counting them as two would brand a
    # perfectly good CDN edge as an "SNI proxy" and pin a foreign IP for the
    # whole session. Only distinct registrable domains count.
    shared_domains: dict[str, set[str]] = {}
    for host, ip in sys_ips.items():
        if ip:
            shared_domains.setdefault(ip, set()).add(_registrable(host))
    shared: dict[str, int] = {ip: len(names) for ip, names in shared_domains.items()}

    # Pass 2a: TLS-probe every system answer concurrently (DPI-blocked hosts
    # time out, so serial probing of 6 hosts took ~11s live; parallel ~4s)
    from concurrent.futures import ThreadPoolExecutor
    probes: dict[str, str] = {}
    probe_hosts = [h for h in hosts if sys_ips.get(h)]
    if probe_hosts:
        with ThreadPoolExecutor(max_workers=min(8, len(probe_hosts))) as pool:
            for host, res in zip(probe_hosts, pool.map(lambda h: _tls_probe(h, sys_ips[h], timeout=4.0), probe_hosts)):
                probes[host] = res

    # Pass 2b: decide per host
    for host in hosts:
        entry = {"status": "unknown", "system_ip": None, "real_ip": None,
                 "fixed": False, "source": ""}
        sys_ip = sys_ips.get(host)
        if not sys_ip:
            entry["status"] = "dns_fail"
            # No answer at all: still try to fix via trusted resolvers
            try:
                ips, source = resolver(host)
            except Exception:
                ips, source = [], ""
            if ips:
                entry["real_ip"], entry["source"] = ips[0], source
                fixes[host] = ips[0]
                entry["status"] = "poisoned_fixed"
            results[host] = entry
            continue
        entry["system_ip"] = sys_ip

        probe = probes.get(host) or _tls_probe(host, sys_ip, timeout=4.0)
        if probe == "ok":
            entry["status"] = "ok_via_proxy" if (sni_proxy_ip and sys_ip == sni_proxy_ip) else "ok"
            results[host] = entry
            continue

        bogus = (
            probe == "cert_mismatch"
            or (sni_proxy_ip is not None and sys_ip == sni_proxy_ip)
            or shared.get(sys_ip, 0) >= 2
        )
        if not bogus:
            entry["status"] = "blocked_not_dns"
            results[host] = entry
            continue

        try:
            ips, source = resolver(host)
        except Exception as exc:
            logger.debug("Trusted resolve failed for %s: %s", host, exc)
            ips, source = [], ""
        if sys_ip in ips:
            # The trusted resolver agrees with the system answer, so the IP was
            # never the problem — this is a DPI block. Overriding it here would
            # pin one CDN edge and disable DNS-based failover for no gain.
            entry["status"] = "blocked_not_dns"
            results[host] = entry
            continue
        real_ip = next((ip for ip in ips if ip != sys_ip), None)
        if real_ip:
            entry["real_ip"], entry["source"] = real_ip, source
            entry["status"] = "poisoned_fixed"
            fixes[host] = real_ip
            logger.info("DNS poisoned: %s -> %s (bogus, %s); real IP %s via %s",
                        host, sys_ip, probe, real_ip, source)
        else:
            entry["status"] = "poisoned_unresolved"
            logger.warning("DNS answer for %s looks bogus (%s) but no trusted resolver answered",
                           host, sys_ip)
        results[host] = entry

    # Pass 3: apply
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

    # Build new block. Everything written here runs as admin and persists on
    # disk, and the IPs originate from network responses, so both fields are
    # validated: a value with a newline would inject arbitrary hosts entries.
    lines = [_MARKER_START]
    written = 0
    for domain, ip in sorted(domain_ip_map.items()):
        if not is_usable_ipv4(ip):
            logger.warning("Refusing to write hosts entry for %s: bad IP %r", domain, ip)
            continue
        if not _VALID_DOMAIN_RE.match(str(domain)):
            logger.warning("Refusing to write hosts entry: bad domain %r", domain)
            continue
        lines.append(f"{ip}\t{domain}")
        written += 1
        # Also pin the www. variant, but only where it makes sense: prefixing
        # "www." onto an already-qualified name (cdn.discordapp.com) just
        # produces a name nothing resolves.
        if domain.count(".") == 1 and not domain.startswith("www."):
            lines.append(f"{ip}\twww.{domain}")
    lines.append(_MARKER_END)
    if not written:
        logger.warning("No valid hosts entries to write")
        return False

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
    """Remove everything between START and END markers (inclusive).

    An unterminated block (crash mid-write, or a user deleting the END line)
    must NOT swallow the rest of the file: the hosts file belongs to the user
    and may hold entries we know nothing about. When START has no matching END,
    only the START line itself is dropped and everything after it is preserved.
    """
    lines = content.split("\n")
    result: list[str] = []
    i = 0
    while i < len(lines):
        if _MARKER_START in lines[i]:
            end = next((j for j in range(i + 1, len(lines)) if _MARKER_END in lines[j]), None)
            if end is None:
                logger.warning(
                    "hosts file has an unterminated Svoboda block - removing the "
                    "marker line only, keeping the %d lines after it", len(lines) - i - 1)
                i += 1          # drop the marker, keep the remainder
                continue
            i = end + 1         # drop the whole block
            continue
        result.append(lines[i])
        i += 1
    # Remove trailing empty lines from cleanup
    while result and result[-1].strip() == "":
        result.pop()
    return "\n".join(result) + "\n" if result else ""
