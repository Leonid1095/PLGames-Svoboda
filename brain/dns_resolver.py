"""Trusted DNS resolution that does not depend on the ISP resolver.

Why: on er-telecom (2026-09-01) the system resolver answered
    youtube.com / x.com / discord.com  -> 147.90.15.214  (one foreign "SNI proxy")
    instagram.com / rutracker.org      -> 188.186.154.79 (ISP block-page stub)
Desync cannot fix a wrong IP, and the previous fix path depended on DoH via
curl, which fails whenever the DoH hostnames themselves are SNI-blocked.

This module is stdlib-only and implements the DNS wire format directly:
    DoH (JSON, via brain.ech.DoHResolver when supplied)
      -> DoT  (TLS on 853 to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 ...)
        -> plain DNS (UDP 53, TCP 53 fallback) to the same public resolvers

Plain DNS to 1.1.1.1 / 8.8.8.8 was verified working on er-telecom while the
ISP resolver was poisoned, so the chain degrades gracefully.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import ssl
import struct
import time
from typing import Callable, Optional

logger = logging.getLogger("svoboda.dns")

# (ip, tls_server_name) — the name is used for DoT certificate validation.
TRUSTED_DNS: list[tuple[str, str]] = [
    ("1.1.1.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
    ("9.9.9.9", "dns.quad9.net"),
    ("1.0.0.1", "cloudflare-dns.com"),
    ("8.8.4.4", "dns.google"),
    ("94.140.14.14", "dns.adguard-dns.com"),
]

_TYPE_A = 1
_CLASS_IN = 1


# ─── wire format ─────────────────────────────────────────────────────────────

def build_query(name: str, qtype: int = _TYPE_A, qid: Optional[int] = None) -> tuple[bytes, int]:
    """Build a standard recursive DNS query. Returns (packet, id)."""
    if qid is None:
        qid = random.randint(1, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise ValueError(f"bad label in {name!r}")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    return header + qname + struct.pack("!HH", qtype, _CLASS_IN), qid


def _skip_name(buf: bytes, off: int) -> int:
    """Return offset just past a (possibly compressed) domain name."""
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        length = buf[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:      # compression pointer (2 bytes)
            if off + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            return off + 2
        off += 1 + length


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    """Read a (possibly compressed) name. Returns (name, offset past it).

    Pointers are followed with a hop budget so a self-referential or cyclic
    pointer cannot loop forever.
    """
    labels: list[str] = []
    end: Optional[int] = None
    hops = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 16:
                raise ValueError("compression pointer loop")
            off = ptr
            continue
        if off + 1 + length > len(buf):
            raise ValueError("truncated label")
        labels.append(buf[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def parse_a_records(buf: bytes, expected_id: Optional[int] = None,
                    expected_name: Optional[str] = None) -> list[str]:
    """Extract IPv4 answers (type A) from a DNS response.

    Raises ValueError on anything malformed, mismatched or truncated — callers
    treat that as "this resolver did not answer" and move on to the next one.
    """
    if len(buf) < 12:
        raise ValueError("short response")
    qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    if expected_id is not None and qid != expected_id:
        raise ValueError("id mismatch")
    if flags & 0x8000 == 0:
        raise ValueError("not a response")
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"rcode {rcode}")
    off = 12
    for i in range(qd):
        qname, off = _read_name(buf, off)
        if off + 4 > len(buf):
            raise ValueError("truncated question")
        off += 4
        # Guard against a forged reply that answers a different question.
        if i == 0 and expected_name and qname.lower().rstrip(".") != expected_name.lower().rstrip("."):
            raise ValueError(f"question mismatch: got {qname!r}, asked {expected_name!r}")
    ips: list[str] = []
    for _ in range(an):
        off = _skip_name(buf, off)
        if off + 10 > len(buf):
            raise ValueError("truncated record header")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            raise ValueError("truncated rdata")
        rdata = buf[off:off + rdlen]
        off += rdlen
        if rtype == _TYPE_A and rclass == _CLASS_IN and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
    return ips


# ─── transports ──────────────────────────────────────────────────────────────

def query_udp(server: str, name: str, timeout: float = 3.0) -> list[str]:
    """Plain DNS over UDP.

    This module exists to defeat an ISP that poisons DNS, and UDP/53 is exactly
    what such an ISP can forge. So the reply is accepted only if it came from
    the server we asked, carries our query id, and echoes the question we sent.
    Off-path spoofing still needs to guess the id and win the race, but an
    unsolicited or mismatched packet is now discarded instead of trusted.
    """
    pkt, qid = build_query(name)
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no valid DNS reply")
            s.settimeout(remaining)
            data, addr = s.recvfrom(4096)
            if addr[0] != server:
                logger.debug("Discarding DNS reply from %s (asked %s)", addr[0], server)
                continue
            try:
                return parse_a_records(data, qid, expected_name=name)
            except ValueError as exc:
                logger.debug("Discarding DNS reply from %s: %s", addr[0], exc)
                continue


def _read_exact(sock, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ValueError("connection closed")
        out += chunk
    return out


def _exchange_stream(sock, pkt: bytes) -> bytes:
    sock.sendall(struct.pack("!H", len(pkt)) + pkt)
    (length,) = struct.unpack("!H", _read_exact(sock, 2))
    return _read_exact(sock, length)


def query_tcp(server: str, name: str, timeout: float = 3.0) -> list[str]:
    pkt, qid = build_query(name)
    with socket.create_connection((server, 53), timeout=timeout) as s:
        data = _exchange_stream(s, pkt)
    return parse_a_records(data, qid)


def query_dot(server: str, server_name: str, name: str, timeout: float = 4.0) -> list[str]:
    """DNS over TLS (RFC 7858) — certificate validated against server_name."""
    pkt, qid = build_query(name)
    ctx = ssl.create_default_context()
    with socket.create_connection((server, 853), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as s:
            data = _exchange_stream(s, pkt)
    return parse_a_records(data, qid)


# ─── chain ───────────────────────────────────────────────────────────────────

def is_usable_ipv4(value: str) -> bool:
    """True only for a global-unicast IPv4 literal.

    Everything this module returns can end up in the Windows hosts file, and the
    DoH path carries provider JSON straight from the network. An unvalidated
    value containing a newline would inject arbitrary hosts-file lines, and a
    loopback/private/multicast answer would blackhole the domain. So every
    candidate is parsed before it is trusted.
    """
    try:
        addr = ipaddress.IPv4Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return not (
        addr.is_loopback or addr.is_private or addr.is_multicast
        or addr.is_reserved or addr.is_unspecified or addr.is_link_local
    )


def _doh_lookup(doh_resolver, name: str) -> list[str]:
    """Adapter for brain.ech.DoHResolver (JSON API answers)."""
    result = doh_resolver.resolve(name, rtype="A")
    if not getattr(result, "success", False):
        return []
    ips = []
    for ans in result.answers:
        if ans.get("type") == _TYPE_A and ans.get("data"):
            candidate = str(ans["data"]).strip()
            if is_usable_ipv4(candidate):
                ips.append(candidate)
            else:
                logger.debug("Discarding non-usable DoH answer for %s: %r", name, candidate)
    return ips


def resolve_trusted(name: str, doh_resolver=None, timeout: float = 3.0,
                    servers: Optional[list[tuple[str, str]]] = None) -> tuple[list[str], str]:
    """Resolve ``name`` bypassing the ISP resolver.

    Returns (ips, source) where source is e.g. "doh:Cloudflare", "dot:1.1.1.1",
    "udp:8.8.8.8", "tcp:8.8.8.8" or "" when every path failed.
    """
    servers = servers or TRUSTED_DNS

    if doh_resolver is not None:
        try:
            ips = _doh_lookup(doh_resolver, name)
            if ips:
                prov = getattr(doh_resolver, "_working_provider", None)
                label = prov[0] if isinstance(prov, tuple) and prov else "doh"
                return ips, f"doh:{label}"
        except Exception as exc:
            logger.debug("DoH lookup %s failed: %s", name, exc)

    attempts: list[tuple[str, Callable[[], list[str]]]] = []
    for ip, sni in servers:
        attempts.append((f"dot:{ip}", lambda ip=ip, sni=sni: query_dot(ip, sni, name, timeout + 1)))
    for ip, _sni in servers:
        attempts.append((f"udp:{ip}", lambda ip=ip: query_udp(ip, name, timeout)))
    for ip, _sni in servers[:2]:
        attempts.append((f"tcp:{ip}", lambda ip=ip: query_tcp(ip, name, timeout)))

    for label, fn in attempts:
        try:
            ips = [ip for ip in fn() if is_usable_ipv4(ip)]
            if ips:
                return ips, label
        except Exception as exc:
            logger.debug("%s %s failed: %s", label, name, exc)
    return [], ""
