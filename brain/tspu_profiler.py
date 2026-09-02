"""TSPU Profiler — fingerprint DPI middlebox characteristics.

Determines:
- Distance to DPI (hop count) via TTL probing
- DPI behavior: what triggers blocking (SNI, Host header, packet pattern)
- Recommended TTL for fake packets

This is critical for autottl calibration — knowing the DPI hop distance
means we can set TTL = dpi_distance - 1 (fake reaches DPI, not server).
"""

from __future__ import annotations

import logging
import platform
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional

from brain.netenv import CURL_DIRECT
logger = logging.getLogger("svoboda.tspu")

# ISPs known to sit behind Roskomnadzor TSPU (every RU ISP is required to).
RU_ISPS = frozenset({
    "rostelecom", "mts", "megafon", "beeline", "tele2", "tattelecom",
    "er-telecom", "ttk", "netbynet", "ufanet", "yota",
})


def is_russian_network(country: str = "", isp: str = "") -> bool:
    """True if the network is Russian: ISO country RU or a known RU ISP name."""
    if (country or "").strip().upper() == "RU":
        return True
    return (isp or "").strip().lower() in RU_ISPS


@dataclass
class TSPUProfile:
    """Fingerprint of the DPI/TSPU middlebox."""
    # Distance
    dpi_hop_distance: Optional[int] = None   # hops to DPI device
    server_hop_distance: Optional[int] = None  # hops to real server
    recommended_ttl: Optional[int] = None    # optimal TTL for fake packets

    # Behavior
    blocks_tls_sni: bool = True              # blocks based on TLS SNI
    blocks_http_host: bool = False           # blocks HTTP Host header
    blocks_quic: bool = False                # blocks QUIC/UDP
    is_stateful: bool = False                # tracks TCP connection state

    # Classification
    dpi_type: str = "unknown"                # ektako_v2, signaltek, generic
    isp: str = "unknown"
    asn: str = ""
    autottl_preferred: bool = False          # True when distance is estimated, not measured
    country: str = ""                        # ISO country of the ISP ("RU" => TSPU by law)
    probe_inconclusive: bool = False         # probe ran behind an active bypass

    # Evidence
    evidence: list[str] = field(default_factory=list)


class TSPUProfiler:
    """Profile the DPI/TSPU middlebox via network probing."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._is_windows = platform.system() == "Windows"

    def profile(self, blocked_host: str = "youtube.com", isp: str = "unknown", asn: str = "",
                country: str = "", bypass_active: bool = False) -> TSPUProfile:
        """Full TSPU profiling for a blocked host.

        Steps:
        1. Measure server distance (TTL from ping/traceroute)
        2. Probe DPI behavior (what triggers the block)
        3. Estimate DPI distance
        4. Recommend optimal fake TTL
        """
        prof = TSPUProfile(isp=isp, asn=asn, country=(country or "").upper())

        # Step 1: Server distance via ping
        prof.server_hop_distance = self._measure_server_distance(blocked_host)
        if prof.server_hop_distance:
            prof.evidence.append(f"Server distance: ~{prof.server_hop_distance} hops")

        # Step 2: DPI behavior probing (inconclusive if a bypass is already running)
        self._probe_dpi_behavior(blocked_host, prof, bypass_active=bypass_active)

        # Step 3: Estimate DPI distance
        self._estimate_dpi_distance(prof)

        # Step 4: Recommend TTL
        # Use autottl when possible (dynamically calibrates from server responses).
        # Fixed TTL is fallback when autottl unavailable or unreliable.
        if prof.dpi_hop_distance:
            prof.recommended_ttl = max(1, prof.dpi_hop_distance - 1)
            # Mark if distance was estimated (not measured) — callers should
            # prefer autottl strategies when distance is uncertain
            if not prof.server_hop_distance:
                prof.autottl_preferred = True
                prof.evidence.append("TTL based on heuristic — autottl preferred")
            prof.evidence.append(f"Recommended fake TTL: {prof.recommended_ttl}")

        # Step 5: Classify DPI type
        self._classify_dpi_type(prof)

        logger.info(
            "TSPU profile: dpi_distance=%s server_distance=%s recommended_ttl=%s type=%s",
            prof.dpi_hop_distance, prof.server_hop_distance,
            prof.recommended_ttl, prof.dpi_type,
        )

        return prof

    # ─── Server distance ─────────────────────────────────────────────────

    def _measure_server_distance(self, host: str) -> Optional[int]:
        """Estimate server hop distance from ping TTL."""
        try:
            if self._is_windows:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", str(self.timeout * 1000), host],
                    capture_output=True, text=True, timeout=self.timeout + 2,
                    encoding="cp866", errors="replace",
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(self.timeout), host],
                    capture_output=True, text=True, timeout=self.timeout + 2,
                )

            # Parse TTL from output
            ttl_match = re.search(r"TTL[=:](\d+)", result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                # Common OS default TTLs: 64 (Linux), 128 (Windows), 255 (Cisco)
                if ttl <= 64:
                    return 64 - ttl
                elif ttl <= 128:
                    return 128 - ttl
                else:
                    return 255 - ttl

        except Exception as exc:
            logger.debug("Ping %s failed: %s", host, exc)

        return None

    # ─── DPI behavior probing ────────────────────────────────────────────

    def _probe_dpi_behavior(self, host: str, prof: TSPUProfile, bypass_active: bool = False) -> None:
        """Test what triggers DPI blocking."""

        # Test 1: Plain HTTPS (should be blocked)
        https_result = self._curl_probe(f"https://{host}")
        if https_result["success"]:
            if bypass_active:
                # winws2 is already desyncing this host: reachability says
                # nothing about the DPI. Live run 2026-05-03 misclassified
                # er-telecom as 'unknown' this way and silently disabled the
                # no-fake policy.
                prof.probe_inconclusive = True
                prof.evidence.append("HTTPS reachable while bypass active - probe inconclusive")
                return
            prof.blocks_tls_sni = False
            prof.evidence.append("HTTPS not blocked (host reachable directly)")
            return

        prof.evidence.append(f"HTTPS blocked: exit={https_result['exit']}, {https_result['error']}")

        # Test 2: HTTP (port 80) — is it also blocked?
        http_result = self._curl_probe(f"http://{host}")
        if not http_result["success"]:
            prof.blocks_http_host = True
            prof.evidence.append("HTTP also blocked")
        else:
            prof.evidence.append("HTTP works, only HTTPS blocked → SNI-based")

        # Test 3: Wrong SNI test — connect to IP with different SNI
        # If connection works with wrong SNI → confirms SNI filtering
        # (Can't easily do this with curl, skip for now)

        # Test 4: Classify by error type
        if https_result["exit"] in {7, 56}:
            # RST = active injection
            prof.evidence.append("RST injection detected")
            prof.is_stateful = False  # RST injection is usually stateless
        elif https_result["exit"] == 28:
            # Timeout = silent drop
            prof.evidence.append("Silent timeout (no RST)")
            prof.is_stateful = True  # silent drop often = stateful DPI
        elif https_result["exit"] in {35, 51, 60}:
            # SSL error = TLS interference
            prof.evidence.append("TLS handshake corrupted")

    def _curl_probe(self, url: str) -> dict:
        """Quick curl probe returning success + error info."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s", *CURL_DIRECT,
                    "--max-time", str(self.timeout),
                    url,
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}",
                ],
                capture_output=True, text=True,
                timeout=self.timeout + 3,
            )

            http_code = 0
            try:
                http_code = int(result.stdout.strip())
            except ValueError:
                pass

            success = http_code in {200, 301, 302, 303, 307, 308, 403, 404}
            error = ""
            if result.returncode in {7, 56}:
                error = "RST"
            elif result.returncode == 28:
                error = "timeout"
            elif result.returncode in {35, 51, 60}:
                error = "SSL"
            elif result.returncode != 0:
                error = f"exit={result.returncode}"

            return {"success": success, "http_code": http_code, "exit": result.returncode, "error": error}

        except subprocess.TimeoutExpired:
            return {"success": False, "http_code": 0, "exit": 28, "error": "timeout"}
        except Exception:
            return {"success": False, "http_code": 0, "exit": -1, "error": "exception"}

    # ─── DPI distance estimation ─────────────────────────────────────────

    def _estimate_dpi_distance(self, prof: TSPUProfile) -> None:
        """Estimate DPI hop distance.

        Russian TSPU is typically installed at:
        - 1-2 hops for large ISPs (Rostelecom, MTS) — at regional node
        - 3-5 hops for smaller ISPs — at upstream provider
        - Very rarely > 6 hops

        We use heuristics based on ISP + server distance.
        """
        # Known ISP DPI distances (empirical)
        isp_dpi_distances = {
            "rostelecom": 2,
            "mts": 2,
            "megafon": 3,
            "beeline": 3,
            "tele2": 3,
            "tattelecom": 2,
            "er-telecom": 3,
            "ttk": 2,
        }

        isp_lower = prof.isp.lower() if prof.isp else ""

        # Check known ISPs
        for isp_key, distance in isp_dpi_distances.items():
            if isp_key in isp_lower:
                prof.dpi_hop_distance = distance
                prof.evidence.append(f"Known ISP '{isp_key}' → DPI at ~{distance} hops")
                return

        # Unknown ISP: estimate from server distance
        if prof.server_hop_distance:
            # DPI is usually in the first third of the path
            estimated = max(2, prof.server_hop_distance // 3)
            prof.dpi_hop_distance = min(estimated, 5)
            prof.evidence.append(f"Estimated DPI distance: {prof.dpi_hop_distance} hops (server at {prof.server_hop_distance})")
        else:
            # Conservative default
            prof.dpi_hop_distance = 3
            prof.evidence.append("Default DPI distance: 3 hops (no ping data)")

    # ─── DPI type classification ─────────────────────────────────────────

    def _classify_dpi_type(self, prof: TSPUProfile) -> None:
        """Classify DPI type based on behavior.

        Russian networks always get a tspu_* type: TSPU is mandatory at every
        RU ISP, so an inconclusive or 'not blocked' probe must not switch off
        the TSPU-specific policies (no fake packets, lower thresholds).
        """
        russian = is_russian_network(prof.country, prof.isp)
        if prof.probe_inconclusive:
            if russian:
                prof.dpi_type = "tspu_stateful"
                prof.evidence.append("DPI type: assumed stateful TSPU (Russian network, probe inconclusive)")
            else:
                prof.dpi_type = "unknown"
                prof.evidence.append("DPI type: unknown (probe inconclusive)")
            return
        if prof.blocks_tls_sni and not prof.blocks_http_host:
            if prof.is_stateful:
                prof.dpi_type = "tspu_stateful"
                prof.evidence.append("DPI type: stateful TSPU (silent drop, SNI-only)")
            else:
                prof.dpi_type = "tspu_rst"
                prof.evidence.append("DPI type: RST-injecting TSPU (SNI-based)")
        elif prof.blocks_tls_sni and prof.blocks_http_host:
            prof.dpi_type = "tspu_full"
            prof.evidence.append("DPI type: full TSPU (blocks both SNI and Host)")
        elif russian:
            prof.dpi_type = "tspu_stateful"
            prof.evidence.append("DPI type: assumed stateful TSPU (Russian network)")
        else:
            prof.dpi_type = "unknown"
            prof.evidence.append("DPI type: unknown")
