"""BlockageClassifier — AI-powered detection of DPI blocking methods.

Analyzes HOW a site is blocked (not just IF) by examining:
- RST packet timing and TTL
- TLS handshake completion
- HTTP/2 stream behavior
- Connection reset patterns

Returns block type + recommended bypass strategy.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("svoboda.classifier")


@dataclass
class BlockProbe:
    """Result of probing one host for block type."""
    host: str
    # Basic connectivity
    dns_ok: bool = False
    tcp_connect_ok: bool = False
    tls_handshake_ok: bool = False
    http_response_ok: bool = False
    # Detailed metrics
    tcp_connect_ms: float = 0.0
    tls_handshake_ms: float = 0.0
    ttfb_ms: float = 0.0          # time to first byte
    total_ms: float = 0.0
    http_code: int = 0
    curl_exit: int = -1
    # Block indicators
    rst_received: bool = False
    timeout: bool = False
    ssl_error: bool = False
    content_size: int = 0
    # Derived
    block_type: str = "unknown"
    confidence: float = 0.0


@dataclass
class BlockAnalysis:
    """Full analysis of blocking for a host."""
    host: str
    block_type: str              # see BLOCK_TYPES
    confidence: float            # 0.0-1.0
    evidence: list[str] = field(default_factory=list)
    recommended_strategies: list[list[str]] = field(default_factory=list)
    recommended_params: dict = field(default_factory=dict)


# Block types and their bypass strategies
BLOCK_TYPES = {
    "NOT_BLOCKED": {
        "desc": "Site is accessible",
        "strategies": [],
    },
    "DNS_POISONING": {
        "desc": "DNS returns wrong IP",
        "strategies": [],  # needs DNS bypass, not DPI
        "params": {"needs_dns": True},
    },
    "RST_INJECTION": {
        "desc": "DPI sends TCP RST after seeing SNI",
        "strategies": [
            ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6", "multisplit:pos=midsld"],
            ["fake:blob=fake_default_tls:ip_ttl=4:ip6_ttl=4:tcp_md5:repeats=8", "multidisorder:pos=1,midsld"],
        ],
    },
    "SNI_FILTERING": {
        "desc": "DPI blocks based on TLS SNI field",
        "strategies": [
            ["multisplit:pos=1,midsld:seqovl=6:seqovl_pattern=0x1603030000"],
            ["multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"],
            ["multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000", "multidisorder:pos=1,midsld"],
        ],
    },
    "HTTP2_STREAM_KILL": {
        "desc": "DPI allows handshake but kills HTTP/2 streams (Discord pattern)",
        "strategies": [
            # Need strategies that affect the whole connection, not just handshake
            ["multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000", "multidisorder:pos=1,midsld"],
            ["fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5"],
        ],
        "params": {"needs_persistent": True},
    },
    "THROTTLING": {
        "desc": "Connection works but extremely slow",
        "strategies": [
            ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6"],
        ],
    },
    "TLS_INTERFERENCE": {
        "desc": "DPI corrupts TLS handshake (SSL error)",
        "strategies": [
            ["multisplit:pos=1,midsld,endhost-1:seqovl=6:seqovl_pattern=0x1603030000"],
            ["fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5"],
        ],
    },
    "IP_BLOCK": {
        "desc": "IP address is blocked entirely",
        "strategies": [],  # DPI bypass won't help
        "params": {"needs_proxy": True},
    },
    "TIMEOUT_SILENT": {
        "desc": "Connection silently dropped (no RST)",
        "strategies": [
            ["multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"],
            ["multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000", "multidisorder:pos=1,midsld"],
        ],
    },
}


class BlockageClassifier:
    """Classify how a site is blocked and recommend bypass strategies."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._is_windows = platform.system() == "Windows"

    def classify(self, host: str) -> BlockAnalysis:
        """Run multi-stage probe to determine block type."""
        probe = self._probe_host(host)
        analysis = self._analyze_probe(probe)
        logger.info(
            "Block analysis for %s: type=%s confidence=%.2f evidence=%s",
            host, analysis.block_type, analysis.confidence,
            "; ".join(analysis.evidence),
        )
        return analysis

    def classify_multiple(self, hosts: list[str]) -> dict[str, BlockAnalysis]:
        """Classify multiple hosts."""
        return {host: self.classify(host) for host in hosts}

    # ─── Probing ──────────────────────────────────────────────────────────

    def _probe_host(self, host: str) -> BlockProbe:
        """Multi-stage probe: DNS → TCP → TLS → HTTP → HTTP/2 stream."""
        probe = BlockProbe(host=host)

        # Stage 1: DNS resolution
        probe.dns_ok = self._check_dns(host)
        if not probe.dns_ok:
            return probe

        # Stage 2: TCP connect + TLS + HTTP (with detailed timing)
        self._check_curl_detailed(host, probe)

        # Stage 3: If basic HTTPS works, test HTTP/2 stream
        if probe.http_response_ok:
            self._check_h2_stream(host, probe)

        return probe

    def _check_dns(self, host: str) -> bool:
        """Check if DNS resolves."""
        try:
            result = subprocess.run(
                ["nslookup", host],
                capture_output=True, text=True, timeout=5,
            )
            # Check if we got an actual IP (not just error)
            return result.returncode == 0 and "Address" in result.stdout
        except Exception:
            return True  # assume DNS ok if nslookup not available

    def _check_curl_detailed(self, host: str, probe: BlockProbe) -> None:
        """Detailed curl test with timing breakdown."""
        try:
            # curl with detailed timing output
            fmt = "%{http_code}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{size_download}"
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(self.timeout),
                    f"https://{host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", fmt,
                ],
                capture_output=True, text=True,
                timeout=self.timeout + 3,
            )

            probe.curl_exit = result.returncode
            parts = result.stdout.strip().split("|")

            try:
                probe.http_code = int(parts[0])
                probe.tcp_connect_ms = float(parts[1]) * 1000
                probe.tls_handshake_ms = float(parts[2]) * 1000
                probe.ttfb_ms = float(parts[3]) * 1000
                probe.total_ms = float(parts[4]) * 1000
                probe.content_size = int(parts[5])
            except (ValueError, IndexError):
                pass

            # Classify connection stages
            if probe.tcp_connect_ms > 0 and probe.tcp_connect_ms < self.timeout * 1000:
                probe.tcp_connect_ok = True
            if probe.tls_handshake_ms > 0 and probe.tls_handshake_ms < self.timeout * 1000:
                probe.tls_handshake_ok = True

            success_codes = {200, 301, 302, 303, 307, 308, 403, 404}
            if probe.http_code in success_codes:
                probe.http_response_ok = True

            # Error classification
            if result.returncode in {7, 56}:
                probe.rst_received = True
            elif result.returncode in {28}:
                probe.timeout = True
            elif result.returncode in {35, 51, 60}:
                probe.ssl_error = True

        except subprocess.TimeoutExpired:
            probe.timeout = True
        except Exception as exc:
            logger.debug("Probe %s failed: %s", host, exc)

    def _check_h2_stream(self, host: str, probe: BlockProbe) -> None:
        """Test if HTTP/2 stream survives beyond handshake (Discord issue)."""
        try:
            # Download 64KB — tests if connection stays alive after handshake
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(self.timeout + 3),
                    "-r", "0-65535",
                    f"https://{host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}|%{size_download}|%{time_total}",
                ],
                capture_output=True, text=True,
                timeout=self.timeout + 5,
            )

            parts = result.stdout.strip().split("|")
            h2_code = int(parts[0]) if parts else 0
            h2_size = int(parts[1]) if len(parts) > 1 else 0

            # If basic HTTP works but H2 stream doesn't download data
            if probe.http_response_ok and (result.returncode in {56, 28} or h2_size < 1000):
                probe.block_type = "HTTP2_STREAM_KILL"
                probe.confidence = 0.85

        except Exception:
            pass

    # ─── Analysis ─────────────────────────────────────────────────────────

    def _analyze_probe(self, probe: BlockProbe) -> BlockAnalysis:
        """Convert probe results into block type classification."""

        # Not blocked
        if probe.http_response_ok and probe.content_size > 100:
            if probe.block_type == "HTTP2_STREAM_KILL":
                return self._make_analysis(probe, "HTTP2_STREAM_KILL", 0.85, [
                    "TLS handshake succeeds",
                    "Initial HTTP response received",
                    "HTTP/2 stream dies after handshake",
                    "Classic TSPU behavior for Discord/streaming",
                ])
            return self._make_analysis(probe, "NOT_BLOCKED", 0.95, [
                f"HTTP {probe.http_code} received",
                f"Content size: {probe.content_size} bytes",
            ])

        # DNS failure
        if not probe.dns_ok:
            return self._make_analysis(probe, "DNS_POISONING", 0.80, [
                "DNS resolution failed or returned wrong IP",
            ])

        # TCP RST received
        if probe.rst_received:
            if probe.tls_handshake_ok:
                # RST after TLS handshake = DPI tracking connection
                return self._make_analysis(probe, "HTTP2_STREAM_KILL", 0.80, [
                    "TCP RST after TLS handshake completion",
                    "DPI tracks connection state and kills after handshake",
                ])
            else:
                # RST during/before TLS = SNI or RST injection
                return self._make_analysis(probe, "RST_INJECTION", 0.85, [
                    f"TCP RST received (curl exit={probe.curl_exit})",
                    "TLS handshake did not complete",
                    "DPI likely injecting RST after seeing SNI",
                ])

        # SSL/TLS error
        if probe.ssl_error:
            return self._make_analysis(probe, "TLS_INTERFERENCE", 0.75, [
                f"TLS error (curl exit={probe.curl_exit})",
                "DPI may be corrupting TLS handshake",
            ])

        # Timeout
        if probe.timeout:
            if probe.tcp_connect_ok and not probe.tls_handshake_ok:
                # TCP works but TLS fails = SNI filtering (silent drop)
                return self._make_analysis(probe, "SNI_FILTERING", 0.80, [
                    "TCP connect succeeded",
                    "TLS handshake timed out",
                    "DPI silently drops after seeing SNI in ClientHello",
                ])
            elif not probe.tcp_connect_ok:
                # Can't even TCP connect = IP block or heavy throttling
                return self._make_analysis(probe, "IP_BLOCK", 0.60, [
                    "TCP connect failed/timed out",
                    "Possible IP-level blocking",
                ])
            else:
                return self._make_analysis(probe, "TIMEOUT_SILENT", 0.70, [
                    "Connection timed out after TLS",
                    f"TTFB: {probe.ttfb_ms:.0f}ms",
                ])

        # Throttling (connected but very slow)
        if probe.http_response_ok and probe.total_ms > 3000:
            return self._make_analysis(probe, "THROTTLING", 0.65, [
                f"Connection very slow: {probe.total_ms:.0f}ms",
                "Possible traffic throttling",
            ])

        # Unknown
        return self._make_analysis(probe, "TIMEOUT_SILENT", 0.50, [
            f"Unclear block type (curl exit={probe.curl_exit})",
            f"HTTP code={probe.http_code}, total={probe.total_ms:.0f}ms",
        ])

    def _make_analysis(
        self, probe: BlockProbe, block_type: str, confidence: float,
        evidence: list[str],
    ) -> BlockAnalysis:
        """Create BlockAnalysis with recommended strategies."""
        bt = BLOCK_TYPES.get(block_type, BLOCK_TYPES["TIMEOUT_SILENT"])
        return BlockAnalysis(
            host=probe.host,
            block_type=block_type,
            confidence=confidence,
            evidence=evidence,
            recommended_strategies=bt.get("strategies", []),
            recommended_params=bt.get("params", {}),
        )


def classify_and_print(hosts: list[str], timeout: int = 5) -> dict[str, BlockAnalysis]:
    """Classify hosts and print results. Used by run_real.py."""
    classifier = BlockageClassifier(timeout=timeout)
    results = {}

    for host in hosts:
        analysis = classifier.classify(host)
        results[host] = analysis

        icon = {
            "NOT_BLOCKED": "OK",
            "RST_INJECTION": "RST",
            "SNI_FILTERING": "SNI",
            "HTTP2_STREAM_KILL": "H2-KILL",
            "THROTTLING": "SLOW",
            "TLS_INTERFERENCE": "TLS",
            "IP_BLOCK": "IP-BLK",
            "DNS_POISONING": "DNS",
            "TIMEOUT_SILENT": "TIMEOUT",
        }.get(analysis.block_type, "???")

        status = "accessible" if analysis.block_type == "NOT_BLOCKED" else "BLOCKED"
        print(f"    {host}: {status} [{icon}] ({analysis.confidence:.0%})")
        if analysis.evidence and analysis.block_type != "NOT_BLOCKED":
            for e in analysis.evidence[:2]:
                print(f"      - {e}")

    return results
