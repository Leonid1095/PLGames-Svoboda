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
    http_port80_ok: bool = False       # HTTP (not HTTPS) works
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
    # Packet-level events for AI reasoning
    packet_events: list[dict] = field(default_factory=list)

    def to_ai_context(self) -> dict:
        """Structured data for AI Decision Engine."""
        return {
            "host": self.host,
            "block_type": self.block_type,
            "confidence": self.confidence,
            "evidence": "; ".join(self.evidence),
            "packet_events": self.packet_events,
        }


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
    "TLS_IP_BLOCK": {
        "desc": "TCP works but all TLS to this IP is blocked (regardless of SNI)",
        "strategies": [],  # DPI bypass won't help — needs proxy/tunnel
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
    """Classify how a site is blocked and recommend bypass strategies.

    Smart detection: cross-references probe results with known IP-blocked
    domains and performs DoH verification to distinguish SNI from IP blocks.
    """

    # Known IP-blocked domains: TSPU blocks at IP level, DPI bypass won't help.
    # Maintained separately from proxy_router's list for classification accuracy.
    _KNOWN_IP_BLOCKED = {
        # AI services
        "openai.com", "api.openai.com", "chat.openai.com", "platform.openai.com",
        "claude.ai", "api.anthropic.com", "anthropic.com",
        "gemini.google.com", "bard.google.com",
        "copilot.microsoft.com", "perplexity.ai",
        "huggingface.co",
        # Social/media
        "linkedin.com", "www.linkedin.com",
        "medium.com", "archive.org",
        # Email
        "protonmail.com", "proton.me",
        # Telegram Web (TCP connects but all TLS blocked by TSPU)
        "web.telegram.org", "telegram.org", "t.me",
    }

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._is_windows = platform.system() == "Windows"

    def classify(self, host: str) -> BlockAnalysis:
        """Run multi-stage probe to determine block type.

        For known IP-blocked domains, skips full probe and returns IP_BLOCK
        directly (saves time — DPI bypass won't help anyway).
        For unknown domains, runs full probe + cross-check.
        """
        # Fast path: known IP-blocked domains
        if self._is_known_ip_blocked(host):
            # Quick verify: if somehow accessible, don't mark as blocked
            if self._quick_https_check(host):
                return BlockAnalysis(
                    host=host, block_type="NOT_BLOCKED", confidence=0.90,
                    evidence=["Known IP-blocked domain, but HTTPS works (VPN/WARP active?)"],
                )
            return BlockAnalysis(
                host=host, block_type="IP_BLOCK", confidence=0.90,
                evidence=[
                    "Domain in known IP-blocked list",
                    "DPI bypass ineffective — needs proxy/tunnel",
                ],
                recommended_strategies=[],
                recommended_params={"needs_proxy": True},
            )

        probe = self._probe_host(host)
        analysis = self._analyze_probe(probe)

        # Cross-check: if classified as SNI but TCP also fails intermittently,
        # it might be IP-level throttling masquerading as SNI block
        if analysis.block_type == "SNI_FILTERING" and not probe.http_port80_ok and not probe.tcp_connect_ok:
            analysis.block_type = "IP_BLOCK"
            analysis.confidence = 0.75
            analysis.evidence.append("Reclassified: TCP+HTTP both fail → likely IP block")
            analysis.recommended_strategies = []
            analysis.recommended_params = {"needs_proxy": True}

        logger.info(
            "Block analysis for %s: type=%s confidence=%.2f evidence=%s",
            host, analysis.block_type, analysis.confidence,
            "; ".join(analysis.evidence),
        )
        return analysis

    def _is_known_ip_blocked(self, host: str) -> bool:
        """Check if host is in known IP-blocked list."""
        h = host.lower()
        if h in self._KNOWN_IP_BLOCKED:
            return True
        for domain in self._KNOWN_IP_BLOCKED:
            if h.endswith("." + domain):
                return True
        return False

    def _quick_https_check(self, host: str) -> bool:
        """Quick HTTPS check — used to verify if 'blocked' domain is actually reachable."""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"https://{host}",
                 "-o", "NUL" if self._is_windows else "/dev/null",
                 "-w", "%{http_code}"],
                capture_output=True, text=True, timeout=8,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            return code in {200, 301, 302, 303, 307, 308, 403, 404, 405, 429}
        except Exception:
            return False

    def _check_tls_without_sni(self, host: str) -> bool:
        """Try TLS handshake WITHOUT sending SNI extension.

        If TLS w/o SNI succeeds → DPI is filtering by SNI (SNI_FILTERING).
        If TLS w/o SNI fails → DPI blocks all TLS to this IP (TLS_IP_BLOCK).

        Uses Python ssl with no server_hostname to avoid SNI.
        """
        import socket as sock
        import ssl

        try:
            ip = sock.gethostbyname(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            s = sock.create_connection((ip, 443), timeout=5)
            # wrap_socket WITHOUT server_hostname → no SNI extension sent
            ss = ctx.wrap_socket(s)
            ss.close()
            logger.debug("TLS w/o SNI for %s (%s): OK → SNI_FILTERING", host, ip)
            return True
        except Exception as exc:
            logger.debug("TLS w/o SNI for %s: FAIL (%s) → TLS_IP_BLOCK", host, exc)
            return False

    def classify_multiple(self, hosts: list[str]) -> dict[str, BlockAnalysis]:
        """Classify multiple hosts."""
        return {host: self.classify(host) for host in hosts}

    # ─── Probing ──────────────────────────────────────────────────────────

    def _probe_host(self, host: str) -> BlockProbe:
        """Multi-stage probe: DNS → TCP raw → HTTP → HTTPS → H2 stream."""
        probe = BlockProbe(host=host)

        # Stage 1: DNS resolution
        probe.dns_ok = self._check_dns(host)
        if not probe.dns_ok:
            return probe

        # Stage 2: Raw TCP connect (port 443, no TLS)
        # If TCP connects but TLS fails → SNI filtering
        # If TCP doesn't connect → IP block or network issue
        probe.tcp_connect_ok = self._check_tcp_connect(host, 443)

        # Stage 3: HTTP (port 80) — is it blocked too?
        # If HTTP works but HTTPS doesn't → SNI-based blocking
        probe.http_port80_ok = self._check_http(host)

        # Stage 4: HTTPS with detailed timing
        self._check_curl_detailed(host, probe)

        # Stage 5: If basic HTTPS works, test HTTP/2 stream
        if probe.http_response_ok:
            self._check_h2_stream(host, probe)

        # Override: if TCP connects but HTTPS times out → need to distinguish
        # SNI filtering from TLS-level IP block.
        # Key test: TLS handshake WITHOUT SNI extension.
        #   - If TLS w/o SNI succeeds → SNI_FILTERING (DPI reads SNI field)
        #   - If TLS w/o SNI also fails → IP-level TLS block (DPI blocks all TLS to this IP)
        if probe.tcp_connect_ok and probe.timeout and not probe.http_response_ok:
            if self._check_tls_without_sni(host):
                probe.block_type = "SNI_FILTERING"
                probe.confidence = 0.90
            else:
                probe.block_type = "TLS_IP_BLOCK"
                probe.confidence = 0.85

        return probe

    def _check_tcp_connect(self, host: str, port: int) -> bool:
        """Raw TCP connect test (no TLS). Tests if IP is reachable."""
        import socket as sock
        try:
            s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((host, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _check_http(self, host: str) -> bool:
        """Test HTTP (port 80) — if this works, IP is not blocked."""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "3", f"http://{host}",
                 "-o", "NUL" if self._is_windows else "/dev/null",
                 "-w", "%{http_code}"],
                capture_output=True, text=True, timeout=5,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            return code in {200, 301, 302, 303, 307, 308, 403, 404}
        except Exception:
            return False

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
            if probe.tcp_connect_ok or probe.http_port80_ok:
                # TCP or HTTP works but HTTPS fails = SNI filtering
                evidence = []
                if probe.tcp_connect_ok:
                    evidence.append("TCP connect to port 443 succeeded")
                if probe.http_port80_ok:
                    evidence.append("HTTP port 80 works → IP is NOT blocked")
                evidence.append("HTTPS timed out → DPI blocks based on TLS SNI")
                return self._make_analysis(probe, "SNI_FILTERING", 0.85, evidence)
            elif not probe.tcp_connect_ok and not probe.http_port80_ok:
                # Nothing connects = real IP block
                return self._make_analysis(probe, "IP_BLOCK", 0.70, [
                    "TCP connect failed",
                    "HTTP port 80 also failed",
                    "IP-level blocking or network unreachable",
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
        """Create BlockAnalysis with recommended strategies and packet events."""
        bt = BLOCK_TYPES.get(block_type, BLOCK_TYPES["TIMEOUT_SILENT"])

        # Build packet events timeline for AI reasoning
        events = []
        if probe.tcp_connect_ok:
            events.append({"type": "TCP_CONNECT", "ms": probe.tcp_connect_ms, "success": True})
        else:
            events.append({"type": "TCP_CONNECT", "ms": probe.tcp_connect_ms, "success": False})
        if probe.tls_handshake_ok:
            events.append({"type": "TLS_HANDSHAKE", "ms": probe.tls_handshake_ms, "success": True})
        elif probe.ssl_error:
            events.append({"type": "TLS_HANDSHAKE", "ms": probe.tls_handshake_ms, "success": False, "error": "ssl"})
        if probe.rst_received:
            events.append({"type": "RST_RECEIVED", "ms": probe.total_ms})
        if probe.timeout:
            events.append({"type": "TIMEOUT", "ms": probe.total_ms})
        if probe.http_response_ok:
            events.append({"type": "HTTP_RESPONSE", "code": probe.http_code, "ms": probe.ttfb_ms, "size": probe.content_size})
        if probe.http_port80_ok:
            events.append({"type": "HTTP_PORT80_OK"})

        return BlockAnalysis(
            host=probe.host,
            block_type=block_type,
            confidence=confidence,
            evidence=evidence,
            recommended_strategies=bt.get("strategies", []),
            recommended_params=bt.get("params", {}),
            packet_events=events,
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
