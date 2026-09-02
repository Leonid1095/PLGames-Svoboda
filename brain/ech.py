"""ECH (Encrypted Client Hello) + DoH (DNS over HTTPS) system.

ECH encrypts the SNI field in TLS ClientHello, making it invisible to DPI.
TSPU cannot filter what it cannot see.

Requirements:
  1. DoH resolver to fetch ECH keys (HTTPS RR / SVCB records)
  2. Browser/curl support for ECH (Chrome 117+, Firefox 118+, curl 8.8+)

Flow:
  1. Resolve domain via DoH → get ECHConfig from HTTPS/SVCB DNS record
  2. Browser uses ECHConfig to encrypt ClientHello
  3. DPI sees encrypted SNI → cannot match against blocklist → passes through
  4. If ECH not available for domain → fall back to zapret2

DoH Providers (censorship-resistant):
  - Cloudflare: https://cloudflare-dns.com/dns-query
  - Google: https://dns.google/dns-query
  - Quad9: https://dns.quad9.net/dns-query
  - PLGames (future): own DoH server in Germany
"""

from __future__ import annotations

import json
import logging
import platform
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from brain.netenv import CURL_DIRECT
logger = logging.getLogger("svoboda.ech")

# DoH providers (JSON API), ordered by reliability from inside RU.
# - IP-URL variants sidestep SNI-based blocking of the DoH hostnames
#   (Flowseal 1.10 even desyncs dns.google / cloudflare-dns.com for this reason).
# - Google JSON lives at /resolve (the /dns-query endpoint is wire-format only,
#   so the old entry never worked); Quad9 JSON is on port 5053.
DOH_PROVIDERS = [
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare-IP", "https://1.1.1.1/dns-query"),
    ("Google", "https://dns.google/resolve"),
    ("Google-IP", "https://8.8.8.8/resolve"),
    ("Quad9", "https://dns.quad9.net:5053/dns-query"),
    ("AdGuard", "https://dns.adguard-dns.com/resolve"),
    ("Mozilla", "https://mozilla.cloudflare-dns.com/dns-query"),
]

# DNS record type for HTTPS/SVCB (contains ECHConfig)
_DNS_TYPE_HTTPS = 65  # HTTPS RR (RFC 9460)
_DNS_TYPE_SVCB = 64   # SVCB RR


@dataclass
class ECHInfo:
    """ECH availability info for a domain."""
    domain: str
    ech_available: bool = False
    ech_config_b64: str = ""       # base64 ECHConfig from DNS
    doh_provider: str = ""         # which DoH returned it
    alpn: list[str] = field(default_factory=list)  # h2, h3, etc.
    target: str = ""               # target name from SVCB


@dataclass
class DoHResult:
    """Result of a DoH query."""
    success: bool = False
    answers: list[dict] = field(default_factory=list)
    provider: str = ""
    latency_ms: float = 0.0
    error: str = ""


class DoHResolver:
    """DNS over HTTPS resolver — bypasses DNS poisoning."""

    def __init__(self, providers: Optional[list[tuple[str, str]]] = None,
                 timeout: int = 5):
        self._providers = providers or DOH_PROVIDERS
        self._timeout = timeout
        self._working_provider: Optional[tuple[str, str]] = None
        self._is_windows = platform.system() == "Windows"

    def resolve(self, domain: str, rtype: str = "A") -> DoHResult:
        """Resolve domain via DoH. Tries providers in order."""
        # Use cached working provider first
        if self._working_provider:
            result = self._query_doh(self._working_provider, domain, rtype)
            if result.success:
                return result

        for provider in self._providers:
            result = self._query_doh(provider, domain, rtype)
            if result.success:
                self._working_provider = provider
                return result

        return DoHResult(error="All DoH providers failed")

    def resolve_https_rr(self, domain: str) -> DoHResult:
        """Resolve HTTPS RR (type 65) — contains ECH keys."""
        return self.resolve(domain, rtype="HTTPS")

    def find_working_provider(self) -> Optional[tuple[str, str]]:
        """Find first working DoH provider."""
        for provider in self._providers:
            result = self._query_doh(provider, "cloudflare.com", "A")
            if result.success:
                logger.info("DoH: working provider = %s (%.0fms)",
                            provider[0], result.latency_ms)
                self._working_provider = provider
                return provider
        return None

    def _query_doh(self, provider: tuple[str, str], domain: str,
                   rtype: str) -> DoHResult:
        """Query a single DoH provider using curl (JSON API)."""
        name, url = provider
        start = time.monotonic()

        try:
            # Use JSON API (simpler than wire format)
            params = f"name={domain}&type={rtype}"
            full_url = f"{url}?{params}"

            result = subprocess.run(
                [
                    "curl", "-s", *CURL_DIRECT,
                    "--max-time", str(self._timeout),
                    "-H", "Accept: application/dns-json",
                    full_url,
                ],
                capture_output=True, text=True,
                timeout=self._timeout + 3,
            )

            latency = (time.monotonic() - start) * 1000

            if result.returncode != 0:
                return DoHResult(provider=name, latency_ms=latency,
                                 error=f"curl exit {result.returncode}")

            data = json.loads(result.stdout)

            if data.get("Status", -1) != 0:
                return DoHResult(provider=name, latency_ms=latency,
                                 error=f"DNS status {data.get('Status')}")

            answers = data.get("Answer", [])
            return DoHResult(
                success=len(answers) > 0,
                answers=answers,
                provider=name,
                latency_ms=latency,
            )

        except json.JSONDecodeError:
            return DoHResult(provider=name, error="Invalid JSON response")
        except subprocess.TimeoutExpired:
            return DoHResult(provider=name, error="Timeout")
        except Exception as exc:
            return DoHResult(provider=name, error=str(exc))


class ECHManager:
    """Manage ECH (Encrypted Client Hello) for SNI encryption.

    Usage:
        ech = ECHManager()
        if ech.setup():
            for host in blocked_hosts:
                info = ech.check_ech(host)
                if info.ech_available:
                    # ECH will encrypt SNI, DPI can't see domain
                    ...
    """

    def __init__(self, config: Optional[dict] = None):
        self._doh = DoHResolver()
        self._ech_cache: dict[str, ECHInfo] = {}
        self._doh_ready = False
        self._config = config or {}
        self._is_windows = platform.system() == "Windows"

    def setup(self) -> bool:
        """Initialize: find working DoH provider."""
        provider = self._doh.find_working_provider()
        if provider:
            self._doh_ready = True
            logger.info("ECH system ready (DoH via %s)", provider[0])
            return True
        logger.warning("ECH: no working DoH provider found")
        return False

    @property
    def is_ready(self) -> bool:
        return self._doh_ready

    def check_ech(self, domain: str) -> ECHInfo:
        """Check if a domain supports ECH via HTTPS RR lookup."""
        if domain in self._ech_cache:
            return self._ech_cache[domain]

        info = ECHInfo(domain=domain)

        if not self._doh_ready:
            self._ech_cache[domain] = info
            return info

        # Query HTTPS RR (type 65) — contains ECHConfig
        result = self._doh.resolve_https_rr(domain)

        if result.success:
            for answer in result.answers:
                data = answer.get("data", "")
                # HTTPS RR format: priority target key=value...
                # Look for ech= parameter (SvcParamKey 5)
                if "ech=" in data.lower():
                    ech_b64 = self._extract_ech_config(data)
                    if ech_b64:
                        info.ech_available = True
                        info.ech_config_b64 = ech_b64
                        info.doh_provider = result.provider
                        logger.info("ECH available for %s (via %s)", domain, result.provider)
                        break

                # Also capture ALPN and target
                if "alpn=" in data.lower():
                    alpn_str = self._extract_param(data, "alpn")
                    info.alpn = alpn_str.split(",") if alpn_str else []
                parts = data.split()
                if len(parts) >= 2:
                    info.target = parts[1].rstrip(".")

        if not info.ech_available:
            logger.debug("ECH not available for %s", domain)

        self._ech_cache[domain] = info
        return info

    def check_multiple(self, domains: list[str]) -> dict[str, ECHInfo]:
        """Check ECH for multiple domains."""
        results = {}
        for domain in domains:
            results[domain] = self.check_ech(domain)
        return results

    def get_ech_domains(self, domains: list[str]) -> list[str]:
        """Return subset of domains that support ECH."""
        return [d for d in domains if self.check_ech(d).ech_available]

    # ─── System DNS configuration ──────────────────────────────────

    def configure_system_doh(self) -> bool:
        """Configure system to use DoH (prevents DNS poisoning).

        WARNING: This changes DNS for ALL system traffic, not just blocked domains.
        Should NOT be called automatically — only on explicit user request.
        For selective DoH, use the DoHResolver directly per-domain.

        Windows 11: native DoH support via netsh.
        Older Windows: set DNS to Cloudflare (1.1.1.1) — not encrypted but
        Cloudflare usually not blocked in RU.
        """
        if not self._is_windows:
            logger.info("System DoH: only Windows supported for auto-config")
            return False

        try:
            # Check Windows version for DoH support (Win 11 / Win 10 21H2+)
            ver = platform.version()
            build = int(ver.split(".")[-1]) if ver else 0

            if build >= 22000:
                # Windows 11+: native DoH via netsh
                return self._configure_win11_doh()
            else:
                # Older: just set DNS servers to Cloudflare
                return self._configure_dns_servers()

        except Exception as exc:
            logger.warning("System DoH config failed: %s", exc)
            return False

    def get_curl_ech_args(self, domain: str) -> list[str]:
        """Get curl arguments for ECH-enabled request.

        Requires curl 8.8+ with ECH support.
        """
        info = self.check_ech(domain)
        if not info.ech_available:
            return []

        args = [
            "--doh-url", self._doh._working_provider[1] if self._doh._working_provider else DOH_PROVIDERS[0][1],
            "--ech", "true",
        ]
        return args

    def get_browser_ech_instructions(self) -> str:
        """Instructions for enabling ECH in browsers."""
        return (
            "Enable ECH (Encrypted Client Hello) in your browser:\n"
            "\n"
            "  Chrome (117+):\n"
            "    1. chrome://flags → search 'Encrypted ClientHello'\n"
            "    2. Enable it\n"
            "    3. Set Secure DNS: Settings → Privacy → Use secure DNS\n"
            "       Provider: Cloudflare (1.1.1.1)\n"
            "\n"
            "  Firefox (118+):\n"
            "    1. about:config → network.dns.echconfig.enabled = true\n"
            "    2. about:config → network.dns.use_https_rr_as_altsvc = true\n"
            "    3. Settings → Privacy → DNS over HTTPS → Max Protection\n"
            "       Provider: Cloudflare\n"
            "\n"
            "  Note: ECH only works for sites that publish ECH keys in DNS.\n"
            "  Major CDNs (Cloudflare, Fastly) support ECH.\n"
            "  When ECH is active, DPI cannot see which site you're visiting."
        )

    # ─── Internal ─────────────────────────────────────────────────

    def _extract_ech_config(self, data: str) -> str:
        """Extract ECH config (base64) from HTTPS RR data string."""
        # Format: "1 . alpn=h2,h3 ech=AAAA... ipv4hint=..."
        parts = data.split()
        for part in parts:
            lower = part.lower()
            if lower.startswith("ech="):
                return part[4:]
        return ""

    def _extract_param(self, data: str, key: str) -> str:
        """Extract a parameter value from SVCB/HTTPS RR data."""
        parts = data.split()
        for part in parts:
            if part.lower().startswith(f"{key}="):
                return part[len(key) + 1:]
        return ""

    def _configure_win11_doh(self) -> bool:
        """Configure Windows 11 native DoH."""
        try:
            # Detect active network interface name
            iface_name = "Ethernet"
            try:
                result = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "interfaces"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "connected":
                        iface_name = " ".join(parts[3:])
                        break
            except Exception:
                pass

            # Set Cloudflare DNS with DoH
            # Windows 11 auto-uses DoH for known DoH-capable servers
            cmds = [
                ["netsh", "interface", "ipv4", "set", "dnsservers",
                 f"name={iface_name}", "static", "1.1.1.1", "primary"],
                ["netsh", "interface", "ipv4", "add", "dnsservers",
                 f"name={iface_name}", "1.0.0.1", "index=2"],
                ["netsh", "interface", "ipv6", "set", "dnsservers",
                 f"name={iface_name}", "static", "2606:4700:4700::1111", "primary"],
            ]

            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=5)

            # Enable DoH via registry (Windows 11)
            subprocess.run([
                "reg", "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                "/v", "EnableAutoDoh", "/t", "REG_DWORD", "/d", "2", "/f",
            ], capture_output=True, timeout=5)

            logger.info("Windows 11 DoH configured (Cloudflare 1.1.1.1)")
            return True

        except Exception as exc:
            logger.warning("Win11 DoH config failed: %s", exc)
            return False

    def _configure_dns_servers(self) -> bool:
        """Set DNS to Cloudflare (not encrypted, but usually not blocked in RU)."""
        try:
            subprocess.run([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                "name=Ethernet", "static", "1.1.1.1", "primary",
            ], capture_output=True, timeout=5)

            subprocess.run([
                "netsh", "interface", "ipv4", "add", "dnsservers",
                "name=Ethernet", "1.0.0.1", "index=2",
            ], capture_output=True, timeout=5)

            logger.info("DNS set to Cloudflare 1.1.1.1 (plain, not DoH)")
            return True
        except Exception as exc:
            logger.warning("DNS config failed: %s", exc)
            return False
