"""ProxyRouter — smart traffic routing based on block type.

Classifies each blocked host and routes through the appropriate layer:
  SNI_FILTERING   → zapret2 (packet manipulation, fastest)
  IP_BLOCK        → WARP SOCKS5 / user VPS proxy (tunnel)
  DNS_POISONING   → DoH resolution (future)
  THROTTLING      → zapret2 anti-throttle strategies

Autonomous: detects available proxies, sets them up, generates PAC file.
User presses 1 button → everything works.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if platform.system() == "Windows":
    import winreg

logger = logging.getLogger("svoboda.router")


@dataclass
class RouteDecision:
    """Routing decision for a blocked host."""
    host: str
    block_type: str
    route: str          # "zapret2" | "warp" | "user_proxy" | "byedpi" | "unroutable"
    proxy_url: str = ""  # SOCKS5 URL if routed through proxy
    reason: str = ""


@dataclass
class RoutingPlan:
    """Full routing plan for all blocked hosts."""
    zapret2_hosts: list[str] = field(default_factory=list)
    proxy_hosts: list[str] = field(default_factory=list)
    unroutable_hosts: list[str] = field(default_factory=list)
    proxy_url: str = ""
    proxy_type: str = ""  # "warp" | "user_proxy" | "byedpi" | ""
    decisions: list[RouteDecision] = field(default_factory=list)


# Known IP-blocked domains (blocked at IP level in Russia, DPI bypass won't help)
IP_BLOCKED_DOMAINS = {
    # AI services
    "openai.com", "api.openai.com", "chat.openai.com", "platform.openai.com",
    "claude.ai", "api.anthropic.com", "anthropic.com",
    "gemini.google.com", "bard.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "huggingface.co",
    # Social (some fully IP-blocked, not just SNI)
    "linkedin.com", "www.linkedin.com",
    # Telegram Web (TCP OK, but all TLS to these IPs blocked)
    "web.telegram.org", "telegram.org", "t.me",
    # Other
    "medium.com",
    "archive.org",
    "protonmail.com", "proton.me",
}


class ProxyRouter:
    """Smart routing: zapret2 for SNI-blocked, proxy for IP-blocked."""

    def __init__(self, config: dict):
        self.config = config
        self._warp = None
        self._user_proxy: str = config.get("user_proxy", "")
        self._is_windows = platform.system() == "Windows"

    def plan_routing(self, block_results: dict) -> RoutingPlan:
        """Create routing plan based on block classification.

        Args:
            block_results: {host: BlockAnalysis} from BlockageClassifier

        Returns:
            RoutingPlan with per-host routing decisions
        """
        plan = RoutingPlan()

        for host, analysis in block_results.items():
            bt = analysis.block_type

            if bt == "NOT_BLOCKED":
                continue

            # Check if this domain is known to be IP-blocked
            is_ip_blocked = (
                bt in ("IP_BLOCK", "TLS_IP_BLOCK")
                or self._is_known_ip_blocked(host)
                or getattr(analysis, 'recommended_params', {}).get("needs_proxy", False)
            )

            if is_ip_blocked:
                plan.proxy_hosts.append(host)
                plan.decisions.append(RouteDecision(
                    host=host, block_type=bt, route="proxy",
                    reason="IP-blocked, needs tunnel/proxy",
                ))
            else:
                # SNI filtering, RST injection, throttling, etc. → zapret2
                plan.zapret2_hosts.append(host)
                plan.decisions.append(RouteDecision(
                    host=host, block_type=bt, route="zapret2",
                    reason=f"DPI bypass via zapret2 ({bt})",
                ))

        return plan

    def setup_proxy(self, plan: RoutingPlan) -> bool:
        """Set up proxy for IP-blocked hosts. Returns True if proxy is ready.

        Priority:
        1. User's VPS proxy (fastest, user controls)
        2. Cloudflare WARP (free, autonomous)
        3. ByeDPI (local, limited)
        """
        if not plan.proxy_hosts:
            return True  # nothing to proxy

        # 1. Try user's own proxy
        if self._user_proxy:
            if self._test_proxy(self._user_proxy, plan.proxy_hosts[0]):
                plan.proxy_url = self._user_proxy
                plan.proxy_type = "user_proxy"
                for d in plan.decisions:
                    if d.route == "proxy":
                        d.proxy_url = self._user_proxy
                        d.route = "user_proxy"
                logger.info("Using user proxy: %s", self._user_proxy)
                return True
            else:
                logger.warning("User proxy %s failed, trying WARP...", self._user_proxy)

        # 2. Try Cloudflare WARP (auto-install if not present)
        try:
            from brain.warp import WarpManager
            self._warp = WarpManager()

            # Auto-install WARP if not available
            if not self._warp.is_available():
                logger.info("WARP not installed, attempting auto-install...")
                self._warp.auto_install()

            if self._warp.is_available():
                logger.info("WARP detected, setting up proxy mode...")
                if self._warp.ensure_proxy_mode():
                    # Test with first IP-blocked host
                    test_host = plan.proxy_hosts[0]
                    if self._warp.test_proxy(test_host):
                        plan.proxy_url = self._warp.proxy_url
                        plan.proxy_type = "warp"
                        for d in plan.decisions:
                            if d.route == "proxy":
                                d.proxy_url = self._warp.proxy_url
                                d.route = "warp"
                        logger.info("WARP proxy ready for %d IP-blocked hosts", len(plan.proxy_hosts))
                        return True
                    else:
                        logger.warning("WARP connected but can't reach %s", test_host)
                else:
                    logger.warning("WARP connect failed")
            else:
                logger.info("WARP install failed or unavailable")
        except Exception as exc:
            logger.debug("WARP setup error: %s", exc)

        # 3. Mark as unroutable
        for host in plan.proxy_hosts:
            plan.unroutable_hosts.append(host)
            for d in plan.decisions:
                if d.host == host and d.route == "proxy":
                    d.route = "unroutable"
                    d.reason = "IP-blocked, no proxy available"

        return False

    def generate_pac_file(self, plan: RoutingPlan, output_path: Path) -> Optional[Path]:
        """Generate PAC (Proxy Auto-Config) file for browser/system proxy.

        Routes only IP-blocked domains through SOCKS5; everything else DIRECT.
        """
        if not plan.proxy_url or not plan.proxy_hosts:
            return None

        # Parse SOCKS5 URL
        proxy_addr = plan.proxy_url.replace("socks5://", "")

        domains_js = ",\n    ".join(f'"{h}": 1' for h in plan.proxy_hosts)

        pac_content = f"""\
// PLGames Svoboda — auto-generated PAC file
// Routes IP-blocked domains through SOCKS5 proxy ({plan.proxy_type})
// Generated automatically. Do not edit manually.

var PROXY_DOMAINS = {{
    {domains_js}
}};

function FindProxyForURL(url, host) {{
    // Strip www prefix for matching
    var h = host.toLowerCase();
    if (h.indexOf("www.") === 0) h = h.substring(4);

    // Check exact match
    if (PROXY_DOMAINS[h]) {{
        return "SOCKS5 {proxy_addr}; DIRECT";
    }}

    // Check if host is a subdomain of a blocked domain
    for (var domain in PROXY_DOMAINS) {{
        if (h.length > domain.length && h.indexOf("." + domain) === h.length - domain.length - 1) {{
            return "SOCKS5 {proxy_addr}; DIRECT";
        }}
    }}

    return "DIRECT";
}}
"""
        try:
            output_path.write_text(pac_content, encoding="utf-8")
            logger.info("PAC file written to %s", output_path)
            return output_path
        except Exception as exc:
            logger.warning("Failed to write PAC file: %s", exc)
            return None

    def get_browser_instructions(self, plan: RoutingPlan, pac_path: Optional[Path] = None) -> str:
        """Generate user-friendly instructions for routing IP-blocked traffic."""
        lines = []

        if not plan.proxy_hosts:
            return ""

        if plan.proxy_url:
            lines.append(f"  SOCKS5 proxy: {plan.proxy_url} ({plan.proxy_type})")
            lines.append(f"  Proxied domains: {', '.join(plan.proxy_hosts)}")

            if pac_path:
                pac_url = pac_path.as_uri() if hasattr(pac_path, 'as_uri') else f"file:///{pac_path}"
                lines.append(f"\n  Auto-config (PAC): {pac_url}")
                lines.append("  Set as system proxy: Settings → Network → Proxy → Auto-config URL")

            lines.append(f"\n  Manual browser setup:")
            lines.append(f"    Chrome: Settings → System → Proxy → SOCKS5 Host={plan.proxy_url.split('//')[1]}")
            lines.append(f"    Firefox: Settings → Network → Manual proxy → SOCKS5 {plan.proxy_url.split('//')[1]}")

            if any("discord" in h for h in plan.proxy_hosts):
                host_port = plan.proxy_url.replace("socks5://", "").split(":")
                lines.append(f"\n    Discord: Settings → Advanced → SOCKS5 {host_port[0]}:{host_port[1]}")

            if any("telegram" in h for h in plan.proxy_hosts):
                host_port = plan.proxy_url.replace("socks5://", "").split(":")
                lines.append(f"    Telegram: Settings → Data → Proxy → SOCKS5 {host_port[0]}:{host_port[1]}")

        if plan.unroutable_hosts:
            lines.append(f"\n  [!] Cannot route (need VPN/proxy): {', '.join(plan.unroutable_hosts)}")
            try:
                from brain.warp import WarpManager
                if not WarpManager().is_available():
                    lines.append(f"      Install Cloudflare WARP (free): https://1.1.1.1/")
                    lines.append(f"      Or set user_proxy in config.json: \"user_proxy\": \"socks5://your-vps:port\"")
            except Exception:
                lines.append(f"      Set user_proxy in config.json: \"user_proxy\": \"socks5://your-vps:port\"")

        return "\n".join(lines)

    def set_system_proxy(self, plan: RoutingPlan, pac_path: Optional[Path] = None) -> bool:
        """Auto-configure system proxy via Windows Registry (selective, PAC-based).

        Sets PAC URL as system auto-proxy. PAC file contains explicit domain list:
        - Only IP-blocked domains → SOCKS5 proxy
        - Everything else → DIRECT (no proxy, normal connection)

        This does NOT route all traffic through proxy. Only blocked domains are affected.
        On exit, the PAC setting is automatically removed from registry.
        """
        if not self._is_windows:
            logger.info("System proxy auto-set only supported on Windows")
            return False

        if not plan.proxy_url or not pac_path:
            return False

        try:
            pac_url = f"file:///{pac_path.resolve().as_posix()}"
            return self._set_windows_proxy_pac(pac_url)
        except Exception as exc:
            logger.warning("System proxy auto-set failed: %s", exc)
            return False

    def clear_system_proxy(self) -> bool:
        """Remove system proxy setting (restore direct connection)."""
        if not self._is_windows:
            return False
        try:
            return self._clear_windows_proxy()
        except Exception as exc:
            logger.warning("System proxy clear failed: %s", exc)
            return False

    def _set_windows_proxy_pac(self, pac_url: str) -> bool:
        """Set Windows system proxy to use PAC file via Registry.

        Modifies: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
        """
        _REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

        try:
            # Save current settings for restore
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0,
                                 winreg.KEY_READ)
            try:
                old_auto, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            except FileNotFoundError:
                old_auto = ""
            winreg.CloseKey(key)

            # Store backup
            self._old_proxy_pac = old_auto

            # Set PAC URL
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0,
                                 winreg.KEY_SET_VALUE)

            # Enable auto-proxy via PAC
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)

            # Ensure ProxyEnable=0 (PAC handles routing, not manual proxy)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(key)

            # Notify system of proxy change (Internet Explorer / WinHTTP refresh)
            self._notify_proxy_change()

            logger.info("System proxy set to PAC: %s", pac_url)
            return True

        except PermissionError:
            logger.warning("No permission to set system proxy (run as admin)")
            return False
        except Exception as exc:
            logger.warning("Registry proxy set failed: %s", exc)
            return False

    def _clear_windows_proxy(self) -> bool:
        """Remove PAC proxy from Windows Registry — only if it's ours.

        Safety: only removes AutoConfigURL if it points to our proxy.pac file.
        Never touches proxy settings that were set by other software.
        """
        _REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        _OUR_PAC_MARKER = "proxy.pac"  # our PAC file name

        try:
            # First check if current PAC is ours
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0,
                                 winreg.KEY_READ)
            try:
                current_pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            except FileNotFoundError:
                current_pac = ""
            winreg.CloseKey(key)

            # Only remove if it's our PAC (contains our filename)
            if not current_pac or _OUR_PAC_MARKER not in current_pac:
                logger.debug("System proxy not ours ('%s'), not clearing", current_pac)
                return False

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0,
                                 winreg.KEY_SET_VALUE)

            # Restore original PAC if we saved one, otherwise remove
            old = getattr(self, '_old_proxy_pac', '')
            if old and _OUR_PAC_MARKER not in old:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, old)
            else:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass

            winreg.CloseKey(key)
            self._notify_proxy_change()
            logger.info("System proxy cleared (was: %s)", current_pac)
            return True

        except Exception as exc:
            logger.warning("Registry proxy clear failed: %s", exc)
            return False

    @staticmethod
    def _notify_proxy_change() -> None:
        """Notify Windows that proxy settings changed (WinINet refresh)."""
        try:
            import ctypes
            # INTERNET_OPTION_SETTINGS_CHANGED = 39
            # INTERNET_OPTION_REFRESH = 37
            internet = ctypes.windll.wininet
            internet.InternetSetOptionW(0, 39, 0, 0)
            internet.InternetSetOptionW(0, 37, 0, 0)
        except Exception:
            pass

    def shutdown(self) -> None:
        """Clean up: remove system proxy if we set it, keep WARP running."""
        if self._is_windows and hasattr(self, '_old_proxy_pac'):
            self.clear_system_proxy()

    # ─── Internal ─────────────────────────────────────────────────────

    def _is_known_ip_blocked(self, host: str) -> bool:
        """Check if host is in the known IP-blocked list."""
        h = host.lower()
        if h in IP_BLOCKED_DOMAINS:
            return True
        # Check if it's a subdomain of a known blocked domain
        for domain in IP_BLOCKED_DOMAINS:
            if h.endswith("." + domain):
                return True
        return False

    def _test_proxy(self, proxy_url: str, test_host: str) -> bool:
        """Test if a SOCKS5 proxy can reach a host."""
        try:
            # Parse socks5://host:port
            addr = proxy_url.replace("socks5://", "").replace("socks5h://", "")
            result = subprocess.run(
                [
                    "curl", "-s", "--max-time", "10",
                    "--socks5-hostname", addr,
                    f"https://{test_host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}",
                ],
                capture_output=True, text=True, timeout=15,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            return code in {200, 301, 302, 307, 308, 403, 404, 405, 429}
        except Exception:
            return False
