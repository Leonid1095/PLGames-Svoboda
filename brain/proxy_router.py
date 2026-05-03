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
    route: str          # "zapret2" | "warp" | "user_proxy" | "naive" | "telemost" | "byedpi" | "unroutable"
    proxy_url: str = ""  # SOCKS5 URL if routed through proxy
    reason: str = ""


@dataclass
class RoutingPlan:
    """Full routing plan for all blocked hosts."""
    zapret2_hosts: list[str] = field(default_factory=list)
    proxy_hosts: list[str] = field(default_factory=list)
    unroutable_hosts: list[str] = field(default_factory=list)
    proxy_url: str = ""
    proxy_type: str = ""  # "warp" | "user_proxy" | "naive" | "byedpi" | ""
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
    # NOTE: googlevideo.com removed — TLS_INTERFERENCE is ISP-specific (er-telecom).
    # On other ISPs desync works fine. Let classifier decide per-ISP.
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
        self._gost_tunnel = None
        self._telemost = None
        self._naive = None
        self._user_proxy: str = config.get("user_proxy", "")
        self._naive_url: str = config.get("naive_proxy_url", "")
        self._naive_port: int = int(config.get("naive_proxy_socks_port", 1084))
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

            # Check if this domain is known to be IP-blocked or TLS_INTERFERENCE
            # (TLS_INTERFERENCE = DPI corrupts TLS handshake, desync can't fix)
            is_ip_blocked = (
                bt in ("IP_BLOCK", "TLS_IP_BLOCK", "TLS_INTERFERENCE")
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

    def setup_proxy(self, plan: RoutingPlan, tier=None) -> bool:
        """Set up proxy for IP-blocked hosts. Returns True if proxy is ready.

        Priority:
        0. PLGames VPS proxy (PRO tier — included in subscription)
        1. User's VPS proxy (fastest, user controls)
        2. NaiveProxy (HTTPS-masquerading, most DPI-resistant; opt-in via naive_proxy_url)
        3. Cloudflare WARP (free, autonomous — often blocked on TSPU)
        4. Telemost WebRTC (OPT-IN ONLY via telemost_auto=true — needs LIVE
           Yandex Telemost call from user. NOT a 24/7 background tunnel.)
        """
        if not plan.proxy_hosts:
            return True  # nothing to proxy

        # 0. PLGames VPS proxy via gost TLS tunnel (PRO tier or owner)
        if tier and tier.has_vps_proxy:
            plgames_proxy = tier.proxy_url
            if plgames_proxy:
                local_proxy = self._start_gost_tunnel(plgames_proxy, plan.proxy_hosts[0])
                if local_proxy:
                    plan.proxy_url = local_proxy
                    plan.proxy_type = "plgames_vps"
                    for d in plan.decisions:
                        if d.route == "proxy":
                            d.proxy_url = local_proxy
                            d.route = "plgames_vps"
                    logger.info("Using PLGames VPS proxy (TLS tunnel): %s", local_proxy)
                    return True
                else:
                    logger.warning("PLGames VPS proxy unavailable, trying alternatives...")

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

        # 2. NaiveProxy (HTTPS-masquerading proxy — most DPI-resistant)
        if self._naive_url:
            try:
                from brain.naive_proxy import NaiveProxy
                self._naive = NaiveProxy(self.config, self._naive_url, local_port=self._naive_port)
                started = False
                try:
                    started = self._naive.start()
                    if started:
                        naive_local = self._naive.local_proxy_url
                        test_host = plan.proxy_hosts[0]
                        if self._test_proxy(naive_local, test_host):
                            plan.proxy_url = naive_local
                            plan.proxy_type = "naive"
                            for d in plan.decisions:
                                if d.route == "proxy":
                                    d.proxy_url = naive_local
                                    d.route = "naive"
                            logger.info("NaiveProxy ready for %d IP-blocked hosts", len(plan.proxy_hosts))
                            return True
                        logger.warning("NaiveProxy up but can't reach %s", test_host)
                    else:
                        logger.warning("NaiveProxy failed to start")
                except Exception as exc_inner:
                    logger.debug("NaiveProxy test error: %s", exc_inner)
                # Stop naive if we didn't return True
                if started:
                    self._naive.stop()
                self._naive = None
            except Exception as exc:
                logger.debug("NaiveProxy setup error: %s", exc)
                if self._naive:
                    self._naive.stop()
                    self._naive = None

        # 3. Try Cloudflare WARP (auto-install if not present)
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

        # 3. Try Telemost WebRTC tunnel (whitelist bypass)
        try:
            from brain.telemost_tunnel import TelemostTunnel
            telemost_cfg = {
                "telemost_room_id": self.config.get("telemost_room_id", ""),
                "telemost_key": self.config.get("telemost_key", ""),
                "telemost_socks_port": self.config.get("telemost_socks_port", 1083),
            }
            # Telemost requires a LIVE Yandex Telemost call running on the
            # user's side — they must keep the call open for the tunnel to
            # exist. This makes Telemost UNUSABLE as a 24/7 background
            # fallback. Opt-in only: requires explicit `telemost_auto: true`
            # in config AND credentials. Default is to skip the entire block
            # so we don't waste 20 seconds connecting to a stale call.
            telemost_optin = bool(self.config.get("telemost_auto", False))
            if (telemost_optin
                and telemost_cfg["telemost_room_id"]
                and telemost_cfg["telemost_key"]):
                ok, dep_msg = TelemostTunnel.check_dependencies()
                if ok:
                    self._telemost = TelemostTunnel(telemost_cfg)
                    started = False
                    try:
                        started = self._telemost.start(timeout=20)
                        if started:
                            test_host = plan.proxy_hosts[0]
                            if self._test_proxy(self._telemost.local_proxy_url, test_host):
                                plan.proxy_url = self._telemost.local_proxy_url
                                plan.proxy_type = "telemost"
                                for d in plan.decisions:
                                    if d.route == "proxy":
                                        d.proxy_url = self._telemost.local_proxy_url
                                        d.route = "telemost"
                                logger.info("Telemost tunnel ready for %d IP-blocked hosts", len(plan.proxy_hosts))
                                return True
                            else:
                                logger.warning("Telemost tunnel up but can't reach %s", test_host)
                        else:
                            logger.warning("Telemost tunnel failed to start")
                    except Exception as exc_inner:
                        logger.debug("Telemost tunnel test error: %s", exc_inner)
                    # Always stop if we didn't return True
                    if started:
                        self._telemost.stop()
                    self._telemost = None
                else:
                    logger.debug("Telemost tunnel deps missing: %s", dep_msg)
        except Exception as exc:
            logger.debug("Telemost tunnel setup error: %s", exc)
            if self._telemost:
                self._telemost.stop()
                self._telemost = None

        # 4. Mark remaining as unroutable, but fallback TLS_INTERFERENCE to zapret2
        for host in plan.proxy_hosts:
            # TLS_INTERFERENCE: desync might partially work, better than nothing
            host_bt = next((d.block_type for d in plan.decisions if d.host == host), "")
            if host_bt == "TLS_INTERFERENCE":
                plan.zapret2_hosts.append(host)
                for d in plan.decisions:
                    if d.host == host and d.route == "proxy":
                        d.route = "zapret2"
                        d.reason = "TLS_INTERFERENCE fallback to desync (no proxy)"
                logger.info("TLS_INTERFERENCE fallback: %s → desync (no proxy available)", host)
            else:
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

        # Parse SOCKS5 URL (strip auth for PAC — PAC doesn't support auth)
        proxy_addr = plan.proxy_url.replace("socks5://", "")
        if "@" in proxy_addr:
            proxy_addr = proxy_addr.split("@", 1)[1]  # host:port only

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
            # Display URL without password in output
            _display_url = plan.proxy_url
            if "@" in _display_url:
                _scheme, _rest = _display_url.split("://", 1)
                _hostport = _rest.split("@", 1)[1]
                _display_url = f"{_scheme}://*:*@{_hostport}"
            lines.append(f"  SOCKS5 proxy: {_display_url} ({plan.proxy_type})")
            lines.append(f"  Proxied domains: {', '.join(plan.proxy_hosts)}")

            # Parse host:port for instructions (strip auth)
            _raw = plan.proxy_url.replace("socks5://", "").replace("socks5h://", "")
            if "@" in _raw:
                _auth, _hp = _raw.split("@", 1)
            else:
                _auth, _hp = "", _raw

            if pac_path:
                pac_url = pac_path.as_uri() if hasattr(pac_path, 'as_uri') else f"file:///{pac_path}"
                lines.append(f"\n  Auto-config (PAC): {pac_url}")
                lines.append("  Set as system proxy: Settings → Network → Proxy → Auto-config URL")

            if any("telegram" in h for h in plan.proxy_hosts):
                lines.append(f"\n    Telegram: Settings → Advanced → Proxy → SOCKS5")
                lines.append(f"      Server: {_hp.split(':')[0]}  Port: {_hp.split(':')[1] if ':' in _hp else '1080'}")
                if _auth and ":" in _auth:
                    _user = _auth.split(':')[0]
                    _pass = _auth.split(':')[1]
                    _masked = _pass[:2] + '*' * max(len(_pass) - 2, 0)
                    lines.append(f"      Username: {_user}  Password: {_masked}")

        if plan.unroutable_hosts:
            lines.append(f"\n  [!] Cannot route (need VPN/proxy): {', '.join(plan.unroutable_hosts)}")
            lines.append(f"      Add to config.json: \"user_proxy\": \"socks5://your-vps:port\"")
            lines.append(f"      Or SSH tunnel: ssh -D 1080 user@your-vps")
            # Check if WARP is blocked vs not installed
            try:
                from brain.warp import WarpManager
                warp = WarpManager()
                if warp.is_available() and warp._is_blocked_by_isp():
                    lines.append(f"      (WARP blocked by ISP — use VPS proxy instead)")
                elif not warp.is_available():
                    lines.append(f"      Or install Cloudflare WARP (free): https://1.1.1.1/")
            except Exception:
                pass

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
        """Clean up: remove system proxy, stop tunnels."""
        if self._is_windows and hasattr(self, '_old_proxy_pac'):
            self.clear_system_proxy()
        if self._gost_tunnel:
            self._gost_tunnel.stop()
            self._gost_tunnel = None
        if getattr(self, '_telemost', None):
            self._telemost.stop()
            self._telemost = None
        if getattr(self, '_naive', None):
            self._naive.stop()
            self._naive = None

    # ─── Internal ─────────────────────────────────────────────────────

    def _start_gost_tunnel(self, plgames_proxy: str, test_host: str) -> Optional[str]:
        """Start TLS tunnel and return local proxy URL if working.

        Uses pure-Python SOCKS5-over-TLS tunnel (gost sends custom SOCKS5
        methods that microsocks doesn't understand).

        Returns socks5://127.0.0.1:PORT or None if failed.
        """
        try:
            from brain.tls_tunnel import TLSTunnel

            self._gost_tunnel = TLSTunnel.from_proxy_url(plgames_proxy, local_port=1082)
            if not self._gost_tunnel.start():
                self._gost_tunnel = None
                return None

            local_url = self._gost_tunnel.local_proxy_url
            # Test if tunnel actually reaches the target
            if self._test_proxy(local_url, test_host):
                return local_url

            logger.warning("TLS tunnel started but cannot reach %s", test_host)
            self._gost_tunnel.stop()
            self._gost_tunnel = None
            return None
        except Exception as exc:
            logger.warning("TLS tunnel setup failed: %s", exc)
            if self._gost_tunnel:
                self._gost_tunnel.stop()
                self._gost_tunnel = None
            return None

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
        """Test if a SOCKS5 proxy can reach a host.

        Supports auth: socks5://user:pass@host:port
        """
        try:
            # curl --proxy handles full URL with auth natively
            result = subprocess.run(
                [
                    "curl", "-s", "--max-time", "10",
                    "--ssl-no-revoke",
                    "--proxy", proxy_url,
                    f"https://{test_host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}",
                ],
                capture_output=True, text=True, timeout=15,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            success = code in {200, 301, 302, 307, 308, 403, 404, 405, 429}
            if success:
                logger.info("Proxy test OK: %s → HTTP %d via %s",
                           test_host, code, proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url)
            return success
        except Exception as exc:
            logger.debug("Proxy test failed: %s", exc)
            return False
