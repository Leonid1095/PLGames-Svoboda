"""Cloudflare WARP integration — autonomous proxy for IP-blocked services.

WARP provides a free encrypted tunnel through Cloudflare's network.
When running in proxy mode, it exposes a SOCKS5 proxy on localhost:40000
that routes traffic through Cloudflare, bypassing IP-level blocks.

Flow:
  1. Detect if WARP is installed (warp-cli.exe)
  2. Set proxy mode (SOCKS5 on localhost:40000)
  3. Connect tunnel
  4. IP-blocked traffic goes through SOCKS5 → Cloudflare → destination
  5. SNI-blocked traffic stays on zapret2 (faster, direct)

No server needed — Cloudflare WARP is free.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.warp")

# Default paths for Cloudflare WARP on Windows
_WARP_PATHS_WIN = [
    Path(r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"),
    Path(r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe"),
]

# WARP download URLs
_WARP_DOWNLOAD_URL = "https://1.1.1.1/"
_WARP_DOWNLOAD_URL_DIRECT = "https://install.appcenter.ms/orgs/cloudflare/apps/1.1.1.1-windows-1/distribution_groups/release"

# Default SOCKS5 proxy port in proxy mode
WARP_PROXY_PORT = 40000
WARP_PROXY_HOST = "127.0.0.1"


class WarpManager:
    """Manage Cloudflare WARP for bypassing IP-level blocks.

    Usage:
        warp = WarpManager()
        if warp.is_available():
            if warp.ensure_proxy_mode():
                # SOCKS5 proxy at 127.0.0.1:40000
                proxy_url = warp.proxy_url
        else:
            # Offer to install
            warp.get_install_instructions()
    """

    def __init__(self, proxy_port: int = WARP_PROXY_PORT):
        self._cli_path: Optional[Path] = None
        self._proxy_port = proxy_port
        self._connected = False
        self._is_windows = platform.system() == "Windows"

    # ─── Detection ────────────────────────────────────────────────────

    def find_cli(self) -> Optional[Path]:
        """Find warp-cli binary."""
        if self._cli_path:
            return self._cli_path

        # Check PATH first
        found = shutil.which("warp-cli")
        if found:
            self._cli_path = Path(found)
            return self._cli_path

        # Check known install locations (Windows)
        if self._is_windows:
            for p in _WARP_PATHS_WIN:
                if p.exists():
                    self._cli_path = p
                    return self._cli_path

        # Linux
        for p in [Path("/usr/bin/warp-cli"), Path("/usr/local/bin/warp-cli")]:
            if p.exists():
                self._cli_path = p
                return self._cli_path

        return None

    def is_available(self) -> bool:
        """Check if WARP is installed."""
        return self.find_cli() is not None

    def is_connected(self) -> bool:
        """Check if WARP tunnel is active."""
        cli = self.find_cli()
        if not cli:
            return False
        try:
            result = subprocess.run(
                [str(cli), "status"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.lower()
            connected = "connected" in output and "disconnected" not in output
            self._connected = connected
            return connected
        except Exception as exc:
            logger.debug("WARP status check failed: %s", exc)
            return False

    def get_mode(self) -> str:
        """Get current WARP mode (warp/doh/proxy/off)."""
        cli = self.find_cli()
        if not cli:
            return "unavailable"
        try:
            result = subprocess.run(
                [str(cli), "settings"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.lower()
            if "proxy" in output:
                return "proxy"
            if "warp" in output:
                return "warp"
            if "doh" in output:
                return "doh"
            return "unknown"
        except Exception:
            return "unknown"

    # ─── Setup ────────────────────────────────────────────────────────

    def ensure_proxy_mode(self) -> bool:
        """Set WARP to proxy mode and connect. Returns True if SOCKS5 proxy is ready.

        Proxy mode: WARP exposes SOCKS5 on localhost:40000 instead of routing
        ALL traffic. This lets us route only IP-blocked domains through it
        while keeping zapret2 for SNI-blocked traffic.
        """
        cli = self.find_cli()
        if not cli:
            logger.warning("WARP CLI not found")
            return False

        try:
            # 1. Register if needed (first time or after daemon restart)
            if not self._is_registered():
                logger.info("Registering WARP...")
                # Clean up stale registration first
                subprocess.run(
                    [str(cli), "registration", "delete"],
                    capture_output=True, timeout=5,
                )
                time.sleep(1)
                reg_result = subprocess.run(
                    [str(cli), "registration", "new"],
                    capture_output=True, text=True, timeout=15,
                )
                if reg_result.returncode != 0:
                    logger.warning("WARP registration failed: %s", reg_result.stderr.strip())
                time.sleep(2)

            # 2. Set proxy mode
            logger.info("Setting WARP to proxy mode (SOCKS5 on port %d)...", self._proxy_port)
            subprocess.run(
                [str(cli), "mode", "proxy"],
                capture_output=True, timeout=5,
            )

            # 3. Set proxy port
            subprocess.run(
                [str(cli), "proxy", "port", str(self._proxy_port)],
                capture_output=True, timeout=5,
            )

            # 4. Connect (with retry)
            for attempt in range(3):
                logger.info("Connecting WARP tunnel (attempt %d/3)...", attempt + 1)
                subprocess.run(
                    [str(cli), "connect"],
                    capture_output=True, timeout=15,
                )
                time.sleep(3)

                # 5. Verify
                if self.is_connected():
                    logger.info("WARP proxy ready at %s:%d", WARP_PROXY_HOST, self._proxy_port)
                    self._connected = True
                    return True

                # If registration lost between attempts, re-register
                if not self._is_registered():
                    logger.info("WARP registration lost, re-registering...")
                    subprocess.run([str(cli), "registration", "delete"],
                                   capture_output=True, timeout=5)
                    time.sleep(1)
                    subprocess.run([str(cli), "registration", "new"],
                                   capture_output=True, timeout=15)
                    time.sleep(2)

            logger.warning("WARP failed to connect after 3 attempts")
            return False

        except subprocess.TimeoutExpired:
            logger.warning("WARP setup timed out")
            return False
        except Exception as exc:
            logger.warning("WARP setup failed: %s", exc)
            return False

    def disconnect(self) -> None:
        """Disconnect WARP tunnel."""
        cli = self.find_cli()
        if not cli:
            return
        try:
            subprocess.run(
                [str(cli), "disconnect"],
                capture_output=True, timeout=5,
            )
            self._connected = False
            logger.info("WARP disconnected")
        except Exception:
            pass

    def _is_registered(self) -> bool:
        """Check if WARP has a valid registration."""
        cli = self.find_cli()
        if not cli:
            return False
        try:
            result = subprocess.run(
                [str(cli), "registration", "show"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.lower() + result.stderr.lower()
            # Registration is valid if we see account info and no "missing" errors
            if "missing" in output or "error" in output or "does not exist" in output:
                return False
            return result.returncode == 0 and ("account" in output or "registration" in output)
        except Exception:
            return False

    # ─── Proxy info ───────────────────────────────────────────────────

    @property
    def proxy_url(self) -> str:
        """SOCKS5 proxy URL for use in apps/browsers."""
        return f"socks5://{WARP_PROXY_HOST}:{self._proxy_port}"

    @property
    def proxy_host(self) -> str:
        return WARP_PROXY_HOST

    @property
    def proxy_port(self) -> int:
        return self._proxy_port

    # ─── Test ─────────────────────────────────────────────────────────

    def test_proxy(self, test_host: str = "api.openai.com", timeout: int = 10) -> bool:
        """Test if SOCKS5 proxy can reach an IP-blocked host."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s",
                    "--max-time", str(timeout),
                    "--socks5-hostname", f"{WARP_PROXY_HOST}:{self._proxy_port}",
                    f"https://{test_host}",
                    "-o", "NUL" if self._is_windows else "/dev/null",
                    "-w", "%{http_code}",
                ],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            success = code in {200, 301, 302, 307, 308, 403, 404, 405, 429}
            if success:
                logger.info("WARP proxy test OK: %s → HTTP %d", test_host, code)
            else:
                logger.info("WARP proxy test FAIL: %s → HTTP %d, exit=%d", test_host, code, result.returncode)
            return success
        except Exception as exc:
            logger.debug("WARP proxy test error: %s", exc)
            return False

    # ─── Install instructions ─────────────────────────────────────────

    # ─── Auto-download & install ────────────────────────────────────

    def auto_install(self, silent: bool = True) -> bool:
        """Download and install Cloudflare WARP automatically.

        Downloads the MSI installer, runs it silently, waits for completion.
        Returns True if WARP is installed and ready.
        """
        if self.is_available():
            logger.info("WARP already installed")
            return True

        if not self._is_windows:
            logger.info("WARP auto-install only supported on Windows")
            return False

        logger.info("Downloading Cloudflare WARP installer...")

        try:
            # Download MSI to temp dir
            tmp_dir = Path(tempfile.mkdtemp(prefix="svoboda_warp_"))
            msi_path = tmp_dir / "Cloudflare_WARP.msi"

            # Direct MSI download URL (stable)
            msi_url = "https://1111-releases.cloudflareclient.com/windows/Cloudflare_WARP_Release-x64.msi"

            dl_result = subprocess.run(
                [
                    "curl", "-sL",
                    "--max-time", "120",
                    "--connect-timeout", "15",
                    "-o", str(msi_path),
                    msi_url,
                ],
                capture_output=True, timeout=130,
            )

            if dl_result.returncode != 0 or not msi_path.exists() or msi_path.stat().st_size < 1_000_000:
                logger.warning("WARP download failed (exit=%d, size=%s)",
                               dl_result.returncode,
                               msi_path.stat().st_size if msi_path.exists() else 0)
                self._cleanup_temp(tmp_dir)
                return False

            size_mb = msi_path.stat().st_size / (1024 * 1024)
            logger.info("WARP installer downloaded (%.1f MB)", size_mb)

            # Install MSI
            install_cmd = ["msiexec", "/i", str(msi_path), "/qn", "/norestart"]
            if not silent:
                install_cmd = ["msiexec", "/i", str(msi_path)]

            logger.info("Installing Cloudflare WARP (this may take a minute)...")
            install_result = subprocess.run(
                install_cmd,
                capture_output=True, timeout=120,
            )

            # msiexec returns 0 on success, 3010 on "success, reboot needed"
            if install_result.returncode not in (0, 3010):
                logger.warning("WARP install failed: msiexec exit %d", install_result.returncode)
                self._cleanup_temp(tmp_dir)
                return False

            # Wait for warp-cli to become available
            for _ in range(10):
                time.sleep(2)
                self._cli_path = None  # reset cache
                if self.find_cli():
                    logger.info("WARP installed successfully")
                    self._cleanup_temp(tmp_dir)
                    return True

            logger.warning("WARP installed but warp-cli not found yet")
            self._cleanup_temp(tmp_dir)
            return self.is_available()

        except subprocess.TimeoutExpired:
            logger.warning("WARP install timed out")
            return False
        except Exception as exc:
            logger.warning("WARP auto-install error: %s", exc)
            return False

    def ensure_available(self) -> bool:
        """Ensure WARP is available — install if needed. Returns True if ready."""
        if self.is_available():
            return True
        return self.auto_install()

    @staticmethod
    def _cleanup_temp(tmp_dir: Path) -> None:
        """Remove temp download directory."""
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    @staticmethod
    def get_install_instructions() -> str:
        """Return human-readable install instructions."""
        return (
            "Cloudflare WARP (free VPN for IP-blocked sites):\n"
            f"  Download: {_WARP_DOWNLOAD_URL}\n"
            "  1. Install Cloudflare WARP\n"
            "  2. Restart this tool\n"
            "  3. WARP will be auto-detected and used for IP-blocked sites"
        )

    @staticmethod
    def get_download_url() -> str:
        return _WARP_DOWNLOAD_URL
