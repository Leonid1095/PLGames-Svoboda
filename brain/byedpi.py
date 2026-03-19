"""ByeDPI SOCKS proxy fallback — DPI bypass without admin rights.

When user doesn't have administrator privileges (no WinDivert),
we run ByeDPI (ciadpi.exe) as a local SOCKS5 proxy on 127.0.0.1:1080.
Apps connect through the proxy and ByeDPI applies desync techniques.

Architecture:
    No admin → start ciadpi.exe → SOCKS5 on localhost:1080
    → configure system/browser proxy → traffic goes through ByeDPI
    → ByeDPI applies split/disorder/fake to TLS ClientHello
    → DPI can't detect SNI → connection succeeds

ByeDPI binary is downloaded from GitHub releases if not present.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.byedpi")

# ByeDPI GitHub release info
BYEDPI_REPO = "hufrea/byedpi"
BYEDPI_BINARY = "ciadpi.exe"  # Windows
BYEDPI_BINARY_LINUX = "ciadpi"  # Linux

# Default SOCKS proxy settings
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1080

# Preset strategies for different block types
BYEDPI_PRESETS = {
    "sni_filtering": [
        # Most effective for Russian TSPU SNI-based blocking
        {"name": "disorder+fake", "args": ["--disorder", "1", "--fake", "-1", "--ttl", "8", "--auto=torst"]},
        {"name": "split+disorder", "args": ["--split", "1+s", "--disorder", "1", "--auto=torst"]},
        {"name": "tlsrec+split", "args": ["--tlsrec", "1+s", "--split", "1", "--disorder", "1"]},
        {"name": "oob+split", "args": ["--oob", "1+s", "--split", "1", "--auto=torst"]},
    ],
    "rst_injection": [
        {"name": "fake+ttl", "args": ["--fake", "-1", "--ttl", "6", "--auto=torst"]},
        {"name": "disorder+fake+ttl", "args": ["--disorder", "1", "--fake", "-1", "--ttl", "4"]},
    ],
    "default": [
        {"name": "auto", "args": ["--disorder", "1", "--split", "1+s", "--fake", "-1", "--ttl", "8", "--auto=torst"]},
    ],
}


class ByeDPIFallback:
    """Manages ByeDPI as a SOCKS5 proxy fallback.

    Usage:
        bdpi = ByeDPIFallback(config, base_dir)
        if bdpi.is_available():
            bdpi.start(block_type="sni_filtering")
            # Configure browser to use SOCKS5 127.0.0.1:1080
            bdpi.stop()
    """

    def __init__(self, config: dict, base_dir: str = "."):
        self._base_dir = Path(base_dir)
        self._host = config.get("byedpi_host", DEFAULT_HOST)
        self._port = config.get("byedpi_port", DEFAULT_PORT)
        self._process: Optional[subprocess.Popen] = None
        self._binary: Optional[Path] = None
        self._current_preset: str = ""
        self._is_windows = platform.system() == "Windows"

    def find_binary(self) -> Optional[Path]:
        """Find ciadpi binary in project or PATH."""
        binary_name = BYEDPI_BINARY if self._is_windows else BYEDPI_BINARY_LINUX

        # Search in project directory
        search_paths = [
            self._base_dir / "byedpi" / binary_name,
            self._base_dir / binary_name,
            self._base_dir / "bin" / binary_name,
        ]

        for p in search_paths:
            if p.exists():
                self._binary = p
                logger.info("Found ByeDPI binary: %s", p)
                return p

        # Search in PATH
        found = shutil.which(binary_name)
        if found:
            self._binary = Path(found)
            logger.info("Found ByeDPI in PATH: %s", found)
            return self._binary

        logger.debug("ByeDPI binary not found")
        return None

    def is_available(self) -> bool:
        """Check if ByeDPI can be used."""
        return self.find_binary() is not None

    def download_binary(self) -> bool:
        """Download ByeDPI binary from GitHub releases."""
        try:
            import requests

            # Get latest release
            api_url = f"https://api.github.com/repos/{BYEDPI_REPO}/releases/latest"
            resp = requests.get(api_url, timeout=15)
            if resp.status_code != 200:
                logger.warning("Cannot fetch ByeDPI releases: HTTP %d", resp.status_code)
                return False

            release = resp.json()

            # Find correct asset (ByeDPI uses various naming: ciadpi-*-win*, *x86_64*, *windows*)
            asset_url = None
            asset_name_found = ""
            for asset in release.get("assets", []):
                name = asset["name"].lower()
                if self._is_windows:
                    if ("win" in name or "windows" in name) and ("x86_64" in name or "x64" in name or "amd64" in name) and name.endswith(".zip"):
                        asset_url = asset["browser_download_url"]
                        asset_name_found = asset["name"]
                        break
                else:
                    if ("linux" in name) and ("x86_64" in name or "x64" in name or "amd64" in name) and (".tar" in name or ".gz" in name):
                        asset_url = asset["browser_download_url"]
                        asset_name_found = asset["name"]
                        break
            # Fallback: try any Windows zip
            if not asset_url and self._is_windows:
                for asset in release.get("assets", []):
                    if asset["name"].lower().endswith(".zip") and "win" in asset["name"].lower():
                        asset_url = asset["browser_download_url"]
                        asset_name_found = asset["name"]
                        break

            if not asset_url:
                logger.warning("No ByeDPI binary found for this platform")
                return False

            # Download
            logger.info("Downloading ByeDPI from %s", asset_url)
            resp = requests.get(asset_url, timeout=60, stream=True)

            byedpi_dir = self._base_dir / "byedpi"
            byedpi_dir.mkdir(exist_ok=True)

            archive_path = byedpi_dir / asset["name"]
            with open(archive_path, "wb") as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)

            # Extract
            if archive_path.suffix == ".zip":
                import zipfile
                with zipfile.ZipFile(archive_path) as zf:
                    zf.extractall(byedpi_dir)
            else:
                import tarfile
                with tarfile.open(archive_path) as tf:
                    tf.extractall(byedpi_dir)

            archive_path.unlink()

            # Find binary after extraction
            if self.find_binary():
                logger.info("ByeDPI downloaded successfully")
                return True

            logger.warning("ByeDPI extracted but binary not found")
            return False

        except Exception as exc:
            logger.warning("ByeDPI download failed: %s", exc)
            return False

    def start(self, block_type: str = "default", custom_args: list[str] = None) -> bool:
        """Start ByeDPI SOCKS proxy.

        Args:
            block_type: Type of blocking detected (sni_filtering, rst_injection, default)
            custom_args: Custom ByeDPI arguments (overrides presets)

        Returns:
            True if started successfully
        """
        if self._process and self._process.poll() is None:
            logger.info("ByeDPI already running (pid=%d)", self._process.pid)
            return True

        if not self._binary:
            if not self.find_binary():
                if not self.download_binary():
                    logger.error("ByeDPI binary not available")
                    return False

        # Build command
        cmd = [str(self._binary)]
        cmd.extend(["--ip", self._host, "--port", str(self._port)])

        if custom_args:
            cmd.extend(custom_args)
        else:
            presets = BYEDPI_PRESETS.get(block_type, BYEDPI_PRESETS["default"])
            # Use first preset (best known for this block type)
            cmd.extend(presets[0]["args"])
            self._current_preset = presets[0]["name"]

        logger.info("Starting ByeDPI: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )

            # Wait a moment to check it started
            time.sleep(1)
            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode(errors="replace").strip()
                logger.error("ByeDPI failed to start: %s", stderr[:200])
                self._process = None
                return False

            logger.info("ByeDPI started (pid=%d) on %s:%d, preset=%s",
                        self._process.pid, self._host, self._port, self._current_preset)
            return True

        except Exception as exc:
            logger.error("ByeDPI start error: %s", exc)
            self._process = None
            return False

    def stop(self) -> None:
        """Stop ByeDPI proxy."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            logger.info("ByeDPI stopped")
            self._process = None

    def is_running(self) -> bool:
        """Check if ByeDPI process is alive."""
        return self._process is not None and self._process.poll() is None

    @property
    def proxy_url(self) -> str:
        """SOCKS5 proxy URL for configuration."""
        return f"socks5://{self._host}:{self._port}"

    def test_proxy(self, host: str = "youtube.com", timeout: int = 10) -> bool:
        """Test if proxy works by making a request through it."""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", str(timeout),
                 "--proxy", self.proxy_url,
                 f"https://{host}",
                 "-o", "/dev/null" if not self._is_windows else "NUL",
                 "-w", "%{http_code}"],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            code = result.stdout.strip()
            ok = code in ("200", "301", "302", "403")
            logger.info("ByeDPI proxy test %s: HTTP %s (%s)", host, code, "OK" if ok else "FAIL")
            return ok
        except Exception as exc:
            logger.debug("ByeDPI proxy test failed: %s", exc)
            return False

    def try_presets(self, block_type: str = "default", test_host: str = "youtube.com") -> Optional[str]:
        """Try all presets for a block type and return the one that works.

        Returns preset name or None if nothing works.
        """
        presets = BYEDPI_PRESETS.get(block_type, BYEDPI_PRESETS["default"])

        for preset in presets:
            self.stop()
            logger.info("Trying ByeDPI preset: %s", preset["name"])

            if self.start(custom_args=["--ip", self._host, "--port", str(self._port)] + preset["args"]):
                time.sleep(1)
                if self.test_proxy(test_host):
                    logger.info("ByeDPI preset works: %s", preset["name"])
                    self._current_preset = preset["name"]
                    return preset["name"]

            self.stop()

        logger.warning("No ByeDPI preset worked for block_type=%s", block_type)
        return None

    def configure_system_proxy(self) -> bool:
        """Configure Windows system proxy to use ByeDPI SOCKS.

        Note: This requires registry changes. Not all apps respect system proxy.
        Better to configure browser directly.
        """
        if not self._is_windows:
            return False

        # Create PAC file for SOCKS proxy
        pac_content = f"""function FindProxyForURL(url, host) {{
    // Only proxy HTTPS traffic through ByeDPI
    if (url.substring(0, 5) == "https") {{
        return "SOCKS5 {self._host}:{self._port}; DIRECT";
    }}
    return "DIRECT";
}}"""
        pac_path = self._base_dir / "proxy.pac"
        pac_path.write_text(pac_content, encoding="utf-8")
        logger.info("PAC file written to %s", pac_path)
        return True

    def get_browser_instructions(self, lang: str = "ru") -> str:
        """Return user-friendly instructions for browser configuration."""
        if lang == "ru":
            return f"""
  ByeDPI SOCKS прокси запущен на {self._host}:{self._port}

  Настройка браузера:
    Chrome: Запустите с флагом --proxy-server="socks5://{self._host}:{self._port}"
    Firefox: Настройки → Сеть → Ручная настройка → SOCKS: {self._host}, Порт: {self._port}

  Или установите расширение Proxy SwitchyOmega (Chrome) / FoxyProxy (Firefox)
"""
        else:
            return f"""
  ByeDPI SOCKS proxy running on {self._host}:{self._port}

  Browser setup:
    Chrome: Launch with --proxy-server="socks5://{self._host}:{self._port}"
    Firefox: Settings → Network → Manual proxy → SOCKS: {self._host}, Port: {self._port}

  Or install Proxy SwitchyOmega (Chrome) / FoxyProxy (Firefox) extension
"""

    def get_status(self) -> dict:
        """Return current status for UI/tray."""
        return {
            "running": self.is_running(),
            "host": self._host,
            "port": self._port,
            "preset": self._current_preset,
            "proxy_url": self.proxy_url,
            "pid": self._process.pid if self._process else None,
        }

    # ─── App-specific proxy configuration ──────────────────────────────

    def find_telegram_exe(self) -> Optional[Path]:
        """Find Telegram Desktop executable."""
        if not self._is_windows:
            return None
        candidates = [
            Path(os.environ.get("APPDATA", "")) / "Telegram Desktop" / "Telegram.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Telegram Desktop" / "Telegram.exe",
            Path("C:/Users") / os.environ.get("USERNAME", "") / "AppData" / "Roaming" / "Telegram Desktop" / "Telegram.exe",
        ]
        for p in candidates:
            if p.exists():
                return p
        # Search in Program Files
        for pf in [Path("C:/Program Files"), Path("C:/Program Files (x86)")]:
            tg = pf / "Telegram Desktop" / "Telegram.exe"
            if tg.exists():
                return tg
        return None

    def configure_telegram_proxy(self) -> bool:
        """Configure Telegram Desktop to use ByeDPI SOCKS5 proxy.

        Telegram supports -proxy flag for SOCKS5.
        We kill existing Telegram and restart with proxy configured.
        """
        tg_exe = self.find_telegram_exe()
        if not tg_exe:
            logger.debug("Telegram Desktop not found")
            return False

        # Kill existing Telegram
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "Telegram.exe"],
                capture_output=True, timeout=5,
            )
            time.sleep(1)
        except Exception:
            pass

        # Start Telegram with SOCKS5 proxy
        # Telegram Desktop supports -proxy socks5://host:port
        try:
            subprocess.Popen(
                [str(tg_exe), "-proxy", f"socks5://{self._host}:{self._port}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            logger.info("Telegram started with SOCKS5 proxy %s:%d", self._host, self._port)
            return True
        except Exception as exc:
            logger.warning("Failed to start Telegram with proxy: %s", exc)
            return False

    def find_discord_exe(self) -> Optional[Path]:
        """Find Discord executable."""
        if not self._is_windows:
            return None
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        discord_dir = local / "Discord"
        if discord_dir.exists():
            for d in sorted(discord_dir.glob("app-*"), reverse=True):
                exe = d / "Discord.exe"
                if exe.exists():
                    return exe
        return None

    # ─── TG WS Proxy (WebSocket tunnel for Telegram) ──────────────

    def start_tg_ws_proxy(self, port: int = 1081) -> bool:
        """Start tg-ws-proxy for Telegram (WebSocket tunnel bypass).

        tg-ws-proxy wraps MTProto in WSS — DPI sees HTTPS, not Telegram.
        This is the most reliable method for Telegram when DPI blocks MTProto.

        Install: pip install tg-ws-proxy
        """
        # Check if tg-ws-proxy is installed
        try:
            result = subprocess.run(
                ["tg-ws-proxy", "--help"],
                capture_output=True, timeout=5,
            )
            if result.returncode not in (0, 1):
                raise FileNotFoundError
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Try to install
            logger.info("Installing tg-ws-proxy...")
            try:
                subprocess.run(
                    ["pip", "install", "tg-ws-proxy", "--quiet"],
                    capture_output=True, timeout=60,
                )
            except Exception as exc:
                logger.warning("Failed to install tg-ws-proxy: %s", exc)
                return False

        # Start tg-ws-proxy
        try:
            self._tg_ws_process = subprocess.Popen(
                ["tg-ws-proxy", "--port", str(port), "--host", "127.0.0.1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            time.sleep(1)
            if self._tg_ws_process.poll() is not None:
                logger.error("tg-ws-proxy failed to start")
                return False

            logger.info("tg-ws-proxy started on 127.0.0.1:%d (pid=%d)",
                        port, self._tg_ws_process.pid)
            return True
        except Exception as exc:
            logger.warning("tg-ws-proxy start failed: %s", exc)
            return False

    def stop_tg_ws_proxy(self) -> None:
        """Stop tg-ws-proxy."""
        if hasattr(self, '_tg_ws_process') and self._tg_ws_process:
            try:
                self._tg_ws_process.terminate()
                self._tg_ws_process.wait(timeout=3)
            except Exception:
                pass
            self._tg_ws_process = None
