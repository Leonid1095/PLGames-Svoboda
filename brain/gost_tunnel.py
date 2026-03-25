"""Gost TLS tunnel — wraps PLGames VPS SOCKS5 proxy in TLS on port 443.

Solves: ISP blocks all ports except 80/443/22, so raw SOCKS5 on :1080
is unreachable. We tunnel SOCKS5 through TLS on :443 via nginx SNI routing.

Chain:
  Client: gost (local :1080) → TLS → proxy.svaboda-shwe.online:443
  VPS:    nginx SNI → stunnel (TLS termination) → microsocks (:1080)

gost is a single Go binary (~15 MB), auto-downloaded on first use.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.gost")

# gost release — single binary, no installer
_GOST_VERSION = "3.0.0-nightly.20250101"
_GOST_DOWNLOAD_BASE = "https://github.com/go-gost/gost/releases/download/v3.0.0-nightly.20250101"
_GOST_FILENAME_WIN = "gost_3.0.0-nightly.20250101_windows_amd64.zip"
_GOST_FILENAME_LINUX = "gost_3.0.0-nightly.20250101_linux_amd64.tar.gz"

# Local port for the SOCKS5 endpoint
DEFAULT_LOCAL_PORT = 1080


class GostTunnel:
    """Manage gost TLS tunnel to PLGames VPS SOCKS5 proxy.

    Usage:
        tunnel = GostTunnel(config)
        if tunnel.start():
            # socks5://127.0.0.1:1080 is now available
            proxy_url = tunnel.local_proxy_url
        tunnel.stop()
    """

    def __init__(self, config: dict, proxy_url: str, local_port: int = DEFAULT_LOCAL_PORT):
        self._config = config
        self._proxy_url = proxy_url  # socks5://user:pass@host:port
        self._local_port = local_port
        self._process: Optional[subprocess.Popen] = None
        self._is_windows = platform.system() == "Windows"
        self._bin_dir = Path(config.get("_base_dir", ".")) / "bin"

    # ─── Public API ────────────────────────────────────────────────────

    @property
    def local_proxy_url(self) -> str:
        """Local SOCKS5 URL after tunnel is up."""
        return f"socks5://127.0.0.1:{self._local_port}"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> bool:
        """Start gost TLS tunnel. Returns True if local SOCKS5 proxy is ready."""
        if self.is_running:
            logger.debug("Gost tunnel already running")
            return True

        gost_bin = self._find_or_download_gost()
        if not gost_bin:
            logger.warning("Could not find or download gost binary")
            return False

        # Build remote URL with TLS
        remote_url = self._build_remote_url(self._proxy_url)
        if not remote_url:
            logger.warning("Failed to parse proxy URL")
            return False

        # gost v3 command:
        # -L :1080                          — listen plain SOCKS5 on local port
        # -F "socks5://user:pass@host:443?tls=true"  — forward through TLS tunnel
        cmd = [
            str(gost_bin),
            "-L", f":{self._local_port}",
            "-F", remote_url,
        ]

        logger.info("Starting gost tunnel → %s",
                     remote_url.split("@")[-1] if "@" in remote_url else remote_url)

        try:
            # Start gost in background
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )

            # Wait for gost to bind
            time.sleep(2)

            if self._process.poll() is not None:
                # gost exited immediately — read stderr for error
                stderr = self._process.stderr.read().decode(errors="replace") if self._process.stderr else ""
                logger.warning("Gost exited immediately (rc=%d): %s",
                               self._process.returncode, stderr[:200])
                self._process = None
                return False

            # Verify local port is listening
            if self._test_local_port():
                logger.info("Gost tunnel ready: socks5://127.0.0.1:%d", self._local_port)
                return True
            else:
                logger.warning("Gost started but local port %d not responding", self._local_port)
                self.stop()
                return False

        except FileNotFoundError:
            logger.warning("Gost binary not found: %s", gost_bin)
            return False
        except Exception as exc:
            logger.warning("Gost start failed: %s", exc)
            return False

    def stop(self) -> None:
        """Stop gost tunnel."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
            logger.info("Gost tunnel stopped")

    # ─── URL building ──────────────────────────────────────────────────

    def _build_remote_url(self, proxy_url: str) -> Optional[str]:
        """Convert config proxy URL to gost -F format with TLS.

        Input:  socks5://user:pass@proxy.svaboda-shwe.online:443
        Output: socks5://user:pass@proxy.svaboda-shwe.online:443?tls=true
        """
        try:
            # Remove scheme
            url = proxy_url
            scheme = "socks5"
            if "://" in url:
                scheme, url = url.split("://", 1)

            # Ensure TLS parameter
            if "?" in url:
                url += "&tls=true"
            else:
                url += "?tls=true"

            return f"{scheme}://{url}"
        except Exception:
            return None

    # ─── Binary management ─────────────────────────────────────────────

    def _find_or_download_gost(self) -> Optional[Path]:
        """Find gost binary or download it."""
        # 1. Check bundled bin/ directory
        ext = ".exe" if self._is_windows else ""
        bundled = self._bin_dir / f"gost{ext}"
        if bundled.exists():
            return bundled

        # 2. Check PATH
        found = shutil.which("gost")
        if found:
            return Path(found)

        # 3. Auto-download
        logger.info("Downloading gost (one-time, ~15 MB)...")
        return self._download_gost()

    def _download_gost(self) -> Optional[Path]:
        """Download gost binary from GitHub releases."""
        try:
            self._bin_dir.mkdir(parents=True, exist_ok=True)

            if self._is_windows:
                filename = _GOST_FILENAME_WIN
            else:
                filename = _GOST_FILENAME_LINUX

            url = f"{_GOST_DOWNLOAD_BASE}/{filename}"
            tmp_dir = Path(tempfile.mkdtemp(prefix="svoboda_gost_"))
            archive_path = tmp_dir / filename

            # Download with curl
            dl_result = subprocess.run(
                [
                    "curl", "-sL",
                    "--max-time", "120",
                    "--connect-timeout", "15",
                    "-o", str(archive_path),
                    url,
                ],
                capture_output=True, timeout=130,
            )

            if dl_result.returncode != 0 or not archive_path.exists():
                logger.warning("Gost download failed (exit=%d)", dl_result.returncode)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            size_mb = archive_path.stat().st_size / (1024 * 1024)
            if size_mb < 1:
                logger.warning("Gost download too small (%.1f MB), likely failed", size_mb)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            logger.info("Gost downloaded (%.1f MB), extracting...", size_mb)

            # Extract
            ext = ".exe" if self._is_windows else ""
            gost_bin = self._bin_dir / f"gost{ext}"

            if filename.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    # Find gost binary in archive
                    for name in zf.namelist():
                        if name.endswith(f"gost{ext}"):
                            with zf.open(name) as src, open(gost_bin, "wb") as dst:
                                dst.write(src.read())
                            break
            elif filename.endswith(".tar.gz"):
                import tarfile
                with tarfile.open(archive_path, "r:gz") as tf:
                    for member in tf.getmembers():
                        if member.name.endswith(f"gost{ext}"):
                            member.name = f"gost{ext}"
                            tf.extract(member, self._bin_dir)
                            break

            # Make executable on Linux
            if not self._is_windows and gost_bin.exists():
                os.chmod(gost_bin, 0o755)

            shutil.rmtree(tmp_dir, ignore_errors=True)

            if gost_bin.exists():
                logger.info("Gost installed: %s", gost_bin)
                return gost_bin

            logger.warning("Gost binary not found after extraction")
            return None

        except subprocess.TimeoutExpired:
            logger.warning("Gost download timed out")
            return None
        except Exception as exc:
            logger.warning("Gost download failed: %s", exc)
            return None

    # ─── Helpers ───────────────────────────────────────────────────────

    def _test_local_port(self) -> bool:
        """Check if local SOCKS5 port is responding."""
        import socket
        try:
            with socket.create_connection(("127.0.0.1", self._local_port), timeout=3):
                return True
        except Exception:
            return False
