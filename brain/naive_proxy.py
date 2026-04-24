"""NaiveProxy client — HTTPS-masquerading proxy.

NaiveProxy (by klzgrad) wraps traffic in real HTTPS (Chrome network stack),
making it DPI-resistant. We run the client locally as a SOCKS5 endpoint and
route only IP-blocked / desync-unsolvable hosts through it via PAC.

Chain:
  Browser → PAC → SOCKS5 127.0.0.1:1082 → naive → HTTPS → nani.plgames-wow.online:443

This is a "smart" fallback: zapret2 stays primary for 99% of sites (native speed),
naive only activates for hosts zapret2 cannot bypass (Discord HTTP2_STREAM_KILL, IP blocks).

naive is a single binary (~30 MB, Chromium network stack), auto-downloaded on first use.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("svoboda.naive")

# Fallback version if GitHub API is unreachable
_NAIVE_FALLBACK_VERSION = "v131.0.6778.85-1"
_NAIVE_RELEASES_API = "https://api.github.com/repos/klzgrad/naiveproxy/releases/latest"

DEFAULT_LOCAL_PORT = 1084


class NaiveProxy:
    """Manage naive local client → HTTPS-masquerading upstream proxy.

    Usage:
        naive = NaiveProxy(config, "naive+https://user:pass@host:443/?padding=1")
        if naive.start():
            # socks5://127.0.0.1:1082 is now available
            proxy_url = naive.local_proxy_url
        naive.stop()
    """

    def __init__(self, config: dict, proxy_url: str, local_port: int = DEFAULT_LOCAL_PORT):
        self._config = config
        self._proxy_url = proxy_url
        self._local_port = local_port
        self._process: Optional[subprocess.Popen] = None
        self._is_windows = platform.system() == "Windows"
        self._bin_dir = Path(config.get("_base_dir", ".")) / "bin"

    # ─── Public API ────────────────────────────────────────────────────

    @property
    def local_proxy_url(self) -> str:
        """Local SOCKS5 URL after client is up."""
        return f"socks5://127.0.0.1:{self._local_port}"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> bool:
        """Start naive client. Returns True if local SOCKS5 endpoint is ready."""
        if self.is_running:
            logger.debug("naive already running")
            return True

        naive_bin = self._find_or_download_naive()
        if not naive_bin:
            logger.warning("naive binary not available")
            return False

        upstream_url = self._build_upstream_url(self._proxy_url)
        if not upstream_url:
            logger.warning("naive: failed to parse proxy URL")
            return False

        cmd = [
            str(naive_bin),
            f"--listen=socks://127.0.0.1:{self._local_port}",
            f"--proxy={upstream_url}",
        ]

        # Log without credentials
        _display = self._mask_credentials(upstream_url)
        logger.info("Starting naive → %s", _display)

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )

            time.sleep(2)

            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode(errors="replace") if self._process.stderr else ""
                logger.warning("naive exited immediately (rc=%d): %s",
                               self._process.returncode, stderr[:200])
                self._process = None
                return False

            if self._test_local_port():
                logger.info("naive ready: socks5://127.0.0.1:%d", self._local_port)
                return True

            logger.warning("naive started but local port %d not responding", self._local_port)
            self.stop()
            return False

        except FileNotFoundError:
            logger.warning("naive binary not found: %s", naive_bin)
            return False
        except Exception as exc:
            logger.warning("naive start failed: %s", exc)
            return False

    def stop(self) -> None:
        """Stop naive client."""
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
            logger.info("naive stopped")

    # ─── URL handling ──────────────────────────────────────────────────

    def _build_upstream_url(self, url: str) -> Optional[str]:
        """Convert config URL to naive --proxy format.

        Accepts:   naive+https://user:pass@host:443/?padding=1#label
        Produces:  https://user:pass@host:443/?padding=1
        """
        try:
            u = url.strip()
            if u.startswith("naive+"):
                u = u[len("naive+"):]
            # drop URL fragment (#label is just a display name)
            if "#" in u:
                u = u.split("#", 1)[0]
            parsed = urlparse(u)
            if parsed.scheme not in ("https", "http", "quic"):
                logger.warning("naive: unsupported scheme '%s'", parsed.scheme)
                return None
            if not parsed.hostname:
                return None
            return u
        except Exception as exc:
            logger.warning("naive: URL parse failed: %s", exc)
            return None

    @staticmethod
    def _mask_credentials(url: str) -> str:
        """Return URL with user:pass replaced by *:* for logging."""
        try:
            if "://" not in url:
                return url
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                _, hostpart = rest.split("@", 1)
                return f"{scheme}://*:*@{hostpart}"
            return url
        except Exception:
            return url

    # ─── Binary management ─────────────────────────────────────────────

    def _find_or_download_naive(self) -> Optional[Path]:
        """Locate naive binary or fetch it from GitHub releases."""
        ext = ".exe" if self._is_windows else ""

        bundled = self._bin_dir / f"naive{ext}"
        if bundled.exists():
            return bundled

        found = shutil.which("naive") or shutil.which(f"naive{ext}")
        if found:
            return Path(found)

        logger.info("Downloading naive (one-time, ~30 MB)...")
        return self._download_naive()

    def _download_naive(self) -> Optional[Path]:
        """Download naive from GitHub releases.

        Release assets are named like `naiveproxy-vVER-win-x64.tar.xz` or
        `naiveproxy-vVER-linux-x64.tar.xz`. We query the GitHub API for the
        latest release, pick the matching asset, download and extract.
        """
        try:
            self._bin_dir.mkdir(parents=True, exist_ok=True)

            # Determine asset pattern for current platform
            if self._is_windows:
                asset_keywords = ("win", "x64")
            elif platform.system() == "Linux":
                asset_keywords = ("linux", "x64")
            else:
                logger.warning("naive: unsupported platform %s", platform.system())
                return None

            # Query GitHub API for release metadata (may fail behind DPI)
            asset_url, asset_name = self._resolve_release_asset(asset_keywords)
            if not asset_url:
                logger.warning("naive: could not resolve release asset")
                return None

            tmp_dir = Path(tempfile.mkdtemp(prefix="svoboda_naive_"))
            archive_path = tmp_dir / asset_name

            dl_result = subprocess.run(
                [
                    "curl", "-sL",
                    "--max-time", "180",
                    "--connect-timeout", "15",
                    "-o", str(archive_path),
                    "-w", "%{http_code}",
                    asset_url,
                ],
                capture_output=True, text=True, timeout=190,
            )

            http_code = dl_result.stdout.strip() if dl_result.stdout else "?"
            if dl_result.returncode != 0 or not archive_path.exists():
                logger.warning("naive download failed: curl exit=%d, HTTP %s",
                               dl_result.returncode, http_code)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            size_mb = archive_path.stat().st_size / (1024 * 1024)
            if size_mb < 5:
                logger.warning("naive archive too small (%.1f MB, HTTP %s)", size_mb, http_code)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            logger.info("naive downloaded (%.1f MB)", size_mb)

            ext = ".exe" if self._is_windows else ""
            naive_bin = self._bin_dir / f"naive{ext}"

            # Extract — naive uses .tar.xz (Linux) or .zip (Windows, sometimes .tar.xz too)
            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(f"naive{ext}"):
                            with zf.open(name) as src, open(naive_bin, "wb") as dst:
                                dst.write(src.read())
                            break
            elif asset_name.endswith(".tar.xz") or asset_name.endswith(".tar.gz"):
                import tarfile
                mode = "r:xz" if asset_name.endswith(".tar.xz") else "r:gz"
                with tarfile.open(archive_path, mode) as tf:
                    for member in tf.getmembers():
                        if member.name.endswith(f"naive{ext}"):
                            member.name = f"naive{ext}"
                            tf.extract(member, self._bin_dir)
                            break
            else:
                logger.warning("naive: unknown archive format: %s", asset_name)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            if not self._is_windows and naive_bin.exists():
                os.chmod(naive_bin, 0o755)

            shutil.rmtree(tmp_dir, ignore_errors=True)

            if naive_bin.exists():
                logger.info("naive installed: %s", naive_bin)
                return naive_bin

            logger.warning("naive binary missing after extraction")
            return None

        except subprocess.TimeoutExpired:
            logger.warning("naive download timed out")
            return None
        except Exception as exc:
            logger.warning("naive download failed: %s", exc)
            return None

    def _resolve_release_asset(self, keywords):
        """Return (download_url, filename) for matching release asset.

        Tries GitHub API first; if that fails, builds URL from fallback version.
        """
        # Try GitHub API
        try:
            result = subprocess.run(
                ["curl", "-sL", "--max-time", "10", _NAIVE_RELEASES_API],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for asset in data.get("assets", []):
                    name = asset.get("name", "")
                    if all(k in name for k in keywords) and (
                        name.endswith(".tar.xz") or name.endswith(".zip")
                    ):
                        return asset.get("browser_download_url"), name
        except Exception as exc:
            logger.debug("naive: GitHub API lookup failed: %s", exc)

        # Fallback: guess URL from known version pattern
        platform_tag = "win-x64" if self._is_windows else "linux-x64"
        filename = f"naiveproxy-{_NAIVE_FALLBACK_VERSION}-{platform_tag}.tar.xz"
        url = f"https://github.com/klzgrad/naiveproxy/releases/download/{_NAIVE_FALLBACK_VERSION}/{filename}"
        return url, filename

    # ─── Helpers ───────────────────────────────────────────────────────

    def _test_local_port(self) -> bool:
        """Check if local SOCKS5 port is listening."""
        import socket
        try:
            with socket.create_connection(("127.0.0.1", self._local_port), timeout=3):
                return True
        except Exception:
            return False
