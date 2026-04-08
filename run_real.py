"""
PLGames Svoboda — DPI Bypass Tool (Production Mode)

Real mode: evolves strategies with actual winws2.exe + WinDivert,
tests real connections, applies best strategy permanently,
monitors with watchdog.

Requires administrator privileges for WinDivert driver.

Usage:
    python run_real.py
"""

from __future__ import annotations

import atexit
import json
import logging
import platform
import shutil
import signal
import subprocess
import sys
import io
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Fix Windows console encoding + force line-buffered output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))


# ─── Safety: kill ALL winws2 on exit ─────────────────────────────────────────

def _emergency_cleanup():
    """Kill ALL child processes and restore network on exit.

    Prevents: WinDivert driver staying loaded (breaks internet),
    PAC proxy pointing to dead file (partial internet),
    gost tunnel lingering (port conflict on next run).
    """
    if platform.system() == "Windows":
        # 1. Kill winws2 + gost
        for proc_name in ("winws2.exe", "gost.exe"):
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", proc_name],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            except Exception:
                pass

        # 2. Remove PAC proxy from registry (direct, no dependency on ProxyRouter)
        try:
            import winreg
            _REG = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG, 0, winreg.KEY_ALL_ACCESS)
            try:
                pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                if pac_url and "proxy.pac" in pac_url:
                    winreg.DeleteValue(key, "AutoConfigURL")
            except FileNotFoundError:
                pass
            # Ensure manual proxy is off
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            # Notify system
            try:
                import ctypes
                ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            except Exception:
                pass
        except Exception:
            pass
    else:
        try:
            subprocess.run(
                ["pkill", "-f", "nfqws2"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:
            pass

    # 3. Remove DNS fix entries from hosts file
    try:
        from brain.dns_fixer import remove_hosts_entries
        remove_hosts_entries()
    except Exception:
        pass

atexit.register(_emergency_cleanup)

# Windows: catch console close (X button), Ctrl+C, logoff, shutdown
if platform.system() == "Windows":
    try:
        import ctypes
        _kernel32 = ctypes.windll.kernel32

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
        def _console_handler(event):
            # 0=CTRL_C, 1=CTRL_BREAK, 2=CLOSE, 5=LOGOFF, 6=SHUTDOWN
            _emergency_cleanup()
            return False  # let default handler run too

        _kernel32.SetConsoleCtrlHandler(_console_handler, True)
    except Exception:
        pass

from brain.analytics import Analytics
from brain.ai_advisor import AIAdvisor
from brain.donate import DonateManager
from brain.genetic import GAConfig, StrategyGene
from brain.manager import StrategyManager
from brain.profiler import ISPProfiler, ISP_SEED_STRATEGIES
from brain.sync import ServerSync
from brain.tester import ConnectionTester
from brain.tier import TierManager

logger = logging.getLogger("svoboda")

# ─── Globals ──────────────────────────────────────────────────────────────────

_running = True
_active_process: Optional[subprocess.Popen] = None
_tspu_recommended_ttl: int = 0  # set by TSPU profiler, used by permanent winws2


def _signal_handler(signum, frame):
    global _running
    _running = False
    from brain.ui import C, warn
    warn("Stopping... (please wait)")


def _print_header():
    from brain.ui import print_banner
    print_banner()


def _find_zapret_binary(base_dir: Path) -> Optional[Path]:
    """Find winws2.exe or nfqws2 binary."""
    is_win = platform.system() == "Windows"
    name = "winws2.exe" if is_win else "nfqws2"

    # Search in zapret2 directories
    pattern = "zapret2*/binaries/windows-x86_64" if is_win else "zapret2*/binaries/linux-*"
    for zdir in sorted(base_dir.glob(pattern), reverse=True):
        p = zdir / name
        if p.exists():
            return p

    # Fallback: bin/, PATH, project root
    for p in [base_dir / "bin" / name, base_dir / name]:
        if p.exists():
            return p

    found = shutil.which(name)
    return Path(found) if found else None


def _find_lua_dir(base_dir: Path) -> Optional[Path]:
    """Find zapret2 Lua libraries."""
    for zdir in sorted(base_dir.glob("zapret2*/lua"), reverse=True):
        if (zdir / "zapret-lib.lua").exists():
            return zdir
    return None


def _download_hostlist(base_dir: Path) -> Optional[Path]:
    """Download blocked domains list from antizapret/refilter.

    Returns path to hostlist file, or None if download failed.
    Uses cached list if less than 24h old.
    """
    hostlist_path = base_dir / "hostlist.txt"
    auto_path = base_dir / "hostlist-auto.txt"

    # Create auto-hostlist file if missing (winws2 needs it to exist)
    if not auto_path.exists():
        auto_path.write_text("", encoding="utf-8")

    # Use cached if fresh (< 24h)
    if hostlist_path.exists():
        age_hours = (time.time() - hostlist_path.stat().st_mtime) / 3600
        if age_hours < 24:
            lines = hostlist_path.read_text(encoding="utf-8", errors="replace").strip().split("\n")
            print(f"  [OK] Hostlist cached: {len(lines)} domains")
            return hostlist_path

    # Try refilter first (faster, GitHub CDN)
    urls = [
        ("Re-filter", "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/domains_all.lst"),
        ("Antizapret", "https://antizapret.prostovpn.org:8443/domains-export.txt"),
    ]

    for name, url in urls:
        print(f"  Downloading {name} blocklist...")
        try:
            result = subprocess.run(
                ["curl", "-sL", "--max-time", "30", "--connect-timeout", "10", url],
                capture_output=True, timeout=40,
            )
            if result.returncode == 0 and len(result.stdout) > 10000:
                hostlist_path.write_bytes(result.stdout)
                lines = result.stdout.decode(errors="replace").strip().split("\n")
                print(f"  [OK] {name}: {len(lines)} domains")
                return hostlist_path
        except Exception as exc:
            print(f"  [!] {name} download failed: {exc}")

    # Fallback: write minimal list of known blocked domains
    if not hostlist_path.exists():
        minimal = [
            "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
            "discord.com", "discord.gg", "discordapp.com", "discord.media",
            "gateway.discord.gg", "cdn.discordapp.com",
            "twitter.com", "x.com", "twimg.com", "t.co",
            "facebook.com", "instagram.com", "whatsapp.com",
            "tiktok.com", "linkedin.com", "medium.com",
            "rutracker.org", "nnmclub.to",
        ]
        hostlist_path.write_text("\n".join(minimal) + "\n", encoding="utf-8")
        print(f"  [!] Using minimal built-in hostlist ({len(minimal)} domains)")

    return hostlist_path


def _start_permanent_zapret(
    binary: Path, lua_dir: Optional[Path], flags: list[str],
    hostlist: Optional[Path] = None, tspu_ttl: int = 0,
    config: Optional[dict] = None,
    extra_profiles: list[str] = None,
) -> Optional[subprocess.Popen]:
    """Start winws2/nfqws2 permanently with the given strategy.

    Uses hostlist for targeted domain filtering + hostlist-auto for
    automatic detection of new blocked domains.

    SAFETY: Always kills any existing winws2 before starting a new one.
    Multiple WinDivert instances cause routing conflicts (partial internet).
    """
    global _active_process
    # Kill previous winws2 to prevent WinDivert conflicts
    if _active_process is not None:
        _stop_permanent_zapret(_active_process)
        _active_process = None

    import os
    cmd = [str(binary)]
    is_win = platform.system() == "Windows"
    cwd = str(binary.parent) if is_win else None
    _streamer_mode = config.get("streamer_mode", False) if config else False

    if is_win:
        if _streamer_mode:
            # Streamer mode: minimal WinDivert filter to reduce overhead.
            # Only intercept TCP 80,443 — no extra UDP ports.
            # This prevents latency spikes on OBS/streaming traffic.
            cmd.extend([
                "--wf-tcp-out=80,443",
                "--wf-udp-out=443",
            ])
        else:
            cmd.extend([
                "--wf-tcp-out=80,443,2053,2083,2087,2096,8443",  # +Discord media ports
                "--wf-udp-out=443,50000-50100",  # +Discord voice/video ports
            ])
    else:
        cmd.extend(["--qnum=200"])

    # Load Lua libraries (relative paths to avoid spaces-in-path issues)
    if lua_dir:
        base = str(binary.parent)
        lib = lua_dir / "zapret-lib.lua"
        antidpi = lua_dir / "zapret-antidpi.lua"
        auto = lua_dir / "zapret-auto.lua"
        if lib.exists():
            cmd.append(f"--lua-init=@{os.path.relpath(str(lib), base)}")
        if antidpi.exists():
            cmd.append(f"--lua-init=@{os.path.relpath(str(antidpi), base)}")
        # NOTE: zapret-auto.lua disabled — it may interfere with multi-profile
        # mode. Shadow tester works without it, permanent doesn't.
        # if auto.exists():
        #     cmd.append(f"--lua-init=@{os.path.relpath(str(auto), base)}")

    # Traffic morphing: apply browser TLS profile
    from brain.morpher import TrafficMorpher
    morpher = TrafficMorpher(
        profile_name=config.get("morphing_profile", "chrome_win") if config else "chrome_win",
        enabled=config.get("morphing_enabled", True) if config else True,
    )
    # NOTE: tls_init disabled — the lua-init with spaces in argument
    # ("fake_default_tls = tls_mod(...)") may break subsequent profiles.
    # Morphing is applied per-call via morph_strategy() instead.
    # tls_init = morpher.get_tls_init()
    # if tls_init:
    #     cmd.append(f"--lua-init={tls_init}")

    # Hostlist: copy to binary dir to avoid path issues
    if hostlist and hostlist.exists():
        import shutil
        bin_dir = binary.parent
        local_hostlist = bin_dir / "hostlist.txt"
        local_auto = bin_dir / "hostlist-auto.txt"
        try:
            shutil.copy2(str(hostlist), str(local_hostlist))
            if not local_auto.exists():
                local_auto.write_text("", encoding="utf-8")
            cmd.append("--hostlist=hostlist.txt")
            cmd.append("--hostlist-auto=hostlist-auto.txt")
            if _streamer_mode:
                # Streamer: high threshold prevents streaming CDNs from being
                # accidentally added to auto-hostlist during normal packet loss
                cmd.append("--hostlist-auto-fail-threshold=20")
                cmd.append("--hostlist-auto-fail-time=120")
            else:
                cmd.append("--hostlist-auto-fail-threshold=8")
                cmd.append("--hostlist-auto-fail-time=60")
            # Exclude Russian services (don't break yandex, vk, mail, etc.)
            exclude_src = Path(config.get("_base_dir", ".")) / "list-exclude.txt" if config else None
            if exclude_src and exclude_src.exists():
                local_exclude = bin_dir / "list-exclude.txt"
                try:
                    shutil.copy2(str(exclude_src), str(local_exclude))
                    cmd.append("--hostlist-exclude=list-exclude.txt")
                except Exception:
                    pass
        except Exception as exc:
            print(f"  [!] Hostlist copy failed: {exc} (running without hostlist)")

    # Recommended fake TTL from TSPU profiler
    # IMPORTANT: DPI may be at hop 3, but CDN edge servers (ytimg, ggpht) are
    # often at hop 5-8. Using TTL=2 kills fakes before DPI AND real packets
    # get corrupted on CDN routes. Minimum TTL=3, default=4.
    quic_ttl = max(tspu_ttl, 3) if tspu_ttl and tspu_ttl > 0 else 4

    # ══════════════════════════════════════════════════════════════
    # Domains that need special handling (excluded from aggressive desync)
    # ══════════════════════════════════════════════════════════════
    # YouTube video: all domains that serve video streams or YouTube API
    # (from OWX-FIX list-google.txt + own testing)
    _yt_video_domains = (
        "googlevideo.com,youtube.com,youtu.be,youtube-nocookie.com,"
        "youtubei.googleapis.com,youtube-ui.l.google.com,"
        "wide-youtube.l.google.com,yt-video-upload.l.google.com"
    )
    # YouTube images: CDN for thumbnails/avatars (NO aggressive desync)
    _yt_image_domains = "ytimg.com,ytimg.l.google.com,ggpht.com,googleusercontent.com,jnn-pa.googleapis.com"
    _yt_cdn_domains = f"{_yt_video_domains},{_yt_image_domains}"
    # Discord: all subdomains (from OWX-FIX list-general.txt)
    _discord_domains = (
        "discord.com,discordapp.com,discordapp.net,discord.gg,"
        "discord.media,discordcdn.com,discord.app,discord.dev,"
        "gateway.discord.gg,updates.discord.com"
    )
    # Critical services that must NEVER be desync'd (breaks Claude Code, Steam, etc.)
    _never_desync = "anthropic.com,claude.ai,openai.com,cursor.sh,github.com,githubusercontent.com,steam.com,steampowered.com,steamstatic.com,microsoft.com,visualstudio.com"
    _gentle_exclude = f"{_yt_cdn_domains},{_discord_domains},{_never_desync}"
    if _streamer_mode:
        _gentle_exclude += (
            ",live.twitch.tv,video-edge.abs.hls.ttvnw.net,usher.ttvnw.net"
            ",ingest.twitch.tv,video-weaver.twitch.tv"
            ",upload.youtube.com,obsproject.com"
            ",live-api-s.facebook.com,edgevideo.svc.7sn.net"
            ",akamaihd.net,cloudfront.net"
        )

    # SNI proxy: winws2 desync MUST be applied to SNI proxy traffic.
    # The combo works: winws2 hides SNI from TSPU, SNI proxy reads full SNI and routes.
    # Do NOT use --ipset-exclude-ip — that breaks video/CDN through SNI proxy.
    _sni_ip = None  # intentionally disabled

    # ══════════════════════════════════════════════════════════════
    # ADAPTIVE PROFILES: use the FOUND strategy everywhere.
    #
    # Old approach: hardcode different strategies per profile.
    # Problem: enumerator finds working strategy, but only Profile 1
    # uses it. YouTube/Discord profiles had their own (broken) strategies.
    #
    # New approach: the found strategy (`flags`) IS the bypass.
    # All profiles use it. For CDN-sensitive profiles (images), we
    # strip fake/fakedsplit (corrupts close CDN) but keep everything else.
    # ══════════════════════════════════════════════════════════════

    # Build CDN-safe version of strategy: remove fake packets that
    # corrupt connections to close CDN servers (5-8 hops).
    _cdn_unsafe_funcs = ("fake:", "fakedsplit:")
    _safe_flags = [f for f in flags if not any(f.startswith(u) for u in _cdn_unsafe_funcs)]
    if not _safe_flags:
        # If strategy was ONLY fake-based, fall back to proven safe default
        _safe_flags = ["multidisorder:pos=1,midsld:seqovl=681"]

    # ══════════════════════════════════════════════════════════════
    # PROFILE 1: TLS (general — all HTTPS except YouTube/Discord)
    # Uses full found strategy including fake if present.
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--filter-tcp=443",
        "--filter-l7=tls",
        f"--hostlist-exclude-domains={_gentle_exclude}",
    ])
    if _sni_ip:
        cmd.append(f"--ipset-exclude-ip={_sni_ip}")
    morph_calls = morpher.get_permanent_calls()
    for mc in morph_calls:
        cmd.append(f"--lua-desync={mc}")
    morphed_flags = morpher.morph_strategy(flags)
    for call in morphed_flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 2a: TLS for YouTube video (googlevideo, youtube.com)
    # Uses FOUND strategy — same as general. If AI/enumerator found
    # it works for youtube.com, it works for googlevideo.com too.
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--new",
        "--filter-tcp=443",
        "--filter-l7=tls",
        f"--hostlist-domains={_yt_video_domains}",
    ])
    for call in flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 2b: TLS for YouTube images (ytimg, ggpht)
    # CDN-safe: no fake (CDN edge at 5-8 hops, fake corrupts them).
    # Uses found strategy with fake stripped out.
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--new",
        "--filter-tcp=443",
        "--filter-l7=tls",
        f"--hostlist-domains={_yt_image_domains}",
    ])
    for call in _safe_flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 3: TLS for Discord
    # Uses FOUND strategy — same as general.
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--new",
        "--filter-tcp=443",
        "--filter-l7=tls",
        f"--hostlist-domains={_discord_domains}",
    ])
    for call in flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 4: HTTP (port 80)
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--new",
        "--filter-tcp=80",
        "--filter-l7=http",
    ])
    for call in flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 5: Discord media (TCP ports 2053-8443)
    # Streamer mode: skip — these ports add WinDivert overhead
    # ══════════════════════════════════════════════════════════════
    if not _streamer_mode:
        cmd.extend([
            "--new",
            "--filter-tcp=2053,2083,2087,2096,8443",
            "--filter-l7=tls",
        ])
        for call in flags:
            cmd.append(f"--lua-desync={call}")

        # ══════════════════════════════════════════════════════════════
        # PROFILE 6: Discord voice (UDP 50000-50100)
        # ══════════════════════════════════════════════════════════════
        cmd.extend([
            "--new",
            "--filter-udp=50000-50100",
            f"--lua-desync=fake:blob=fake_default_quic:ip_ttl={quic_ttl}:ip6_ttl={quic_ttl}:repeats=12",
        ])

    # ══════════════════════════════════════════════════════════════
    # PROFILE 6: QUIC (YouTube video + other UDP/443)
    # fake with known TTL from TSPU profiler
    # ══════════════════════════════════════════════════════════════
    quic_profile = [
        "--new",
        "--filter-udp=443",
        "--filter-l7=quic",
        "--payload=quic_initial",
        f"--lua-desync=fake:blob=fake_default_quic:ip_ttl={quic_ttl}:ip6_ttl={quic_ttl}:repeats=11",
    ]
    # Add Telegram IP ranges if ipset file exists
    tg_ipset = Path(cwd) / ".." / ".." / ".." / "telegram_ips.txt"
    if not tg_ipset.exists():
        tg_ipset = Path(config.get("_base_dir", ".")) / "telegram_ips.txt" if config else None
    if tg_ipset and tg_ipset.exists():
        try:
            import shutil
            dest = Path(cwd) / "telegram_ips.txt"
            if not dest.exists():
                shutil.copy2(tg_ipset, dest)
            quic_profile.insert(1, "--ipset=telegram_ips.txt")
        except Exception:
            pass
    cmd.extend(quic_profile)

    # Add extra per-host profiles if any
    if extra_profiles:
        cmd.extend(extra_profiles)

    # Kill any existing winws2 before starting new one (prevents dual-process conflicts)
    # This is critical for early-start → full-start replacement
    try:
        if is_win:
            subprocess.run(
                ["taskkill", "/F", "/IM", "winws2.exe"],
                capture_output=True, timeout=5,
            )
        else:
            subprocess.run(["pkill", "-f", "nfqws2"], capture_output=True, timeout=5)
        time.sleep(1)  # wait for WinDivert driver to unload
    except Exception:
        pass

    log = logging.getLogger("svoboda")
    log.info("Permanent winws2 cmd: %s", " ".join(cmd))
    log.info("Permanent winws2 cwd: %s", cwd)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd=cwd,
            creationflags=subprocess.CREATE_NO_WINDOW if is_win else 0,
        )
        time.sleep(2)
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            print(f"  [ERROR] winws2 exited immediately: {stderr[:300]}")
            log.error("Permanent winws2 crashed: %s", stderr[:500])
            return None
        log.info("Permanent winws2 started (pid=%d)", proc.pid)
        # Flush DNS cache so browser picks up real IPs instead of cached blocked
        _flush_dns_cache()
        return proc
    except Exception as exc:
        print(f"  [ERROR] Failed to start winws2: {exc}")
        log.error("Permanent winws2 launch error: %s", exc)
        return None


def _flush_dns_cache() -> None:
    """Flush system DNS cache after zapret2 starts.

    Without this, browsers (Chrome/Firefox) keep cached DNS responses from
    the blocked state, causing 'works in incognito but not normal' symptom.
    """
    try:
        if platform.system() == "Windows":
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, timeout=5,
            )
            logger.debug("DNS cache flushed (ipconfig /flushdns)")
        else:
            # Linux: systemd-resolved
            subprocess.run(
                ["resolvectl", "flush-caches"],
                capture_output=True, timeout=5,
            )
    except Exception:
        pass  # non-critical


def _restart_stuck_apps() -> None:
    """Restart apps that cache connection failures (Discord updater, etc.).

    Problem: if Discord was started before zapret2, its updater hangs on
    'Checking for updates' and never retries. Standard zapret2 doesn't have
    this issue because it runs as a Windows service (starts before apps).

    Solution: kill the updater process so Discord restarts it fresh,
    now routing through the active zapret2.
    """
    if platform.system() != "Windows":
        return
    log = logging.getLogger("svoboda")

    # Discord: kill Update.exe (updater). Discord's main process will
    # detect it died and relaunch it — this time through working zapret2.
    try:
        check = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Update.exe"],
            capture_output=True, text=True, timeout=5,
        )
        if "Update.exe" in check.stdout:
            subprocess.run(
                ["taskkill", "/F", "/IM", "Update.exe"],
                capture_output=True, timeout=5,
            )
            log.info("Restarted Discord updater (was stuck before zapret2)")
    except Exception:
        pass


def _stop_permanent_zapret(proc: Optional[subprocess.Popen]) -> None:
    """Stop permanent winws2/nfqws2 instance + force kill ALL winws2."""
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            pass
    # Force kill ALL winws2 instances to release WinDivert
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "winws2.exe"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass
    time.sleep(1)  # wait for WinDivert driver to unload


def _quick_connectivity_check(hosts: list[str], timeout: int = 5) -> dict[str, bool]:
    """Quick curl test to each host. Returns {host: success}."""
    results = {}
    for host in hosts:
        r = _curl_check_one(host, timeout)
        results[host] = r["success"]
    return results


def _curl_check_one(host: str, timeout: int = 5) -> dict:
    """Curl test with latency + error classification. Returns detailed result."""
    is_win = platform.system() == "Windows"
    _SUCCESS_CODES = {200, 301, 302, 303, 307, 308, 403}
    try:
        result = subprocess.run(
            ["curl", "-s", "--ssl-no-revoke",
             "--max-time", str(timeout),
             f"https://{host}",
             "-o", "NUL" if is_win else "/dev/null",
             "-w", "%{http_code}|%{time_total}"],
            capture_output=True, text=True, timeout=timeout + 3,
        )
        parts = result.stdout.strip().split("|")
        http_code = 0
        latency_ms = 0.0
        try:
            http_code = int(parts[0])
        except (ValueError, IndexError):
            pass
        try:
            latency_ms = round(float(parts[1]) * 1000, 1)
        except (ValueError, IndexError):
            pass

        # HTTP success code + (clean exit OR timeout) = page reached
        success = http_code in _SUCCESS_CODES and (result.returncode == 0 or result.returncode == 28)

        # Classify error
        error_type = ""
        if not success:
            if result.returncode in {7, 56}:
                error_type = "rst"
            elif result.returncode in {28}:
                error_type = "timeout"
            elif result.returncode in {6}:
                error_type = "dns"
            elif result.returncode in {35, 51, 60}:
                error_type = "ssl"
            elif result.returncode != 0:
                error_type = "error"

        return {
            "success": success, "http_code": http_code,
            "latency_ms": latency_ms, "error_type": error_type,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "http_code": 0, "latency_ms": timeout * 1000, "error_type": "timeout"}
    except Exception:
        return {"success": False, "http_code": 0, "latency_ms": 0, "error_type": "error"}


def main():
    global _running, _active_process, _tspu_recommended_ttl

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    _print_header()

    # ─── Load config ──────────────────────────────────────────────────
    config = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
    config["_base_dir"] = str(BASE_DIR)

    # ─── Streamer mode toggle ─────────────────────────────────────────
    # Streamer mode reduces WinDivert overhead for OBS/streaming:
    #   - Minimal packet interception (only TCP 80,443 + UDP 443)
    #   - High auto-hostlist threshold (won't capture CDN on packet loss)
    #   - Streaming CDN excludes (Twitch, YouTube ingest, etc.)
    # Toggle via config.json "streamer_mode": true or launch arg --streamer
    if "--streamer" in sys.argv:
        config["streamer_mode"] = True
    if config.get("streamer_mode"):
        print("  [STREAMER] Low-overhead mode (streaming CDNs excluded)")

    # ─── Logging ──────────────────────────────────────────────────────
    log = logging.getLogger("svoboda")
    log.setLevel(logging.DEBUG)

    from logging.handlers import RotatingFileHandler
    fh = RotatingFileHandler(
        BASE_DIR / config.get("log_file", "svoboda.log"),
        maxBytes=10 * 1024 * 1024, backupCount=7, encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(fh)

    # ─── AI Feedback Loop ────────────────────────────────────────────
    from brain.ai_feedback import AIFeedbackLoop
    ai_feedback = AIFeedbackLoop()

    # ─── Verify zapret2 ──────────────────────────────────────────────
    zapret_bin = _find_zapret_binary(BASE_DIR)
    lua_dir = _find_lua_dir(BASE_DIR)

    from brain import ui

    if not zapret_bin:
        ui.error("winws2.exe not found!")
        ui.detail("Download zapret2 from: https://github.com/bol-van/zapret2")
        ui.detail("Extract to this directory.")
        input("\n  Press Enter to exit...")
        return

    ui.ok(f"zapret2: {zapret_bin}")
    if lua_dir:
        ui.ok(f"Lua libs: {lua_dir}")
    else:
        ui.warn("zapret2 Lua libraries not found (limited functionality)")

    # ─── Init modules ─────────────────────────────────────────────────
    analytics = Analytics(config)
    manager = StrategyManager(config)
    tier = TierManager(config)
    donate = DonateManager(config)
    sync = ServerSync(config, analytics)
    sync.set_tier_manager(tier)
    ai = AIAdvisor(config, analytics, tier_manager=tier)
    ai.set_install_id(sync.install_id)
    sync.register_dependent(ai)
    sync.register_dependent(donate)

    # Auto-register with server
    if sync.is_configured:
        if sync.register_if_needed():
            ai.set_server_key(sync.api_key)
            ui.ok("Server connected")
        else:
            ui.warn("Server unavailable (offline mode)")

    # ─── ISP Detection (use cache first, ipinfo.io may be blocked) ────
    ui.step("Detecting ISP...")
    profiler = ISPProfiler(config)
    isp_name = "unknown"
    asn = "?"
    try:
        profile = profiler.detect()
        if profile:
            isp_name = profile.isp_name or "unknown"
            asn = profile.asn or "?"
            ui.ok(f"ISP: {isp_name} ({asn})")
        else:
            ui.warn("ISP detection failed (using generic strategies)")
    except Exception as exc:
        # ipinfo.io likely blocked by DPI — use cached profile
        logger.debug("ISP detection error (DPI may block ipinfo.io): %s", exc)
        try:
            profiler._load_profile()
            if profiler.profile:
                isp_name = profiler.profile.isp_name or "unknown"
                asn = profiler.profile.asn or "?"
                ui.ok(f"ISP: {isp_name} ({asn}) (cached)")
            else:
                ui.warn("ISP unknown (will detect after bypass)")
        except Exception:
            ui.warn("ISP unknown (will detect after bypass)")

    # ─── Smart DNS diagnosis ─────────────────────────────────────────
    from brain.dns_fixer import detect_sni_proxy, remove_hosts_entries
    atexit.register(remove_hosts_entries)  # Clean hosts file on ANY exit

    _sni_proxy_ip = detect_sni_proxy(["youtube.com", "discord.com", "x.com"])
    if _sni_proxy_ip:
        print(f"\n  [DNS] SNI proxy detected: {_sni_proxy_ip}")
        print(f"        winws2 desync + SNI proxy = working combo")
        print(f"        (winws2 hides SNI from TSPU, proxy routes traffic)")
    # Do NOT set config["_sni_proxy_ip"] — ipset-exclude is disabled intentionally
    config["_sni_proxy_ip"] = None

    # ─── Download blocklist ─────────────────────────────────────────
    print()
    hostlist = _download_hostlist(BASE_DIR)

    # ─── Early Start: apply cached strategy + validate immediately ───
    # Problem: if cached strategy is stale, apps (Discord, browser) connect
    # through broken zapret2, cache the failure internally, and then even
    # after we find a working strategy they won't retry → "incognito only".
    # Solution: start cached → quick-validate → if stale, kill immediately
    # and try top community/enum strategies before full analysis.
    _early_process = None
    _early_validated = False
    cached_best = manager.get_best_strategy(isp_name)
    if cached_best and cached_best.fitness > 0.3:
        print(f"\n  Quick-start with cached strategy (fitness={cached_best.fitness:.3f})...")
        _early_process = _start_permanent_zapret(
            zapret_bin, lua_dir, cached_best.flags, hostlist,
            4,  # default TTL, will be refined after TSPU profiling
            config,
        )
        if _early_process:
            _active_process = _early_process
            # Quick-validate: 1 curl to youtube (8s max)
            time.sleep(2)  # let WinDivert load
            _validate_host = config.get("test_hosts", ["youtube.com"])[0]
            _vr = _curl_check_one(_validate_host, timeout=6)
            if _vr["success"]:
                _early_validated = True
                ui.ok(f"DPI bypass active (cached strategy works)")
                _restart_stuck_apps()
            else:
                # Stale strategy — kill immediately so apps don't cache failures
                print(f"  [!] Cached strategy stale — trying fallback...")
                _stop_permanent_zapret(_early_process)
                _active_process = None
                _early_process = None

                # Fast fallback: try top 5 enum strategies (~30s total)
                from brain.enumerator import StrategyEnumerator
                _fb_enum = StrategyEnumerator()
                _fb_found = False
                for _fb_i, _fb_s in enumerate(_fb_enum.strategies[:5]):
                    _fb_proc = _start_permanent_zapret(
                        zapret_bin, lua_dir, _fb_s["flags"], hostlist, 4, config,
                    )
                    if not _fb_proc:
                        continue
                    time.sleep(2)
                    _fb_vr = _curl_check_one(_validate_host, timeout=6)
                    if _fb_vr["success"]:
                        _active_process = _fb_proc
                        _early_validated = True
                        _fb_found = True
                        ui.ok(f"DPI bypass active (fallback: {_fb_s['name']})")
                        _restart_stuck_apps()
                        # Save this working strategy for next time
                        manager.save_strategy(_fb_s["flags"], 0.5, isp_name)
                        break
                    else:
                        _stop_permanent_zapret(_fb_proc)

                if not _fb_found:
                    print("  [!] No quick fallback worked — full analysis needed")
    else:
        print("\n  No cached strategy — full analysis needed...")

    # ─── TSPU Profiling ─────────────────────────────────────────────
    from brain.tspu_profiler import TSPUProfiler
    tspu_profile = None
    try:
        ui.step("Profiling DPI/TSPU...")
        tspu = TSPUProfiler(timeout=5)
        tspu_profile = tspu.profile("youtube.com", isp=isp_name, asn=asn if 'asn' in dir() else "")
        if tspu_profile.dpi_hop_distance:
            _tspu_recommended_ttl = tspu_profile.recommended_ttl or 0
            ui.tspu_info(
                tspu_profile.dpi_hop_distance, tspu_profile.dpi_type,
                tspu_profile.recommended_ttl, tspu_profile.evidence,
            )
    except Exception as exc:
        ui.warn(f"TSPU profiling error: {exc}")

    # ─── ECH (Encrypted Client Hello) ──────────────────────────────
    from brain.ech import ECHManager
    ech = ECHManager(config)
    _ech_ready = False
    try:
        if ech.setup():
            _ech_ready = True
            ui.ok(f"DoH ready (ECH system active)")
        else:
            ui.warn("DoH unavailable (ECH disabled)")
    except Exception as exc:
        logger.debug("ECH setup error: %s", exc)

    # ─── Smart block detection ──────────────────────────────────────
    # Ensure basic desync is running during classification — without it,
    # classifier sees TCP connect failures and misdiagnoses SNI filtering as IP_BLOCK.
    if not _active_process:
        _classify_proc = _start_permanent_zapret(
            zapret_bin, lua_dir,
            ["multisplit:pos=1:seqovl=4096"],  # basic desync for classification
            hostlist, 4, config,
        )
        if _classify_proc:
            _active_process = _classify_proc
            time.sleep(2)

    from brain.block_classifier import BlockageClassifier

    hosts = config.get("test_hosts", ["youtube.com", "discord.com", "cdn.discordapp.com"])
    ui.step("Analyzing blocking methods...")
    classifier = BlockageClassifier(timeout=5)
    block_results = {}
    for host in hosts:
        analysis = classifier.classify(host)
        block_results[host] = analysis
        ui.block_status(host, analysis.block_type, analysis.confidence, analysis.evidence)

    blocked = {h: r for h, r in block_results.items() if r.block_type != "NOT_BLOCKED"}
    all_accessible = len(blocked) == 0
    dpi_type = tspu_profile.dpi_type if tspu_profile else "unknown"

    if all_accessible:
        ui.ok("All sites accessible without DPI bypass.")
        print("  Starting monitoring mode (will activate if blocking detected)...")
        _monitoring_loop(hosts, config, zapret_bin, lua_dir, analytics, manager,
                         ai, sync, tier, profiler, isp_name, hostlist,
                         ai_feedback=ai_feedback, tspu_profile=tspu_profile,
                         dpi_type=dpi_type)
        analytics.close()
        return

    # Collect block types for AI context
    block_summary = {h: r.block_type for h, r in blocked.items()}
    print(f"\n  {len(blocked)} site(s) blocked: {', '.join(f'{h}={t}' for h, t in block_summary.items())}")

    # ─── Smart routing: separate SNI-blocked from IP-blocked ─────────
    from brain.proxy_router import ProxyRouter
    router = ProxyRouter(config)
    atexit.register(router.shutdown)  # Ensure PAC proxy is cleaned on ANY exit
    routing_plan = router.plan_routing(blocked)

    # Also check known IP-blocked services (AI, LinkedIn, etc.)
    ip_test_hosts = config.get("ip_blocked_test_hosts", [])
    if ip_test_hosts:
        ip_extra_results = {}
        for host in ip_test_hosts:
            if host not in block_results:
                analysis = classifier.classify(host)
                if analysis.block_type != "NOT_BLOCKED":
                    ip_extra_results[host] = analysis
        if ip_extra_results:
            extra_plan = router.plan_routing(ip_extra_results)
            routing_plan.proxy_hosts.extend(extra_plan.proxy_hosts)
            routing_plan.decisions.extend(extra_plan.decisions)

    # Setup proxy for IP-blocked hosts (WARP → user VPS → instructions)
    _proxy_ready = False
    if routing_plan.proxy_hosts:
        print(f"\n  {len(routing_plan.proxy_hosts)} IP-blocked site(s): {', '.join(routing_plan.proxy_hosts)}")
        print("  (DPI bypass won't help — need proxy/tunnel)")
        ui.step("Setting up proxy for IP-blocked sites...")

        _proxy_ready = router.setup_proxy(routing_plan, tier=tier)
        if _proxy_ready:
            ui.ok(f"Proxy ready ({routing_plan.proxy_type}): {routing_plan.proxy_url}")
            # Generate PAC file (selective: only blocked domains → SOCKS5, rest → DIRECT)
            pac_path = router.generate_pac_file(routing_plan, BASE_DIR / "proxy.pac")
            # System proxy auto-set: only via PAC (selective, not full proxy)
            # PAC ensures only blocked domains go through proxy, all other traffic stays DIRECT
            if pac_path:
                if router.set_system_proxy(routing_plan, pac_path):
                    ui.ok("System proxy set (only blocked domains routed, rest direct)")
                else:
                    # Can't set registry (no admin?) — show manual instructions
                    print(f"  PAC file: {pac_path.resolve()}")
                    print("  Set manually: Settings → Network → Proxy → Auto-config URL")
            instructions = router.get_browser_instructions(routing_plan, pac_path)
            if instructions:
                print(instructions)
        else:
            instructions = router.get_browser_instructions(routing_plan)
            if instructions:
                print(instructions)

    # Filter: only pass DPI-bypassable hosts to zapret2 pipeline
    dpi_blocked = {h: r for h, r in blocked.items() if h in routing_plan.zapret2_hosts}
    if not dpi_blocked and not routing_plan.zapret2_hosts:
        # All blocked sites are IP-blocked, no DPI bypass needed
        if _proxy_ready:
            ui.ok("All blocked sites routed through proxy.")
            print(f"\n  Monitoring... (Ctrl+C to stop)\n")
            while _running:
                time.sleep(1)
            router.shutdown()
            analytics.close()
            return
        else:
            ui.warn("All sites are IP-blocked and no proxy available.")
            print("  Install Cloudflare WARP (free): https://1.1.1.1/")
            print("  Or add to config.json: \"user_proxy\": \"socks5://your-vps:port\"")
            analytics.close()
            input("  Press Enter to exit...")
            return

    # ─── ECH check for DPI-blocked hosts ──────────────────────────
    if _ech_ready and dpi_blocked:
        ech_domains = ech.get_ech_domains(list(dpi_blocked.keys()))
        if ech_domains:
            ui.ok(f"ECH available for: {', '.join(ech_domains)}")
            print("  (Enable ECH in browser for invisible SNI encryption)")
            print(ech.get_browser_ech_instructions())

    # Collect recommended strategies from classifier (DPI-bypassable hosts only)
    classifier_strategies: list[list[str]] = []
    for h, r in dpi_blocked.items():
        for s in r.recommended_strategies:
            if s not in classifier_strategies:
                classifier_strategies.append(s)

    # ─── Initialize tester ──────────────────────────────────────────
    # Remove IP-blocked and proxy-routed domains from test_hosts.
    # These can NEVER be unblocked by DPI bypass — testing them wastes
    # time and drags fitness below threshold.
    _ip_blocked_hosts = {h for h, r in blocked.items() if r.block_type == "IP_BLOCK"}
    _proxy_hosts = set(routing_plan.proxy_hosts) if routing_plan else set()
    _untestable = _ip_blocked_hosts | _proxy_hosts
    if _untestable:
        _old_hosts = config.get("test_hosts", [])
        _new_hosts = [h for h in _old_hosts if h not in _untestable]
        if _new_hosts:
            config["test_hosts"] = _new_hosts
            logger.info("Test hosts updated: removed %s (IP-blocked/proxied), keeping %s",
                        _untestable, _new_hosts)
    tester = ConnectionTester(config, mock=False, hostlist_path=hostlist)
    # Refresh hosts after IP-blocked filtering (watchdog uses this)
    hosts = config.get("test_hosts", hosts)

    # ─── Unified watchdog with auto-recovery ─────────────────────────
    # All code paths (AI Engine, community, cached, enum, GA) converge here
    # after applying initial strategy.  Recovery cycle never exits — it
    # retries community → AI → enum → GA → per-host until Ctrl+C.
    def _unified_watchdog(current_flags, strategy_id):
        """Monitor connection and auto-recover on degradation.

        Runs until Ctrl+C.  On health drop:
          1. Classify block type
          2. AI failure analysis
          2.5. Community strategy
          3. AI-suggested fix
          4. Fast enumeration
          5. GA evolution
          6. Per-host solver
        Also monitors hostlist-auto for newly blocked domains (discovery).
        """
        global _active_process

        _wd_interval = config.get("watchdog_interval_minutes", 5) * 60
        _wd_fail_thr = config.get("watchdog_fail_threshold", 2)
        _wd_min_fit = config.get("watchdog_min_fitness", 0.6)
        _wd_ga_cfg = GAConfig.from_config(config)
        _wd_ga_cfg.generations = min(_wd_ga_cfg.generations, 15)
        _wd_ga_cfg.population_size = min(_wd_ga_cfg.population_size, 10)
        _wd_flags = list(current_flags)
        _wd_sid = strategy_id
        _wd_extra = []

        # Load saved per-host strategies on entry
        try:
            from brain.host_solver import HostSolver as _HSBoot
            _hs_boot = _HSBoot(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
            _wd_extra = _hs_boot.build_extra_profiles(lua_dir)
            if _wd_extra and _active_process:
                ui.info(f"Loaded {len(_wd_extra) // 4} saved per-host strategies")
                _stop_permanent_zapret(_active_process)
                _active_process = _start_permanent_zapret(
                    zapret_bin, lua_dir, _wd_flags, hostlist,
                    _tspu_recommended_ttl, config, extra_profiles=_wd_extra,
                )
        except Exception as _hs_exc:
            logger.debug("Per-host load: %s", _hs_exc)

        # Discovery pipeline
        _discovery = None
        try:
            from brain.discovery import DiscoveryPipeline
            from brain.host_solver import HostSolver as _HSDisc
            _ds = _HSDisc(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
            _discovery = DiscoveryPipeline(
                config, tester=tester, classifier=BlockageClassifier(timeout=5),
                host_solver=_ds, proxy_router=router,
                server_sync=sync, isp=isp_name,
            )
        except Exception:
            pass

        _known_auto = set()
        _auto_path = Path(zapret_bin).parent / "hostlist-auto.txt" if zapret_bin else None
        if _auto_path and _auto_path.exists():
            try:
                _known_auto = set(_auto_path.read_text(encoding="utf-8", errors="ignore").strip().splitlines())
            except Exception:
                pass

        while _running:
            for _ in range(_wd_interval):
                if not _running:
                    break
                time.sleep(1)
            if not _running:
                break

            # ── Health check ──────────────────────────────────────────
            now = datetime.now().strftime("%H:%M")
            status_parts = []
            for host in hosts:
                r = _curl_check_one(host, timeout=10)
                analytics.log_test_result(
                    strategy_id=_wd_sid, host=host,
                    http_code=r["http_code"], success=r["success"],
                    latency_ms=r["latency_ms"], error_type=r["error_type"],
                )
                short = host.replace(".com", "").replace(".discordapp", "")
                if r["success"]:
                    status_parts.append(f"{short}:OK({r['latency_ms']:.0f}ms)")
                else:
                    status_parts.append(f"{short}:{(r['error_type'] or 'FAIL').upper()}")

            health = analytics.get_all_hosts_health(hosts, minutes=10)
            overall = health["overall_rate"]
            degraded = health.get("degraded", [])
            print(f"  [{now}] {' | '.join(status_parts)}  (health={overall:.0%})")

            # ── Discovery: new blocked domains ────────────────────────
            if _auto_path and _auto_path.exists() and _discovery:
                try:
                    cur_auto = set(_auto_path.read_text(encoding="utf-8", errors="ignore").strip().splitlines())
                    new_doms = [d for d in (cur_auto - _known_auto) if d.strip() and not d.startswith("#")]
                    if new_doms:
                        print(f"  [{now}] New blocked domains: {', '.join(new_doms[:3])}")
                        _stop_permanent_zapret(_active_process)
                        _active_process = None
                        time.sleep(1)
                        try:
                            for dr in _discovery.process_new_domains(new_doms):
                                st = "SOLVED" if dr.solved else ("proxy" if dr.route == "proxy" else "unsolved")
                                print(f"  [{now}] {dr.domain} -> {st}")
                        except Exception as de:
                            logger.warning("Discovery: %s", de)
                        finally:
                            d_extra = []
                            try:
                                d_extra = _discovery.get_extra_profiles()
                            except Exception:
                                pass
                            _active_process = _start_permanent_zapret(
                                zapret_bin, lua_dir, _wd_flags, hostlist,
                                _tspu_recommended_ttl, config,
                                extra_profiles=d_extra or _wd_extra,
                            )
                    _known_auto = cur_auto
                except Exception as exc:
                    logger.debug("Discovery check: %s", exc)
                    if _active_process is None:
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags, hostlist,
                            _tspu_recommended_ttl, config, extra_profiles=_wd_extra,
                        )

            # ── Failure detection ─────────────────────────────────────
            needs_recovery = False
            if overall < _wd_min_fit:
                needs_recovery = True
                print(f"  [!] Health degraded: {overall:.0%} < {_wd_min_fit:.0%}")
            for host in hosts:
                hd = health["hosts"].get(host, {})
                if hd.get("streak_fail", 0) >= _wd_fail_thr:
                    needs_recovery = True
                    print(f"  [!] {host}: {hd['streak_fail']} consecutive failures")

            # ── Per-host solving (partial failures, overall OK) ───────
            pfails = [
                h for h in hosts
                if health["hosts"].get(h, {}).get("streak_fail", 0) >= 3
                and not needs_recovery
                and (h not in blocked or blocked[h].block_type != "TLS_INTERFERENCE")
            ]
            if pfails:
                from brain.host_solver import HostSolver
                ui.separator()
                ui.warn(f"Persistent failures: {', '.join(pfails)}")
                ui.info("Searching per-host strategies...")
                # Stop permanent zapret BEFORE solving — shadow tester
                # does taskkill /F /IM winws2.exe which would kill it anyway,
                # leaving _active_process as a stale reference.
                _stop_permanent_zapret(_active_process)
                _active_process = None
                solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
                solved = False
                try:
                    for fh in pfails[:2]:
                        if solver.get(fh):
                            ui.info(f"{fh}: already solved")
                            continue
                        ui.step(f"Solving: {fh}")
                        sr = solver.solve(fh, isp=isp_name)
                        if sr:
                            ui.ok(f"{fh}: fitness={sr.fitness:.3f}")
                            solved = True
                            if sync.is_configured:
                                sync.vote_strategy(sr.flags, success=True, fitness=sr.fitness, isp=isp_name)
                        else:
                            ui.warn(f"No fix for {fh}")
                finally:
                    # Always restart permanent zapret (with or without per-host profiles)
                    _wd_extra = solver.build_extra_profiles(lua_dir) if solved else None
                    _active_process = _start_permanent_zapret(
                        zapret_bin, lua_dir, _wd_flags, hostlist,
                        _tspu_recommended_ttl, config, extra_profiles=_wd_extra,
                    )
                    if not _active_process:
                        # Fallback: restart without per-host profiles
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags, hostlist,
                            _tspu_recommended_ttl, config,
                        )
                    if _active_process:
                        if solved:
                            ui.ok("Restarted with per-host profiles")
                        else:
                            ui.ok("Permanent zapret restarted")
                if sync.is_configured:
                    sync.sync_now()
                ui.separator()

            # ── Full recovery cycle (degraded connection) ─────────────
            if needs_recovery:
                from brain.failure_analyzer import FailureAnalyzer
                from brain.enumerator import StrategyEnumerator

                ui.separator()
                ui.warn("Connection degraded — autonomous recovery")

                # Step 1: Classify
                ui.step("Step 1: Block analysis...")
                _rc = BlockageClassifier(timeout=5)
                for fh in list(degraded)[:3]:
                    try:
                        a = _rc.classify(fh)
                        ui.block_status(fh, a.block_type, a.confidence, a.evidence)
                        ai_feedback.record_test([f"watchdog:{fh}"], 0.0, failure_mode=a.block_type.lower())
                    except Exception:
                        pass

                # Step 2: AI analysis
                report = None
                ui.step("Step 2: Failure analysis...")
                try:
                    fa = FailureAnalyzer()
                    report = fa.analyze(
                        flags=_wd_flags, fitness=overall,
                        host_results=health.get("hosts", {}),
                        tspu_profile=tspu_profile,
                    )
                    ui.info(f"Root cause: {report.root_cause} ({report.confidence:.0%})")
                    ui.detail(report.explanation[:120])
                except Exception as fe:
                    logger.warning("FailureAnalyzer: %s", fe)

                _stop_permanent_zapret(_active_process)
                _active_process = None
                found_fix = False

                # Step 2.5: Community
                if sync.is_configured:
                    ui.step("Step 2.5: Community strategy...")
                    try:
                        cs = sync.get_instant_strategy(isp_name, dpi_type)
                        if cs and cs.get("flags"):
                            fit = tester.test_strategy(cs["flags"])
                            ai_feedback.record_test(cs["flags"], fit, "ok" if fit > 0.3 else "timeout")
                            if fit > 0.5:
                                ui.ok(f"Community fix! fitness={fit:.3f}")
                                rec = manager.save_strategy(cs["flags"], fit, isp_name)
                                _wd_sid = rec.id
                                _wd_flags = list(cs["flags"])
                                _active_process = _start_permanent_zapret(
                                    zapret_bin, lua_dir, _wd_flags, hostlist,
                                    _tspu_recommended_ttl, config,
                                )
                                found_fix = bool(_active_process)
                    except Exception:
                        pass

                # Step 3: AI suggestion
                if report and hasattr(report, 'improved_flags') and report.improved_flags and not found_fix:
                    ui.step("Step 3: AI suggestion...")
                    for imp in report.improved_flags[:2]:
                        fit = tester.test_strategy(imp)
                        ai_feedback.record_test(imp, fit, "ok" if fit > 0.3 else "timeout")
                        if fit > 0.5:
                            ui.ok(f"AI fix! fitness={fit:.3f}")
                            rec = manager.save_strategy(imp, fit, isp_name)
                            _wd_sid = rec.id
                            _wd_flags = list(imp)
                            _active_process = _start_permanent_zapret(
                                zapret_bin, lua_dir, _wd_flags, hostlist,
                                _tspu_recommended_ttl, config,
                            )
                            found_fix = bool(_active_process)
                            if found_fix and sync.is_configured:
                                sync.vote_strategy(imp, success=True, fitness=fit, isp=isp_name)
                            break

                # Step 4: Enumeration
                if not found_fix:
                    ui.step("Step 4: Fast enumeration...")
                    excluded = ai_feedback.get_excluded_functions()
                    en = StrategyEnumerator(excluded_functions=excluded)
                    _wd_thr = 0.40 if (tspu_profile and "tspu" in getattr(tspu_profile, 'dpi_type', '').lower()) else 0.55
                    er = en.enumerate(
                        tester, threshold=_wd_thr,
                        on_progress=lambda i, t, n, f: ui.enum_line(i, t, n, f, _wd_thr),
                    )
                    if er:
                        ui.ok(f"Found: {er['name']} (fitness={er['fitness']:.3f})")
                        rec = manager.save_strategy(er["flags"], er["fitness"], isp_name)
                        _wd_sid = rec.id
                        _wd_flags = list(er["flags"])
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags, hostlist,
                            _tspu_recommended_ttl, config,
                        )
                        found_fix = bool(_active_process)

                # Step 5: GA
                if not found_fix:
                    ui.step("Step 5: GA evolution...")
                    seeds = _get_seeds(isp_name, ai, ai_feedback=ai_feedback, tspu_profile=tspu_profile)
                    gb = _run_evolution(
                        tester, _wd_ga_cfg, seeds, analytics, isp_name,
                        ai_feedback=ai_feedback, dpi_type=dpi_type,
                    )
                    if gb and gb.fitness > 0.1:
                        rec = manager.save_strategy(gb.flags, gb.fitness, isp_name)
                        _wd_sid = rec.id
                        _wd_flags = list(gb.flags)
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags, hostlist,
                            _tspu_recommended_ttl, config,
                        )
                        found_fix = bool(_active_process)

                # Step 6: Per-host
                if found_fix and _active_process and _running:
                    time.sleep(2)
                    vf = _quick_connectivity_check(hosts)
                    bad = [h for h, ok in vf.items() if not ok]
                    if bad:
                        ui.step(f"Step 6: Solving {len(bad)} host(s)...")
                        from brain.host_solver import HostSolver
                        # Stop permanent zapret before per-host solving
                        # (shadow tester needs exclusive WinDivert access)
                        _stop_permanent_zapret(_active_process)
                        _active_process = None
                        sv = HostSolver(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
                        try:
                            for fh in bad[:2]:
                                r = sv.solve(fh, isp=isp_name)
                                if r:
                                    ui.ok(f"Solved {fh}: fitness={r.fitness:.3f}")
                        finally:
                            _wd_extra = sv.build_extra_profiles(lua_dir)
                            _active_process = _start_permanent_zapret(
                                zapret_bin, lua_dir, _wd_flags, hostlist,
                                _tspu_recommended_ttl, config,
                                extra_profiles=_wd_extra,
                            )

                # Sync
                if sync.is_configured:
                    sync.sync_now()

                if found_fix:
                    ui.ok("Recovery complete — bypass restored")
                else:
                    ui.warn("No fix found. Retrying next cycle.")
                    # Keep old strategy as fallback
                    if _active_process is None:
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags, hostlist,
                            _tspu_recommended_ttl, config, extra_profiles=_wd_extra,
                        )
                ui.separator()
                # IMPORTANT: continue loop, don't break!

        # Clean exit (Ctrl+C)
        if _active_process:
            _stop_permanent_zapret(_active_process)
            _active_process = None

    # ─── AI Engine — reserved for per-host solving after community/enum ──
    # Community + enum are free and fast. AI Engine uses LLM (rate limited).
    # AI Engine activates in per-host solver for hosts that enum can't fix.
    _ai_engine_used = False
    # AI Engine — try if available, skip gracefully on rate limit
    _ai_engine_used = False
    if ai.is_available and len(blocked) > 0:
        try:
            from brain.ai_engine import AIEngine, build_engine_context
            from brain.host_solver import HostSolver

            # Build tool handlers (accept **kwargs for flexible AI tool calls)
            # NOTE: All tools that call tester must stop permanent zapret first
            # (shadow winws2 can't run alongside permanent — WinDivert conflict)
            def _tool_run_enumerator(hosts=None, forbid_genes=None, stop_on_fitness=0.5, **kwargs):
                global _active_process
                from brain.enumerator import StrategyEnumerator
                if kwargs.get("exclude_fake"):
                    forbid_genes = (forbid_genes or []) + ["fake"]
                excluded = set(forbid_genes or []) | ai_feedback.get_excluded_functions()
                enum = StrategyEnumerator(excluded_functions=excluded)
                best_fit, best_flags, best_name = 0.0, [], ""
                # Stop permanent so shadow tester can use WinDivert
                _was_running = _active_process is not None
                if _was_running:
                    _stop_permanent_zapret(_active_process)
                    _active_process = None
                try:
                    for s in enum.strategies:
                        if not _running:
                            break
                        fit = tester.test_strategy(s["flags"])
                        _hr = tester._last_report.host_results if tester._last_report else {}
                        ai_feedback.record_test(s["flags"], fit, "ok" if fit > 0.3 else "timeout", host_results=_hr)
                        if fit > best_fit:
                            best_fit, best_flags, best_name = fit, s["flags"], s["name"]
                        if fit >= stop_on_fitness:
                            break
                finally:
                    # Restart permanent if it was running (unless apply_strategy will do it)
                    if _was_running and not _active_process:
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags if '_wd_flags' in dir() else best_flags,
                            hostlist, _tspu_recommended_ttl, config,
                        )
                return {"strategy": " | ".join(best_flags), "fitness": best_fit, "name": best_name}

            def _tool_per_host_solver(host="", **kwargs):
                global _active_process
                # TLS_INTERFERENCE means IP-level block — desync can't fix it, skip immediately
                if blocked.get(host) and blocked[host].block_type == "TLS_INTERFERENCE":
                    return {"strategy": "", "fitness": 0.0, "reason": "TLS_INTERFERENCE — proxy only, desync won't help"}
                _was_running = _active_process is not None
                if _was_running:
                    _stop_permanent_zapret(_active_process)
                    _active_process = None
                try:
                    solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
                    result = solver.solve(host, isp=isp_name)
                    if result:
                        return {"strategy": " | ".join(result.flags), "fitness": result.fitness}
                    return {"strategy": "", "fitness": 0.0}
                finally:
                    if _was_running and not _active_process:
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, _wd_flags if '_wd_flags' in dir() else [],
                            hostlist, _tspu_recommended_ttl, config,
                        )

            def _tool_test_strategy(strategy="", hosts=None, **kwargs):
                global _active_process
                flags = [f.strip() for f in strategy.split("|")]
                _was_running = _active_process is not None
                if _was_running:
                    _stop_permanent_zapret(_active_process)
                    _active_process = None
                try:
                    fit = tester.test_strategy(flags)
                    verify = _quick_connectivity_check(hosts or list(blocked.keys()))
                    return {"fitness": fit, "host_status": {h: ok for h, ok in verify.items()}}
                finally:
                    if _was_running and not _active_process:
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, flags, hostlist,
                            _tspu_recommended_ttl, config,
                        )

            def _tool_get_block_analysis(host="", **kwargs):
                analysis = classifier.classify(host)
                return {
                    "block_type": analysis.block_type,
                    "confidence": analysis.confidence,
                    "evidence": analysis.evidence,
                }

            def _tool_apply_strategy(strategy="", extra_profiles=None, **kwargs):
                global _active_process
                flags = [f.strip() for f in strategy.split("|")]
                _active_process = _start_permanent_zapret(
                    zapret_bin, lua_dir, flags, hostlist,
                    _tspu_recommended_ttl, config,
                )
                time.sleep(2)
                verify = _quick_connectivity_check(list(blocked.keys()))
                return {"success": _active_process is not None, "host_status": {h: ok for h, ok in verify.items()}}

            # Build context
            tspu_dict = {}
            if tspu_profile:
                tspu_dict = {
                    "dpi_distance": tspu_profile.dpi_hop_distance,
                    "dpi_type": tspu_profile.dpi_type,
                    "recommended_ttl": tspu_profile.recommended_ttl,
                }

            block_analysis_dict = {
                h: {"block_type": r.block_type, "confidence": r.confidence, "evidence": r.evidence}
                for h, r in blocked.items()
            }

            context = build_engine_context(
                isp=isp_name,
                asn=asn if 'asn' in dir() else "",
                tspu_profile=tspu_dict,
                block_analysis=block_analysis_dict,
                test_history=[r.to_dict() for r in ai_feedback.history[-10:]],
                excluded_functions=list(ai_feedback.get_excluded_functions()),
            )

            engine = AIEngine(
                config=config,
                ai_chat_fn=ai._chat,
                max_iterations=8,
            )
            engine.register_tool("run_enumerator", _tool_run_enumerator)
            engine.register_tool("run_per_host_solver", _tool_per_host_solver)
            engine.register_tool("test_strategy", _tool_test_strategy)
            engine.register_tool("get_block_analysis", _tool_get_block_analysis)
            engine.register_tool("apply_strategy", _tool_apply_strategy)
            engine.register_tool("done", lambda **kw: kw)

            print("\n  AI Engine: autonomous mode...")
            result = engine.run(context)

            if result.get("applied_strategy") and _active_process:
                _ai_engine_used = True
                working = sum(1 for ok in result.get("host_status", {}).values() if ok)
                total_h = len(hosts)
                for host, ok in result.get("host_status", {}).items():
                    print(f"    {host}: {'OK' if ok else 'FAIL'}")

                if working > 0:
                    strategy_str = result["applied_strategy"]
                    ui.bypass_active(working, total_h, strategy_str,
                                     tier.get_status_line(), donate.page_url)

                    # Solve remaining fails
                    failed = [h for h, ok in result.get("host_status", {}).items() if not ok]
                    for fh in result.get("per_host_strategies", {}):
                        print(f"    {fh}: per-host strategy applied")
                        failed = [h for h in failed if h != fh]

                    print(f"\n  Monitoring connection... (Ctrl+C to stop)\n")

                    # Enter unified watchdog with auto-recovery
                    _applied_flags = [f.strip() for f in strategy_str.split("|")]
                    _unified_watchdog(_applied_flags, "ai_engine")
                    analytics.close()
                    return
        except Exception as exc:
            logger.warning("AI Engine failed, falling back to linear pipeline: %s", exc)
            print(f"  [!] AI Engine: {exc}")
            print("  Falling back to standard mode...\n")

    # ─── Fallback: community → cache → enum → GA ────────────────────

    # Step 1: Community instant strategy
    if sync.is_configured:
        community = sync.get_instant_strategy(isp_name, dpi_type)
        if community and community.get("flags"):
            print(f"\n  Trying community strategy (fitness={community['fitness']:.3f}, {community['report_count']} users)...")
            verified = tester.test_strategy(community["flags"])
            if verified >= 0.45:
                # Accept community but check if throttled — if so, try enum for better
                is_good_enough = verified > 0.7  # >0.7 = no throttling, skip enum
                if is_good_enough:
                    print(f"  [OK] Community strategy works! (fitness={verified:.3f})")
                else:
                    print(f"  [OK] Community strategy partial (fitness={verified:.3f}, searching better...)")
                sync.vote_strategy(community["flags"], success=True, fitness=verified, isp=isp_name, dpi_type=dpi_type)
                record = manager.save_strategy(community["flags"], verified, isp_name)
                ai_feedback.record_test(community["flags"], verified, "ok")

                if not is_good_enough:
                    # Throttled — try enum for faster strategy before applying
                    from brain.enumerator import StrategyEnumerator
                    excluded = ai_feedback.get_excluded_functions()
                    enum = StrategyEnumerator(excluded_functions=excluded)
                    better = enum.enumerate(tester, threshold=verified + 0.05,
                        on_progress=lambda i, t, n, f: print(f"    [{i}/{t}] {n}: {f:.3f}") if f > 0 else None)
                    if better and better["fitness"] > verified:
                        print(f"  [OK] Found better: {better['name']} (fitness={better['fitness']:.3f})")
                        community["flags"] = better["flags"]
                        verified = better["fitness"]

                _active_process = _start_permanent_zapret(zapret_bin, lua_dir, community["flags"], hostlist, _tspu_recommended_ttl, config)
                if _active_process:
                    time.sleep(2)
                    verify = _quick_connectivity_check(hosts)
                    working = sum(1 for ok_v in verify.values() if ok_v)
                    total_h = len(verify)
                    for host, ok_v in verify.items():
                        print(f"    {host}: {'OK' if ok_v else 'FAIL'}")
                    if working > 0:
                        ui.bypass_active(working, total_h, " | ".join(community["flags"]),
                                         tier.get_status_line(), donate.page_url)

                        # Immediately solve failed hosts (skip TLS_INTERFERENCE — desync can't help)
                        failed_hosts = [h for h, ok_v in verify.items() if not ok_v
                                        and (h not in blocked or blocked[h].block_type != "TLS_INTERFERENCE")]
                        if failed_hosts and _running:
                            # Must stop permanent winws2 so shadow can use same ports
                            print(f"\n  {len(failed_hosts)} host(s) still blocked, searching solutions...")
                            _stop_permanent_zapret(_active_process)
                            _active_process = None
                            time.sleep(1)

                            extra = []
                            try:
                                from brain.host_solver import HostSolver
                                solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
                                any_solved = False
                                for fh in failed_hosts:
                                    if not _running:
                                        break
                                    print(f"\n  Solving: {fh}...")
                                    result = solver.solve(fh, isp=isp_name)
                                    if result:
                                        print(f"  [OK] Found strategy for {fh} (fitness={result.fitness:.3f})")
                                        any_solved = True
                                    else:
                                        print(f"  [!] No strategy found for {fh}")
                                extra = solver.build_extra_profiles(lua_dir) if any_solved else []
                            except Exception as solve_exc:
                                logger.warning("Host solver failed: %s", solve_exc)
                            finally:
                                # ALWAYS restart zapret2 — even if solver crashed
                                _active_process = _start_permanent_zapret(
                                    zapret_bin, lua_dir, community["flags"],
                                    hostlist, _tspu_recommended_ttl, config,
                                    extra_profiles=extra,
                                )
                            time.sleep(2)

                        # Launch ByeDPI SOCKS5 for remaining failed hosts
                        still_failed = [h for h, ok_v in _quick_connectivity_check(hosts).items() if not ok_v]
                        if still_failed and _running:
                            try:
                                from brain.byedpi import ByeDPIFallback
                                _byedpi = ByeDPIFallback(config, base_dir=str(BASE_DIR))
                                if _byedpi.find_binary() or _byedpi.download_binary():
                                    print(f"\n  Starting SOCKS5 proxy for: {', '.join(still_failed)}...")
                                    if _byedpi.start(block_type="sni_filtering"):
                                        print(f"  [OK] ByeDPI SOCKS5 on {_byedpi.proxy_url}")
                                        # Auto-configure Telegram if it's in failed list
                                        tg_hosts = [h for h in still_failed if "telegram" in h]
                                        if tg_hosts:
                                            if _byedpi.configure_telegram_proxy():
                                                print("  [OK] Telegram configured with SOCKS5 proxy")
                                            else:
                                                print(f"  [!] Configure Telegram manually: Settings → Data → Proxy → SOCKS5 {_byedpi._host}:{_byedpi._port}")
                                        # Show instructions for other apps
                                        discord_hosts = [h for h in still_failed if "discord" in h]
                                        if discord_hosts:
                                            print(f"  [!] Discord app: Settings → Advanced → SOCKS5 {_byedpi._host}:{_byedpi._port}")
                                    else:
                                        print("  [!] ByeDPI failed to start")
                            except Exception as exc:
                                logger.debug("ByeDPI launch failed: %s", exc)

                        # Enter unified watchdog with auto-recovery
                        _unified_watchdog(list(community["flags"]), record.id)
                        analytics.close()
                        return
            else:
                print(f"  [!] Community strategy failed (fitness={verified:.3f})")
                sync.vote_strategy(community["flags"], success=False, fitness=verified, isp=isp_name, dpi_type=dpi_type)

    # Step 2: Local cache
    cached_best = manager.get_best_strategy(isp_name)
    if cached_best and cached_best.fitness > 0.3:
        print(f"\n  Trying cached strategy (fitness={cached_best.fitness:.3f})...")
        verified = tester.test_strategy_thorough(cached_best.flags)
        if verified > 0.5:
            print(f"  [OK] Cached strategy works! (fitness={verified:.3f})")
            # Skip evolution — apply immediately
            best_flags = cached_best.flags
            best_fitness = verified
            # Jump to apply
            record = manager.save_strategy(best_flags, best_fitness, isp_name)
            analytics.log_strategy(
                strategy_id=record.id, flags=best_flags, fitness=best_fitness,
                isp=isp_name, source="cached",
            )

            print(f"\n  Applying cached strategy (fitness={best_fitness:.3f})...")
            print(f"  Strategy: {' | '.join(best_flags)}")
            _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best_flags, hostlist, _tspu_recommended_ttl, config)

            if _active_process:
                time.sleep(2)
                verify = _quick_connectivity_check(hosts)
                working = sum(1 for ok in verify.values() if ok)
                total = len(verify)
                print()
                for host, ok in verify.items():
                    print(f"    {host}: {'OK' if ok else 'FAIL'}")
                if working > 0:
                    print(f"\n  === DPI BYPASS ACTIVE ({working}/{total} sites) ===")
                    _restart_stuck_apps()
                    print(f"\n  Tier:     {tier.get_status_line()}")
                    print(f"  Donate:   {donate.page_url}")
                    print(f"\n  Monitoring connection... (Ctrl+C to stop)\n")
                    _unified_watchdog(best_flags, record.id)
                    analytics.close()
                    return
                else:
                    print("\n  [!] Cached strategy failed verification, evolving...")
                    _stop_permanent_zapret(_active_process)
                    _active_process = None
        else:
            print(f"  [!] Cached strategy outdated (fitness={verified:.3f}), evolving...")

    # ─── Fast enumeration (blockcheck2-style) ──────────────────────
    from brain.enumerator import StrategyEnumerator, KNOWN_STRATEGIES

    excluded = ai_feedback.get_excluded_functions()
    if excluded:
        ui.info(f"AI excluded from search: {', '.join(excluded)}")

    # Build priority list: classifier recommendations first, then known strategies
    priority_strategies = []
    for i, flags in enumerate(classifier_strategies):
        priority_strategies.append({
            "name": f"ai_recommended_{i+1}",
            "flags": flags,
            "desc": f"AI-recommended for detected block type",
        })
    priority_strategies.extend(KNOWN_STRATEGIES)

    # Adaptive threshold: TSPU throttling caps fitness at ~0.50 with the old
    # formula. After fixing throttle_ms and removing WS test, strategies
    # typically score 0.55-0.70. Use lower threshold when TSPU is detected
    # so enum finds a working strategy fast instead of falling to slow GA.
    enum_threshold = 0.55
    if tspu_profile and getattr(tspu_profile, 'dpi_type', None) and "tspu" in tspu_profile.dpi_type.lower():
        enum_threshold = 0.40
        ui.info(f"TSPU detected → acceptance threshold {enum_threshold}")

    print(f"\n  Fast strategy enumeration ({len(priority_strategies)} strategies, AI-prioritized)...")
    enumerator = StrategyEnumerator(strategies=priority_strategies, excluded_functions=excluded)

    def _enum_progress(i, total, name, fitness):
        ui.enum_line(i, total, name, fitness, threshold=enum_threshold)

    def _enum_record(flags, fitness):
        ai_feedback.record_test(flags, fitness, "ok" if fitness > 0.3 else "timeout")

    enum_result = enumerator.enumerate(
        tester, threshold=enum_threshold, on_progress=_enum_progress, on_result=_enum_record,
    )

    if enum_result:
        # Found a working strategy via enumeration!
        best_flags = enum_result["flags"]
        best_fitness = enum_result["fitness"]
        print(f"\n  [OK] Found: {enum_result['name']} (fitness={best_fitness:.3f})")
        print(f"       {enum_result.get('desc', '')}")
        ai_feedback.record_test(best_flags, best_fitness, "ok")

        # Save and apply
        record = manager.save_strategy(best_flags, best_fitness, isp_name)
        analytics.log_strategy(
            strategy_id=record.id, flags=best_flags, fitness=best_fitness,
            isp=isp_name, source="enumeration",
        )

        _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best_flags, hostlist, _tspu_recommended_ttl, config)
        if not _active_process:
            print("  [ERROR] winws2 failed to start with enumerated strategy, trying GA...")
            enum_result = None  # fall through to GA
        if _active_process:
            time.sleep(2)
            verify = _quick_connectivity_check(hosts)
            working = sum(1 for ok in verify.values() if ok)
            total_h = len(verify)
            print()
            for host, ok in verify.items():
                print(f"    {host}: {'OK' if ok else 'FAIL'}")

            if working > 0:
                print(f"\n  === DPI BYPASS ACTIVE ({working}/{total_h} sites) ===")
                _restart_stuck_apps()
                print(f"\n  Strategy: {' | '.join(best_flags)}")
                print(f"  Tier:     {tier.get_status_line()}")
                print(f"  Donate:   {donate.page_url}")

                # Immediately solve failed hosts (skip TLS_INTERFERENCE — desync can't help)
                failed_hosts = [h for h, ok in verify.items() if not ok
                                and (h not in blocked or blocked[h].block_type != "TLS_INTERFERENCE")]
                if failed_hosts and _running:
                    from brain.host_solver import HostSolver
                    # Stop permanent zapret — shadow tester needs exclusive WinDivert
                    _stop_permanent_zapret(_active_process)
                    _active_process = None
                    solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback, server_sync=sync)
                    try:
                        for fh in failed_hosts:
                            if not _running:
                                break
                            print(f"\n  Solving: {fh}...")
                            result = solver.solve(fh, isp=isp_name)
                            if result:
                                print(f"  [OK] Found strategy for {fh} (fitness={result.fitness:.3f})")
                            else:
                                print(f"  [!] No strategy found for {fh}")
                    finally:
                        extra = solver.build_extra_profiles(lua_dir)
                        _active_process = _start_permanent_zapret(
                            zapret_bin, lua_dir, best_flags,
                            hostlist, _tspu_recommended_ttl, config,
                            extra_profiles=extra,
                        )

                print(f"\n  Monitoring connection... (Ctrl+C to stop)\n")
                _unified_watchdog(best_flags, record.id)
                analytics.close()
                return
            else:
                print("\n  [!] Strategy works in test but not in permanent, trying evolution...")
                _stop_permanent_zapret(_active_process)
                _active_process = None
                enum_result = None  # fall through to GA

    best = None  # will be set by GA if enumerator didn't apply
    if not enum_result:
        print(f"\n  Starting GA evolution (this may take a few minutes)...")

        # ─── Build seed strategies ────────────────────────────────────────
        seeds = _get_seeds(isp_name, ai, ai_feedback=ai_feedback, tspu_profile=tspu_profile)

        # ─── Real Evolution ──────────────────────────────────────────────
        ga_config = GAConfig.from_config(config)
        ga_config.generations = min(ga_config.generations, 15)
        ga_config.population_size = min(ga_config.population_size, 10)
        fitness_threshold = config.get("fitness_apply_threshold", 0.7)

        best = _run_evolution(tester, ga_config, seeds, analytics, isp_name, ai_feedback=ai_feedback, dpi_type=dpi_type)

    if not best or best.fitness < 0.1:
        print()
        print("  [!] No working strategy found.")
        print("  This may mean DPI is too aggressive or network issues.")
        print("  Try running again or check your connection.")
        analytics.close()
        input("  Press Enter to exit...")
        return

    # Thorough verification of winner (full trials + timeout)
    print(f"\n  Verifying best strategy...")
    verified_fitness = tester.test_strategy_thorough(best.flags)
    if verified_fitness < 0.1:
        print(f"  [!] Strategy failed verification (fitness={verified_fitness:.3f})")
        print("  Try running again.")
        analytics.close()
        input("  Press Enter to exit...")
        return
    best.fitness = verified_fitness
    print(f"  [OK] Verified: fitness={verified_fitness:.3f}")

    # Save strategy
    record = manager.save_strategy(best.flags, best.fitness, isp_name)
    analytics.log_strategy(
        strategy_id=record.id, flags=best.flags, fitness=best.fitness,
        isp=isp_name, source="local",
    )
    analytics.enqueue_strategy_result(
        flags=best.flags, fitness=best.fitness, isp=isp_name,
        middlebox_type="unknown", region="", host_results={},
    )

    # Sync with server
    if sync.is_configured:
        sync.sync_now()

    # ─── Apply strategy ──────────────────────────────────────────────
    print()
    print(f"  Applying strategy (fitness={best.fitness:.3f})...")
    print(f"  Strategy: {' | '.join(best.flags)}")

    _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best.flags, hostlist, _tspu_recommended_ttl, config)

    if _active_process is None:
        print("  [ERROR] Failed to start DPI bypass!")
        analytics.close()
        input("  Press Enter to exit...")
        return

    # Verify it works
    time.sleep(2)
    verify = _quick_connectivity_check(hosts)
    working = sum(1 for ok in verify.values() if ok)
    total = len(verify)

    print()
    for host, ok in verify.items():
        status = "OK" if ok else "FAIL"
        print(f"    {host}: {status}")

    if working == 0:
        print()
        print("  [!] Strategy applied but sites still blocked.")
        print("  Watchdog will attempt recovery immediately...")
        # Keep zapret2 running with current strategy as baseline —
        # watchdog will detect failure and run full recovery cycle.
        # Do NOT stop zapret2 here, or user has no bypass for 5 min.
    else:
        print()
        print(f"  === DPI BYPASS ACTIVE ({working}/{total} sites) ===")
        _restart_stuck_apps()
        print()
        print(f"  Tier:     {tier.get_status_line()}")
        print(f"  Donate:   {donate.page_url}")
        print()
        print("  Monitoring connection... (Ctrl+C to stop)")
        print()

    # ─── Unified watchdog with auto-recovery ─────────────────────────
    _unified_watchdog(best.flags if best else [], record.id if record else "unknown")

    # ─── Shutdown ─────────────────────────────────────────────────────
    print()
    print("  Shutting down...")
    _stop_permanent_zapret(_active_process)
    _active_process = None

    stats = analytics.get_stats_summary()
    print(f"  Strategies tested: {stats['total_strategies']}")
    print(f"  Avg fitness:       {stats['avg_fitness']:.3f}")
    analytics.close()
    print("  Done.")
    print()


def _monitoring_loop(hosts, config, zapret_bin, lua_dir, analytics, manager,
                     ai, sync, tier, profiler, isp_name, hostlist=None,
                     ai_feedback=None, tspu_profile=None, dpi_type: str = "unknown"):
    """Monitor connectivity and activate bypass if blocking detected."""
    global _running, _active_process
    interval = config.get("watchdog_interval_minutes", 5) * 60

    print()
    print("  Monitoring for DPI blocking... (Ctrl+C to stop)")
    print()

    tester = ConnectionTester(config, mock=False, hostlist_path=hostlist)
    ga_config = GAConfig.from_config(config)

    while _running:
        for _ in range(interval):
            if not _running:
                break
            time.sleep(1)

        if not _running:
            break

        now = datetime.now().strftime("%H:%M")
        status_parts = []
        any_blocked = False

        for host in hosts:
            r = _curl_check_one(host, timeout=10)
            # Log to analytics (no strategy active yet, use "baseline")
            analytics.log_test_result(
                strategy_id="baseline", host=host,
                http_code=r["http_code"], success=r["success"],
                latency_ms=r["latency_ms"], error_type=r["error_type"],
            )
            short = host.replace(".com", "")
            if r["success"]:
                status_parts.append(f"{short}:OK({r['latency_ms']:.0f}ms)")
            else:
                err = r["error_type"] or "FAIL"
                status_parts.append(f"{short}:{err.upper()}")
                any_blocked = True

        print(f"  [{now}] {' | '.join(status_parts)}")

        if any_blocked and _active_process is None:
            # Check streaks — only activate if consistent blocking
            health = analytics.get_all_hosts_health(hosts, minutes=10)
            if health["degraded"]:
                print(f"\n  [!] Blocking detected: {', '.join(health['degraded'])}")

                best_flags = None
                best_fitness = 0.0

                # Step 1: Community instant strategy (~5 sec)
                if sync.is_configured:
                    print("  Trying community strategy...")
                    community = sync.get_instant_strategy(isp_name)
                    if community and community.get("flags"):
                        fit = tester.test_strategy(community["flags"])
                        if fit > 0.5:
                            best_flags = community["flags"]
                            best_fitness = fit
                            print(f"  [OK] Community strategy: fitness={fit:.3f}")

                # Step 2: Enumerator (~30-60 sec) if community failed
                # TSPU DPI reduces max achievable fitness (googlevideo TLS_INTERFERENCE
                # always fails), so lower threshold to accept partial bypass
                if not best_flags:
                    print("  Running enumerator (anti-throttle first)...")
                    from brain.enumerator import StrategyEnumerator
                    excluded = ai_feedback.get_excluded_functions() if ai_feedback else set()
                    enum = StrategyEnumerator(excluded_functions=excluded)
                    result = enum.enumerate(tester, threshold=0.40,
                        on_progress=lambda i, t, n, f: print(f"    [{i}/{t}] {n}: {f:.3f}") if f > 0 else None)
                    if result:
                        best_flags = result["flags"]
                        best_fitness = result["fitness"]
                        print(f"  [OK] Enumerator: {result['name']} fitness={best_fitness:.3f}")

                # Step 3: GA evolution as last resort (~10-15 min)
                if not best_flags:
                    print("  Running GA evolution (last resort)...")
                    seeds = _get_seeds(isp_name, ai, ai_feedback=ai_feedback, tspu_profile=tspu_profile)
                    best_result = _run_evolution(tester, ga_config, seeds, analytics, isp_name, ai_feedback=ai_feedback, dpi_type=dpi_type)
                    if best_result and best_result.fitness > 0.1:
                        best_flags = best_result.flags
                        best_fitness = best_result.fitness

                if best_flags:
                    manager.save_strategy(best_flags, best_fitness, isp_name)
                    _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best_flags, hostlist, _tspu_recommended_ttl, config)
                    if _active_process:
                        print(f"\n  === DPI BYPASS ACTIVE (fitness={best_fitness:.3f}) ===\n")
                        _restart_stuck_apps()

    _stop_permanent_zapret(_active_process)
    analytics.close()


def _get_seeds(isp_name: str, ai: AIAdvisor, ai_feedback=None, tspu_profile=None) -> list[list[str]]:
    """Get seed strategies from ISP profile + AI.

    Seeds are ordered: proven TSPU combos first, then generic.
    Key insight: Russian TSPU needs fake+TTL for stream/video traffic,
    not just split/disorder which only helps initial handshake.
    """
    seeds = [
        # ── Anti-throttle FIRST (ER-Telecom/Dom.ru TSPU 2025+) ──────────────
        # seqovl=4096 overwhelms TSPU state buffer → no throttling
        ["multisplit:pos=1:seqovl=4096"],
        ["multisplit:pos=1:seqovl=4096", "multidisorder:pos=1,midsld"],
        # seqovl=681 = exact SNI field offset (Flowseal/Dom.ru proven)
        ["multisplit:pos=1:seqovl=681", "multidisorder:pos=1,midsld"],
        ["multisplit:pos=sniext+1:seqovl=681:seqovl_pattern=fake_default_tls"],
        # wssize=1 breaks HTTP/2 multiplexing → TSPU can't track streams
        ["wssize:wsize=1:scale=0", "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000"],
        ["wssize:wsize=1:scale=0", "multisplit:pos=1:seqovl=681"],
        # fake + seqovl=4096 (combined, for ISPs that need SNI confusion)
        ["fake:blob=fake_default_tls:ip_ttl=5:ip6_ttl=5:tcp_md5:repeats=6:tls_mod=rnd,dupsid", "multisplit:pos=1:seqovl=4096"],
        # ── autottl fake (for ISPs where fake works) ──────────────────────
        ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6", "multisplit:pos=midsld"],
        ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5", "multidisorder:pos=1,midsld"],
        ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5:repeats=8", "multisplit:pos=1,midsld"],
        ["fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5"],
        # ── NOTE: seqovl=8 intentionally excluded from seeds ─────────────
        # seqovl=8 is throttled by TSPU on ER-Telecom/AS42116.
        # It passes single-shot tests (fast response) but degrades to 8s
        # under sustained traffic. Let enumerator try it as fallback only.
    ]

    # ISP-specific seeds
    if isp_name in ISP_SEED_STRATEGIES:
        seeds = ISP_SEED_STRATEGIES[isp_name] + seeds
        print(f"  Using {isp_name} seed strategies + generic")

    # AI suggestions (with structured feedback if available)
    if ai.is_available:
        print("  Asking AI for strategy suggestions...")
        try:
            ai_seeds = ai.suggest_strategies(
                isp=isp_name, middlebox_type="unknown",
                ai_feedback=ai_feedback, tspu_profile=tspu_profile,
            )
            if ai_seeds:
                print(f"  AI suggested {len(ai_seeds)} strategies")
                seeds.extend(ai_seeds)
        except Exception as exc:
            print(f"  [!] AI unavailable: {exc}")

    return seeds


def _run_evolution(tester, ga_config, seeds, analytics, isp_name, ai_feedback=None,
                   dpi_type: str = "tspu") -> Optional:
    """Run one GA evolution cycle with real testing."""
    from brain.genetic import StrategyGene, Individual

    print()
    print("  Starting evolution (this may take a few minutes)...")
    print("  Each strategy is tested with real connections.")
    print()

    # Get excluded functions from AI feedback (if provided)
    _excluded = ai_feedback.get_excluded_functions() if ai_feedback else []
    ga = StrategyGene(ga_config, seed_strategies=seeds, excluded_functions=_excluded,
                      dpi_type=dpi_type, country="ru")

    def on_gen(gen, best):
        if not _running:
            return
        from brain.ui import gen_line
        avg = sum(i.fitness for i in ga.population) / len(ga.population)
        gen_line(gen, best.fitness, avg)

        analytics.log_evolution_generation(
            generation=gen, best_fitness=best.fitness, avg_fitness=avg,
            best_flags=best.flags, population_size=len(ga.population),
            isp=isp_name,
        )

    ga.set_generation_callback(on_gen)
    best = ga.evolve(tester.test_strategy)

    if best:
        print()
        print(f"  [OK] Best: fitness={best.fitness:.3f}")
        print(f"       Strategy: {' | '.join(best.flags)}")

    return best


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\n  [FATAL ERROR] {exc}")
        import traceback
        traceback.print_exc()
    finally:
        # Ensure cleanup even on unhandled exception
        _emergency_cleanup()
    input("\n  Press Enter to exit...")
