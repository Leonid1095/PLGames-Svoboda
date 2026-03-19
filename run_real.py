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
    """Kill any remaining winws2/nfqws2 processes on exit.

    This prevents WinDivert driver from staying loaded after crash,
    which would break DNS and internet until reboot.
    """
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "winws2.exe"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
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
    """
    import os
    cmd = [str(binary)]
    is_win = platform.system() == "Windows"
    cwd = str(binary.parent) if is_win else None

    if is_win:
        cmd.extend([
            "--wf-tcp-out=80,443",
            "--wf-udp-out=443",
            # NOTE: --wf-tcp-in NOT needed! SYN-ACK/FIN/RST are captured
            # automatically by WinDivert filter constructor. This enables
            # autottl calibration without the CPU cost of capturing all data.
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
        if auto.exists():
            cmd.append(f"--lua-init=@{os.path.relpath(str(auto), base)}")

    # Traffic morphing: apply browser TLS profile
    from brain.morpher import TrafficMorpher
    morpher = TrafficMorpher(
        profile_name=config.get("morphing_profile", "chrome_win") if config else "chrome_win",
        enabled=config.get("morphing_enabled", True) if config else True,
    )
    tls_init = morpher.get_tls_init()
    if tls_init:
        cmd.append(f"--lua-init={tls_init}")

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
            cmd.append("--hostlist-auto-fail-threshold=3")
            cmd.append("--hostlist-auto-fail-time=60")
        except Exception as exc:
            print(f"  [!] Hostlist copy failed: {exc} (running without hostlist)")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 1: TLS (all HTTPS except YouTube CDN)
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist-exclude-domains=googlevideo.com,googleapis.com,ggpht.com,ytimg.com",
    ])
    # Traffic morphing: browser-like TCP window
    morph_calls = morpher.get_permanent_calls()
    for mc in morph_calls:
        cmd.append(f"--lua-desync={mc}")
    # Tested strategy (exactly what scored in enumeration/GA)
    morphed_flags = morpher.morph_strategy(flags)
    for call in morphed_flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 2: TLS for YouTube CDN (googlevideo etc.)
    # These need gentler desync — only fake, no aggressive split
    # ══════════════════════════════════════════════════════════════
    quic_ttl = tspu_ttl if tspu_ttl and tspu_ttl > 0 else 4
    cmd.extend([
        "--new",
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist-domains=googlevideo.com,googleapis.com,ggpht.com,ytimg.com,youtube.com,youtu.be",
        f"--lua-desync=fake:blob=fake_default_tls:ip_ttl={quic_ttl}:ip6_ttl={quic_ttl}:tcp_md5:repeats=6",
        "--lua-desync=multisplit:pos=midsld",
    ])

    # ══════════════════════════════════════════════════════════════
    # PROFILE 3: HTTP (port 80)
    # ══════════════════════════════════════════════════════════════
    cmd.extend([
        "--new",
        "--filter-tcp=80",
        "--filter-l7=http",
    ])
    for call in flags:
        cmd.append(f"--lua-desync={call}")

    # ══════════════════════════════════════════════════════════════
    # PROFILE 4: QUIC (YouTube video + other UDP/443)
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
        return proc
    except Exception as exc:
        print(f"  [ERROR] Failed to start winws2: {exc}")
        log.error("Permanent winws2 launch error: %s", exc)
        return None


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
            ["curl", "-s", "--max-time", str(timeout),
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
    global _running, _active_process

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    _print_header()

    # ─── Load config ──────────────────────────────────────────────────
    config = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
    config["_base_dir"] = str(BASE_DIR)

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
            cached = profiler._load_cached_profile()
            if cached:
                isp_name = cached.get("isp_name", "unknown")
                asn = cached.get("asn", "?")
                ui.ok(f"ISP: {isp_name} ({asn}) (cached)")
            else:
                ui.warn("ISP unknown (will detect after bypass)")
        except Exception:
            ui.warn("ISP unknown (will detect after bypass)")

    # ─── Download blocklist ─────────────────────────────────────────
    print()
    hostlist = _download_hostlist(BASE_DIR)

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

    # ─── Smart block detection ──────────────────────────────────────
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

    if all_accessible:
        ui.ok("All sites accessible without DPI bypass.")
        print("  Starting monitoring mode (will activate if blocking detected)...")
        _monitoring_loop(hosts, config, zapret_bin, lua_dir, analytics, manager,
                         ai, sync, tier, profiler, isp_name, hostlist)
        analytics.close()
        return

    # Collect block types for AI context
    block_summary = {h: r.block_type for h, r in blocked.items()}
    print(f"\n  {len(blocked)} site(s) blocked: {', '.join(f'{h}={t}' for h, t in block_summary.items())}")

    # Collect recommended strategies from classifier
    classifier_strategies: list[list[str]] = []
    for r in blocked.values():
        for s in r.recommended_strategies:
            if s not in classifier_strategies:
                classifier_strategies.append(s)

    # ─── Initialize tester ──────────────────────────────────────────
    tester = ConnectionTester(config, mock=False, hostlist_path=hostlist)
    dpi_type = tspu_profile.dpi_type if tspu_profile else "unknown"

    # ─── AI Engine — reserved for per-host solving after community/enum ──
    # Community + enum are free and fast. AI Engine uses LLM (rate limited).
    # AI Engine activates in per-host solver for hosts that enum can't fix.
    _ai_engine_used = False
    if False:  # AI Engine runs inside per-host solver, not here
        try:
            from brain.ai_engine import AIEngine, build_engine_context
            from brain.host_solver import HostSolver

            # Build tool handlers
            def _tool_run_enumerator(hosts=None, forbid_genes=None, stop_on_fitness=0.5):
                from brain.enumerator import StrategyEnumerator
                excluded = set(forbid_genes or []) | ai_feedback.get_excluded_functions()
                enum = StrategyEnumerator(excluded_functions=excluded)
                best_fit, best_flags, best_name = 0.0, [], ""
                for s in enum.strategies:
                    if not _running:
                        break
                    fit = tester.test_strategy(s["flags"])
                    ai_feedback.record_test(s["flags"], fit, "ok" if fit > 0.3 else "timeout")
                    if fit > best_fit:
                        best_fit, best_flags, best_name = fit, s["flags"], s["name"]
                    if fit >= stop_on_fitness:
                        break
                return {"strategy": " | ".join(best_flags), "fitness": best_fit, "name": best_name}

            def _tool_per_host_solver(host=""):
                solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback)
                result = solver.solve(host)
                if result:
                    return {"strategy": " | ".join(result.flags), "fitness": result.fitness}
                return {"strategy": "", "fitness": 0.0}

            def _tool_test_strategy(strategy="", hosts=None):
                flags = [f.strip() for f in strategy.split("|")]
                fit = tester.test_strategy(flags)
                verify = _quick_connectivity_check(hosts or list(blocked.keys()))
                return {"fitness": fit, "host_status": {h: ok for h, ok in verify.items()}}

            def _tool_get_block_analysis(host=""):
                analysis = classifier.classify(host)
                return {
                    "block_type": analysis.block_type,
                    "confidence": analysis.confidence,
                    "evidence": analysis.evidence,
                }

            def _tool_apply_strategy(strategy="", extra_profiles=None):
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

                    # Enter watchdog loop
                    watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
                    while _running:
                        for _ in range(watchdog_interval):
                            if not _running:
                                break
                            time.sleep(1)
                        if not _running:
                            break
                        now = datetime.now().strftime("%H:%M")
                        host_statuses = []
                        for host in hosts:
                            r = _curl_check_one(host, timeout=8)
                            host_statuses.append((host, r["success"], r["latency_ms"]))
                        health = analytics.get_all_hosts_health(hosts, minutes=10)
                        ui.monitor_line(now, host_statuses, health["overall_rate"])
                    if _active_process:
                        _stop_permanent_zapret(_active_process)
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
            if verified > 0.5:
                print(f"  [OK] Community strategy works! (fitness={verified:.3f})")
                sync.vote_strategy(community["flags"], success=True, fitness=verified, isp=isp_name, dpi_type=dpi_type)
                # Apply directly — skip everything
                record = manager.save_strategy(community["flags"], verified, isp_name)
                ai_feedback.record_test(community["flags"], verified, "ok")
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

                        # Immediately solve failed hosts
                        failed_hosts = [h for h, ok_v in verify.items() if not ok_v]
                        if failed_hosts and _running:
                            # Must stop permanent winws2 so shadow can use same ports
                            print(f"\n  {len(failed_hosts)} host(s) still blocked, searching solutions...")
                            _stop_permanent_zapret(_active_process)
                            _active_process = None
                            time.sleep(1)

                            from brain.host_solver import HostSolver
                            solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback)
                            any_solved = False
                            for fh in failed_hosts:
                                if not _running:
                                    break
                                print(f"\n  Solving: {fh}...")
                                result = solver.solve(fh)
                                if result:
                                    print(f"  [OK] Found strategy for {fh} (fitness={result.fitness:.3f})")
                                    any_solved = True
                                else:
                                    print(f"  [!] No strategy found for {fh}")

                            # Restart permanent with main + per-host strategies
                            extra = solver.build_extra_profiles(lua_dir) if any_solved else []
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

                        # Watchdog loop
                        watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
                        while _running:
                            for _ in range(watchdog_interval):
                                if not _running:
                                    break
                                time.sleep(1)
                            if not _running:
                                break
                            now = datetime.now().strftime("%H:%M")
                            host_statuses = []
                            for host in hosts:
                                r = _curl_check_one(host, timeout=5)
                                host_statuses.append((host, r["success"], r["latency_ms"]))
                            health = analytics.get_all_hosts_health(hosts, minutes=10)
                            ui.monitor_line(now, host_statuses, health["overall_rate"])
                            if health["overall_rate"] < config.get("watchdog_min_fitness", 0.6):
                                ui.warn("Health degraded, re-evolving...")
                                _stop_permanent_zapret(_active_process)
                                _active_process = None
                                break
                        if _running and _active_process:
                            _stop_permanent_zapret(_active_process)
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
                    print(f"\n  Tier:     {tier.get_status_line()}")
                    print(f"  Donate:   {donate.page_url}")
                    print(f"\n  Monitoring connection... (Ctrl+C to stop)\n")

                    # Go to watchdog
                    watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
                    fail_threshold = config.get("watchdog_fail_threshold", 2)
                    min_fitness = config.get("watchdog_min_fitness", 0.6)
                    active_strategy_id = record.id
                    ga_config = GAConfig.from_config(config)
                    ga_config.generations = min(ga_config.generations, 15)
                    ga_config.population_size = min(ga_config.population_size, 10)

                    while _running:
                        for _ in range(watchdog_interval):
                            if not _running:
                                break
                            time.sleep(1)
                        if not _running:
                            break

                        now = datetime.now().strftime("%H:%M")
                        status_parts = []
                        for host in hosts:
                            r = _curl_check_one(host, timeout=5)
                            analytics.log_test_result(
                                strategy_id=active_strategy_id,
                                host=host, http_code=r["http_code"],
                                success=r["success"], latency_ms=r["latency_ms"],
                                error_type=r["error_type"],
                            )
                            short = host.replace(".com", "").replace(".discordapp", "")
                            if r["success"]:
                                status_parts.append(f"{short}:OK({r['latency_ms']:.0f}ms)")
                            else:
                                err = r["error_type"] or "FAIL"
                                status_parts.append(f"{short}:{err.upper()}")

                        health = analytics.get_all_hosts_health(hosts, minutes=10)
                        print(f"  [{now}] {' | '.join(status_parts)}  (health={health['overall_rate']:.0%})")

                        if health["overall_rate"] < min_fitness:
                            print(f"\n  [!] Health degraded, re-evolving...")
                            _stop_permanent_zapret(_active_process)
                            _active_process = None
                            break  # Fall through to evolution

                    if _running and _active_process:
                        # Clean exit from watchdog
                        _stop_permanent_zapret(_active_process)
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

    print(f"\n  Fast strategy enumeration ({len(priority_strategies)} strategies, AI-prioritized)...")
    enumerator = StrategyEnumerator(strategies=priority_strategies, excluded_functions=excluded)

    def _enum_progress(i, total, name, fitness):
        ui.enum_line(i, total, name, fitness, threshold=0.5)

    def _enum_record(flags, fitness):
        ai_feedback.record_test(flags, fitness, "ok" if fitness > 0.3 else "timeout")

    enum_result = enumerator.enumerate(
        tester, threshold=0.5, on_progress=_enum_progress, on_result=_enum_record,
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
                print(f"\n  Strategy: {' | '.join(best_flags)}")
                print(f"  Tier:     {tier.get_status_line()}")
                print(f"  Donate:   {donate.page_url}")

                # Immediately solve failed hosts
                failed_hosts = [h for h, ok in verify.items() if not ok]
                if failed_hosts and _running:
                    from brain.host_solver import HostSolver
                    solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback)
                    for fh in failed_hosts:
                        if not _running:
                            break
                        print(f"\n  Solving: {fh}...")
                        result = solver.solve(fh)
                        if result:
                            print(f"  [OK] Found strategy for {fh} (fitness={result.fitness:.3f})")
                            extra = solver.build_extra_profiles(lua_dir)
                            if extra:
                                _stop_permanent_zapret(_active_process)
                                _active_process = _start_permanent_zapret(
                                    zapret_bin, lua_dir, best_flags,
                                    hostlist, _tspu_recommended_ttl, config,
                                    extra_profiles=extra,
                                )
                                time.sleep(2)
                                r = _curl_check_one(fh, timeout=8)
                                print(f"    {fh}: {'OK' if r['success'] else 'FAIL'}")
                        else:
                            print(f"  [!] No strategy found for {fh}")

                print(f"\n  Monitoring connection... (Ctrl+C to stop)\n")

                # Watchdog for enumerated strategy
                watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
                active_strategy_id = record.id
                _watchdog_checks = 0
                _donate_shown = False
                _donate_notified = False
                while _running:
                    for _ in range(watchdog_interval):
                        if not _running:
                            break
                        time.sleep(1)
                    if not _running:
                        break
                    _watchdog_checks += 1
                    now = datetime.now().strftime("%H:%M")
                    status_parts = []
                    for host in hosts:
                        r = _curl_check_one(host, timeout=5)
                        analytics.log_test_result(
                            strategy_id=active_strategy_id,
                            host=host, http_code=r["http_code"],
                            success=r["success"], latency_ms=r["latency_ms"],
                            error_type=r["error_type"],
                        )
                        short = host.replace(".com", "").replace(".discordapp", "")
                        if r["success"]:
                            status_parts.append(f"{short}:OK({r['latency_ms']:.0f}ms)")
                        else:
                            status_parts.append(f"{short}:{(r['error_type'] or 'FAIL').upper()}")
                    health = analytics.get_all_hosts_health(hosts, minutes=10)
                    print(f"  [{now}] {' | '.join(status_parts)}  (health={health['overall_rate']:.0%})")

                    # Donate reminder: terminal at 10 min, notification at 30 min
                    if _watchdog_checks == 2 and not _donate_shown:
                        ui.donate_reminder(donate.page_url, tier.current_tier_name if hasattr(tier, 'current_tier_name') else "FREE")
                        _donate_shown = True
                    if _watchdog_checks == 6 and not _donate_notified:
                        ui.donate_notification(donate.page_url)
                        _donate_notified = True

                    if health["overall_rate"] < config.get("watchdog_min_fitness", 0.6):
                        print(f"\n  [!] Health degraded, re-evolving...")
                        _stop_permanent_zapret(_active_process)
                        _active_process = None
                        break
                # Clean exit or degraded — either way we're done
                if _running and _active_process:
                    _stop_permanent_zapret(_active_process)
                analytics.close()
                return
            else:
                print("\n  [!] Strategy works in test but not in permanent, trying evolution...")
                _stop_permanent_zapret(_active_process)
                _active_process = None
                enum_result = None  # fall through to GA

    if not enum_result:
        print(f"\n  Starting GA evolution (this may take a few minutes)...")

        # ─── Build seed strategies ────────────────────────────────────────
        seeds = _get_seeds(isp_name, ai)

        # ─── Real Evolution ──────────────────────────────────────────────
        ga_config = GAConfig.from_config(config)
        ga_config.generations = min(ga_config.generations, 15)
        ga_config.population_size = min(ga_config.population_size, 10)
        fitness_threshold = config.get("fitness_apply_threshold", 0.7)

        best = _run_evolution(tester, ga_config, seeds, analytics, isp_name)

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
        print("  Trying next evolution cycle...")
        _stop_permanent_zapret(_active_process)
        _active_process = None
    else:
        print()
        print(f"  === DPI BYPASS ACTIVE ({working}/{total} sites) ===")
        print()
        print(f"  Tier:     {tier.get_status_line()}")
        print(f"  Donate:   {donate.page_url}")
        print()
        print("  Monitoring connection... (Ctrl+C to stop)")
        print()

    # ─── Watchdog loop ────────────────────────────────────────────────
    watchdog_interval = config.get("watchdog_interval_minutes", 5) * 60
    fail_threshold = config.get("watchdog_fail_threshold", 2)
    min_fitness = config.get("watchdog_min_fitness", 0.6)
    cycle_num = 0
    active_strategy_id = record.id if record else "unknown"

    while _running:
        # Sleep in small chunks
        for _ in range(watchdog_interval):
            if not _running:
                break
            time.sleep(1)

        if not _running:
            break

        # ── Detailed connectivity check with latency ──────────────
        now = datetime.now().strftime("%H:%M")
        status_parts = []
        for host in hosts:
            r = _curl_check_one(host, timeout=5)
            # Log every check to analytics for streak tracking
            analytics.log_test_result(
                strategy_id=active_strategy_id,
                host=host, http_code=r["http_code"],
                success=r["success"], latency_ms=r["latency_ms"],
                error_type=r["error_type"],
            )
            short = host.replace(".com", "")
            if r["success"]:
                status_parts.append(f"{short}:OK({r['latency_ms']:.0f}ms)")
            else:
                err = r["error_type"] or "FAIL"
                status_parts.append(f"{short}:{err.upper()}")

        # ── Get rolling health from analytics ─────────────────────
        health = analytics.get_all_hosts_health(hosts, minutes=10)
        overall = health["overall_rate"]
        degraded = health["degraded"]

        print(f"  [{now}] {' | '.join(status_parts)}  (health={overall:.0%})")

        # ── Check streak-based triggers ───────────────────────────
        # Re-evolve if: overall health drops below threshold, OR
        # any host has 3+ consecutive failures (streak_fail >= 3)
        needs_reevolve = False
        if overall < min_fitness:
            needs_reevolve = True
            print(f"  [!] Health degraded: {overall:.0%} < {min_fitness:.0%}")

        for host in hosts:
            h = health["hosts"].get(host, {})
            streak_fail = h.get("streak_fail", 0)
            if streak_fail >= fail_threshold:
                needs_reevolve = True
                print(f"  [!] {host}: {streak_fail} consecutive failures")

        # ── Per-host problem solving (without breaking working hosts) ──
        # If some hosts fail but overall health is OK, try to find
        # a separate strategy for each failing host
        persistent_fails = [
            h for h in hosts
            if health["hosts"].get(h, {}).get("streak_fail", 0) >= 3
            and not needs_reevolve
        ]
        if persistent_fails and not needs_reevolve:
            from brain.host_solver import HostSolver

            ui.separator()
            ui.warn(f"Persistent failures: {', '.join(persistent_fails)}")
            ui.info("Searching for per-host strategies...")

            solver = HostSolver(config, tester=tester, ai_feedback=ai_feedback)
            solved_any = False

            for fail_host in persistent_fails[:2]:
                # Skip if already solved
                cached = solver.get(fail_host)
                if cached:
                    ui.info(f"{fail_host}: already solved (fitness={cached.fitness:.3f})")
                    continue

                ui.step(f"Solving: {fail_host}")

                def _solve_progress(i, total, name, fitness):
                    status = "OK" if fitness > 0.3 else ""
                    ui.detail(f"[{i}/{total}] {name}: {fitness:.3f} {status}")

                result = solver.solve(
                    fail_host, isp=isp_name,
                    on_progress=_solve_progress,
                )

                if result:
                    ui.ok(f"Found strategy for {fail_host}! fitness={result.fitness:.3f}")
                    ui.detail(f"Strategy: {' | '.join(result.flags)}")
                    solved_any = True

                    # Report to server
                    if sync.is_configured:
                        sync.vote_strategy(
                            result.flags, success=True, fitness=result.fitness,
                            isp=isp_name,
                        )
                else:
                    ui.warn(f"No strategy found for {fail_host}")

            # If we found per-host fixes, restart winws2 with extra profiles
            if solved_any and _active_process:
                ui.info("Restarting winws2 with per-host profiles...")
                _stop_permanent_zapret(_active_process)
                _active_process = None

                # Rebuild with extra per-host profiles
                main_flags = best.flags if best else []
                _active_process = _start_permanent_zapret(
                    zapret_bin, lua_dir, main_flags, hostlist,
                    _tspu_recommended_ttl, config,
                )

                # Append per-host profiles
                # (Note: would need winws2 restart — for now, the main
                # strategy may help the solved host too since we tested it)
                if _active_process:
                    ui.ok("winws2 restarted with updated strategies")

            if sync.is_configured:
                sync.sync_now()

            ui.separator()

        if needs_reevolve:
            from brain.block_classifier import BlockageClassifier
            from brain.failure_analyzer import FailureAnalyzer
            from brain.enumerator import StrategyEnumerator, KNOWN_STRATEGIES

            ui.separator()
            ui.warn("Connection degraded — starting autonomous recovery cycle")

            # ── Step 1: Classify what's broken ───────────────────────
            ui.step("Step 1: Analyzing block type...")
            classifier = BlockageClassifier(timeout=5)
            failed_hosts = [h for h in degraded]
            for fh in failed_hosts[:3]:
                analysis = classifier.classify(fh)
                ui.block_status(fh, analysis.block_type, analysis.confidence, analysis.evidence)
                # Record for AI feedback
                ai_feedback.record_test(
                    [f"watchdog_check:{fh}"], 0.0,
                    failure_mode=analysis.block_type.lower(),
                )

            # ── Step 2: AI analysis of failure ───────────────────────
            ui.step("Step 2: AI analyzing failure pattern...")
            analyzer = FailureAnalyzer()
            report = analyzer.analyze(
                flags=best.flags if best else [],
                fitness=overall,
                host_results=health.get("hosts", {}),
                tspu_profile=tspu_profile,
            )
            ui.info(f"Root cause: {report.root_cause} ({report.confidence:.0%})")
            ui.detail(report.explanation[:120])
            for change in report.changes[:2]:
                ui.detail(f"Suggestion: {change.action} {change.target} → {change.new_value}")

            # ── Step 3: Try AI-suggested fix first ───────────────────
            _stop_permanent_zapret(_active_process)
            _active_process = None
            cycle_num += 1
            found_fix = False

            if report.improved_flags:
                ui.step("Step 3: Testing AI suggestion...")
                for improved in report.improved_flags[:2]:
                    fit = tester.test_strategy(improved)
                    ai_feedback.record_test(improved, fit, "ok" if fit > 0.3 else "timeout")
                    if fit > 0.5:
                        ui.ok(f"AI fix works! fitness={fit:.3f}")
                        record = manager.save_strategy(improved, fit, isp_name)
                        active_strategy_id = record.id
                        _active_process = _start_permanent_zapret(zapret_bin, lua_dir, improved, hostlist, _tspu_recommended_ttl, config)
                        found_fix = bool(_active_process)
                        if found_fix:
                            sync.vote_strategy(improved, success=True, fitness=fit, isp=isp_name)
                            break

            # ── Step 4: Fast enumeration if AI didn't help ───────────
            if not found_fix:
                ui.step("Step 4: Fast enumeration...")
                excluded = ai_feedback.get_excluded_functions()
                enum = StrategyEnumerator(excluded_functions=excluded)
                result = enum.enumerate(tester, threshold=0.5,
                    on_progress=lambda i, t, n, f: ui.enum_line(i, t, n, f, 0.5))
                if result:
                    ui.ok(f"Found: {result['name']} (fitness={result['fitness']:.3f})")
                    record = manager.save_strategy(result["flags"], result["fitness"], isp_name)
                    active_strategy_id = record.id
                    _active_process = _start_permanent_zapret(zapret_bin, lua_dir, result["flags"], hostlist, _tspu_recommended_ttl, config)
                    found_fix = bool(_active_process)

            # ── Step 5: GA evolution as last resort ──────────────────
            if not found_fix:
                ui.step("Step 5: GA evolution (last resort)...")
                seeds = _get_seeds(isp_name, ai)
                best = _run_evolution(tester, ga_config, seeds, analytics, isp_name)
                if best and best.fitness > 0.1:
                    record = manager.save_strategy(best.flags, best.fitness, isp_name)
                    active_strategy_id = record.id
                    _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best.flags, hostlist, _tspu_recommended_ttl, config)
                    found_fix = bool(_active_process)

            # ── Step 6: Report to server ─────────────────────────────
            if sync.is_configured:
                sync.sync_now()

            if found_fix:
                ui.ok(f"Recovery complete — bypass restored")
            else:
                ui.warn("Could not find working strategy. Will retry next cycle.")
            ui.separator()

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
                     ai, sync, tier, profiler, isp_name, hostlist=None):
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
            r = _curl_check_one(host, timeout=5)
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
                print("  Starting DPI bypass...")

                seeds = _get_seeds(isp_name, ai)
                best = _run_evolution(tester, ga_config, seeds, analytics, isp_name)

                if best and best.fitness > 0.1:
                    manager.save_strategy(best.flags, best.fitness, isp_name)
                    _active_process = _start_permanent_zapret(zapret_bin, lua_dir, best.flags, hostlist, _tspu_recommended_ttl, config)
                    if _active_process:
                        print(f"\n  === DPI BYPASS ACTIVE (fitness={best.fitness:.3f}) ===\n")

    _stop_permanent_zapret(_active_process)
    analytics.close()


def _get_seeds(isp_name: str, ai: AIAdvisor) -> list[list[str]]:
    """Get seed strategies from ISP profile + AI.

    Seeds are ordered: proven TSPU combos first, then generic.
    Key insight: Russian TSPU needs fake+TTL for stream/video traffic,
    not just split/disorder which only helps initial handshake.
    """
    seeds = [
        # autottl fake — auto-calibrates TTL to reach DPI but not server
        ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=6", "multisplit:pos=midsld"],
        ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5", "multidisorder:pos=1,midsld"],
        # Known winner: multisplit + multidisorder
        ["multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000", "multidisorder:pos=1,midsld"],
        # autottl + high repeats (aggressive TSPU)
        ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5:repeats=8", "multisplit:pos=1,midsld"],
        # fakedsplit with autottl
        ["fakedsplit:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5"],
        # Combined winner + fake
        ["fake:blob=fake_default_tls:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:tcp_md5:repeats=4", "multisplit:pos=3:seqovl=8:seqovl_pattern=0x00000000"],
    ]

    # ISP-specific seeds
    if isp_name in ISP_SEED_STRATEGIES:
        seeds = ISP_SEED_STRATEGIES[isp_name] + seeds
        print(f"  Using {isp_name} seed strategies + generic")

    # AI suggestions (with structured feedback if available)
    if ai.is_available:
        print("  Asking AI for strategy suggestions...")
        try:
            _fb = ai_feedback
            _tp = tspu_profile if tspu_profile else None
            ai_seeds = ai.suggest_strategies(
                isp=isp_name, middlebox_type="unknown",
                ai_feedback=_fb, tspu_profile=_tp,
            )
            if ai_seeds:
                print(f"  AI suggested {len(ai_seeds)} strategies")
                seeds.extend(ai_seeds)
        except Exception as exc:
            print(f"  [!] AI unavailable: {exc}")

    return seeds


def _run_evolution(tester, ga_config, seeds, analytics, isp_name) -> Optional:
    """Run one GA evolution cycle with real testing."""
    from brain.genetic import StrategyGene, Individual

    print()
    print("  Starting evolution (this may take a few minutes)...")
    print("  Each strategy is tested with real connections.")
    print()

    # Get excluded functions from AI feedback (global)
    _excluded = ai_feedback.get_excluded_functions()
    ga = StrategyGene(ga_config, seed_strategies=seeds, excluded_functions=_excluded)

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
        input("\n  Press Enter to exit...")
