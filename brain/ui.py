"""UI — terminal output helpers with colors, banners, and progress bars.

Works on Windows 10+ (VT100 escape codes) and Linux/macOS.
Falls back to plain text if terminal doesn't support colors.
"""

from __future__ import annotations

import os
import platform
import sys
import shutil

# ─── Enable VT100 on Windows ─────────────────────────────────────────────────

def _enable_vt100():
    """Enable ANSI escape codes on Windows 10+."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass

_enable_vt100()

# ─── Colors ───────────────────────────────────────────────────────────────────

class C:
    """ANSI color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    # Colors
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    # Backgrounds
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

# Detect if terminal supports colors
_NO_COLOR = os.environ.get("NO_COLOR") or not sys.stdout.isatty()
if _NO_COLOR:
    for attr in dir(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""{C.CYAN}{C.BOLD}
   ____  _     ____                           ____            _               _
  |  _ \\| |   / ___|__ _ _ __ ___   ___  ___ / ___|_   _____| |__   ___   __| | __ _
  | |_) | |  | |  _/ _` | '_ ` _ \\ / _ \\/ __| |___\\ \\ / / _ \\ '_ \\ / _ \\ / _` |/ _` |
  |  __/| |__| |_| | (_| | | | | | |  __/\\__ \\___ |\\ V /  __/ |_) | (_) | (_| | (_| |
  |_|   |____\\____|\\__,_|_| |_| |_|\\___||___/____/ \\_/ \\___|_.__/ \\___/ \\__,_|\\__,_|
{C.RESET}
{C.GRAY}  DPI Bypass Tool with Genetic Algorithm + AI{C.RESET}
{C.GRAY}  github.com/Leonid1095/PLGames-Svoboda{C.RESET}
"""

BANNER_SMALL = f"""{C.CYAN}{C.BOLD}
  === PLGames Svoboda ==={C.RESET}
{C.GRAY}  DPI Bypass Tool | AI + Genetic Algorithm{C.RESET}
"""


def print_banner():
    """Print startup banner. Uses small version if terminal is narrow."""
    cols = shutil.get_terminal_size((80, 24)).columns
    if cols >= 90:
        print(BANNER)
    else:
        print(BANNER_SMALL)


# ─── Status messages ──────────────────────────────────────────────────────────

def ok(msg: str):
    """Print success message."""
    print(f"  {C.GREEN}[OK]{C.RESET} {msg}")

def fail(msg: str):
    """Print failure message."""
    print(f"  {C.RED}[FAIL]{C.RESET} {msg}")

def warn(msg: str):
    """Print warning message."""
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

def info(msg: str):
    """Print info message."""
    print(f"  {C.BLUE}[i]{C.RESET} {msg}")

def error(msg: str):
    """Print error message."""
    print(f"  {C.RED}{C.BOLD}[ERROR]{C.RESET} {msg}")

def step(msg: str):
    """Print step/section header."""
    print(f"\n  {C.BOLD}{msg}{C.RESET}")

def detail(msg: str):
    """Print indented detail line."""
    print(f"       {C.GRAY}{msg}{C.RESET}")


# ─── Block status ─────────────────────────────────────────────────────────────

_BLOCK_ICONS = {
    "NOT_BLOCKED":      f"{C.GREEN}OK{C.RESET}",
    "RST_INJECTION":    f"{C.RED}RST{C.RESET}",
    "SNI_FILTERING":    f"{C.RED}SNI{C.RESET}",
    "HTTP2_STREAM_KILL": f"{C.RED}H2-KILL{C.RESET}",
    "THROTTLING":       f"{C.YELLOW}SLOW{C.RESET}",
    "TLS_INTERFERENCE": f"{C.RED}TLS{C.RESET}",
    "IP_BLOCK":         f"{C.RED}IP-BLK{C.RESET}",
    "DNS_POISONING":    f"{C.RED}DNS{C.RESET}",
    "TIMEOUT_SILENT":   f"{C.YELLOW}TIMEOUT{C.RESET}",
}

def block_status(host: str, block_type: str, confidence: float, evidence: list[str] = None):
    """Print block analysis result for one host."""
    icon = _BLOCK_ICONS.get(block_type, f"{C.GRAY}???{C.RESET}")
    if block_type == "NOT_BLOCKED":
        print(f"    {C.GREEN}{host}: accessible{C.RESET}")
    else:
        print(f"    {host}: {C.RED}BLOCKED{C.RESET} [{icon}] ({confidence:.0%})")
        if evidence:
            for e in evidence[:2]:
                print(f"      {C.GRAY}- {e}{C.RESET}")


# ─── Progress bars ────────────────────────────────────────────────────────────

def progress_bar(current: int, total: int, width: int = 25, fill: str = "#", empty: str = ".") -> str:
    """Generate a progress bar string."""
    ratio = current / total if total > 0 else 0
    filled = int(width * ratio)
    return f"[{fill * filled}{empty * (width - filled)}]"

def gen_line(gen: int, best_fitness: float, avg_fitness: float):
    """Print one generation line with colored progress bar."""
    bar_len = int(best_fitness * 25)
    bar = f"{C.GREEN}{'#' * bar_len}{C.GRAY}{'.' * (25 - bar_len)}{C.RESET}"
    color = C.GREEN if best_fitness >= 0.7 else C.YELLOW if best_fitness >= 0.4 else C.RED
    print(f"  Gen {gen:02d} [{bar}] {color}best={best_fitness:.3f}{C.RESET} avg={avg_fitness:.3f}")

def enum_line(index: int, total: int, name: str, fitness: float, threshold: float = 0.5):
    """Print one enumeration test line."""
    if fitness >= threshold:
        print(f"    {C.GREEN}[{index}/{total}]{C.RESET} {name}: {C.GREEN}{fitness:.3f} (OK){C.RESET}")
    elif fitness > 0:
        print(f"    {C.YELLOW}[{index}/{total}]{C.RESET} {name}: {C.YELLOW}{fitness:.3f}{C.RESET}")
    else:
        print(f"    {C.GRAY}[{index}/{total}]{C.RESET} {name}: {C.GRAY}{fitness:.3f}{C.RESET}")


# ─── Monitoring ───────────────────────────────────────────────────────────────

def monitor_line(time_str: str, host_statuses: list[tuple[str, bool, float]], health: float):
    """Print one monitoring check line."""
    parts = []
    for host, success, latency_ms in host_statuses:
        short = host.replace(".com", "").replace(".discordapp", "")
        if success:
            parts.append(f"{C.GREEN}{short}:OK({latency_ms:.0f}ms){C.RESET}")
        else:
            parts.append(f"{C.RED}{short}:FAIL{C.RESET}")

    health_color = C.GREEN if health >= 0.8 else C.YELLOW if health >= 0.5 else C.RED
    print(f"  {C.GRAY}[{time_str}]{C.RESET} {' | '.join(parts)}  {health_color}(health={health:.0%}){C.RESET}")


# ─── Active status ────────────────────────────────────────────────────────────

def bypass_active(working: int, total: int, strategy: str, tier: str, donate: str):
    """Print bypass active banner."""
    print()
    print(f"  {C.GREEN}{C.BOLD}=== DPI BYPASS ACTIVE ({working}/{total} sites) ==={C.RESET}")
    print()
    print(f"  {C.BOLD}Strategy:{C.RESET} {C.CYAN}{strategy}{C.RESET}")
    print(f"  {C.BOLD}Tier:{C.RESET}     {tier}")
    print(f"  {C.BOLD}Donate:{C.RESET}   {C.BLUE}{donate}{C.RESET}")
    print()
    print(f"  {C.GRAY}Monitoring connection... (Ctrl+C to stop){C.RESET}")
    print()


def bypass_failed():
    """Print bypass failed message."""
    print()
    print(f"  {C.RED}{C.BOLD}[!] No working strategy found.{C.RESET}")
    print(f"  {C.GRAY}This may mean DPI is too aggressive or network issues.{C.RESET}")
    print(f"  {C.GRAY}Try running again or check your connection.{C.RESET}")


# ─── TSPU info ────────────────────────────────────────────────────────────────

def tspu_info(dpi_distance: int, dpi_type: str, recommended_ttl: int, evidence: list[str]):
    """Print TSPU profiling results."""
    ok(f"DPI at ~{C.BOLD}{dpi_distance} hops{C.RESET}, type: {C.CYAN}{dpi_type}{C.RESET}")
    if recommended_ttl:
        detail(f"Recommended fake TTL: {C.BOLD}{recommended_ttl}{C.RESET}")
    for e in evidence[:3]:
        detail(e)


# ─── Separator ────────────────────────────────────────────────────────────────

def separator():
    """Print a thin separator line."""
    cols = min(shutil.get_terminal_size((80, 24)).columns, 60)
    print(f"  {C.GRAY}{'─' * cols}{C.RESET}")
