"""Live strategy harvester — pulls fresh DPI bypass configs from
community repos and translates them to zapret2 lua syntax.

Why: the hardcoded KNOWN_STRATEGIES list grows stale. Flowseal pushes
new configs weekly, GoodbyeDPI updates its examples, ntc.party threads
share fresh tricks. Without auto-harvest, we miss all of it.

How: every 6h, fetch raw .bat / .json / .cmd files from configured
sources via GitHub raw API, parse out --dpi-desync args, translate to
our zapret2 lua syntax (multisplit/multidisorder/fake), dedupe by
flags signature, append to enumerator pool.

Limitations:
  - Only parses zapret v1 .bat (Flowseal-style) right now
  - Translator covers ~6 most common patterns (split2, disorder2,
    fake, fakedsplit etc). Unknown functions → strategy skipped.
  - No GitHub auth → public raw URLs only, rate limit ~60/h shared
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger("svoboda.harvester")

CACHE_TTL_SECONDS = 6 * 3600
CACHE_FILE = Path("harvested_strategies.json")
USER_AGENT = "PLGames-Svoboda-Harvester/1.0"
FETCH_TIMEOUT = 10

# Configured sources. Each: name, url to raw file, parser key, tag prefix.
SOURCES: list[dict] = [
    {
        "name": "Flowseal/general",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general.bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal"],
    },
    {
        "name": "Flowseal/general-alt",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt"],
    },
    {
        "name": "Flowseal/general-alt2",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT2).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt2"],
    },
    {
        "name": "Flowseal/general-alt3",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT3).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt3"],
    },
    {
        "name": "Flowseal/general-alt4",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT4).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt4"],
    },
    {
        "name": "Flowseal/general-alt5",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT5).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt5"],
    },
    {
        "name": "Flowseal/general-alt6",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT6).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt6"],
    },
    {
        "name": "Flowseal/general-alt7",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT7).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt7"],
    },
]


# ─── Translator: zapret v1 → zapret2 lua syntax ────────────────────

def translate_zapret_v1(args: dict[str, str]) -> Optional[list[str]]:
    """Translate zapret v1 CLI flags → zapret2 lua-desync flags.

    Returns None if any function in the desync chain is unsupported —
    we'd rather skip than guess and break.
    """
    desync_chain = args.get("--dpi-desync", "")
    if not desync_chain:
        return None

    pos = args.get("--dpi-desync-split-pos", "1")
    pos = _normalize_pos(pos)
    repeats = args.get("--dpi-desync-repeats", "1")
    ttl = args.get("--dpi-desync-ttl", "")
    fooling = args.get("--dpi-desync-fooling", "")

    flags: list[str] = []
    for func in desync_chain.split(","):
        func = func.strip()
        if not func:
            continue
        translated = _translate_single(func, pos, repeats, ttl, fooling, args)
        if translated is None:
            logger.debug("Skip strategy: unsupported desync function %r", func)
            return None
        flags.append(translated)

    return flags if flags else None


def _translate_single(
    func: str, pos: str, repeats: str, ttl: str, fooling: str, args: dict,
) -> Optional[str]:
    seqovl = args.get("--dpi-desync-split-seqovl", "")
    has_pattern = bool(args.get("--dpi-desync-split-seqovl-pattern", ""))

    if func == "split" or func == "split2":
        return f"multisplit:pos={pos}"
    if func == "disorder" or func == "disorder2":
        return f"multidisorder:pos={pos},midsld"
    if func == "multisplit":
        parts = [f"pos={pos}"]
        if seqovl:
            parts.append(f"seqovl={seqovl}")
            if has_pattern:
                parts.append("seqovl_pattern=fake_default_tls")
        return f"multisplit:{':'.join(parts)}"
    if func == "multidisorder":
        parts = [f"pos={pos},midsld"]
        if seqovl:
            parts.append(f"seqovl={seqovl}")
            if has_pattern:
                parts.append("seqovl_pattern=fake_default_tls")
        return f"multidisorder:{':'.join(parts)}"
    if func == "fake":
        parts = ["blob=fake_default_tls", f"repeats={repeats}"]
        if ttl:
            parts.append(f"ip_ttl={ttl}")
            parts.append(f"ip6_ttl={ttl}")
        if "md5sig" in fooling:
            parts.append("fool=md5sig")
        elif "badseq" in fooling:
            parts.append("fool=badseq")
        return f"fake:{':'.join(parts)}"
    if func == "fakedsplit":
        return f"multisplit:pos={pos}:seqovl=681:seqovl_pattern=fake_default_tls"
    if func == "fakeddisorder":
        return f"multidisorder:pos={pos},midsld:seqovl=681:seqovl_pattern=fake_default_tls"
    if func == "syndata":
        return None
    return None


def _normalize_pos(pos: str) -> str:
    """zapret v1 accepts numeric or sniext-relative positions."""
    if pos.lstrip("-+").isdigit():
        return pos
    if pos in ("sniext", "host", "midsld", "endhost"):
        return pos
    if "+" in pos or "-" in pos:
        return pos
    return "1"


# ─── Parser: Flowseal .bat ─────────────────────────────────────────

_BAT_START_RE = re.compile(
    r'start\s+"([^"]*)"\s+[^\n]*?winws\.exe"?\s+(.+?)(?=\nstart\s+"|\Z)',
    re.IGNORECASE | re.DOTALL,
)


def _join_continuation_lines(text: str) -> str:
    """Flowseal .bat uses `^\\n` line continuation for the long start cmd.
    Collapse those into a single logical line."""
    return re.sub(r"\^[ \t]*\r?\n[ \t]*", " ", text)


def parse_zapret_v1_bat(content: str, source_name: str, tags: list[str]) -> list[dict]:
    """Parse Flowseal-style .bat content into strategy dicts.

    Modern Flowseal has ONE long `start "zapret: %~n0"` command containing
    multiple sub-profiles separated by `--new`. We extract each sub-profile
    as its own strategy.
    """
    content = _join_continuation_lines(content)
    strategies: list[dict] = []
    seen_in_file: set[str] = set()
    for match in _BAT_START_RE.finditer(content):
        title = match.group(1)
        big_args_str = match.group(2)
        # Split into sub-profiles by --new
        sub_profiles = re.split(r"\s+--new\s+", big_args_str)
        for idx, sub in enumerate(sub_profiles):
            args = _parse_cli_args(sub)
            flags = translate_zapret_v1(args)
            if not flags:
                continue
            signature = "|".join(flags)
            if signature in seen_in_file:
                continue
            seen_in_file.add(signature)

            # Build a meaningful name from filter/hostlist hints
            hint = _profile_hint(args, idx)
            clean_title = re.sub(r"[^a-z0-9]+", "_", f"{title}_{hint}".lower()).strip("_")[:50]
            if not clean_title:
                clean_title = f"strat_{len(strategies)}"
            strategies.append({
                "name": f"harvest_{clean_title}",
                "flags": flags,
                "desc": f"Harvested from {source_name}: profile {idx} ({hint})",
                "tags": list(tags),
                "source": source_name,
            })
    return strategies


def _profile_hint(args: dict, idx: int) -> str:
    """Derive a short hint for naming based on filter/hostlist clues."""
    domains = args.get("--hostlist-domains", "")
    if "discord" in domains.lower():
        return "discord"
    if "youtube" in domains.lower() or "googlevideo" in domains.lower():
        return "youtube"
    hostlist = args.get("--hostlist", "").lower()
    for keyword in ("discord", "google", "youtube", "general", "twitter"):
        if keyword in hostlist:
            return keyword
    filter_l7 = args.get("--filter-l7", "").lower()
    if "discord" in filter_l7 or "stun" in filter_l7:
        return "discord_stun"
    return f"p{idx}"


def _parse_cli_args(line: str) -> dict[str, str]:
    """Parse --key=value or --key value pairs from a CLI line."""
    args: dict[str, str] = {}
    tokens = re.findall(
        r'--[\w-]+(?:=(?:"[^"]*"|[^\s]+))?',
        line,
    )
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            args[k] = v.strip('"')
        else:
            args[tok] = "1"
    return args


# ─── Fetcher + cache ───────────────────────────────────────────────

def _fetch(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        logger.warning("Harvest fetch failed %s: %s", url, exc)
        return None


def harvest(force_refresh: bool = False, cache_path: Optional[Path] = None) -> list[dict]:
    """Returns harvested strategies, cached on disk for CACHE_TTL_SECONDS.

    Network failures are swallowed — returns cached version if any,
    or empty list. Never raises.
    """
    cache = cache_path or CACHE_FILE
    if not force_refresh and cache.exists():
        age = time.time() - cache.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                cached = json.loads(cache.read_text("utf-8"))
                logger.info("Using harvest cache: %d strategies (age %ds)", len(cached), int(age))
                return cached
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Cache read failed, refetching: %s", exc)

    all_strategies: list[dict] = []
    seen_signatures: set[str] = set()
    sources_ok = 0
    for src in SOURCES:
        content = _fetch(src["url"])
        if not content:
            continue
        sources_ok += 1
        if src["parser"] == "zapret_v1_bat":
            new = parse_zapret_v1_bat(content, src["name"], src.get("tags", []))
        else:
            logger.warning("Unknown parser %r for %s", src["parser"], src["name"])
            continue
        for s in new:
            sig = "|".join(s["flags"])
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            all_strategies.append(s)

    logger.info(
        "Harvested %d strategies from %d/%d sources",
        len(all_strategies), sources_ok, len(SOURCES),
    )

    if all_strategies:
        try:
            cache.write_text(
                json.dumps(all_strategies, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Cache write failed: %s", exc)
    elif cache.exists():
        try:
            return json.loads(cache.read_text("utf-8"))
        except Exception:
            pass

    return all_strategies


def harvest_safe() -> list[dict]:
    """Like harvest() but never raises and returns [] on any error."""
    try:
        return harvest()
    except Exception as exc:
        logger.warning("Harvest crashed, ignoring: %s", exc)
        return []
