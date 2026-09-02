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
    # ALT8-13 added 2026-09: newest Flowseal profiles (hostfakesplit, fake-tls-mod,
    # ts fooling) — now translatable since _translate_single learned those.
    {
        "name": "Flowseal/general-alt9",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT9).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt9"],
    },
    {
        "name": "Flowseal/general-alt11",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT11).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt11"],
    },
    {
        "name": "Flowseal/general-alt13",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(ALT13).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "alt13"],
    },
    {
        "name": "Flowseal/general-fake-tls-auto",
        "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/general%20(FAKE%20TLS%20AUTO).bat",
        "parser": "zapret_v1_bat",
        "tags": ["harvested", "flowseal", "fake-tls-auto"],
    },
]

# Flowseal ships its real-ClientHello / QUIC / STUN blobs in bin/. When a
# harvested strategy references one (seqovl_pattern=tls_clienthello_4pda_to,
# blob=...), the .bin must be present or zapret2 v1.0.4 skips that packet
# (VERDICT_PASS). We mirror them into <project>/blobs/ where brain.zapret_blobs
# discovers them.
FLOWSEAL_BLOB_BASE = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/bin/"
_SAFE_BLOB_NAME = re.compile(r"^[A-Za-z0-9._-]+\.bin$")


# ─── Translator: zapret v1 → zapret2 lua syntax ────────────────────

def translate_zapret_v1(args: dict[str, str], blobs: Optional[set] = None) -> Optional[list[str]]:
    """Translate zapret v1 CLI flags → zapret2 lua-desync flags.

    Returns None if any function in the desync chain is unsupported —
    we'd rather skip than guess and break. When ``blobs`` is provided, the
    names of any referenced blob files (real ClientHello patterns, fake TLS
    blobs) are added to it so the caller can fetch them.
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
        translated = _translate_single(func, pos, repeats, ttl, fooling, args, blobs)
        if translated is None:
            logger.debug("Skip strategy: unsupported desync function %r", func)
            return None
        flags.append(translated)

    return flags if flags else None


# zapret v1 --dpi-desync-fooling → zapret2 standard-fooling tokens.
# Verified against zapret2-v1.0.4/lua/zapret-antidpi.lua (lines 20-45): the
# fooling vocabulary is tcp_seq/tcp_ack/tcp_ts/tcp_md5/badsum, NOT "fool=badseq"
# (fool= names a custom Lua function). The old translator emitted fool=md5sig /
# fool=badseq, which winws2 rejects — every harvested fake strategy was broken.
_FOOLING_MAP: dict[str, str] = {
    "md5sig": "tcp_md5",
    "badseq": "tcp_seq=-10000",
    "badack": "tcp_ack=-66000",
    "ts": "tcp_ts=-600000",     # Flowseal's dominant fooling (17/22 profiles)
    "badsum": "badsum",
}
# Foolings with no zapret2 standard-fooling equivalent — dropped (the candidate
# is still tested before use), never guessed.
_FOOLING_IGNORED = frozenset({"datanoack", "hostcase", "hosttcp", "none", ""})


def _fooling_parts(fooling: str, ttl: str) -> list[str]:
    parts: list[str] = []
    for tok in (fooling or "").split(","):
        tok = tok.strip().lower()
        if not tok or tok in _FOOLING_IGNORED:
            continue
        mapped = _FOOLING_MAP.get(tok)
        if mapped:
            parts.append(mapped)
    if ttl:
        try:
            # CLAUDE.md: fake TTL minimum 3 (CDN edges sit at hops 5-8).
            ttl_n = max(3, int(ttl))
            parts.append(f"ip_ttl={ttl_n}")
            parts.append(f"ip6_ttl={ttl_n}")
        except ValueError:
            pass
    return parts


def _ip_id_part(args: dict) -> list[str]:
    """--ip-id=zero|seq|rnd|none → ip_id=... (zapret2 standard ipid).

    ip_id=zero matters on TSPU: it triggers a block when a fake and a real
    packet repeat the same non-zero IP-ID (bol-van readme). Windows then
    re-numbers the zeros sequentially.
    """
    val = (args.get("--ip-id", "") or "").strip().lower()
    return [f"ip_id={val}"] if val in ("zero", "seq", "rnd", "none") else []


def _pattern_part(args: dict, blobs: Optional[set] = None) -> Optional[str]:
    """seqovl-pattern → seqovl_pattern=<blob>. Preserves REAL ClientHello blobs.

    The old translator collapsed every pattern to fake_default_tls, discarding
    exactly what makes Flowseal's split effective (a real google/4pda
    ClientHello in the overlap). We keep the blob NAME; the blob file is loaded
    via --blob (see brain/zapret_blobs) and recorded in ``blobs`` for fetching.
    """
    raw = args.get("--dpi-desync-split-seqovl-pattern", "")
    if not raw:
        return None
    raw = raw.strip().strip('"')
    if raw.startswith("0x"):
        return f"seqovl_pattern={raw}"        # inline hex literal, pass through
    from brain.zapret_blobs import blob_name
    name = blob_name(raw)
    if blobs is not None:
        blobs.add(raw)
    return f"seqovl_pattern={name}"


def _fake_blob_part(args: dict, blobs: Optional[set] = None) -> str:
    """--dpi-desync-fake-tls=<file|hex|!> → blob=<name> (default fake_default_tls)."""
    raw = (args.get("--dpi-desync-fake-tls", "") or "").split(",")[0].strip().strip('"')
    if not raw or raw in ("!", "^!", "0x00000000"):
        return "blob=fake_default_tls"
    if raw.startswith("0x"):
        return f"blob={raw}"
    from brain.zapret_blobs import blob_name
    if blobs is not None:
        blobs.add(raw)
    return f"blob={blob_name(raw)}"


def _translate_single(
    func: str, pos: str, repeats: str, ttl: str, fooling: str, args: dict,
    blobs: Optional[set] = None,
) -> Optional[str]:
    seqovl = args.get("--dpi-desync-split-seqovl", "")
    pattern = _pattern_part(args, blobs)
    fooling_parts = _fooling_parts(fooling, ttl)
    ipid = _ip_id_part(args)

    if func in ("split", "split2"):
        parts = [f"pos={pos}"] + ipid
        return f"multisplit:{':'.join(parts)}"
    if func in ("disorder", "disorder2"):
        parts = [f"pos={pos},midsld"] + ipid
        return f"multidisorder:{':'.join(parts)}"
    if func == "multisplit":
        parts = [f"pos={pos}"]
        if seqovl:
            parts.append(f"seqovl={seqovl}")
            parts.append(pattern or "seqovl_pattern=fake_default_tls")
        parts += ipid
        return f"multisplit:{':'.join(parts)}"
    if func == "multidisorder":
        parts = [f"pos={pos},midsld"]
        if seqovl:
            parts.append(f"seqovl={seqovl}")
            parts.append(pattern or "seqovl_pattern=fake_default_tls")
        parts += ipid
        return f"multidisorder:{':'.join(parts)}"
    if func == "fake":
        parts = [_fake_blob_part(args, blobs), f"repeats={repeats}"]
        mod = (args.get("--dpi-desync-fake-tls-mod", "") or "").strip().strip('"')
        if mod and mod.lower() != "none":
            parts.append(f"tls_mod={mod}")
        parts += fooling_parts + ipid
        return f"fake:{':'.join(parts)}"
    # fakedsplit/fakeddisorder become plain split/disorder with a fake blob in
    # the overlap. Fooling is NOT carried over: zapret2 applies fooling to the
    # packets a function GENERATES, and these generate real data segments -- an
    # ip_ttl or bad tcp_seq on those would stop the request reaching the server.
    if func == "fakedsplit":
        parts = [f"pos={pos}", "seqovl=681", pattern or "seqovl_pattern=fake_default_tls"] + ipid
        return f"multisplit:{':'.join(parts)}"
    if func == "fakeddisorder":
        parts = [f"pos={pos},midsld", "seqovl=681", pattern or "seqovl_pattern=fake_default_tls"] + ipid
        return f"multidisorder:{':'.join(parts)}"
    if func == "hostfakesplit":
        # Flowseal: --dpi-desync-hostfakesplit-mod=host=www.google.com,altorder=1
        mod = args.get("--dpi-desync-hostfakesplit-mod", "")
        host = "www.google.com"
        for kv in mod.split(","):
            kv = kv.strip()
            if kv.startswith("host="):
                host = kv[5:] or host  # altorder=1 has no zapret2 equivalent — dropped
        parts = [f"host={host}", f"repeats={repeats}"] + fooling_parts + ipid
        return f"hostfakesplit:{':'.join(parts)}"
    if func == "syndata":
        return "syndata"       # valid zapret2 function (used in KNOWN_STRATEGIES)
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
            blobs: set[str] = set()
            flags = translate_zapret_v1(args, blobs)
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
                "blobs": sorted(blobs),
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


def _fetch_bytes(url: str) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            return resp.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        logger.warning("Blob fetch failed %s: %s", url, exc)
        return None


def fetch_blobs(blob_files: set, base_dir: Optional[Path] = None) -> int:
    """Mirror referenced Flowseal blob files into <base_dir>/blobs/.

    ``blob_files`` holds raw pattern strings as they appeared on the command
    line (e.g. "%BIN%tls_clienthello_4pda_to.bin" or "tls_clienthello_max_ru.bin").
    Only .bin basenames are fetched; already-present files and engine-shipped
    blobs are skipped. Returns the count newly downloaded. Never raises.
    """
    root = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
    blob_dir = root / "blobs"
    names: set[str] = set()
    for raw in blob_files or ():
        raw = str(raw).strip().strip('"')
        if raw.startswith("0x") or not raw:
            continue
        # Strip a %BIN% env-var prefix and any path, keeping the basename.
        base = raw.replace("\\", "/").split("/")[-1].rsplit("%", 1)[-1]
        # Whitelist the result. These names come from a third-party repo and are
        # written by an admin process: "C:foo.bin" would slip past a separator
        # strip, because Path("blobs") / "C:foo.bin" discards the left operand.
        if not _SAFE_BLOB_NAME.match(base):
            logger.warning("Ignoring unsafe blob filename %r", raw)
            continue
        names.add(base)
    if not names:
        return 0
    # Skip blobs the engine already ships (found by brain.zapret_blobs).
    try:
        from brain.zapret_paths import find_zapret_dirs
        zdirs = [d / "files" / "fake" for d in find_zapret_dirs(root)]
        engine_have = {p.name for d in zdirs if d.is_dir() for p in d.glob("*.bin")}
    except Exception:
        engine_have = set()
    downloaded = 0
    for name in sorted(names):
        dest = blob_dir / name
        if dest.exists() or name in engine_have:
            continue
        data = _fetch_bytes(FLOWSEAL_BLOB_BASE + name)
        if data and len(data) < 65536:      # ClientHello/QUIC blobs are tiny
            try:
                blob_dir.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                downloaded += 1
            except OSError as exc:
                logger.warning("Blob write failed %s: %s", name, exc)
    if downloaded:
        logger.info("Fetched %d blob file(s) into %s", downloaded, blob_dir)
    return downloaded


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

    # Mirror referenced blob files (real ClientHello patterns) so the strategies
    # that use them actually work instead of being silently VERDICT_PASS'd.
    try:
        needed: set[str] = set()
        for s in all_strategies:
            needed.update(s.get("blobs", []))
        if needed:
            fetch_blobs(needed)
    except Exception as exc:
        logger.debug("Blob fetch skipped: %s", exc)

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
