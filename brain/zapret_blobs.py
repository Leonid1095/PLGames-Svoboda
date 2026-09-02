"""Named binary blobs for zapret2 strategies (``--blob=<name>:@<file>``).

zapret2 strategies reference blobs by Lua variable name, e.g.
``multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google`` or
``fake:blob=tls_google:ip_id=zero``. Only three blobs are built in
(``fake_default_tls``, ``fake_default_http``, ``fake_default_quic``); every other
name must be loaded on the command line. Flowseal 1.10 gets most of its effect
from REAL ClientHello patterns (www.google.com, 4pda.to, sochi-park, stun2),
which the old harvester silently replaced with ``fake_default_tls``.

Sources (first match wins):
  1. ``<project>/blobs/*.bin``            — fetched by the harvester (Flowseal bin/)
                                            or dropped in by the user
  2. ``<zapret2 release>/files/fake/*.bin`` — shipped with the engine

Only blobs actually referenced by the launched strategy are put on the command
line: winws2 has a history of crashing on very long command lines
(feedback_simplicity), so we never pass the whole library.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, Optional

STANDARD_BLOBS = frozenset({"fake_default_tls", "fake_default_http", "fake_default_quic"})

# Short aliases for engine-shipped files (names used by zapret2 forks / presets)
ALIASES: dict[str, str] = {
    "tls_google": "tls_clienthello_www_google_com.bin",
    "quic_google": "quic_initial_www_google_com.bin",
    "stun": "stun.bin",
    "discord_ipd": "discord-ip-discovery-with-port.bin",
    "tls_iana": "tls_clienthello_iana_org.bin",
    "tls_vk": "tls_clienthello_vk_com.bin",
    "tls_gosuslugi": "tls_clienthello_gosuslugi_ru.bin",
    "tls_sber": "tls_clienthello_sberbank_ru.bin",
    "tls_alert": "tls_alert.bin",
}

_BLOB_ARG_KEYS = ("blob", "seqovl_pattern", "fake_blob")
_BLOB_REF_RE = re.compile(r"(?:^|:)(?:%s)=([A-Za-z_][A-Za-z0-9_]*)" % "|".join(_BLOB_ARG_KEYS))


def blob_name(filename: str) -> str:
    """Lua-identifier name for a blob file: stem, non-alnum -> '_', digit-safe.

    Robust to the forms blobs appear in on a Flowseal command line:
    ``%BIN%tls_clienthello_4pda_to.bin``, ``bin\\stun2.bin``, ``stun.bin`` — all
    reduce to the basename stem so the reference matches the fetched file, which
    brain.zapret_blobs/strategy_harvester store and discover by basename.
    """
    raw = str(filename).replace("\\", "/")
    raw = raw.rsplit("%", 1)[-1]          # drop a leading %VAR% env-var prefix
    stem = Path(raw).name
    stem = stem[:-4] if stem.lower().endswith(".bin") else stem
    name = re.sub(r"[^A-Za-z0-9_]", "_", stem)
    if not name or name[0].isdigit():
        name = "b_" + name
    return name


def referenced_blobs(flags: Iterable[str]) -> set[str]:
    """Blob names referenced by lua-desync calls (standard blobs and hex literals excluded)."""
    names: set[str] = set()
    for flag in flags or ():
        for m in _BLOB_REF_RE.finditer(str(flag)):
            name = m.group(1)
            if name in STANDARD_BLOBS:
                continue
            names.add(name)
    return names


def discover_blobs(base_dir, zapret_root: Optional[Path] = None) -> dict[str, Path]:
    """name -> file for every blob we can load. Project blobs/ overrides engine files."""
    found: dict[str, Path] = {}
    if zapret_root:
        fake_dir = Path(zapret_root) / "files" / "fake"
        if fake_dir.is_dir():
            for f in sorted(fake_dir.glob("*.bin")):
                found.setdefault(blob_name(f.name), f)
            for alias, fname in ALIASES.items():
                if (fake_dir / fname).exists():
                    found.setdefault(alias, fake_dir / fname)
    proj = Path(base_dir) / "blobs"
    if proj.is_dir():
        for f in sorted(proj.glob("*.bin")):
            found[blob_name(f.name)] = f          # project copy wins
            for alias, fname in ALIASES.items():
                if fname == f.name:
                    found[alias] = f
    return found


def blob_args(flags: Iterable[str], base_dir, zapret_root: Optional[Path], cwd) -> list[str]:
    """``--blob=name:@relpath`` for each blob the strategy references and we can find.

    Paths are relative to ``cwd`` (the winws2 binary dir) to avoid the
    spaces-in-path issues the launchers already work around for --lua-init.
    Unknown names are left out: zapret2 v1.0.4 then stops that execution plan
    and passes the packet (VERDICT_PASS) instead of crashing.
    """
    wanted = referenced_blobs(flags)
    if not wanted:
        return []
    available = discover_blobs(base_dir, zapret_root)
    out: list[str] = []
    for name in sorted(wanted):
        path = available.get(name)
        if path is None:
            continue
        try:
            rel = os.path.relpath(str(path), str(cwd))
        except ValueError:          # different drive on Windows
            rel = str(path)
        out.append(f"--blob={name}:@{rel}")
    return out


def missing_blobs(flags: Iterable[str], base_dir, zapret_root: Optional[Path]) -> set[str]:
    """Referenced blob names that no source provides (for logging / skipping)."""
    return referenced_blobs(flags) - set(discover_blobs(base_dir, zapret_root))
