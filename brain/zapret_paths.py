"""Locate bundled zapret2 release directories, newest version first.

Release zips extract to ``zapret2-vX.Y.Z/``. A plain string sort is wrong
once versions have different widths (``zapret2-v0.9.4.5`` > ``zapret2-v0.10``,
and ``zapret2-v1.0.4`` must beat both). run_real.py and brain/tester.py must
agree on the pick so the shadow tester and the permanent instance run the
same winws2 build.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

_VER_RE = re.compile(r"zapret2-v?(\d+(?:\.\d+)*)", re.IGNORECASE)


def version_key(path) -> tuple[int, ...]:
    """Numeric version tuple parsed from the ``zapret2-vX.Y.Z`` path segment.

    Only path SEGMENTS are examined, never the whole string: a project checked
    out under e.g. ``C:/zapret2-v1.0.0/app`` would otherwise stamp that version
    onto every candidate and collapse the ordering. The deepest matching
    segment wins, so ``.../zapret2-v1.0.4/binaries/...`` reads as 1.0.4.
    Directories without a version (a git checkout named ``zapret2``) sort below
    every versioned release.
    """
    best: tuple[int, ...] = (0,)
    for part in Path(path).parts:
        m = _VER_RE.fullmatch(part)
        if m:
            best = tuple(int(x) for x in m.group(1).split("."))
    return best


def newest_first(paths: Iterable) -> list[Path]:
    """Sort paths by embedded zapret2 version, newest first (stable on ties)."""
    return sorted(
        (Path(p) for p in paths),
        key=lambda p: (version_key(p), p.as_posix()),
        reverse=True,
    )


def find_zapret_dirs(base_dir, subpath: str = "") -> list[Path]:
    """All ``zapret2*/<subpath>`` directories under base_dir, newest first."""
    pattern = f"zapret2*/{subpath}" if subpath else "zapret2*"
    return [p for p in newest_first(Path(base_dir).glob(pattern)) if p.is_dir()]
