"""Static validator for zapret2 ``--lua-desync`` strategy strings.

Why this exists: winws2.exe requires elevation even to parse its arguments, so
a typo in a strategy is only discovered on a live run — as a crash, or worse,
as a silently skipped desync that scores like a working bypass. The 2026-09
audit found the harvester emitting ``fool=md5sig`` / ``fool=badseq`` for every
Flowseal fake profile; zapret2's fooling vocabulary has no such argument
(``fool=`` names a custom Lua *function*), so those strategies were dead.

The vocabulary is parsed out of the INSTALLED engine's ``zapret-antidpi.lua``,
whose header documents the standard argument groups and whose per-function
comment blocks list the rest:

    -- standard args : direction, payload, fooling, ip_id, rawsend, ...
    -- arg : seqovl_pattern=<blob> . override pattern
    function multisplit(ctx, desync)

Reading the engine instead of hardcoding a table means the linter keeps up with
whatever zapret2 version is bundled. If the lua cannot be read, ``lint()``
reports nothing rather than inventing failures.
"""

from __future__ import annotations

import functools
import logging
import re
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("svoboda.lint")

# Group header in the lua preamble -> the args it introduces are collected from
# the "* name..." bullet lines that follow, until the next blank-line group.
_GROUP_RE = re.compile(r"^standard (\w+)\s*:\s*$")
_BULLET_RE = re.compile(r"^\*\s*([a-z_0-9]+)")
_FUNC_RE = re.compile(r"^function\s+([a-z_0-9]+)\s*\(")
_STD_ARGS_RE = re.compile(r"^--\s*standard args\s*:\s*(.+)$")
_ARG_RE = re.compile(r"^--\s*arg\s*:\s*([a-z_0-9]+)")

# Helpers in the lua that are not desync entry points.
_NOT_DESYNC = frozenset({"pos_normalize", "pos_array_normalize", "multidisorder_send"})

# Arguments whose values come from a closed set (documented in the lua header).
_ENUM_VALUES: dict[str, frozenset[str]] = {
    "ip_id": frozenset({"seq", "rnd", "zero", "none"}),
    "dir": frozenset({"in", "out", "any"}),
}

# zapret v1 --dpi-desync-fooling names. They are NOT zapret2 arguments: in
# zapret2 `fool=` names a custom Lua function, so `fool=md5sig` silently
# references a function that does not exist. This is the exact bug the 2026-09
# audit found in the strategy harvester, hence a dedicated check.
_V1_FOOLING_NAMES: dict[str, str] = {
    "md5sig": "tcp_md5",
    "badseq": "tcp_seq=-10000",
    "badack": "tcp_ack=-66000",
    "ts": "tcp_ts=-600000",
    "badsum": "badsum",
    "datanoack": "(no zapret2 equivalent)",
    "hostcase": "(no zapret2 equivalent)",
    "hosttcp": "(no zapret2 equivalent)",
}


class Vocabulary:
    """Function -> allowed argument names, parsed from a zapret-antidpi.lua."""

    def __init__(self, functions: dict[str, set[str]], groups: dict[str, set[str]]):
        self.functions = functions
        self.groups = groups

    def known_function(self, name: str) -> bool:
        return name in self.functions

    def allowed_args(self, func: str) -> set[str]:
        return self.functions.get(func, set())


def _parse_groups(text: str) -> dict[str, set[str]]:
    groups: dict[str, set[str]] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        m = _GROUP_RE.match(line)
        if m:
            current = m.group(1)
            groups.setdefault(current, set())
            continue
        if current:
            b = _BULLET_RE.match(line)
            if b:
                groups[current].add(b.group(1))
            elif line and not line.startswith("*"):
                # A non-bullet, non-empty line ends the group block.
                if not line.startswith("]"):
                    current = None
    return groups


def _parse_functions(text: str, groups: dict[str, set[str]]) -> dict[str, set[str]]:
    functions: dict[str, set[str]] = {}
    pending_std: set[str] = set()
    pending_args: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        m = _STD_ARGS_RE.match(stripped)
        if m:
            # The list may be followed by free prose, e.g.
            #   "-- standard args : direction, ..., reconstruct. FOOLING AND
            #    REPEATS APPLIED ONLY TO FAKES."
            # so cut at the first sentence break before splitting on commas.
            for grp in m.group(1).split(".", 1)[0].split(","):
                grp = grp.strip()
                pending_std |= groups.get(grp, set())
            continue
        a = _ARG_RE.match(stripped)
        if a:
            pending_args.add(a.group(1))
            # "-- arg : nofake1, nofake2 - ..." style lists
            head = stripped.split("-", 2)[0]
            for extra in re.findall(r"\b([a-z_0-9]+)\b", head.split(":", 1)[-1]):
                pending_args.add(extra)
            continue
        f = _FUNC_RE.match(line)
        if f:
            name = f.group(1)
            if name not in _NOT_DESYNC:
                functions[name] = pending_std | pending_args
            pending_std, pending_args = set(), set()
            continue
        if not stripped.startswith("--") and stripped:
            # Any other code line ends the comment block preceding a function.
            if not stripped.startswith("*") and "function" not in stripped:
                pending_std, pending_args = set(), set()
    return functions


def _find_antidpi_lua(base_dir) -> Optional[Path]:
    try:
        from brain.zapret_paths import find_zapret_dirs
        for d in find_zapret_dirs(base_dir, "lua"):
            p = d / "zapret-antidpi.lua"
            if p.exists():
                return p
    except Exception as exc:
        logger.debug("zapret lua lookup failed: %s", exc)
    return None


@functools.lru_cache(maxsize=4)
def load_vocabulary(base_dir: str = ".") -> Optional[Vocabulary]:
    """Parse the installed engine's lua. Returns None when unavailable.

    Svoboda's own primitives (``alpn_strip``, ``tls_pad``, ...) live in
    ``lua/svoboda_*.lua`` and are loaded by the same ``--lua-init`` chain, so
    they are folded into the vocabulary too. Their arguments are not documented
    in the engine's comment format, so they are accepted with any arguments
    rather than reported as unknown.
    """
    path = _find_antidpi_lua(base_dir)
    if path is None:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("cannot read %s: %s", path, exc)
        return None
    groups = _parse_groups(text)
    functions = _parse_functions(text, groups)
    if not functions:
        return None

    custom_dir = Path(base_dir) / "lua"
    if custom_dir.is_dir():
        for lua_file in sorted(custom_dir.glob("svoboda_*.lua")):
            try:
                for line in lua_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    f = _FUNC_RE.match(line)
                    if f:
                        functions.setdefault(f.group(1), set())   # empty == any args
            except OSError:
                continue
    return Vocabulary(functions, groups)


def parse_call(call: str) -> tuple[str, list[tuple[str, Optional[str]]]]:
    """Split ``func:arg=val:flag`` into (func, [(arg, value|None), ...]).

    Colons inside a value are kept: ``pos=1,midsld`` and ``tls_mod=rnd,sni=x``
    are single arguments, and a leading ``--lua-desync=`` is tolerated.
    """
    call = call.strip()
    if call.startswith("--lua-desync="):
        call = call[len("--lua-desync="):]
    parts = call.split(":")
    func = parts[0].strip()
    args: list[tuple[str, Optional[str]]] = []
    for raw in parts[1:]:
        if not raw:
            continue
        if "=" in raw:
            k, v = raw.split("=", 1)
            args.append((k.strip(), v))
        else:
            args.append((raw.strip(), None))
    return func, args


def lint_call(call: str, vocab: Optional[Vocabulary]) -> list[str]:
    """Problems with a single desync call. Empty list == looks valid."""
    problems: list[str] = []
    func, args = parse_call(call)
    if not func:
        return [f"{call!r}: empty function name"]
    if vocab is None:
        return problems                     # engine unavailable: do not guess
    if not vocab.known_function(func):
        return [f"{call!r}: unknown desync function {func!r}"]
    allowed = vocab.allowed_args(func)
    for name, value in args:
        if allowed and name not in allowed:
            problems.append(f"{call!r}: {func} has no argument {name!r}")
            continue
        problems.extend(_lint_value(call, name, value))
    return problems


def _lint_value(call: str, name: str, value: Optional[str]) -> list[str]:
    """Check the value of arguments that take a closed set of names."""
    if value is None:
        return []
    if name == "fool":
        v1 = _V1_FOOLING_NAMES.get(value.strip().lower())
        if v1:
            return [f"{call!r}: fool={value!r} is a zapret v1 fooling name, "
                    f"not a Lua function - use {v1}"]
        return []
    allowed = _ENUM_VALUES.get(name)
    if allowed and value.strip().lower() not in allowed:
        return [f"{call!r}: {name}={value!r} must be one of {sorted(allowed)}"]
    return []


def lint(flags: Iterable[str], base_dir: str = ".") -> list[str]:
    """Problems across a whole strategy (list of desync calls)."""
    vocab = load_vocabulary(str(base_dir))
    out: list[str] = []
    for call in flags or ():
        out.extend(lint_call(str(call), vocab))
    return out
