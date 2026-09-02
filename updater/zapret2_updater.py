"""zapret2 engine updater — installs the newest GitHub release next to the project.

zapret2 binaries are NOT in the git repository (binaries/readme.txt: "Binaries
are only in releases"), so the old run.bat flow (git clone + reset) never
produced a winws2.exe. This module talks to the GitHub Releases API instead.

Layout after install:  <project>/zapret2-v1.0.4/{binaries,lua,docs,...}
run_real.py / brain.tester pick the newest ``zapret2-v*`` via
brain.zapret_paths, so old versions can stay as a manual fallback.

CLI:
    python -m updater.zapret2_updater             # check + install if newer
    python -m updater.zapret2_updater --check     # exit 2 if an update exists
    python -m updater.zapret2_updater --quiet     # one-line output (run.bat)

Exit codes: 0 up to date / installed, 2 update available (--check), 1 error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.zapret_paths import newest_first, version_key  # noqa: E402

REPO = "bol-van/zapret2"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
USER_AGENT = "PLGames-Svoboda-Updater/1.0"
TIMEOUT = 15

_PLATFORM_DIR = "windows-x86_64" if platform.system() == "Windows" else "linux-x86_64"
_ENGINE_BIN = "winws2.exe" if platform.system() == "Windows" else "nfqws2"


def _session():
    import requests
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


# ─── local state ─────────────────────────────────────────────────────────────

def installed_engine_dirs(base: Path = BASE_DIR) -> list[Path]:
    """Release dirs that actually contain an engine binary, newest first."""
    out = []
    for d in newest_first(base.glob("zapret2*")):
        if d.is_dir() and (d / "binaries" / _PLATFORM_DIR / _ENGINE_BIN).exists():
            out.append(d)
    return out


def installed_version(base: Path = BASE_DIR) -> tuple[int, ...]:
    dirs = installed_engine_dirs(base)
    return version_key(dirs[0]) if dirs else (0,)


def _fmt(v: tuple[int, ...]) -> str:
    return "none" if v == (0,) else "v" + ".".join(str(x) for x in v)


# ─── remote ──────────────────────────────────────────────────────────────────

def latest_release(session=None) -> Optional[dict]:
    """{tag, version, zip_url, sha_url} for the latest release, or None."""
    s = session or _session()
    r = s.get(API_LATEST, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    tag = str(data.get("tag_name", ""))
    zip_url = sha_url = ""
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name == f"zapret2-{tag}.zip":
            zip_url = url
        elif name == "sha256sum.txt":
            sha_url = url
    if not tag or not zip_url:
        return None
    return {"tag": tag, "version": version_key(f"zapret2-{tag}"), "zip_url": zip_url, "sha_url": sha_url}


def _download(session, url: str, dest: Path) -> None:
    with session.get(url, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(1 << 16):
                if chunk:
                    fh.write(chunk)


def parse_sha256sum(text: str) -> dict[str, str]:
    """'<hash>  path' lines -> {path: hash} (posix paths, as in the release)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1].lstrip("*").replace("\\", "/")] = parts[0].lower()
    return out


def verify_tree(extract_root: Path, sums: dict[str, str], subdir: str) -> list[str]:
    """Check every listed file under ``subdir`` (e.g. binaries/windows-x86_64).

    Returns a list of problems (empty == verified). Missing checksum file for a
    present binary is reported too: an unverifiable engine must not be installed.
    """
    problems = []
    listed = {p: h for p, h in sums.items() if f"/{subdir}/" in p}
    if not listed:
        return [f"no checksums listed for {subdir}"]
    for rel, expected in listed.items():
        # rel is "zapret2-vX/binaries/.../file" — strip the leading release dir
        local = extract_root / Path(*Path(rel).parts[1:])
        if not local.exists():
            problems.append(f"missing {rel}")
            continue
        h = hashlib.sha256(local.read_bytes()).hexdigest()
        if h != expected:
            problems.append(f"sha256 mismatch {rel}")
    return problems


# ─── install ─────────────────────────────────────────────────────────────────

def install_release(rel: dict, base: Path = BASE_DIR, session=None, log=print) -> Path:
    """Download, verify and move the release into <base>/zapret2-<tag>/."""
    s = session or _session()
    final = base / f"zapret2-{rel['tag']}"
    if (final / "binaries" / _PLATFORM_DIR / _ENGINE_BIN).exists():
        log(f"  already installed: {final.name}")
        return final

    with tempfile.TemporaryDirectory(prefix="zapret2-dl-", dir=str(base)) as tmp:
        tmp_p = Path(tmp)
        zip_path = tmp_p / "release.zip"
        log(f"  downloading {rel['zip_url'].rsplit('/', 1)[-1]} ...")
        _download(s, rel["zip_url"], zip_path)

        sums: dict[str, str] = {}
        if rel.get("sha_url"):
            sha_path = tmp_p / "sha256sum.txt"
            _download(s, rel["sha_url"], sha_path)
            sums = parse_sha256sum(sha_path.read_text(encoding="utf-8", errors="replace"))

        with zipfile.ZipFile(zip_path) as zf:
            # zip-slip guard
            for n in zf.namelist():
                if n.startswith("/") or ".." in Path(n).parts:
                    raise RuntimeError(f"unsafe path in archive: {n}")
            zf.extractall(tmp_p)
        extracted = tmp_p / f"zapret2-{rel['tag']}"
        if not extracted.is_dir():
            cands = [d for d in tmp_p.iterdir() if d.is_dir() and d.name.startswith("zapret2")]
            if not cands:
                raise RuntimeError("archive layout unexpected (no zapret2-* dir)")
            extracted = cands[0]

        problems = verify_tree(extracted, sums, f"binaries/{_PLATFORM_DIR}")
        if problems:
            raise RuntimeError("verification failed: " + "; ".join(problems[:5]))
        log(f"  verified {_PLATFORM_DIR} binaries against sha256sum.txt")

        if final.exists():
            shutil.rmtree(final, ignore_errors=True)
        shutil.move(str(extracted), str(final))
    return final


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Update the bundled zapret2 engine")
    ap.add_argument("--check", action="store_true", help="only report; exit 2 if newer exists")
    ap.add_argument("--force", action="store_true", help="reinstall even if up to date")
    ap.add_argument("--quiet", action="store_true", help="single-line output")
    args = ap.parse_args(argv)
    say = (lambda *_a, **_k: None) if args.quiet else print

    local = installed_version()
    try:
        rel = latest_release()
    except Exception as exc:
        print(f"zapret2: {_fmt(local)} installed, update check failed ({exc.__class__.__name__})")
        return 1
    if rel is None:
        print(f"zapret2: {_fmt(local)} installed, no release info")
        return 1

    newer = rel["version"] > local
    if args.check:
        print(f"zapret2: installed {_fmt(local)}, latest {rel['tag']}{' (UPDATE AVAILABLE)' if newer else ''}")
        return 2 if newer else 0
    if not newer and not args.force:
        print(f"zapret2: {_fmt(local)} is up to date")
        return 0

    say(f"zapret2: installed {_fmt(local)} -> installing {rel['tag']}")
    try:
        path = install_release(rel, log=say)
    except Exception as exc:
        print(f"zapret2: update to {rel['tag']} failed: {exc}")
        return 1
    print(f"zapret2: installed {rel['tag']} -> {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
