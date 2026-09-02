"""Tests for brain/zapret_paths.py and the zapret2 updater helpers."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.zapret_paths import find_zapret_dirs, newest_first, version_key  # noqa: E402
from updater import zapret2_updater as upd  # noqa: E402


class TestVersionOrdering(unittest.TestCase):
    def test_version_key(self):
        self.assertEqual(version_key("zapret2-v1.0.4"), (1, 0, 4))
        self.assertEqual(version_key(Path("zapret2-v0.9.4.5/binaries/windows-x86_64")), (0, 9, 4, 5))
        self.assertEqual(version_key("zapret2"), (0,))
        self.assertEqual(version_key("zapret2-1.2"), (1, 2))

    def test_newest_first_beats_string_sort(self):
        dirs = ["zapret2-v0.9.4.5", "zapret2-v1.0.4", "zapret2-v0.10.0", "zapret2"]
        ordered = [p.name for p in newest_first(dirs)]
        self.assertEqual(ordered, ["zapret2-v1.0.4", "zapret2-v0.10.0", "zapret2-v0.9.4.5", "zapret2"])
        # plain string sort would have put v0.9.4.5 above v0.10.0
        self.assertEqual(sorted(dirs, reverse=True)[1], "zapret2-v0.9.4.5")

    def test_find_zapret_dirs_and_engine_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name, with_bin in (("zapret2-v0.9.4.5", True), ("zapret2-v1.0.4", True), ("zapret2-v1.1.0", False)):
                d = base / name / "binaries" / upd._PLATFORM_DIR
                d.mkdir(parents=True)
                if with_bin:
                    (d / upd._ENGINE_BIN).write_bytes(b"x")
            found = [p.name for p in find_zapret_dirs(base)]
            self.assertEqual(found[0], "zapret2-v1.1.0")
            engines = [p.name for p in upd.installed_engine_dirs(base)]
            self.assertEqual(engines, ["zapret2-v1.0.4", "zapret2-v0.9.4.5"])  # v1.1.0 has no binary
            self.assertEqual(upd.installed_version(base), (1, 0, 4))
            self.assertEqual(upd.installed_version(base / "empty"), (0,))


class TestUpdaterHelpers(unittest.TestCase):
    def test_parse_sha256sum(self):
        text = (
            "31702b09b424893be881116f3fe9257721d9795e8c570aa27c66a900fe384bfb  zapret2-v1.0.4/binaries/windows-x86_64/winws2.exe\n"
            "bad line\n"
            "16abd6a029e65557c6a309bea7b13bf81fff4e193567582e1cddbf6719f323e0 *zapret2-v1.0.4\\binaries\\windows-x86_64\\WinDivert.dll\n"
        )
        sums = upd.parse_sha256sum(text)
        self.assertEqual(len(sums), 2)
        self.assertIn("zapret2-v1.0.4/binaries/windows-x86_64/WinDivert.dll", sums)

    def test_verify_tree(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "zapret2-v9.9"
            bins = root / "binaries" / "windows-x86_64"
            bins.mkdir(parents=True)
            (bins / "winws2.exe").write_bytes(b"engine")
            good = hashlib.sha256(b"engine").hexdigest()
            sums = {"zapret2-v9.9/binaries/windows-x86_64/winws2.exe": good}
            self.assertEqual(upd.verify_tree(root, sums, "binaries/windows-x86_64"), [])
            sums_bad = {"zapret2-v9.9/binaries/windows-x86_64/winws2.exe": "0" * 64}
            self.assertTrue(upd.verify_tree(root, sums_bad, "binaries/windows-x86_64"))
            self.assertTrue(upd.verify_tree(root, {}, "binaries/windows-x86_64"))  # nothing listed => refuse
            missing = {"zapret2-v9.9/binaries/windows-x86_64/WinDivert.dll": good}
            self.assertTrue(upd.verify_tree(root, missing, "binaries/windows-x86_64"))


if __name__ == "__main__":
    unittest.main()
