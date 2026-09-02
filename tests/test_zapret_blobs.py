"""Tests for brain/zapret_blobs.py — named blobs for zapret2 strategies."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import zapret_blobs as zb  # noqa: E402


class TestNames(unittest.TestCase):
    def test_blob_name(self):
        self.assertEqual(zb.blob_name("tls_clienthello_www_google_com.bin"), "tls_clienthello_www_google_com")
        self.assertEqual(zb.blob_name("discord-ip-discovery-with-port.bin"), "discord_ip_discovery_with_port")
        # %BIN% env-var prefix and bin/ path both reduce to the basename stem,
        # so a strategy's seqovl_pattern=<name> matches the fetched file.
        self.assertEqual(zb.blob_name(r"%BIN%tls_clienthello_4pda_to.bin"), "tls_clienthello_4pda_to")
        self.assertEqual(zb.blob_name(r"bin\stun2.bin"), "stun2")
        self.assertEqual(zb.blob_name("4pda.bin"), "b_4pda")

    def test_referenced_blobs(self):
        flags = [
            "multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google:ip_id=zero",
            "fake:blob=fake_default_tls:repeats=6",          # standard -> ignored
            "multidisorder:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",  # hex -> ignored
            "--lua-desync=fake:blob=discord_ipd:repeats=6",   # raw CLI form
            "hostfakesplit:host=www.google.com:tcp_ts=-600000",
        ]
        self.assertEqual(zb.referenced_blobs(flags), {"tls_google", "discord_ipd"})
        self.assertEqual(zb.referenced_blobs([]), set())


class TestDiscoveryAndArgs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.base = root / "project"
        self.zroot = root / "zapret2-v9"
        self.cwd = self.zroot / "binaries" / "windows-x86_64"
        (self.zroot / "files" / "fake").mkdir(parents=True)
        self.cwd.mkdir(parents=True)
        (self.zroot / "files" / "fake" / "tls_clienthello_www_google_com.bin").write_bytes(b"g")
        (self.zroot / "files" / "fake" / "stun.bin").write_bytes(b"s")
        (self.base / "blobs").mkdir(parents=True)
        (self.base / "blobs" / "tls_clienthello_4pda_to.bin").write_bytes(b"4")

    def tearDown(self):
        self.tmp.cleanup()

    def test_discover_merges_engine_and_project(self):
        found = zb.discover_blobs(self.base, self.zroot)
        self.assertIn("tls_google", found)                       # alias
        self.assertIn("tls_clienthello_www_google_com", found)   # full name
        self.assertIn("stun", found)
        self.assertIn("tls_clienthello_4pda_to", found)          # project blob
        self.assertNotIn("discord_ipd", found)                   # file absent

    def test_project_copy_overrides_engine(self):
        (self.base / "blobs" / "stun.bin").write_bytes(b"project")
        found = zb.discover_blobs(self.base, self.zroot)
        self.assertEqual(found["stun"].read_bytes(), b"project")

    def test_blob_args_only_referenced_and_relative(self):
        flags = ["multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google",
                 "fake:blob=nope:repeats=2"]
        args = zb.blob_args(flags, self.base, self.zroot, self.cwd)
        self.assertEqual(len(args), 1)
        self.assertTrue(args[0].startswith("--blob=tls_google:@"))
        rel = args[0].split("@", 1)[1]
        self.assertFalse(os.path.isabs(rel))
        self.assertEqual((self.cwd / rel).resolve(),
                         (self.zroot / "files" / "fake" / "tls_clienthello_www_google_com.bin").resolve())
        self.assertEqual(zb.missing_blobs(flags, self.base, self.zroot), {"nope"})

    def test_no_references_no_args(self):
        self.assertEqual(zb.blob_args(["multisplit:pos=1:seqovl=568"], self.base, self.zroot, self.cwd), [])
        self.assertEqual(zb.blob_args([], self.base, None, self.cwd), [])


class TestBundledEngineShipsAliases(unittest.TestCase):
    def test_bundled_release_has_alias_files(self):
        """Every alias must exist in the newest bundled zapret2 release (if present)."""
        from brain.zapret_paths import find_zapret_dirs
        dirs = [d for d in find_zapret_dirs(BASE_DIR) if (d / "files" / "fake").is_dir()]
        if not dirs:
            self.skipTest("no zapret2 release extracted")
        fake_dir = dirs[0] / "files" / "fake"
        for alias, fname in zb.ALIASES.items():
            self.assertTrue((fake_dir / fname).exists(), f"{alias} -> {fname} missing in {dirs[0].name}")


if __name__ == "__main__":
    unittest.main()
