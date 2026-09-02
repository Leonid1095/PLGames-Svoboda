"""Hostlist / exclude-list consistency.

zapret2 matches hostlists by domain SUFFIX, so `--hostlist-exclude` shadows every
subdomain of an excluded entry. Two config errors follow from that, and the repo
has shipped both:

* a domain in BOTH lists -- the old hostlist.txt listed steamcommunity.com,
  steampowered.com, epicgames.com and riotgames.com while list-exclude.txt also
  excluded them, so the intent was contradictory;
* a hostlist entry shadowed by an excluded PARENT -- e.g. ytimg.l.google.com is
  dead weight while google.com is excluded.

Neither breaks the internet, but both make the hostlist lie about what is being
processed, which wastes debugging time when a site does not unblock.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

CURATED = BASE_DIR / "hostlist-curated.txt"
EXCLUDE = BASE_DIR / "list-exclude.txt"


def _load(path: Path) -> set[str]:
    entries = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line.lower())
    return entries


class TestHostlistConsistency(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CURATED.exists(), "hostlist-curated.txt is the tracked source of truth")
        self.hostlist = _load(CURATED)
        self.exclude = _load(EXCLUDE)

    def test_no_domain_in_both_lists(self):
        both = sorted(self.hostlist & self.exclude)
        self.assertEqual(both, [], f"listed AND excluded (contradiction): {both}")

    def test_no_hostlist_entry_shadowed_by_excluded_parent(self):
        shadowed = sorted(
            h for h in self.hostlist
            for e in self.exclude
            if h != e and h.endswith("." + e)
        )
        self.assertEqual(shadowed, [], f"dead entries shadowed by an excluded parent: {shadowed}")

    def test_valid_domain_syntax(self):
        # Single-character labels are legal: t.co is Twitter's shortener.
        for entry in sorted(self.hostlist):
            self.assertRegex(entry, r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", f"bad domain: {entry!r}")

    def test_core_blocked_services_present(self):
        for domain in ("discord.com", "youtube.com", "googlevideo.com", "x.com",
                       "instagram.com", "telegram.org"):
            self.assertIn(domain, self.hostlist, f"{domain} must be in the hostlist")

    def test_doh_resolvers_present(self):
        """DoH endpoints are SNI-blocked at several RU ISPs since 2026-07-03;
        desyncing their TLS is what makes encrypted DNS work again."""
        for domain in ("dns.google", "cloudflare-dns.com"):
            self.assertIn(domain, self.hostlist, f"{domain} must be desynced")

    def test_anticheat_and_launchers_excluded_not_listed(self):
        """Desyncing anti-cheat gets users banned; launchers break."""
        for domain in ("easyanticheat.net", "battleye.com", "riotgames.com",
                       "steampowered.com", "epicgames.com", "twitch.tv"):
            self.assertIn(domain, self.exclude, f"{domain} must be excluded")
            self.assertNotIn(domain, self.hostlist, f"{domain} must NOT be desynced")

    def test_geo_blocked_services_are_not_listed(self):
        """Sanctions/geo restrictions are not DPI: desync cannot fix them and
        only risks breaking the service."""
        for domain in ("netflix.com", "spotify.com", "playstation.com",
                       "xbox.com", "ea.com", "crunchyroll.com"):
            self.assertNotIn(domain, self.hostlist, f"{domain} is geo-blocked, not DPI-blocked")

    def test_critical_infrastructure_excluded(self):
        for domain in ("anthropic.com", "claude.ai", "github.com", "google.com",
                       "microsoft.com", "kaspersky.com", "sberbank.ru", "gosuslugi.ru"):
            self.assertIn(domain, self.exclude, f"{domain} must be in list-exclude.txt")


if __name__ == "__main__":
    unittest.main()
