"""Tests for brain/dns_resolver.py and the generalized DNS diagnosis."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain import dns_fixer, dns_resolver  # noqa: E402


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _response(qid: int, name: str, ips: list[str], cname: str | None = None, rcode: int = 0) -> bytes:
    answers = []
    if cname:
        rdata = _encode_name(cname)
        answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata)
    for ip in ips:
        rdata = bytes(int(x) for x in ip.split("."))
        answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + rdata)
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    return hdr + _encode_name(name) + struct.pack("!HH", 1, 1) + b"".join(answers)


class TestWireFormat(unittest.TestCase):
    def test_build_query_layout(self):
        pkt, qid = dns_resolver.build_query("discord.com", qid=0x1234)
        self.assertEqual(qid, 0x1234)
        self.assertEqual(pkt[:2], b"\x12\x34")
        self.assertEqual(pkt[2:4], b"\x01\x00")            # RD flag
        self.assertEqual(pkt[4:6], b"\x00\x01")            # one question
        self.assertIn(b"\x07discord\x03com\x00", pkt)
        self.assertEqual(pkt[-4:], b"\x00\x01\x00\x01")    # A / IN

    def test_build_query_rejects_bad_labels(self):
        with self.assertRaises(ValueError):
            dns_resolver.build_query("a..b")
        with self.assertRaises(ValueError):
            dns_resolver.build_query("x" * 64 + ".com")

    def test_parse_a_records_with_cname_and_pointers(self):
        pkt = _response(7, "discord.com", ["162.159.137.232", "162.159.138.232"], cname="cdn.example.net")
        self.assertEqual(dns_resolver.parse_a_records(pkt, 7), ["162.159.137.232", "162.159.138.232"])

    def test_parse_rejects_id_mismatch_and_rcode(self):
        pkt = _response(7, "x.com", ["1.2.3.4"])
        with self.assertRaises(ValueError):
            dns_resolver.parse_a_records(pkt, 8)
        with self.assertRaises(ValueError):
            dns_resolver.parse_a_records(_response(7, "x.com", [], rcode=3), 7)  # NXDOMAIN
        with self.assertRaises(ValueError):
            dns_resolver.parse_a_records(b"\x00\x01", 1)

    def test_parse_ignores_non_a_answers(self):
        pkt = _response(9, "x.com", [], cname="only.cname")
        self.assertEqual(dns_resolver.parse_a_records(pkt, 9), [])


class TestResolveChain(unittest.TestCase):
    def test_doh_first(self):
        class FakeDoH:
            _working_provider = ("Cloudflare", "u")

            def resolve(self, name, rtype="A"):
                class R:
                    success = True
                    answers = [{"type": 1, "data": "1.1.1.1"}, {"type": 5, "data": "cname"}]
                return R()

        ips, src = dns_resolver.resolve_trusted("x.com", doh_resolver=FakeDoH())
        self.assertEqual(ips, ["1.1.1.1"])
        self.assertEqual(src, "doh:Cloudflare")

    def test_falls_through_dot_udp_tcp(self):
        calls = []

        def dot(*a, **k):
            calls.append("dot"); raise OSError("853 blocked")

        def udp(*a, **k):
            calls.append("udp"); raise TimeoutError()

        def tcp(server, name, timeout=3.0):
            calls.append("tcp"); return ["5.6.7.8"]

        with patch.object(dns_resolver, "query_dot", dot), \
             patch.object(dns_resolver, "query_udp", udp), \
             patch.object(dns_resolver, "query_tcp", tcp):
            ips, src = dns_resolver.resolve_trusted("x.com", servers=[("9.9.9.9", "q9")])
        self.assertEqual(ips, ["5.6.7.8"])
        self.assertEqual(src, "tcp:9.9.9.9")
        self.assertEqual(calls, ["dot", "udp", "tcp"])

    def test_all_fail(self):
        with patch.object(dns_resolver, "query_dot", side_effect=OSError), \
             patch.object(dns_resolver, "query_udp", side_effect=OSError), \
             patch.object(dns_resolver, "query_tcp", side_effect=OSError):
            self.assertEqual(dns_resolver.resolve_trusted("x.com", servers=[("1.1.1.1", "c")]), ([], ""))


class TestDiagnoseAndFix(unittest.TestCase):
    """Live er-telecom picture 2026-09-01: youtube/x/discord/instagram all resolve
    to one foreign SNI proxy (147.90.15.214). It serves youtube and x, but
    NOT discord/instagram; rutracker resolves correctly but is DPI-blocked."""

    SYS = {
        "youtube.com": "147.90.15.214", "x.com": "147.90.15.214",
        "discord.com": "147.90.15.214", "instagram.com": "147.90.15.214",
        "rutracker.org": "104.21.32.39", "nowhere.invalid": None,
    }
    PROBE = {
        "youtube.com": "ok", "x.com": "ok",
        "discord.com": "cert_mismatch", "instagram.com": "fail",
        "rutracker.org": "fail",
    }
    REAL = {
        "discord.com": ["162.159.138.232"], "instagram.com": ["57.144.244.34"],
        "rutracker.org": ["104.21.32.39"], "nowhere.invalid": [],
    }

    def _run(self, hosts, sni_proxy_ip=None):
        written = {}

        def fake_write(m):
            written.update(m); return True

        def ghbn(h):
            ip = self.SYS.get(h)
            if ip is None:
                raise OSError("NXDOMAIN")
            return ip

        with patch.object(dns_fixer.socket, "gethostbyname", ghbn), \
             patch.object(dns_fixer, "_tls_probe", lambda h, ip, timeout=4.0: self.PROBE.get(h, "fail")), \
             patch.object(dns_fixer, "write_hosts_entries", fake_write), \
             patch.object(dns_fixer, "flush_dns", lambda: None):
            res = dns_fixer.diagnose_and_fix_dns(
                hosts, sni_proxy_ip=sni_proxy_ip,
                resolver=lambda h: (self.REAL.get(h, []), "dot:1.1.1.1"))
        return res, written

    def test_only_bogus_answers_are_overridden(self):
        res, written = self._run(["youtube.com", "x.com", "discord.com", "instagram.com", "rutracker.org"])
        self.assertEqual(res["youtube.com"]["status"], "ok")
        self.assertEqual(res["x.com"]["status"], "ok")
        self.assertEqual(res["discord.com"]["status"], "poisoned_fixed")
        self.assertEqual(res["instagram.com"]["status"], "poisoned_fixed")   # shared stub IP
        self.assertEqual(res["rutracker.org"]["status"], "blocked_not_dns")  # DPI, leave to desync
        self.assertEqual(written, {"discord.com": "162.159.138.232", "instagram.com": "57.144.244.34"})
        self.assertTrue(res["discord.com"]["fixed"])
        self.assertFalse(res["rutracker.org"]["fixed"])

    def test_cert_mismatch_alone_is_enough(self):
        # Single host, no shared IP, no known proxy: certificate for another name => bogus
        res, written = self._run(["discord.com"])
        self.assertEqual(res["discord.com"]["status"], "poisoned_fixed")
        self.assertEqual(written, {"discord.com": "162.159.138.232"})

    def test_plain_fail_without_evidence_is_not_touched(self):
        res, written = self._run(["rutracker.org"])
        self.assertEqual(res["rutracker.org"]["status"], "blocked_not_dns")
        self.assertEqual(written, {})

    def test_known_sni_proxy_ip_flags_single_host(self):
        res, written = self._run(["instagram.com"], sni_proxy_ip="147.90.15.214")
        self.assertEqual(res["instagram.com"]["status"], "poisoned_fixed")

    def test_dns_failure_is_repaired_when_trusted_answers(self):
        self.REAL["nowhere.invalid"] = ["9.9.9.9"]
        try:
            res, written = self._run(["nowhere.invalid"])
            self.assertEqual(res["nowhere.invalid"]["status"], "poisoned_fixed")
            self.assertEqual(written, {"nowhere.invalid": "9.9.9.9"})
        finally:
            self.REAL["nowhere.invalid"] = []

    def test_unresolvable_bogus_answer_is_reported(self):
        saved = self.REAL.pop("discord.com")
        try:
            res, written = self._run(["discord.com"])
            self.assertEqual(res["discord.com"]["status"], "poisoned_unresolved")
            self.assertEqual(written, {})
        finally:
            self.REAL["discord.com"] = saved


class TestIpValidation(unittest.TestCase):
    """Everything this module returns can reach the Windows hosts file, and the
    DoH path carries provider JSON straight off the network."""

    def test_accepts_global_unicast_only(self):
        for good in ("1.2.3.4", "8.8.8.8", "162.159.138.232"):
            self.assertTrue(dns_resolver.is_usable_ipv4(good), good)
        for bad in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0",
                    "224.0.0.1", "169.254.1.1"):
            self.assertFalse(dns_resolver.is_usable_ipv4(bad), bad)

    def test_rejects_injection_and_garbage(self):
        injection = "1.2.3.4" + chr(10) + "0.0.0.0 evil.com"
        tabbed = "1.2.3.4" + chr(9) + "evil.com"
        for bad in (injection, tabbed, "not-an-ip", "", "1.2.3.4.5", "::1", None):
            self.assertFalse(dns_resolver.is_usable_ipv4(bad), repr(bad))

    def test_doh_answers_are_filtered(self):
        injection = "1.2.3.4" + chr(10) + "0.0.0.0 evil.com"

        class FakeDoH:
            _working_provider = ("X", "u")

            def resolve(self, name, rtype="A"):
                class R:
                    success = True
                    answers = [
                        {"type": 1, "data": injection},     # hosts-file injection
                        {"type": 1, "data": "127.0.0.1"},   # loopback blackhole
                        {"type": 1, "data": "9.9.9.9"},     # the only usable one
                    ]
                return R()

        ips, _src = dns_resolver.resolve_trusted("x.com", doh_resolver=FakeDoH())
        self.assertEqual(ips, ["9.9.9.9"])


class TestSpoofResistance(unittest.TestCase):
    """This module exists to defeat DNS poisoning, so a forged answer must be
    rejected rather than written into the hosts file."""

    def test_question_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            dns_resolver.parse_a_records(_response(5, "evil.com", ["6.6.6.6"]), 5,
                                         expected_name="discord.com")
        self.assertEqual(
            dns_resolver.parse_a_records(_response(5, "discord.com", ["6.6.6.6"]), 5,
                                         expected_name="discord.com"),
            ["6.6.6.6"])

    def test_truncated_records_raise_valueerror(self):
        full = _response(3, "x.com", ["1.2.3.4"])
        for cut in range(13, len(full)):
            with self.assertRaises(ValueError):
                dns_resolver.parse_a_records(full[:cut], 3)

    def test_compression_pointer_loop_is_bounded(self):
        hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        buf = hdr + b"\xc0\x0c" + struct.pack("!HH", 1, 1)   # name points at itself
        with self.assertRaises(ValueError):
            dns_resolver.parse_a_records(buf, 1, expected_name="x.com")

    def test_udp_ignores_reply_from_wrong_source(self):
        class FakeSock:
            def __init__(self, *a, **k):
                self.sent = None
                self.first = True

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def settimeout(self, t):
                pass

            def sendto(self, pkt, addr):
                self.sent = pkt

            def recvfrom(self, n):
                qid = struct.unpack("!H", self.sent[:2])[0]
                if self.first:
                    self.first = False
                    # off-path spoofer, correct id but wrong source address
                    return _response(qid, "x.com", ["6.6.6.6"]), ("9.9.9.9", 53)
                return _response(qid, "x.com", ["5.5.5.5"]), ("1.1.1.1", 53)

        with patch.object(dns_resolver.socket, "socket", FakeSock):
            self.assertEqual(dns_resolver.query_udp("1.1.1.1", "x.com"), ["5.5.5.5"])


class TestAliasNotTreatedAsPoisoning(unittest.TestCase):
    """youtube.com and www.youtube.com share one CDN IP. On a blocking ISP both
    TLS probes fail; counting them as 2 unrelated sites would brand a correct
    edge as a stub and pin a foreign IP for the whole session."""

    def _run(self, sys_map, trusted):
        written = {}
        with patch.object(dns_fixer.socket, "gethostbyname", lambda h: sys_map[h]), \
             patch.object(dns_fixer, "_tls_probe", lambda h, ip, timeout=4.0: "fail"), \
             patch.object(dns_fixer, "write_hosts_entries",
                          lambda m: (written.update(m), True)[1]), \
             patch.object(dns_fixer, "flush_dns", lambda: None):
            res = dns_fixer.diagnose_and_fix_dns(
                list(sys_map), resolver=lambda h: (trusted[h], "dot:1.1.1.1"))
        return res, written

    def test_www_alias_pair_is_not_fixed(self):
        sys_map = {"youtube.com": "142.250.1.1", "www.youtube.com": "142.250.1.1"}
        trusted = {h: ["142.250.1.1"] for h in sys_map}
        res, written = self._run(sys_map, trusted)
        for h in sys_map:
            self.assertEqual(res[h]["status"], "blocked_not_dns", h)
        self.assertEqual(written, {})

    def test_two_unrelated_sites_on_one_stub_are_fixed(self):
        sys_map = {"discord.com": "147.90.15.214", "instagram.com": "147.90.15.214"}
        trusted = {"discord.com": ["162.159.138.232"], "instagram.com": ["57.144.244.34"]}
        res, written = self._run(sys_map, trusted)
        for h in sys_map:
            self.assertEqual(res[h]["status"], "poisoned_fixed", h)
        self.assertEqual(written, trusted_flat := {k: v[0] for k, v in trusted.items()})

    def test_trusted_resolver_agreeing_means_dpi_not_dns(self):
        sys_map = {"rutracker.org": "104.21.32.39"}
        res, written = self._run(sys_map, {"rutracker.org": ["104.21.32.39"]})
        self.assertEqual(res["rutracker.org"]["status"], "blocked_not_dns")
        self.assertEqual(written, {})

    def test_registrable_domain(self):
        self.assertEqual(dns_fixer._registrable("www.youtube.com"), "youtube.com")
        self.assertEqual(dns_fixer._registrable("cdn.discordapp.com"), "discordapp.com")
        self.assertEqual(dns_fixer._registrable("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(dns_fixer._registrable("t.co"), "t.co")


class TestHostsFileSafety(unittest.TestCase):
    def test_unterminated_block_keeps_user_entries(self):
        start = dns_fixer._MARKER_START
        broken = "127.0.0.1\tlocalhost\n" + start + "\n1.2.3.4\tyoutube.com\n192.168.1.9\tprinter\n"
        out = dns_fixer._remove_marker_block(broken)
        self.assertIn("printer", out, "a missing END marker must not truncate the hosts file")
        self.assertIn("localhost", out)

    def test_well_formed_block_is_removed(self):
        start, end = dns_fixer._MARKER_START, dns_fixer._MARKER_END
        full = ("127.0.0.1\tlocalhost\n" + start + "\n1.2.3.4\tyoutube.com\n" + end
                + "\n192.168.1.9\tprinter\n")
        out = dns_fixer._remove_marker_block(full)
        self.assertNotIn("youtube.com", out)
        self.assertIn("localhost", out)
        self.assertIn("printer", out)


if __name__ == "__main__":
    unittest.main()
