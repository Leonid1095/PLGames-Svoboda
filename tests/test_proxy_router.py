"""Tests for brain/proxy_router.py — smart traffic routing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.proxy_router import ProxyRouter, RoutingPlan, RouteDecision, IP_BLOCKED_DOMAINS


class TestIPBlockedDomains(unittest.TestCase):
    """Test known IP-blocked domain detection."""

    def test_known_domains(self):
        router = ProxyRouter({})
        # Telegram and LinkedIn are commonly IP-blocked
        for domain in IP_BLOCKED_DOMAINS:
            self.assertTrue(
                router._is_known_ip_blocked(domain),
                f"{domain} should be detected as IP-blocked"
            )

    def test_subdomain_detection(self):
        """Subdomains of IP-blocked domains should also be detected."""
        router = ProxyRouter({})
        if "linkedin.com" in IP_BLOCKED_DOMAINS:
            self.assertTrue(router._is_known_ip_blocked("www.linkedin.com"))

    def test_non_blocked_domain(self):
        router = ProxyRouter({})
        self.assertFalse(router._is_known_ip_blocked("youtube.com"))
        self.assertFalse(router._is_known_ip_blocked("discord.com"))


class TestBrowserInstructions(unittest.TestCase):
    """Test get_browser_instructions output."""

    def test_empty_plan(self):
        router = ProxyRouter({})
        plan = RoutingPlan()
        output = router.get_browser_instructions(plan)
        self.assertEqual(output, "")

    def test_no_proxy_hosts_returns_empty(self):
        router = ProxyRouter({})
        plan = RoutingPlan(zapret2_hosts=["youtube.com"])
        output = router.get_browser_instructions(plan)
        self.assertEqual(output, "")

    def test_proxy_url_displayed_masked(self):
        """Proxy URL should have auth masked as *:*."""
        router = ProxyRouter({})
        plan = RoutingPlan(
            proxy_hosts=["some.blocked.com"],
            proxy_url="socks5://user:pass@host.com:443",
            proxy_type="test",
        )
        output = router.get_browser_instructions(plan)
        self.assertIn("*:*@", output)
        self.assertNotIn("user:pass@", output)

    def test_telegram_instructions_mask_password(self):
        """Telegram SOCKS5 instructions must mask the password."""
        router = ProxyRouter({})
        plan = RoutingPlan(
            proxy_hosts=["web.telegram.org"],
            proxy_url="socks5://admin:S3cretP4ss@proxy.example.com:443",
            proxy_type="plgames",
        )
        output = router.get_browser_instructions(plan)
        self.assertIn("Telegram:", output)
        self.assertIn("admin", output)
        self.assertNotIn("S3cretP4ss", output)
        # First 2 chars visible
        self.assertIn("S3", output)
        # Stars
        self.assertIn("*" * 5, output)

    def test_unroutable_hosts_instructions(self):
        router = ProxyRouter({})
        # Need proxy_hosts for instructions to be generated
        plan = RoutingPlan(
            proxy_hosts=["some.host.com"],
            proxy_url="socks5://127.0.0.1:1080",
            proxy_type="warp",
            unroutable_hosts=["blocked.example.com"],
        )
        output = router.get_browser_instructions(plan)
        self.assertIn("Cannot route", output)
        self.assertIn("blocked.example.com", output)

    def test_no_auth_in_proxy_url(self):
        """Proxy URL without auth should not crash."""
        router = ProxyRouter({})
        plan = RoutingPlan(
            proxy_hosts=["web.telegram.org"],
            proxy_url="socks5://host.com:1080",
            proxy_type="warp",
        )
        output = router.get_browser_instructions(plan)
        self.assertIn("host.com", output)


class TestRoutingPlan(unittest.TestCase):
    """Test RoutingPlan dataclass."""

    def test_default_empty(self):
        plan = RoutingPlan()
        self.assertEqual(plan.zapret2_hosts, [])
        self.assertEqual(plan.proxy_hosts, [])
        self.assertEqual(plan.unroutable_hosts, [])
        self.assertEqual(plan.proxy_url, "")

    def test_route_decision(self):
        rd = RouteDecision(
            host="test.com", block_type="IP_BLOCK",
            route="warp", proxy_url="socks5://127.0.0.1:1080",
        )
        self.assertEqual(rd.host, "test.com")
        self.assertEqual(rd.route, "warp")


class TestRouterShutdown(unittest.TestCase):
    """Test ProxyRouter cleanup."""

    def test_shutdown_no_crash_when_clean(self):
        """Shutdown on fresh router should not crash."""
        router = ProxyRouter({})
        router.shutdown()  # Should not raise

    def test_shutdown_stops_tunnel(self):
        """Shutdown should stop gost tunnel if active."""
        router = ProxyRouter({})
        mock_tunnel = MagicMock()
        router._gost_tunnel = mock_tunnel
        router.shutdown()
        mock_tunnel.stop.assert_called_once()
        self.assertIsNone(router._gost_tunnel)


if __name__ == "__main__":
    unittest.main()
