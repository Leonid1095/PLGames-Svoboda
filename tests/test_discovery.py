"""Tests for brain/discovery.py — DiscoveryPipeline domain processing."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from brain.discovery import DiscoveryPipeline, DiscoveryResult, _COOLDOWN_SECONDS, _IGNORE_DOMAINS


class TestDiscoveryFiltering(unittest.TestCase):
    """Test domain filtering and validation."""

    def setUp(self):
        self.pipeline = DiscoveryPipeline(config={}, isp="test-isp")

    def test_skip_empty_domain(self):
        results = self.pipeline.process_new_domains(["", "   "])
        self.assertEqual(len(results), 0)

    def test_skip_ignored_domains(self):
        results = self.pipeline.process_new_domains(["localhost", "127.0.0.1", "wpad"])
        self.assertEqual(len(results), 0)

    def test_skip_short_domains(self):
        results = self.pipeline.process_new_domains(["a.b", "ab"])
        self.assertEqual(len(results), 0)

    def test_skip_no_dot(self):
        results = self.pipeline.process_new_domains(["nodotdomain"])
        self.assertEqual(len(results), 0)

    def test_domain_normalization(self):
        """Domains should be lowercased and stripped."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        results = pipeline.process_new_domains(["  YouTube.COM  "])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].domain, "youtube.com")

    def test_cooldown_prevents_reprocessing(self):
        """Same domain should not be reprocessed within cooldown."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        r1 = pipeline.process_new_domains(["test.example.com"])
        r2 = pipeline.process_new_domains(["test.example.com"])
        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r2), 0)  # Cooldown active

    def test_not_blocked_returns_none(self):
        """NOT_BLOCKED result should be skipped."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="NOT_BLOCKED", confidence=0.95
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        results = pipeline.process_new_domains(["unblocked.example.com"])
        self.assertEqual(len(results), 0)


class TestDiscoveryRouting(unittest.TestCase):
    """Test block type routing decisions."""

    def test_ip_block_routes_to_proxy(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="IP_BLOCK", confidence=0.9
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        results = pipeline.process_new_domains(["blocked.example.com"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].route, "proxy")
        self.assertFalse(results[0].solved)

    def test_sni_filtering_routes_to_zapret(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        results = pipeline.process_new_domains(["sni-blocked.example.com"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].route, "zapret2")

    def test_solver_success(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.return_value = MagicMock(
            flags=["multisplit:pos=1"], fitness=0.85
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, isp="test"
        )
        results = pipeline.process_new_domains(["solved.example.com"])
        self.assertTrue(results[0].solved)
        self.assertAlmostEqual(results[0].fitness, 0.85)

    def test_solver_failure(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.return_value = None
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, isp="test"
        )
        results = pipeline.process_new_domains(["unsolvable.example.com"])
        self.assertFalse(results[0].solved)

    def test_solver_exception_handled(self):
        """Solver crash should not propagate."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.side_effect = RuntimeError("solver crashed")
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, isp="test"
        )
        # Should not raise
        results = pipeline.process_new_domains(["crash.example.com"])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].solved)

    def test_classifier_exception_defaults_to_sni(self):
        """Classifier crash should default to SNI_FILTERING."""
        mock_classifier = MagicMock()
        mock_classifier.classify.side_effect = RuntimeError("classify crashed")
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        results = pipeline.process_new_domains(["fallback.example.com"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].block_type, "SNI_FILTERING")

    def test_monitored_domains_tracking(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier, isp="test"
        )
        pipeline.process_new_domains(["a.example.com", "b.example.com"])
        self.assertEqual(len(pipeline.monitored_domains), 2)

    def test_solved_count(self):
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.return_value = MagicMock(flags=["f"], fitness=0.8)
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, isp="test"
        )
        pipeline.process_new_domains(["a.example.com", "b.example.com"])
        self.assertEqual(pipeline.solved_count, 2)

    def test_server_report_on_high_fitness(self):
        """High-fitness solutions should be reported to server."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.return_value = MagicMock(flags=["f"], fitness=0.8)
        mock_sync = MagicMock()
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, server_sync=mock_sync, isp="test"
        )
        results = pipeline.process_new_domains(["report.example.com"])
        mock_sync.report_host_strategy.assert_called_once()
        self.assertTrue(results[0].reported_to_server)

    def test_no_server_report_on_low_fitness(self):
        """Low-fitness solutions should not be reported."""
        mock_classifier = MagicMock()
        mock_classifier.classify.return_value = MagicMock(
            block_type="SNI_FILTERING", confidence=0.9
        )
        mock_solver = MagicMock()
        mock_solver.solve.return_value = MagicMock(flags=["f"], fitness=0.3)
        mock_sync = MagicMock()
        pipeline = DiscoveryPipeline(
            config={}, classifier=mock_classifier,
            host_solver=mock_solver, server_sync=mock_sync, isp="test"
        )
        results = pipeline.process_new_domains(["low.example.com"])
        mock_sync.report_host_strategy.assert_not_called()


class TestDiscoveryExtraProfiles(unittest.TestCase):
    """Test extra profile generation."""

    def test_no_solver_returns_empty(self):
        pipeline = DiscoveryPipeline(config={}, isp="test")
        self.assertEqual(pipeline.get_extra_profiles(), [])

    def test_delegates_to_solver(self):
        mock_solver = MagicMock()
        mock_solver.build_extra_profiles.return_value = ["--filter-tcp=443", "--dpi-desync=fake"]
        pipeline = DiscoveryPipeline(
            config={}, host_solver=mock_solver, isp="test"
        )
        profiles = pipeline.get_extra_profiles()
        self.assertEqual(profiles, ["--filter-tcp=443", "--dpi-desync=fake"])


if __name__ == "__main__":
    unittest.main()
