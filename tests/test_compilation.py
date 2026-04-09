"""Compilation and import tests — verify all modules can be loaded."""

from __future__ import annotations

import importlib
import py_compile
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


class TestCompilation(unittest.TestCase):
    """Verify all Python files compile without syntax errors."""

    def test_run_real_compiles(self):
        """CRITICAL: run_real.py must always compile."""
        py_compile.compile(str(BASE_DIR / "run_real.py"), doraise=True)

    def test_run_shadow_compiles(self):
        py_compile.compile(str(BASE_DIR / "run_shadow.py"), doraise=True)

    def test_all_brain_modules_compile(self):
        """Every .py file in brain/ must compile."""
        brain_dir = BASE_DIR / "brain"
        failures = []
        for pyfile in sorted(brain_dir.glob("*.py")):
            try:
                py_compile.compile(str(pyfile), doraise=True)
            except py_compile.PyCompileError as e:
                failures.append(f"{pyfile.name}: {e}")
        self.assertEqual(failures, [], "Brain module compilation failures:\n" + "\n".join(failures))

    def test_server_api_compiles(self):
        py_compile.compile(str(BASE_DIR / "server" / "api.py"), doraise=True)

    def test_all_python_files_compile(self):
        """Every .py file in the project must compile."""
        failures = []
        for pyfile in BASE_DIR.rglob("*.py"):
            if "__pycache__" in str(pyfile) or ".git" in str(pyfile):
                continue
            try:
                py_compile.compile(str(pyfile), doraise=True)
            except py_compile.PyCompileError as e:
                failures.append(f"{pyfile.relative_to(BASE_DIR)}: {e}")
        self.assertEqual(failures, [], "Compilation failures:\n" + "\n".join(failures))


class TestImports(unittest.TestCase):
    """Verify key modules can be imported without side effects."""

    def test_import_tier(self):
        from brain.tier import TierManager, TIERS
        self.assertIn("free", TIERS)

    def test_import_analytics(self):
        from brain.analytics import Analytics
        self.assertTrue(callable(Analytics))

    def test_import_discovery(self):
        from brain.discovery import DiscoveryPipeline, DiscoveryResult
        self.assertTrue(callable(DiscoveryPipeline))

    def test_import_host_solver(self):
        from brain.host_solver import HostSolver, HostStrategy
        self.assertTrue(callable(HostSolver))

    def test_import_proxy_router(self):
        from brain.proxy_router import ProxyRouter, RoutingPlan
        self.assertTrue(callable(ProxyRouter))

    def test_import_block_classifier(self):
        from brain.block_classifier import BlockProbe, BlockAnalysis
        # BlockProbe is a dataclass — check the class itself is importable
        self.assertTrue(callable(BlockProbe))

    def test_import_genetic(self):
        from brain.genetic import Individual, GAConfig, StrategyGene
        self.assertTrue(callable(Individual))

    def test_import_morpher(self):
        from brain.morpher import TrafficMorpher
        self.assertTrue(callable(TrafficMorpher))

    def test_import_ui(self):
        from brain.ui import C
        self.assertTrue(hasattr(C, "RED"))
        self.assertTrue(hasattr(C, "GREEN"))
        self.assertTrue(hasattr(C, "RESET"))

    def test_import_failure_analyzer(self):
        from brain.failure_analyzer import FailureAnalyzer
        self.assertTrue(callable(FailureAnalyzer))

    def test_import_watchdog(self):
        from brain.watchdog import WatchDog
        self.assertTrue(callable(WatchDog))


if __name__ == "__main__":
    unittest.main()
