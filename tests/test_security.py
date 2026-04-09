"""Security tests — verify no secrets are leaked in source code or output."""

from __future__ import annotations

import ast
import base64
import re
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class TestNoHardcodedSecrets(unittest.TestCase):
    """Scan all Python files for hardcoded secrets and credentials."""

    PYTHON_FILES: list[Path] = []

    @classmethod
    def setUpClass(cls):
        cls.PYTHON_FILES = list(BASE_DIR.rglob("*.py"))

    # Patterns that indicate hardcoded secrets
    SECRET_PATTERNS = [
        # API keys (long hex/alphanum strings assigned to key-like vars)
        (r'(?:api_key|apikey|api_secret)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', "hardcoded API key"),
        # Passwords
        (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded password"),
        # Bearer tokens
        (r'Bearer\s+[A-Za-z0-9\._\-]{20,}', "hardcoded bearer token"),
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', "AWS access key"),
        # Private keys
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "private key"),
        # JWT tokens
        (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}', "JWT token"),
    ]

    # Files/patterns to exclude from scanning
    EXCLUDE_PATTERNS = [
        "test_security.py",  # This file itself
        "__pycache__",
        ".git/",
    ]

    def _should_skip(self, path: Path) -> bool:
        path_str = str(path)
        return any(ex in path_str for ex in self.EXCLUDE_PATTERNS)

    def test_no_hardcoded_api_keys(self):
        """Ensure no API keys are hardcoded in source files."""
        violations = []
        for pyfile in self.PYTHON_FILES:
            if self._should_skip(pyfile):
                continue
            try:
                content = pyfile.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pattern, desc in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for m in matches:
                    # Skip if it's inside a comment
                    line_start = content.rfind("\n", 0, m.start()) + 1
                    line = content[line_start:content.find("\n", m.end())]
                    stripped = line.lstrip()
                    if stripped.startswith("#"):
                        continue
                    # Skip os.environ.get patterns (these are safe)
                    if "os.environ" in line or "environ.get" in line:
                        continue
                    # Skip placeholder values
                    if "CHANGE_ME" in line or "your-" in line or "example" in line.lower():
                        continue
                    violations.append(
                        f"{pyfile.relative_to(BASE_DIR)}:{desc} → {line.strip()[:80]}"
                    )
        self.assertEqual(violations, [], f"Hardcoded secrets found:\n" + "\n".join(violations))

    def test_no_embedded_proxy_credentials(self):
        """Verify tier.py no longer contains decodable proxy credentials."""
        tier_path = BASE_DIR / "brain" / "tier.py"
        content = tier_path.read_text(encoding="utf-8")

        # Should not contain XOR-encoded proxy URL
        xor_pattern = r'_d\s*=\s*"[A-Za-z0-9+/=]{40,}"'
        matches = re.findall(xor_pattern, content)
        self.assertEqual(
            len(matches), 0,
            "tier.py still contains XOR-obfuscated data that could hide credentials"
        )

    def test_tier_decode_returns_empty(self):
        """Verify _decode_embedded_proxy returns empty string (credentials removed)."""
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from brain.tier import TierManager
        result = TierManager._decode_embedded_proxy()
        self.assertEqual(result, "", "Embedded proxy fallback should return empty string")

    def test_no_base64_encoded_urls_in_source(self):
        """Scan for base64 strings that decode to URLs (potential hidden credentials)."""
        violations = []
        b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']')

        for pyfile in self.PYTHON_FILES:
            if self._should_skip(pyfile):
                continue
            try:
                content = pyfile.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in b64_pattern.finditer(content):
                try:
                    decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                    if any(proto in decoded.lower() for proto in ["://", "socks5", "http", "ftp"]):
                        violations.append(
                            f"{pyfile.relative_to(BASE_DIR)}: base64 decodes to URL-like string"
                        )
                except Exception:
                    pass

        self.assertEqual(violations, [], f"Base64-encoded URLs found:\n" + "\n".join(violations))

    def test_config_json_in_gitignore(self):
        """Verify config.json and sensitive files are in .gitignore."""
        gitignore = (BASE_DIR / ".gitignore").read_text(encoding="utf-8")
        sensitive_files = [
            "config.json",
            ".env",
            ".api_key",
            ".ai_key",
            ".deepseek_key",
            "license.json",
        ]
        for f in sensitive_files:
            self.assertIn(f, gitignore, f"{f} must be in .gitignore")

    def test_server_secrets_use_environ(self):
        """Verify server/api.py gets all secrets from environment variables."""
        api_path = BASE_DIR / "server" / "api.py"
        content = api_path.read_text(encoding="utf-8")

        # Check that secrets are loaded from environment, not hardcoded
        # The env var names may differ from Python var names
        env_vars_expected = [
            "AI_API_KEY", "DEEPSEEK_API_KEY", "DONATEPAY_API_KEY",
            "SVOBODA_API_KEY", "REGISTRATION_SECRET", "PRO_PROXY_URL",
        ]
        for env_var in env_vars_expected:
            pattern = rf'os\.environ\.get\(\s*"{env_var}"'
            self.assertTrue(
                re.search(pattern, content),
                f"Environment variable {env_var} must be loaded via os.environ.get() in server/api.py"
            )

    def test_no_credentials_in_log_format(self):
        """Verify no passwords/tokens are included in log format strings."""
        violations = []
        log_pattern = re.compile(
            r'(?:logger\.\w+|logging\.\w+|print)\s*\(.*(?:password|secret|token|api_key|credential).*\)',
            re.IGNORECASE
        )
        for pyfile in self.PYTHON_FILES:
            if self._should_skip(pyfile):
                continue
            try:
                content = pyfile.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(content.split("\n"), 1):
                if log_pattern.search(line):
                    # Skip lines that just log the variable name, not the value
                    if "password" in line.lower() and ("%" not in line and "f'" not in line and "f\"" not in line):
                        continue
                    # Skip debug/meta references
                    if "password" in line.lower() and ("mask" in line.lower() or "redact" in line.lower()):
                        continue
                    violations.append(f"{pyfile.relative_to(BASE_DIR)}:{i}: {line.strip()[:100]}")

        # Filter out false positives:
        # - password masking code
        # - lines that mention token/secret as a concept, not logging actual values
        safe_patterns = [
            "_masked", "CHANGE_ME",
            "got per-install token",      # informational, doesn't log the token
            "Saved API token to",         # informational, doesn't log the token
            "Failed to save API token",   # error message, no actual token
        ]
        real_violations = [
            v for v in violations
            if not any(sp in v for sp in safe_patterns)
        ]
        self.assertEqual(real_violations, [],
                         f"Potential credential logging:\n" + "\n".join(real_violations))


class TestPasswordMasking(unittest.TestCase):
    """Verify credentials are properly masked in user-facing output."""

    def test_proxy_url_display_masks_password(self):
        """Verify proxy_router masks password in browser instructions."""
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from brain.proxy_router import ProxyRouter, RoutingPlan

        plan = RoutingPlan(
            proxy_hosts=["web.telegram.org"],
            proxy_url="socks5://user:SuperSecretPass123@proxy.example.com:443",
            proxy_type="plgames",
        )

        router = ProxyRouter({})
        output = router.get_browser_instructions(plan)

        # Password must be masked
        self.assertNotIn("SuperSecretPass123", output, "Full password must not appear in output")
        # First 2 chars should be visible for identification
        self.assertIn("Su", output, "First 2 chars of password should be visible")
        # Masked part
        self.assertIn("*" * 5, output, "Password should contain asterisks")
        # Username can be shown
        self.assertIn("user", output)

    def test_proxy_display_url_masks_auth(self):
        """Verify top-level proxy display uses *:* for auth."""
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from brain.proxy_router import ProxyRouter, RoutingPlan

        plan = RoutingPlan(
            proxy_hosts=["web.telegram.org"],
            proxy_url="socks5://myuser:mypass@host.com:443",
            proxy_type="test",
        )

        router = ProxyRouter({})
        output = router.get_browser_instructions(plan)

        self.assertIn("*:*@", output, "Auth section should show *:* in display URL")
        self.assertNotIn("myuser:mypass@", output, "Raw credentials must not appear in display URL")


class TestListExclude(unittest.TestCase):
    """Verify list-exclude.txt integrity and usage."""

    def test_exclude_file_exists(self):
        exclude = BASE_DIR / "list-exclude.txt"
        self.assertTrue(exclude.exists(), "list-exclude.txt must exist")

    def test_exclude_contains_critical_domains(self):
        """Critical infrastructure domains must be in exclude list."""
        content = (BASE_DIR / "list-exclude.txt").read_text(encoding="utf-8")
        domains = {line.strip() for line in content.split("\n") if line.strip()}

        critical = [
            "anthropic.com", "claude.ai", "github.com", "google.com",
            "microsoft.com", "steam.com", "svaboda-shwe.online",
        ]
        for d in critical:
            self.assertIn(d, domains, f"Critical domain {d} must be in list-exclude.txt")

    def test_exclude_no_empty_lines_or_invalid(self):
        """list-exclude.txt should have valid domain format."""
        content = (BASE_DIR / "list-exclude.txt").read_text(encoding="utf-8")
        for i, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            self.assertTrue(
                re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', line),
                f"list-exclude.txt line {i}: invalid domain format: {line!r}"
            )


if __name__ == "__main__":
    unittest.main()
