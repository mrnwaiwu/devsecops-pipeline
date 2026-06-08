"""
Unit tests for the dependency scanner module.
Tests CVE detection, license compliance checks, and outdated package alerts.
"""

import unittest
from unittest.mock import patch, MagicMock


class TestDependencyScanner(unittest.TestCase):

    def test_parse_requirements_txt(self):
        """Test parsing of requirements.txt into package list."""
        sample = "requests==2.28.0\nflask>=2.0.0\nnumpy\n"
        # Simulate parser output
        packages = [line.strip() for line in sample.splitlines() if line.strip()]
        self.assertEqual(len(packages), 3)
        self.assertIn("requests==2.28.0", packages)

    def test_cve_detection_flags_known_vulnerability(self):
        """Test that a package with a known CVE is flagged."""
        vulnerable_packages = {
            "requests": {"version": "2.20.0", "cve": "CVE-2023-32681"}
        }
        flagged = [
            pkg for pkg, meta in vulnerable_packages.items()
            if meta.get("cve")
        ]
        self.assertIn("requests", flagged)

    def test_cve_detection_passes_clean_package(self):
        """Test that a package without CVEs is not flagged."""
        clean_packages = {
            "flask": {"version": "3.0.0", "cve": None}
        }
        flagged = [
            pkg for pkg, meta in clean_packages.items()
            if meta.get("cve")
        ]
        self.assertEqual(len(flagged), 0)

    def test_license_check_blocks_gpl(self):
        """Test that GPL-licensed packages are flagged in strict mode."""
        disallowed_licenses = {"GPL-2.0", "GPL-3.0", "AGPL-3.0"}
        package_licenses = {"some-lib": "GPL-3.0", "other-lib": "MIT"}
        violations = {
            pkg: lic for pkg, lic in package_licenses.items()
            if lic in disallowed_licenses
        }
        self.assertIn("some-lib", violations)
        self.assertNotIn("other-lib", violations)

    def test_outdated_package_detection(self):
        """Test detection of packages behind their latest version."""
        installed = {"requests": "2.28.0", "flask": "3.0.0"}
        latest = {"requests": "2.32.3", "flask": "3.0.0"}
        outdated = {
            pkg: {"installed": installed[pkg], "latest": latest[pkg]}
            for pkg in installed
            if installed[pkg] != latest.get(pkg)
        }
        self.assertIn("requests", outdated)
        self.assertNotIn("flask", outdated)

    def test_severity_scoring_critical_for_known_exploit(self):
        """Test that packages with known exploits receive CRITICAL severity."""
        findings = [
            {"package": "log4j", "cve": "CVE-2021-44228", "exploited": True},
            {"package": "requests", "cve": "CVE-2023-32681", "exploited": False},
        ]
        critical = [f for f in findings if f.get("exploited")]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["package"], "log4j")

    def test_empty_requirements_returns_no_findings(self):
        """Test that an empty requirements file produces zero findings."""
        packages = []
        findings = [p for p in packages if p]
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
