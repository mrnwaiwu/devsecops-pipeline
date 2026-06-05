"""
Unit tests for DevSecOps pipeline security gates.
Validates that critical security checks enforce expected pass/fail behaviour.
"""

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def passing_scan_result():
    return {
        "critical": 0,
        "high": 0,
        "medium": 3,
        "low": 12,
        "status": "pass",
    }


@pytest.fixture
def failing_scan_result():
    return {
        "critical": 2,
        "high": 5,
        "medium": 8,
        "low": 20,
        "status": "fail",
    }


@pytest.fixture
def sast_report():
    return {
        "findings": [
            {"rule": "sql-injection", "severity": "high", "file": "app/db.py", "line": 42},
            {"rule": "hardcoded-secret", "severity": "critical", "file": "config.py", "line": 7},
        ],
        "scanned_files": 134,
    }


# ---------------------------------------------------------------------------
# Helpers (lightweight stubs that mirror actual gate logic)
# ---------------------------------------------------------------------------

def evaluate_vuln_gate(scan_result: dict, max_critical: int = 0, max_high: int = 0) -> bool:
    """Return True if scan passes the vulnerability threshold gate."""
    return (
        scan_result["critical"] <= max_critical
        and scan_result["high"] <= max_high
    )


def has_critical_sast_findings(sast_report: dict) -> bool:
    """Return True if any SAST finding is severity 'critical'."""
    return any(f["severity"] == "critical" for f in sast_report["findings"])


def secret_scan_clean(findings: list) -> bool:
    """Return True if no hardcoded-secret findings are present."""
    return not any(f["rule"] == "hardcoded-secret" for f in findings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVulnerabilityGate:
    def test_passes_with_no_critical_or_high(self, passing_scan_result):
        assert evaluate_vuln_gate(passing_scan_result) is True

    def test_fails_with_critical_vulns(self, failing_scan_result):
        assert evaluate_vuln_gate(failing_scan_result) is False

    def test_fails_with_high_vulns_over_threshold(self):
        result = {"critical": 0, "high": 3, "medium": 5, "low": 10, "status": "fail"}
        assert evaluate_vuln_gate(result, max_critical=0, max_high=2) is False

    def test_passes_when_high_within_threshold(self):
        result = {"critical": 0, "high": 2, "medium": 5, "low": 10, "status": "pass"}
        assert evaluate_vuln_gate(result, max_critical=0, max_high=2) is True


class TestSastGate:
    def test_detects_critical_finding(self, sast_report):
        assert has_critical_sast_findings(sast_report) is True

    def test_no_critical_when_only_low_findings(self):
        report = {
            "findings": [
                {"rule": "missing-csrf", "severity": "medium", "file": "views.py", "line": 88},
            ],
            "scanned_files": 50,
        }
        assert has_critical_sast_findings(report) is False

    def test_empty_findings_not_critical(self):
        report = {"findings": [], "scanned_files": 20}
        assert has_critical_sast_findings(report) is False


class TestSecretScan:
    def test_flags_hardcoded_secret(self, sast_report):
        assert secret_scan_clean(sast_report["findings"]) is False

    def test_clean_when_no_secrets(self):
        findings = [
            {"rule": "sql-injection", "severity": "high", "file": "app/db.py", "line": 42},
        ]
        assert secret_scan_clean(findings) is True

    def test_clean_on_empty_findings(self):
        assert secret_scan_clean([]) is True
