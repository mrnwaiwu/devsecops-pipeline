"""
Unit tests for compliance check integrations in the DevSecOps pipeline.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestComplianceChecks:
    """Tests for pipeline compliance gate enforcement."""

    def test_license_check_passes_for_approved_licenses(self):
        """Ensure approved OSS licenses pass the compliance gate."""
        approved = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]
        for license_id in approved:
            assert _is_license_approved(license_id) is True

    def test_license_check_fails_for_gpl(self):
        """GPL licenses should fail the compliance gate by default."""
        restricted = ["GPL-2.0", "GPL-3.0", "LGPL-2.1", "AGPL-3.0"]
        for license_id in restricted:
            assert _is_license_approved(license_id) is False

    def test_sbom_generation_produces_required_fields(self):
        """SBOM output must include name, version, and license for each component."""
        sbom = _generate_mock_sbom()
        for component in sbom.get("components", []):
            assert "name" in component
            assert "version" in component
            assert "license" in component

    def test_policy_gate_blocks_on_critical_findings(self):
        """Pipeline should be blocked when critical policy violations exist."""
        findings = [
            {"severity": "CRITICAL", "rule": "no-root-containers"},
            {"severity": "LOW", "rule": "image-tag-pinned"},
        ]
        assert _policy_gate_passes(findings) is False

    def test_policy_gate_passes_with_no_critical_findings(self):
        """Pipeline should proceed when no critical findings are present."""
        findings = [
            {"severity": "MEDIUM", "rule": "resource-limits-set"},
            {"severity": "LOW", "rule": "image-tag-pinned"},
        ]
        assert _policy_gate_passes(findings) is True

    def test_policy_gate_passes_with_empty_findings(self):
        """Pipeline should proceed when there are no findings at all."""
        assert _policy_gate_passes([]) is True


# ---------------------------------------------------------------------------
# Helpers (stubs — replace with real imports once module is wired up)
# ---------------------------------------------------------------------------

def _is_license_approved(license_id: str) -> bool:
    approved = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"}
    return license_id in approved


def _generate_mock_sbom() -> dict:
    return {
        "components": [
            {"name": "requests", "version": "2.31.0", "license": "Apache-2.0"},
            {"name": "flask", "version": "3.0.2", "license": "BSD-3-Clause"},
        ]
    }


def _policy_gate_passes(findings: list) -> bool:
    return not any(f.get("severity") == "CRITICAL" for f in findings)
