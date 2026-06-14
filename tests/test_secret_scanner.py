"""
Tests for the secret scanner module.
Validates detection of hardcoded credentials, API keys, and tokens in source files.
"""

import pytest
import re
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Patterns under test (mirrors what the scanner module uses)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
    "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "generic_api_key": re.compile(r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9]{16,}['\"]"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
}


def scan_content(content: str) -> list[dict]:
    """Scan a string for secret patterns. Returns list of findings."""
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            findings.append({
                "type": secret_type,
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
            })
    return findings


# ---------------------------------------------------------------------------
# Tests: AWS credentials
# ---------------------------------------------------------------------------

class TestAWSCredentialDetection:
    def test_detects_aws_access_key(self):
        content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        findings = scan_content(content)
        assert any(f["type"] == "aws_access_key" for f in findings)

    def test_detects_aws_secret_key_in_config(self):
        content = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        findings = scan_content(content)
        assert any(f["type"] == "aws_secret_key" for f in findings)

    def test_no_false_positive_on_placeholder(self):
        content = "aws_access_key_id = YOUR_KEY_HERE"
        findings = scan_content(content)
        assert not any(f["type"] == "aws_access_key" for f in findings)


# ---------------------------------------------------------------------------
# Tests: GitHub tokens
# ---------------------------------------------------------------------------

class TestGitHubTokenDetection:
    def test_detects_github_pat(self):
        content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = scan_content(content)
        assert any(f["type"] == "github_token" for f in findings)

    def test_no_false_positive_short_string(self):
        content = "ref: ghp_short"
        findings = scan_content(content)
        assert not any(f["type"] == "github_token" for f in findings)


# ---------------------------------------------------------------------------
# Tests: Generic API keys
# ---------------------------------------------------------------------------

class TestGenericAPIKeyDetection:
    def test_detects_api_key_assignment(self):
        content = "api_key = 'abcdef1234567890abcdef'"
        findings = scan_content(content)
        assert any(f["type"] == "generic_api_key" for f in findings)

    def test_detects_apikey_no_underscore(self):
        content = 'APIKEY="supersecretvalue12345"'
        findings = scan_content(content)
        assert any(f["type"] == "generic_api_key" for f in findings)

    def test_no_false_positive_on_env_var_reference(self):
        content = "api_key = os.environ['API_KEY']"
        findings = scan_content(content)
        assert not any(f["type"] == "generic_api_key" for f in findings)


# ---------------------------------------------------------------------------
# Tests: Private key headers
# ---------------------------------------------------------------------------

class TestPrivateKeyDetection:
    def test_detects_rsa_private_key_header(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"
        findings = scan_content(content)
        assert any(f["type"] == "private_key_header" for f in findings)

    def test_detects_ec_private_key_header(self):
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = scan_content(content)
        assert any(f["type"] == "private_key_header" for f in findings)

    def test_detects_generic_private_key_header(self):
        content = "-----BEGIN PRIVATE KEY-----"
        findings = scan_content(content)
        assert any(f["type"] == "private_key_header" for f in findings)


# ---------------------------------------------------------------------------
# Tests: Multiple secrets in one file
# ---------------------------------------------------------------------------

class TestMultiSecretScan:
    def test_detects_multiple_secrets(self):
        content = (
            "AKIAIOSFODNN7EXAMPLE\n"
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
        )
        findings = scan_content(content)
        types_found = {f["type"] for f in findings}
        assert "aws_access_key" in types_found
        assert "github_token" in types_found

    def test_clean_file_returns_no_findings(self):
        content = (
            "import os\n"
            "api_key = os.environ.get('API_KEY')\n"
            "region = 'us-east-1'\n"
        )
        findings = scan_content(content)
        assert len(findings) == 0
