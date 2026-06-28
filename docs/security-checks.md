# Security Checks Reference

This document describes the automated security checks run in the DevSecOps pipeline.

## Static Analysis (SAST)

| Tool | Stage | Fail Threshold |
|---|---|---|
| Bandit | pre-build | HIGH severity findings |
| Semgrep | pre-build | Any security rules match |
| Checkov | pre-build | CRITICAL IaC misconfigs |

## Dependency Scanning (SCA)

| Tool | Stage | Fail Threshold |
|---|---|---|
| pip-audit | build | CVSS ≥ 8.0 |
| Safety | build | Any known vuln |
| OWASP Dependency-Check | build | CVSS ≥ 7.0 |

## Container Security

| Tool | Stage | Fail Threshold |
|---|---|---|
| Trivy | post-build | CRITICAL CVEs in image |
| Hadolint | pre-build | Dockerfile best-practice violations |
| Docker Bench | post-deploy | CIS Docker benchmark failures |

## Secrets Detection

Gitleaks runs on every commit. Any detected secret causes an immediate pipeline failure and alerts the security team.

Patterns scanned:
- API keys (AWS, GCP, Azure, Anthropic, etc.)
- Private keys and certificates
- Database connection strings
- OAuth tokens

## Supply Chain Security

| Tool | Stage | Fail Threshold |
|---|---|---|
| Sigstore/Cosign | post-build | Unsigned container images |
| SLSA Provenance | post-build | Missing build provenance attestation |
| in-toto | post-build | Failed link verification |

All build artifacts are signed with Sigstore and provenance attestations are generated per SLSA Level 2 requirements. Unsigned or unverifiable images are blocked from promotion to staging. The signing key is stored in Google Cloud KMS and access is audited via Cloud Audit Logs.

## Runtime Security (DAST)

OWASP ZAP runs against the staging environment after deployment.

- Active scan profile: `api-scan`
- Fail on: MEDIUM or above findings not in the known-false-positives list

## Notifications

Security findings are posted to `#security-alerts` Slack channel and opened as GitHub issues with the `security` label.
