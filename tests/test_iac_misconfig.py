"""Tests for IaC misconfiguration detection in the security pipeline.

Covers common Terraform/Kubernetes misconfigurations that the pipeline
should flag before allowing a deploy to proceed.
"""


def detect_misconfigs(resource):
    """Return a list of misconfiguration findings for a resource dict."""
    findings = []

    if resource.get("type") == "aws_s3_bucket":
        if resource.get("acl") == "public-read":
            findings.append("S3 bucket has public-read ACL")
        if not resource.get("encryption"):
            findings.append("S3 bucket missing server-side encryption")

    if resource.get("type") == "aws_security_group":
        for rule in resource.get("ingress", []):
            if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") == 22:
                findings.append("Security group exposes SSH (22) to 0.0.0.0/0")

    if resource.get("type") == "k8s_pod":
        if resource.get("privileged"):
            findings.append("Pod runs in privileged mode")
        if resource.get("run_as_user") == 0:
            findings.append("Pod runs as root (uid 0)")

    return findings


def test_public_s3_bucket_flagged():
    res = {"type": "aws_s3_bucket", "acl": "public-read", "encryption": True}
    findings = detect_misconfigs(res)
    assert "S3 bucket has public-read ACL" in findings


def test_unencrypted_s3_bucket_flagged():
    res = {"type": "aws_s3_bucket", "acl": "private", "encryption": False}
    assert "S3 bucket missing server-side encryption" in detect_misconfigs(res)


def test_open_ssh_flagged():
    res = {
        "type": "aws_security_group",
        "ingress": [{"cidr": "0.0.0.0/0", "port": 22}],
    }
    assert "Security group exposes SSH (22) to 0.0.0.0/0" in detect_misconfigs(res)


def test_privileged_pod_flagged():
    res = {"type": "k8s_pod", "privileged": True}
    assert "Pod runs in privileged mode" in detect_misconfigs(res)


def test_root_pod_flagged():
    res = {"type": "k8s_pod", "run_as_user": 0}
    assert "Pod runs as root (uid 0)" in detect_misconfigs(res)


def test_clean_resource_has_no_findings():
    res = {"type": "aws_s3_bucket", "acl": "private", "encryption": True}
    assert detect_misconfigs(res) == []
