"""Smoke tests for the app's health endpoint.

These keep the pipeline honest: if the service fails to import or the
health route changes shape, CI catches it before deploy.
"""

import json

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_returns_json(client):
    resp = client.get("/health")
    assert resp.content_type.startswith("application/json")


def test_health_reports_ok_status(client):
    resp = client.get("/health")
    payload = json.loads(resp.data)
    assert payload.get("status") == "ok"
