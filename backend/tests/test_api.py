"""Input validation and caller authentication."""
import pytest

import app.auth
from tests.conftest import email


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize("body", [
    {"subject": "no sender"},                                   # required field missing
    {"from_header": "a" * 5_000},                               # too long
    {"from_header": "a@b.com", "hack": 1},                      # unknown field
    {"from_header": "a@b.com", "attachments": [{"filename": "x", "sha256": "not-a-hash"}]},
    {"from_header": "a@b.com", "links": [{"href": "x"}] * 101}, # too many links
])
def test_rejects_malformed_input(client, body):
    assert client.post("/analyze", json=body).status_code == 422


@pytest.fixture
def locked(monkeypatch):
    """Turn dev mode off for one test so the real token check runs."""
    monkeypatch.setattr(app.auth, "DEV_MODE", False)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "test-client")
    monkeypatch.setenv("ALLOWED_EMAILS", "user@example.com")


def test_missing_token_is_401(client, locked):
    assert client.post("/analyze", json=email()).status_code == 401


def test_wrong_scheme_is_401(client, locked):
    r = client.post("/analyze", json=email(), headers={"Authorization": "Basic abc"})
    assert r.status_code == 401


def test_unconfigured_server_refuses_everyone(client, locked, monkeypatch):
    monkeypatch.delenv("ALLOWED_EMAILS")
    r = client.post("/analyze", json=email(), headers={"Authorization": "Bearer x"})
    assert r.status_code == 503


def test_each_authentication_header_has_a_length_limit(client):
    # The list size was limited, but not each header in it.
    too_long = {"from_header": "a@b.com", "authentication_results": ["x" * 4_001]}
    assert client.post("/analyze", json=too_long).status_code == 422
