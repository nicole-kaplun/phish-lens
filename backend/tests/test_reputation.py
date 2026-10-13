"""VirusTotal lookups, with the network replaced by fake responses."""
import pytest
import requests

from app.analyzers import reputation
from app.models import EmailPayload

HASH = "a" * 64
EMAIL = EmailPayload(from_header="a@b.com", attachments=[{"filename": "invoice.pdf", "sha256": HASH}])


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


def stats(malicious):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "undetected": 70 - malicious}}}}


@pytest.fixture
def vt(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    def respond_with(response=None, error=None):
        def fake_get(url, headers, timeout):
            assert HASH in url and timeout == reputation.TIMEOUT_SECONDS
            if error:
                raise error
            return response
        monkeypatch.setattr(reputation.requests, "get", fake_get)
    return respond_with


def titles(findings):
    return [(f.title, f.points) for f in findings]


def test_known_malicious_is_critical(vt):
    vt(FakeResponse(200, stats(40)))
    [finding] = reputation.analyze(EMAIL)
    assert finding.severity.value == "critical"


def test_few_engines_is_medium(vt):
    vt(FakeResponse(200, stats(2)))
    assert titles(reputation.analyze(EMAIL)) == [("Attachment flagged by some antivirus engines", 25)]


@pytest.mark.parametrize("response", [FakeResponse(404), FakeResponse(200, stats(0))])
def test_unknown_or_clean_file_adds_nothing(vt, response):
    vt(response)
    assert reputation.analyze(EMAIL) == []


@pytest.mark.parametrize("response,error", [
    (None, requests.Timeout()),
    (FakeResponse(429), None),                       # rate limited
    (FakeResponse(200, ["not", "a", "dict"]), None), # unexpected shape
    (FakeResponse(200, stats(-5)), None),            # implausible numbers
])
def test_failures_degrade_to_unavailable_never_safe(vt, response, error):
    vt(response, error)
    assert titles(reputation.analyze(EMAIL)) == [("File reputation check unavailable", 0)]


def test_without_api_key_reports_not_configured(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert titles(reputation.analyze(EMAIL)) == [("File reputation check unavailable", 0)]