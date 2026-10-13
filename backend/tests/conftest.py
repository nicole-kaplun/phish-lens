import os

# Tests run the API in local-dev mode (no Google token needed) and never
# call VirusTotal for real. Set before the app is imported.
os.environ["PHISHLENS_DEV"] = "1"
os.environ.pop("VT_API_KEY", None)
os.environ.pop("GEMINI_MODEL", None)

import pytest
from fastapi.testclient import TestClient

from app.main import app

GOOGLE_PASS = "mx.google.com; dkim=pass; spf=pass; dmarc=pass"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never reach the internet. Any lookup that tries fails as 'unavailable'."""
    import requests

    from app.analyzers import domain_age

    def offline(*args, **kwargs):
        raise requests.ConnectionError("network disabled in tests")
    monkeypatch.setattr(requests, "get", offline)
    monkeypatch.setattr(requests, "post", offline)
    domain_age._cache.clear()


@pytest.fixture
def client():
    return TestClient(app)


def email(**fields):
    """A clean, authenticated email; tests override only what they care about."""
    return {"from_header": "Dana <dana@example.com>", "authentication_results": [GOOGLE_PASS], **fields}