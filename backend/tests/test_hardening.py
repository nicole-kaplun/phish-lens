"""Regression tests for issues found in an external review."""
import pytest

from app.analyzers import attachments, authentication, content, sender
from app.models import EmailPayload
from tests.conftest import email


def results(header):
    return authentication.parse_results([header])


@pytest.mark.parametrize("header", [
    "mx.google.com.evil.example; dkim=pass; spf=pass; dmarc=pass",   # look-alike authserv-id
    "evil.example; dmarc=pass",
    "",
])
def test_only_googles_exact_authserv_id_is_trusted(header):
    assert results(header) is None


def test_comments_cannot_change_the_result():
    header = "mx.google.com; dmarc=fail (p=REJECT; note dmarc=pass) header.from=paypal.com"
    assert results(header) == {"dmarc": "fail"}


def test_a_value_mentioning_pass_is_not_a_result():
    header = "mx.google.com; dmarc=fail header.from=dmarc=pass.example"
    assert results(header)["dmarc"] == "fail"


def test_conflicting_results_take_the_worst():
    assert results("mx.google.com; dmarc=pass; dmarc=fail")["dmarc"] == "fail"


def test_one_valid_dkim_signature_is_enough():
    assert results("mx.google.com; dkim=fail header.i=@a.com; dkim=pass header.i=@b.com")["dkim"] == "pass"


def test_personal_outlook_mailbox_is_not_microsoft(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    mail = EmailPayload(from_header="Microsoft Support <attacker@outlook.com>",
                        authentication_results=["mx.google.com; dmarc=pass"],
                        body_text="Your account will be closed today.")
    assert not content._verified_brand(mail)
    assert "Display name impersonates Microsoft" in [f.title for f in sender.analyze(mail)]


def test_repeated_weak_attachments_count_once(client):
    body = email(attachments=[{"filename": f"part{i}.zip"} for i in range(6)])
    result = client.post("/analyze", json=body).json()
    zips = [f for f in result["findings"] if f["title"] == "Compressed attachment"]
    assert result["verdict"] == "safe" and len(zips) == 1 and "6 attachments" in zips[0]["detail"]


def test_missing_authentication_is_reported_honestly():
    [finding] = authentication.analyze(EmailPayload(from_header="a@b.com"))
    assert finding.title == "Authentication results unavailable" and finding.points == 0