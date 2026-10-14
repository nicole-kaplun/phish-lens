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


def test_a_crashing_check_does_not_hide_the_others(client, monkeypatch):
    def broken(email):
        raise RuntimeError("bug")
    monkeypatch.setattr(attachments, "analyze", broken)
    result = client.post("/analyze", json=email(from_header="service@paypal.com <x@evil.com>")).json()
    titles = [f["title"] for f in result["findings"]]
    assert result["verdict"] == "malicious"                 # the other checks still ran
    assert "Attachments check unavailable" in titles        # and the gap is reported


@pytest.mark.parametrize("header", [
    "mx.google.com; none",                               # Google checked, recorded nothing
    "mx.google.com; spf=none; dkim=none; dmarc=none",    # domain publishes nothing
])
def test_no_result_is_not_the_same_as_a_pass(header):
    [finding] = authentication.analyze(EmailPayload(from_header="a@b.com", authentication_results=[header]))
    assert finding.title == "Authentication results unavailable" and finding.points == 0


def test_a_real_pass_gets_no_note():
    mail = EmailPayload(from_header="a@b.com", authentication_results=["mx.google.com; spf=pass; dmarc=pass"])
    assert authentication.analyze(mail) == []


def test_a_slow_check_cannot_hold_the_whole_result(client, monkeypatch):
    import time
    from app import main
    monkeypatch.setattr(main, "DEADLINE_SECONDS", 0.5)
    monkeypatch.setattr(content, "analyze", lambda mail: time.sleep(3) or [])

    start = time.monotonic()
    result = client.post("/analyze", json=email()).json()

    assert time.monotonic() - start < 2
    assert "Content check unavailable" in [f["title"] for f in result["findings"]]


TRACKED = {"href": "https://go.flashy.app/c/abc123", "text": "https://www.shop.example"}


def test_tracking_link_from_a_verified_sender_is_not_deceptive(client):
    # A newsletter from shop.example names its own site; the link goes through its mailing service.
    mail = email(from_header="Shop <news@shop.example>", links=[TRACKED])
    result = client.post("/analyze", json=mail).json()
    assert result["verdict"] == "safe"
    assert result["link_xray"]["rows"][0]["flagged"] is False


def test_same_link_without_dmarc_is_still_flagged(client):
    mail = email(from_header="Shop <news@shop.example>", links=[TRACKED], authentication_results=[])
    titles = [f["title"] for f in client.post("/analyze", json=mail).json()["findings"]]
    assert "Link text hides its real destination" in titles


def test_verified_sender_showing_another_brand_is_still_flagged(client):
    # An attacker can pass DMARC for their own domain; showing paypal.com is still deception.
    mail = email(from_header="Support <help@evil.example>",
                 links=[{"href": "https://evil.example/login", "text": "paypal.com/login"}])
    titles = [f["title"] for f in client.post("/analyze", json=mail).json()["findings"]]
    assert "Link text hides its real destination" in titles

