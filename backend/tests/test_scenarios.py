"""End-to-end verdicts for realistic emails, one row per scenario."""
import pytest

from tests.conftest import email

SCENARIOS = [
    # (name, request body, expected verdict, a finding title that must appear)
    ("clean mail", email(), "safe", None),
    ("real PayPal", email(from_header="PayPal <service@paypal.com>"), "safe", None),
    ("sent within Gmail", email(authentication_results=[]), "safe", None),
    ("brand in display name", email(from_header="PayPal Security <alerts@random-mailer.com>"),
     "suspicious", "Display name impersonates Paypal"),
    ("fake address in name", email(from_header="service@paypal.com <x@evil.com>"),
     "malicious", "Fake address in display name"),
    ("look-alike domain", email(from_header="PayPal <support@paypa1.com>"),
     "malicious", "Sender domain imitates Paypal"),
    ("DMARC fail", email(authentication_results=["mx.google.com; dkim=pass; spf=pass; dmarc=fail"]),
     "suspicious", "DMARC fail"),
    ("forged pass below Google's fail",
     email(authentication_results=["mx.google.com; dkim=fail; spf=fail; dmarc=fail",
                                   "mx.google.com; dkim=pass; spf=pass; dmarc=pass"]),
     "malicious", "DMARC fail"),
    ("deceptive link text", email(links=[{"href": "https://evil.com/x", "text": "paypal.com/login"}]),
     "suspicious", "Link text hides its real destination"),
    ("@ trick in link", email(links=[{"href": "https://paypal.com@evil.com/x", "text": "Click"}]),
     "suspicious", "Link disguises its destination with '@'"),
    ("double extension", email(attachments=[{"filename": "invoice.pdf.exe"}]),
     "malicious", "Executable disguised as a document"),
         ("one weak signal stays safe", email(attachments=[{"filename": "docs.zip"}]), "safe", None),
    ("weak signals add up",
     email(authentication_results=["mx.google.com; dkim=pass; spf=fail; dmarc=pass"],
           attachments=[{"filename": "docs.zip"}]),
     "suspicious", "SPF fail"),
    ("right-to-left override", email(attachments=[{"filename": "invoice\u202efdp.exe"}]),
     "malicious", "File name is visually reversed"),
]


@pytest.mark.parametrize("name,body,verdict,title", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario(client, name, body, verdict, title):
    result = client.post("/analyze", json=body).json()
    assert result["verdict"] == verdict
    if title:
        assert title in [f["title"] for f in result["findings"]]


def test_findings_are_ranked_most_severe_first(client):
    result = client.post("/analyze", json=email(
        from_header="service@paypal.com <x@evil.com>")).json()
    points = [f["points"] for f in result["findings"]]
    assert points == sorted(points, reverse=True)