"""Domain age lookups, with RDAP replaced by fake responses."""
from datetime import datetime, timedelta, timezone

import pytest
import requests

from app.analyzers import domain_age
from app.models import EmailPayload


def rdap(days_ago):
    when = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return {"events": [{"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": when}]}


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


@pytest.fixture
def lookups(monkeypatch):
    """Answer RDAP lookups from a dict {domain: FakeResponse or exception}; record what was asked."""
    asked = []

    def install(answers):
        def fake_get(url, timeout, headers):
            domain = url.rsplit("/", 1)[-1]
            asked.append(domain)
            answer = answers[domain]
            if isinstance(answer, Exception):
                raise answer
            return answer
        monkeypatch.setattr(domain_age.requests, "get", fake_get)
        return asked
    return install


def mail(sender="Billing <billing@fresh-invoices.com>", links=()):
    return EmailPayload(from_header=sender, links=[{"href": h} for h in links])


@pytest.mark.parametrize("host,expected", [
    ("mail.paypal.com", "paypal.com"),
    ("www.leumi.co.il", "leumi.co.il"),
    ("example.com", "example.com"),
    ("185.23.4.17", None),
    ("localhost", None),
])
def test_registered_domain(host, expected):
    assert domain_age.registered_domain(host) == expected


@pytest.mark.parametrize("days,title,points", [
    (2, "Brand-new domain", 35),
    (20, "Recently registered domain", 20),
])
def test_young_domains_are_flagged(lookups, days, title, points):
    lookups({"fresh-invoices.com": FakeResponse(200, rdap(days))})
    [finding] = domain_age.analyze(mail())
    assert (finding.title, finding.points) == (title, points)


def test_old_domain_adds_nothing(lookups):
    lookups({"fresh-invoices.com": FakeResponse(200, rdap(3000))})
    assert domain_age.analyze(mail()) == []


def test_registry_without_rdap_adds_nothing(lookups):
    lookups({"fresh-invoices.com": FakeResponse(404)})
    assert domain_age.analyze(mail()) == []


@pytest.mark.parametrize("answer", [
    requests.Timeout(),
    FakeResponse(500),
    FakeResponse(200, {"events": [{"eventAction": "registration", "eventDate": "not a date"}]}),
    FakeResponse(200, {"events": [{"eventAction": "registration", "eventDate": "2999-01-01T00:00:00Z"}]}),
    FakeResponse(200, ["not", "a", "dict"]),
])
def test_failures_become_a_note_not_points(lookups, answer):
    lookups({"fresh-invoices.com": answer})
    [finding] = domain_age.analyze(mail())
    assert finding.points == 0 and finding.title == "Domain age check unavailable"


def test_checks_sender_and_links_skips_known_brands_and_caps_lookups(lookups):
    old = FakeResponse(200, rdap(3000))
    asked = lookups({d: old for d in ["fresh-invoices.com", "a.com", "b.com", "c.com"]})
    domain_age.analyze(mail(links=["https://www.paypal.com/x", "https://x.a.com/1", "https://a.com/2",
                                   "https://b.com", "https://c.com", "http://10.0.0.1/"]))
    assert asked == ["fresh-invoices.com", "a.com", "b.com"]


def test_results_are_cached(lookups):
    asked = lookups({"fresh-invoices.com": FakeResponse(200, rdap(3000))})
    domain_age.analyze(mail())
    domain_age.analyze(mail())
    assert asked == ["fresh-invoices.com"]