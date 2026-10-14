"""Reply-To mismatch, the signature of Business Email Compromise."""
import pytest

from tests.conftest import email

CEO_FRAUD = email(from_header="David Cohen <david@company.com>",
                  reply_to="David Cohen <david.cohen.ceo@gmail.com>")


def findings(client, body):
    result = client.post("/analyze", json=body).json()
    return result["verdict"], [f["title"] for f in result["findings"] if f["points"] > 0]


def test_company_mail_with_personal_reply_to_is_suspicious(client):
    assert findings(client, CEO_FRAUD) == ("suspicious", ["Replies go to a personal address"])


@pytest.mark.parametrize("from_header,reply_to", [
    ("Billing <billing@company.com>", ""),                          # no Reply-To
    ("Billing <billing@company.com>", "support@company.com"),       # same domain
    ("News <news@mail.company.com>", "help@company.com"),           # same site, subdomain
    ("Dana <dana@gmail.com>", "dana.work@gmail.com"),               # both personal, same provider
])
def test_matching_reply_to_adds_nothing(client, from_header, reply_to):
    assert findings(client, email(from_header=from_header, reply_to=reply_to)) == ("safe", [])


def test_other_organisation_is_only_a_weak_signal(client):
    verdict, titles = findings(client, email(from_header="Shop <orders@shop.com>",
                                             reply_to="tickets@helpdesk-provider.com"))
    assert (verdict, titles) == ("safe", ["Replies go to a different domain"])


SHARED_FILE = dict(from_header="WeTransfer <noreply@wetransfer.com>", reply_to="sharer.name@gmail.com",
                   subject="sharer.name@gmail.com sent you 00000003 via WeTransfer")


def test_sharing_service_naming_the_person_is_only_a_weak_signal(client):
    # A real WeTransfer notification: replies go to the person who sent the files,
    # and the message says who that is.
    assert findings(client, email(**SHARED_FILE)) == ("safe", ["Replies go to a different domain"])


def test_same_message_without_dmarc_is_still_suspicious(client):
    verdict, titles = findings(client, email(**SHARED_FILE, authentication_results=[]))
    assert verdict == "suspicious" and "Replies go to a personal address" in titles

