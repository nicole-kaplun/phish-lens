"""Reply-To mismatch: replies silently go somewhere other than the sender.

Users see the From address but almost never the Reply-To. Business Email
Compromise relies on this: the message looks like it is from a colleague or
a supplier, and the answer (with the invoice, the gift card codes, the bank
details) goes to the attacker's personal mailbox. These messages often have
no links or attachments, so nothing else in PhishLens would notice them.
"""
from email.utils import parseaddr

from app.analyzers.authentication import dmarc_passed
from app.brands import belongs_to
from app.models import EmailPayload, Finding, Severity

NAME = "reply_to"

# Free mailboxes anyone can open in a minute.
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
             "icloud.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
             "yandex.com", "zoho.com", "walla.co.il"}


def _domain(header: str) -> str:
    address = parseaddr(header)[1]
    return address.rpartition("@")[2].lower() if "@" in address else ""


def _same_site(a: str, b: str) -> bool:
    return belongs_to(a, [b]) or belongs_to(b, [a])


def analyze(email: EmailPayload) -> list[Finding]:
    reply_domain = _domain(email.reply_to)
    from_domain = _domain(email.from_header)
    if not reply_domain or not from_domain or _same_site(reply_domain, from_domain):
        return []

    reply_address = parseaddr(email.reply_to)[1][:80]
    # Sharing services (WeTransfer, shared documents, invitations) send on a person's
    # behalf, set Reply-To to that person and name them in the message. BEC depends on
    # the reader never seeing where replies go; from a verified sender that shows the
    # address in the message itself, the redirect is not hidden, so it stays a weak signal.
    shown = reply_address.lower() in f"{email.subject} {email.body_text}".lower()
    disclosed = shown and dmarc_passed(email)
    if reply_domain in FREE_MAIL and from_domain not in FREE_MAIL and not disclosed:
        # An organisation asking for answers at a personal mailbox: classic BEC.
        return [Finding(
            analyzer=NAME, title="Replies go to a personal address",
            detail=f"The message is from {from_domain}, but if you reply it goes to "
                   f"{reply_address}, a free mailbox anyone can open.",
            severity=Severity.HIGH, points=30)]
    # Different organisations can be legitimate (help desks, mailing services),
    # so on its own this is only a weak signal.
    return [Finding(
        analyzer=NAME, title="Replies go to a different domain",
        detail=f"The message is from {from_domain}, but replies go to {reply_address}.",
        severity=Severity.LOW, points=15)]