"""Links: where a click would really take the user.

Each check reports at most once per message, with a count, so an email with
fifty identical tracking links does not score fifty times higher than one.
"""
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from app.analyzers.authentication import dmarc_passed
from app.brands import belongs_to, brand_label, lookalike_brand
from app.models import EmailPayload, Finding, Link, Severity

NAME = "links"

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
SAFE_SCHEMES = {"http", "https", "mailto", "tel"}

# A domain-looking word inside the visible link text, e.g. "paypal.com/login".
_DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)


def _short(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _same_site(a: str, b: str) -> bool:
    a, b = _strip_www(a), _strip_www(b)
    return belongs_to(a, [b]) or belongs_to(b, [a])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _verified_sender_domain(email: EmailPayload) -> str:
    """The sender's domain, but only when Google confirms it with DMARC; otherwise ""."""
    address = parseaddr(email.from_header)[1]
    if "@" not in address or not dmarc_passed(email):
        return ""
    return address.rpartition("@")[2].lower()


def _check_link(link: Link, verified_sender: str = "") -> list[tuple[str, str, Severity, int]]:
    """Returns (title, example, severity, points) for each problem in one link.

    verified_sender: the DMARC-verified sender domain, or "" when not verified.
    """
    try:
        parts = urlsplit(link.href.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return [("Malformed link", _short(link.href), Severity.LOW, 10)]

    scheme = parts.scheme.lower()
    # javascript:, data: and file: links can run code or open local files.
    if scheme and scheme not in SAFE_SCHEMES:
        return [(f"Link uses unusual '{scheme}:' scheme", _short(link.href), Severity.MEDIUM, 25)]
    if scheme in ("mailto", "tel") or not host:
        return []

    problems = []
    # The text names one site and the link opens another: the classic phishing link.
    shown = _DOMAIN_IN_TEXT.search(link.text)
    # Marketing mail wraps every link in a click-tracking redirect, so the text names the
    # sender's own site while the link opens the mailing service. When the text names the
    # verified sender itself, that is tracking, not deception. The redirect host is still
    # checked below (look-alike, IP, shortener) and by the domain age check.
    own_site = bool(shown and verified_sender and _same_site(shown.group(1).lower(), verified_sender))
    if shown and not own_site and not _same_site(shown.group(1).lower(), host):
        problems.append(("Link text hides its real destination",
                         f'shows "{_short(link.text)}" but opens {host}', Severity.HIGH, 35))
    # paypa1.com, paypal-secure.net, a Cyrillic "а" (see brands.py).
    imitated = lookalike_brand(host)
    if imitated:
        problems.append((f"Link to a domain imitating {brand_label(imitated)}", host, Severity.HIGH, 40))
    # In https://paypal.com@evil.com everything before "@" is a user name: the browser opens evil.com.
    if "@" in parts.netloc:
        problems.append(("Link disguises its destination with '@'",
                         f"looks like {_short(parts.netloc.split('@')[0])} but opens {host}", Severity.HIGH, 30))
    # Real companies link to their domain names, not to raw server addresses.
    if _is_ip(host):
        problems.append(("Link points to a raw IP address", host, Severity.MEDIUM, 20))
    if host in SHORTENERS:
        problems.append(("Shortened link hides its destination", host, Severity.LOW, 10))
    return problems


def analyze(email: EmailPayload) -> list[Finding]:
    """Check every link; report each kind of problem once, with a count."""
    grouped: dict[str, tuple[str, Severity, int, int]] = {}
    verified_sender = _verified_sender_domain(email)
    for link in email.links:
        for title, example, severity, points in _check_link(link, verified_sender):
            if title in grouped:
                first_example, sev, pts, count = grouped[title]
                grouped[title] = (first_example, sev, pts, count + 1)
            else:
                grouped[title] = (example, severity, points, 1)

    findings = []
    for title, (example, severity, points, count) in grouped.items():
        more = f" ({count} links like this)" if count > 1 else ""
        findings.append(Finding(
            analyzer=NAME, title=title, detail=f"Example: {example}{more}.",
            severity=severity, points=points,
        ))
    return findings

def xray(email: EmailPayload, limit: int = 10) -> dict:
    """What each link shows versus where it really goes, for the card.

    Not a check: nothing here adds points. It lets the user see the gap
    between link text and destination for themselves. Flagged links first.
    """
    rows, seen = [], set()
    verified_sender = _verified_sender_domain(email)
    for link in email.links:
        try:
            parts = urlsplit(link.href.strip())
            host = (parts.hostname or "").lower()
            scheme = parts.scheme.lower()
        except ValueError:
            host, scheme = "", ""
        if scheme in ("mailto", "tel"):
            continue
        shown = " ".join(link.text.split()) or "(no visible text)"
        key = (shown, host)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "shown": _short(shown),
            "opens": host or _short(link.href),
            "flagged": bool(_check_link(link, verified_sender)),
        })
    rows.sort(key=lambda r: not r["flagged"])  # stable: flagged first, original order kept
    return {"rows": rows[:limit], "total": len(rows)}
