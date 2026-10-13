"""Links: where a click would really take the user.

Each check reports at most once per message, with a count, so an email with
fifty identical tracking links does not score fifty times higher than one.
"""
import ipaddress
import re
from urllib.parse import urlsplit

from app.brands import belongs_to, lookalike_brand
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


def _check_link(link: Link) -> list[tuple[str, str, Severity, int]]:
    """Returns (title, example, severity, points) for each problem in one link."""
    try:
        parts = urlsplit(link.href.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return [("Malformed link", _short(link.href), Severity.LOW, 10)]

    scheme = parts.scheme.lower()
    if scheme and scheme not in SAFE_SCHEMES:
        return [(f"Link uses unusual '{scheme}:' scheme", _short(link.href), Severity.MEDIUM, 25)]
    if scheme in ("mailto", "tel") or not host:
        return []

    problems = []
    shown = _DOMAIN_IN_TEXT.search(link.text)
    if shown and not _same_site(shown.group(1).lower(), host):
        problems.append(("Link text hides its real destination",
                         f'shows "{_short(link.text)}" but opens {host}', Severity.HIGH, 35))
    imitated = lookalike_brand(host)
    if imitated:
        problems.append((f"Link to a domain imitating {imitated.title()}", host, Severity.HIGH, 40))
    if "@" in parts.netloc:
        problems.append(("Link disguises its destination with '@'",
                         f"looks like {_short(parts.netloc.split('@')[0])} but opens {host}", Severity.HIGH, 30))
    if _is_ip(host):
        problems.append(("Link points to a raw IP address", host, Severity.MEDIUM, 20))
    if host in SHORTENERS:
        problems.append(("Shortened link hides its destination", host, Severity.LOW, 10))
    return problems


def analyze(email: EmailPayload) -> list[Finding]:
    grouped: dict[str, tuple[str, Severity, int, int]] = {}
    for link in email.links:
        for title, example, severity, points in _check_link(link):
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