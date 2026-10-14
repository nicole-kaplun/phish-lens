"""Domain age via RDAP: how long ago was the sender's or a link's domain registered?

Phishing domains are usually registered days before an attack and abandoned
soon after, so a very young domain is one of the strongest signals there is.
RDAP is the public, standard successor to WHOIS and needs no API key. The
server for each top-level domain comes from IANA's official bootstrap file,
so lookups go straight to the registry, with no third-party redirector.

The RDAP response is external input: only one date is read from it, and it
must parse and be plausible. Lookups that fail add a note, never points.
"""
import ipaddress
import logging
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import urlsplit

import requests

from app.analyzers.reply_to import FREE_MAIL
from app.brands import BRANDS, belongs_to
from app.models import EmailPayload, Finding, Severity

NAME = "domain_age"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT_SECONDS = 3
MAX_LOOKUPS = 3
CACHE_SECONDS = 24 * 3600

# Suffixes where the registrable domain has three labels (example.co.il).
_TWO_LEVEL_SUFFIXES = {"co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
                       "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.in", "co.za"}
# Brands we know, and big mail providers: decades old, no point asking.
_KNOWN_GOOD = [d for domains in BRANDS.values() for d in domains] + sorted(FREE_MAIL)

_cache: dict[str, tuple[float, datetime | None]] = {}
_bootstrap: dict[str, str] | None = None
log = logging.getLogger(__name__)


def registered_domain(host: str) -> str | None:
    """mail.paypal.com -> paypal.com, www.leumi.co.il -> leumi.co.il."""
    host = host.lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _candidate_domains(email: EmailPayload) -> list[str]:
    """The sender's domain and the link domains, without duplicates or well-known ones."""
    hosts = [parseaddr(email.from_header)[1].rpartition("@")[2]]
    for link in email.links:
        try:
            hosts.append(urlsplit(link.href.strip()).hostname or "")
        except ValueError:
            continue
    seen: list[str] = []
    for host in hosts:
        domain = registered_domain(host) if host else None
        if domain and domain not in seen and not belongs_to(domain, _KNOWN_GOOD):
            seen.append(domain)
    return seen[:MAX_LOOKUPS]


def _parse_registration(body: object) -> datetime | None:
    """The registration date from an RDAP reply. Raises if the date is implausible."""
    for event in body.get("events", []):  # type: ignore[union-attr]
        if event.get("eventAction") == "registration":
            when = datetime.fromisoformat(str(event["eventDate"]).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if not datetime(1985, 1, 1, tzinfo=timezone.utc) <= when <= datetime.now(timezone.utc):
                raise ValueError("implausible registration date")
            return when
    return None


def _rdap_base(tld: str) -> str | None:
    """The registry's RDAP server for a top-level domain, from IANA (loaded once)."""
    global _bootstrap
    if _bootstrap is None:
        resp = requests.get(BOOTSTRAP_URL, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        table = {}
        for tlds, urls in resp.json()["services"]:
            https = [u for u in urls if u.startswith("https://")]
            for t in tlds:
                if https:
                    table[t.lower()] = https[0]
        _bootstrap = table
    return _bootstrap.get(tld)


def _registration_date(domain: str) -> datetime | None:
    """Raises on failure. Returns None when the registry has no RDAP data."""
    cached = _cache.get(domain)
    if cached and time.time() - cached[0] < CACHE_SECONDS:
        return cached[1]
    base = _rdap_base(domain.rsplit(".", 1)[-1])
    if base is None:
        _cache[domain] = (time.time(), None)  # this registry does not publish RDAP
        return None
    resp = requests.get(f"{base.rstrip('/')}/domain/{domain}", timeout=TIMEOUT_SECONDS,
                        headers={"Accept": "application/rdap+json"})
    if resp.status_code == 404:
        when = None  # registry does not publish RDAP (common for some country codes)
    else:
        resp.raise_for_status()
        when = _parse_registration(resp.json())
    _cache[domain] = (time.time(), when)
    return when


def analyze(email: EmailPayload) -> list[Finding]:
    """Flag sender or link domains registered in the last 7 or 30 days."""
    findings = []
    failed = []
    for domain in _candidate_domains(email):
        try:
            registered = _registration_date(domain)
        except (requests.RequestException, ValueError, KeyError, AttributeError, TypeError) as exc:
            status = getattr(getattr(exc, "response", None), "status_code", "")
            log.warning("rdap lookup failed: %s %s", type(exc).__name__, status)
            failed.append(domain)
            continue
        if registered is None:
            continue
        days = (datetime.now(timezone.utc) - registered).days
        if days < 7:
            findings.append(Finding(
                analyzer=NAME, title="Brand-new domain",
                detail=f"{domain} was registered {days} day{'s' if days != 1 else ''} ago. "
                       "Phishing sites are usually only days old.",
                severity=Severity.HIGH, points=35))
        elif days < 30:
            findings.append(Finding(
                analyzer=NAME, title="Recently registered domain",
                detail=f"{domain} was registered {days} days ago.",
                severity=Severity.MEDIUM, points=20))
    if failed:
        findings.append(Finding(
            analyzer=NAME, title="Domain age check unavailable",
            detail=f"Could not look up when {', '.join(failed)} was registered.",
            severity=Severity.INFO, points=0))
    return findings
