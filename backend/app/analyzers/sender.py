"""Sender impersonation.

Most users see only the display name ("PayPal Security"), not the real
address behind it. Attackers either put a trusted brand in the display name
while sending from their own domain, or register a domain that looks like
the brand (paypa1.com). Both pass SPF/DKIM/DMARC for the attacker's domain.
"""
import re
from email.utils import parseaddr

from app.brands import BRANDS, belongs_to, lookalike_brand, normalize
from app.models import EmailPayload, Finding, Severity

NAME = "sender"

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_ANGLE_ADDR = re.compile(r"\s*(.*?)\s*<([^<>]+)>\s*")


def _split_from(header: str) -> tuple[str, str, bool]:
    """Returns (display_name, address, malformed)."""
    name, address = parseaddr(header)
    if "@" in address:
        return name, address, False
    # Python's strict parser rejects ambiguous headers such as an unquoted
    # "@" in the display name. Attackers use exactly those, so instead of
    # skipping the check we fall back to a simple split and flag it.
    match = _ANGLE_ADDR.fullmatch(header)
    if match:
        return match.group(1).strip('"').strip(), match.group(2).strip(), True
    return "", "", True


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _short(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def analyze(email: EmailPayload) -> list[Finding]:
    display_name, address, malformed = _split_from(email.from_header)
    domain = _domain_of(address)

    findings = []
    if malformed:
        findings.append(Finding(
            analyzer=NAME,
            title="Malformed sender header",
            detail="The From header does not follow the email standard. "
                   "Attackers do this to confuse mail clients and filters.",
            severity=Severity.LOW,
            points=10,
        ))
    if not domain:
        return findings

    imitated = lookalike_brand(domain)
    if imitated:
        findings.append(Finding(
            analyzer=NAME,
            title=f"Sender domain imitates {imitated.title()}",
            detail=f"The message comes from {domain}, which looks like "
                   f"{imitated.title()} but is not one of its real domains.",
            severity=Severity.HIGH,
            points=40,
        ))

    if not display_name:
        return findings

    skeleton = normalize(display_name)
    for brand, domains in BRANDS.items():
        pattern = rf"\b{re.escape(normalize(brand))}\b"
        if re.search(pattern, skeleton) and not belongs_to(domain, domains):
            findings.append(Finding(
                analyzer=NAME,
                title=f"Display name impersonates {brand.title()}",
                detail=f'The sender calls itself "{_short(display_name)}" but the message '
                       f"comes from {domain}, which does not belong to {brand.title()}.",
                severity=Severity.MEDIUM,
                points=25,
            ))
            break

    fake = _EMAIL_IN_NAME.search(display_name)
    if fake and fake.group(1).lower() != domain:
        findings.append(Finding(
            analyzer=NAME,
            title="Fake address in display name",
            detail=f"The display name shows {_short(fake.group(0))}, "
                   f"but the real sender is {_short(address)}.",
            severity=Severity.HIGH,
            points=30,
        ))
    return findings