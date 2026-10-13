"""Display-name impersonation.

Most users see only the display name ("PayPal Security"), not the real
address behind it. Attackers put a trusted brand in the display name while
sending from their own domain, which passes SPF/DKIM/DMARC for that domain.
"""
import re
import unicodedata
from email.utils import parseaddr

from app.models import EmailPayload, Finding, Severity

NAME = "sender"

# Characters that look like Latin letters. Attackers use them so that a
# naive search for "paypal" misses "pаypal" (Cyrillic а) or "PayPaI" (capital I).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "0": "o", "1": "l", "|": "l", "i": "l",
})
_INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")
_SPACED_LETTERS = re.compile(r"\b(?:\w[ .\-_]){2,}\w\b")

# Brand keyword -> domains that legitimately send mail as that brand.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "apple": ["apple.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com"],
    "leumi": ["leumi.co.il"],
    "hapoalim": ["bankhapoalim.co.il"],
}

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_ANGLE_ADDR = re.compile(r"\s*(.*?)\s*<([^<>]+)>\s*")


def normalize(text: str) -> str:
    """Reduce text to a 'skeleton' so look-alike spellings compare equal."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.lower()
    text = _SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_]", "", m.group()), text)
    return text.translate(_CONFUSABLES)


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


def _belongs_to(domain: str, allowed: list[str]) -> bool:
    # "mail.paypal.com" belongs to paypal.com; "paypal.com.evil.com" does not.
    return any(domain == d or domain.endswith("." + d) for d in allowed)


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
    if not display_name or not domain:
        return findings

    skeleton = normalize(display_name)

    for brand, domains in BRANDS.items():
        pattern = rf"\b{re.escape(normalize(brand))}\b"
        if re.search(pattern, skeleton) and not _belongs_to(domain, domains):
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