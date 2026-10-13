"""Sender authentication: SPF, DKIM and DMARC.

Gmail records its own results in the Authentication-Results header.
Only the header written by Google is trusted, because an attacker
can add any header they like before sending. The header is parsed by
its structure (authserv-id, then one result per ";"-separated part, with
parenthesised comments removed), never by searching for words in it.
"""
import re

from app.models import EmailPayload, Finding, Severity

NAME = "authentication"
TRUSTED_AUTHSERV_ID = "mx.google.com"

_COMMENT = re.compile(r"\([^()]*\)")
_RESULT = re.compile(r"\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# (mechanism, result) -> (points, severity, explanation for the user)
_PENALTIES = {
    ("dmarc", "fail"): (35, Severity.HIGH,
        "DMARC failed: the sender's domain does not confirm this message came from them."),
    ("spf", "fail"): (20, Severity.LOW,
        "SPF failed: the sending server is not authorized to send for this domain."),
    ("spf", "softfail"): (10, Severity.LOW,
        "SPF soft-failed: the sending server is probably not authorized for this domain."),
    ("dkim", "fail"): (15, Severity.LOW,
        "DKIM failed: the signature is invalid, so the message may have been altered."),
}


def _strip_comments(header: str) -> str:
    previous = None
    while previous != header:  # nested comments: remove innermost first
        previous, header = header, _COMMENT.sub(" ", header)
    return header


def parse_results(headers: list[str]) -> dict[str, str] | None:
    """Google's verdict per mechanism, or None if the topmost header is not Google's.

    Mail servers prepend headers, so only the topmost one was written by the
    last hop. Its authserv-id must be exactly mx.google.com, not merely start
    with it (mx.google.com.evil.example is someone else's server).
    """
    if not headers:
        return None
    parts = _strip_comments(headers[0]).split(";")
    if parts[0].strip().lower().split(" ")[0] != TRUSTED_AUTHSERV_ID:
        return None

    seen: dict[str, set[str]] = {}
    for part in parts[1:]:
        match = _RESULT.match(part)
        if match:
            seen.setdefault(match.group(1).lower(), set()).add(match.group(2).lower())

    outcome = {}
    for mech, values in seen.items():
        if mech == "dkim" and "pass" in values:
            outcome[mech] = "pass"  # several signatures are normal; one valid one is enough
        elif values == {"pass"}:
            outcome[mech] = "pass"
        else:  # conflicting or failing results: take the worst, never the best
            outcome[mech] = "fail" if "fail" in values else sorted(values - {"pass"})[0]
    return outcome


def dmarc_passed(email: EmailPayload) -> bool:
    """True only if Google's own header says DMARC passed, and nothing else."""
    results = parse_results(email.authentication_results)
    return bool(results) and results.get("dmarc") == "pass"


def analyze(email: EmailPayload) -> list[Finding]:
    results = parse_results(email.authentication_results)

    findings = []
    for mech, res in (results or {}).items():
        if (mech, res) in _PENALTIES:
            points, severity, detail = _PENALTIES[(mech, res)]
            findings.append(Finding(
                analyzer=NAME,
                title=f"{mech.upper()} {res}",
                detail=detail,
                severity=severity,
                points=points,
            ))

    # "Nothing failed" is not the same as "something passed". If no check
    # passed and none failed (no header from Google, "mx.google.com; none",
    # or only "none" results), the sender was never verified, so say so.
    if not findings and "pass" not in (results or {}).values():
        if results is None:
            detail = ("Gmail recorded no SPF/DKIM/DMARC results, so the sender could not be verified. "
                      "This is normal for messages sent within Gmail.")
        else:
            detail = "Gmail checked this message but no SPF, DKIM or DMARC check passed, so the sender is not verified."
        findings.append(Finding(
            analyzer=NAME,
            title="Authentication results unavailable",
            detail=detail,
            severity=Severity.INFO,
            points=0,
        ))
    return findings