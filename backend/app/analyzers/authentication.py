"""Sender authentication: SPF, DKIM and DMARC.

Gmail records its own results in the Authentication-Results header.
Only the header written by Google is trusted, because an attacker
can add any header they like before sending.
"""
import re

from app.models import EmailPayload, Finding, Severity

NAME = "authentication"
TRUSTED_AUTHSERV_ID = "mx.google.com"

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

def _trusted_header(headers: list[str]) -> str | None:
    # Mail servers prepend their headers, so the topmost one was added by
    # the last hop (Google). Anything below it may have been forged.
    if not headers:
        return None
    topmost = headers[0]
    if topmost.strip().lower().startswith(TRUSTED_AUTHSERV_ID):
        return topmost
    return None

# (mechanism, result) -> (points, severity, explanation for the user)
_PENALTIES = {
    ("dmarc", "fail"): (35, Severity.HIGH,
        "DMARC failed: the sender's domain does not confirm this message came from them."),
    ("spf", "fail"): (20, Severity.MEDIUM,
        "SPF failed: the sending server is not authorized to send for this domain."),
    ("spf", "softfail"): (10, Severity.LOW,
        "SPF soft-failed: the sending server is probably not authorized for this domain."),
    ("dkim", "fail"): (15, Severity.MEDIUM,
        "DKIM failed: the signature is invalid, so the message may have been altered."),
}


def analyze(email: EmailPayload) -> list[Finding]:
    header = _trusted_header(email.authentication_results)
    if header is None:
        return [Finding(
            analyzer=NAME,
            title="No trusted authentication results",
            detail="Gmail's own SPF/DKIM/DMARC results were not found for this message.",
            severity=Severity.LOW,
            points=10,
        )]

    results = {mech.lower(): res.lower() for mech, res in _RESULT_RE.findall(header)}

    findings = []
    for mech, res in results.items():
        if (mech, res) in _PENALTIES:
            points, severity, detail = _PENALTIES[(mech, res)]
            findings.append(Finding(
                analyzer=NAME,
                title=f"{mech.upper()} {res}",
                detail=detail,
                severity=severity,
                points=points,
            ))
    return findings