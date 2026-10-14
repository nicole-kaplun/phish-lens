"""Turns findings into a 0-100 score and a verdict.

A transparent weighted sum is used instead of machine learning: there is
no labelled data to train on, and the user must be able to see exactly
why a message was flagged.
"""
from app.models import Finding, Severity

SUSPICIOUS_THRESHOLD = 30  # 0-29 Low risk, 30-59 Suspicious
MALICIOUS_THRESHOLD = 60   # 60-100 Malicious


def score(findings: list[Finding]) -> dict:
    """Sum the points, then let the most severe finding set a minimum verdict."""
    total = min(100, sum(f.points for f in findings))
    severities = {f.severity for f in findings}

    if Severity.CRITICAL in severities:
        # Some findings are near-certainty (a disguised .exe, a known malware hash):
        # they do not wait for other signals to add up.
        verdict = "malicious"
        total = max(total, MALICIOUS_THRESHOLD)
    elif total >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif total >= SUSPICIOUS_THRESHOLD or severities & {Severity.MEDIUM, Severity.HIGH}:
        # A single medium-or-higher finding is enough to ask the user to check.
        # Without this, an impersonation warning could appear on a "Low risk" card.
        verdict = "suspicious"
        total = max(total, SUSPICIOUS_THRESHOLD)
    else:
        verdict = "safe"  # shown to the user as "Low risk": no tool can promise safe

    # Most important reason first, so the card leads with it.
    ranked = sorted(findings, key=lambda f: f.points, reverse=True)
    return {"score": total, "verdict": verdict, "findings": ranked}
