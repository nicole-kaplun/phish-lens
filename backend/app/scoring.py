"""Turns findings into a 0-100 score and a verdict.

A transparent weighted sum is used instead of machine learning: there is
no labelled data to train on, and the user must be able to see exactly
why a message was flagged.
"""
from app.models import Finding, Severity

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 60


def score(findings: list[Finding]) -> dict:
    total = min(100, sum(f.points for f in findings))

    if any(f.severity == Severity.CRITICAL for f in findings):
        verdict = "malicious"
        total = max(total, MALICIOUS_THRESHOLD)
    elif total >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif total >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "safe"

    ranked = sorted(findings, key=lambda f: f.points, reverse=True)
    return {"score": total, "verdict": verdict, "findings": ranked}