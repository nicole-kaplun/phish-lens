"""File reputation via VirusTotal, using the SHA-256 hash only.

We ask "has anyone seen this exact file before, and was it malicious?"
without uploading the file. The API key is read from the environment and
never logged. VirusTotal's response is external input, so it is parsed
defensively, and any failure degrades to "check unavailable", never "safe".
"""
import logging
import os

import requests

from app.models import EmailPayload, Finding, Severity

NAME = "reputation"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
TIMEOUT_SECONDS = 5
MAX_LOOKUPS = 4  # free API tier allows 4 requests per minute

log = logging.getLogger(__name__)


def _engine_counts(body: object) -> tuple[int, int]:
    """Return (malicious, total) engine counts from a VirusTotal file report."""
    stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})  # type: ignore[union-attr]
    malicious = int(stats.get("malicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    if not 0 <= malicious <= total <= 1000:
        raise ValueError("implausible engine counts")
    return malicious, total


def _unavailable(reason: str) -> Finding:
    return Finding(analyzer=NAME, title="File reputation check unavailable",
                   detail=reason, severity=Severity.INFO, points=0)


def analyze(email: EmailPayload) -> list[Finding]:
    hashed = [a for a in email.attachments if a.sha256][:MAX_LOOKUPS]
    if not hashed:
        return []

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return [_unavailable("Reputation lookups are not configured on this server.")]

    findings = []
    for att in hashed:
        try:
            resp = requests.get(VT_URL.format(att.sha256), headers={"x-apikey": api_key},
                                timeout=TIMEOUT_SECONDS)
            if resp.status_code == 404:
                continue  # never seen before: no evidence either way
            resp.raise_for_status()
            malicious, total = _engine_counts(resp.json())
        except (requests.RequestException, ValueError, AttributeError, TypeError) as exc:
            # Log the kind of failure only: never the key, never the file name.
            log.warning("virustotal lookup failed: %s", type(exc).__name__)
            findings.append(_unavailable("Could not reach the reputation service for one attachment."))
            continue

        name = att.filename[:80]
        if malicious >= 3:
            findings.append(Finding(
                analyzer=NAME, title="Known malicious attachment",
                detail=f'"{name}" is flagged as malicious by {malicious} of {total} antivirus engines.',
                severity=Severity.CRITICAL, points=60))
        elif malicious >= 1:
            findings.append(Finding(
                analyzer=NAME, title="Attachment flagged by some antivirus engines",
                detail=f'"{name}" is flagged by {malicious} of {total} antivirus engines.',
                severity=Severity.MEDIUM, points=25))
    return findings