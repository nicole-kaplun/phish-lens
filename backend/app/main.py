import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi import Depends, FastAPI

from app.analyzers import (
    attachments, authentication, content, domain_age, links, reply_to, reputation, sender,
)
from app.auth import DEV_MODE, require_user
from app.models import EmailPayload, Finding, Severity
from app.scoring import score

# The interactive docs describe the API to anyone who finds the URL,
# so they exist only in local development.
app = FastAPI(
    title="PhishLens",
    docs_url="/docs" if DEV_MODE else None,
    redoc_url=None,
    openapi_url="/openapi.json" if DEV_MODE else None,
)

# Each analyzer takes the email and returns a list of findings.
ANALYZERS = [authentication, sender, reply_to, links, attachments, reputation, domain_age, content]

log = logging.getLogger("phishlens")


def _run(analyzer, email: EmailPayload) -> list[Finding]:
    """Run one check. A bug in one check must not hide the results of the others."""
    try:
        return analyzer.analyze(email)
    except Exception as exc:  # deliberately broad: this is the last line of defence
        # Only the check name and error type: exception messages can contain email data.
        log.error("analyzer %s crashed: %s", analyzer.NAME, type(exc).__name__)
        label = analyzer.NAME.replace("_", " ").capitalize()
        return [Finding(analyzer=analyzer.NAME, title=f"{label} check unavailable",
                        detail="An internal error stopped this check, so the result may be incomplete.",
                        severity=Severity.INFO, points=0)]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(email: EmailPayload, user: str = Depends(require_user)):
    # Three analyzers wait on outside services (VirusTotal, RDAP, Gemini).
    # Running all of them at once makes the card as slow as the slowest
    # check instead of the sum of all of them.
    with ThreadPoolExecutor(max_workers=len(ANALYZERS)) as pool:
        results = list(pool.map(lambda analyzer: _run(analyzer, email), ANALYZERS))
    findings = [finding for result in results for finding in result]

    result = score(findings)
    result["link_xray"] = links.xray(email)
    return result