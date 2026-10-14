"""The PhishLens API: one endpoint that turns an email into a verdict.

POST /analyze -> verify the caller (auth.py) -> validate the input (models.py)
-> run every analyzer in parallel -> combine the findings (scoring.py).
"""
import logging
from concurrent.futures import ThreadPoolExecutor, wait

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

# The add-on gives up after about 30 seconds, so the whole analysis gets a
# fixed time budget. A check that is still waiting on a slow outside service
# when time runs out is reported as unavailable instead of holding the card.
DEADLINE_SECONDS = 20


def _unavailable(analyzer, detail: str) -> Finding:
    label = analyzer.NAME.replace("_", " ").capitalize()
    return Finding(analyzer=analyzer.NAME, title=f"{label} check unavailable",
                   detail=detail, severity=Severity.INFO, points=0)


def _run(analyzer, email: EmailPayload) -> list[Finding]:
    """Run one check. A bug in one check must not hide the results of the others."""
    try:
        return analyzer.analyze(email)
    except Exception as exc:  # deliberately broad: this is the last line of defence
        # Only the check name and error type: exception messages can contain email data.
        log.error("analyzer %s crashed: %s", analyzer.NAME, type(exc).__name__)
        return [_unavailable(analyzer, "An internal error stopped this check, so the result may be incomplete.")]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(email: EmailPayload, user: str = Depends(require_user)):
    # Three analyzers wait on outside services (VirusTotal, RDAP, Gemini).
    # Running all of them at once makes the card as slow as the slowest
    # check instead of the sum of all of them, and the deadline caps even that.
    pool = ThreadPoolExecutor(max_workers=len(ANALYZERS))
    futures = [pool.submit(_run, analyzer, email) for analyzer in ANALYZERS]
    done, _ = wait(futures, timeout=DEADLINE_SECONDS)
    # Don't wait for late checks. They stop on their own request timeouts.
    pool.shutdown(wait=False, cancel_futures=True)

    findings = []
    for analyzer, future in zip(ANALYZERS, futures):
        if future in done:
            findings.extend(future.result())
        else:
            log.warning("analyzer %s missed the deadline", analyzer.NAME)
            findings.append(_unavailable(analyzer, "This check took too long, so the result may be incomplete."))

    result = score(findings)
    result["link_xray"] = links.xray(email)
    return result
