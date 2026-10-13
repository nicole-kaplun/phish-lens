from concurrent.futures import ThreadPoolExecutor

from fastapi import Depends, FastAPI

from app.analyzers import (
    attachments, authentication, content, domain_age, links, reply_to, reputation, sender,
)
from app.auth import DEV_MODE, require_user
from app.models import EmailPayload
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(email: EmailPayload, user: str = Depends(require_user)):
    # Three analyzers wait on outside services (VirusTotal, RDAP, Gemini).
    # Running all of them at once makes the card as slow as the slowest
    # check instead of the sum of all of them.
    with ThreadPoolExecutor(max_workers=len(ANALYZERS)) as pool:
        results = list(pool.map(lambda analyzer: analyzer.analyze(email), ANALYZERS))
    findings = [finding for result in results for finding in result]

    result = score(findings)
    result["link_xray"] = links.xray(email)
    return result