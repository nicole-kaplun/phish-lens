from fastapi import Depends, FastAPI

from app.analyzers import attachments, authentication, links, sender
from app.auth import DEV_MODE, require_user
from app.models import EmailPayload
from app.scoring import score
from app.analyzers import attachments, authentication, links, reputation, sender

# The interactive docs describe the API to anyone who finds the URL,
# so they exist only in local development.
app = FastAPI(
    title="PhishLens",
    docs_url="/docs" if DEV_MODE else None,
    redoc_url=None,
    openapi_url="/openapi.json" if DEV_MODE else None,
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(email: EmailPayload, user: str = Depends(require_user)):
    findings = (
        authentication.analyze(email)
        + sender.analyze(email)
        + links.analyze(email)
        + attachments.analyze(email)
        + reputation.analyze(email)
    )
    return score(findings)