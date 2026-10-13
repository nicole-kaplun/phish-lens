from fastapi import FastAPI

from app.analyzers import attachments, authentication, links, sender
from app.models import EmailPayload
from app.scoring import score

app = FastAPI(title="PhishLens")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(email: EmailPayload):
    findings = (
        authentication.analyze(email)
        + sender.analyze(email)
        + links.analyze(email)
        + attachments.analyze(email)
    )
    return score(findings)