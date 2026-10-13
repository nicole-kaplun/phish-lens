"""Who is allowed to call the backend.

The add-on sends a Google-signed ID token (ScriptApp.getIdentityToken()).
We check Google's signature, that the token was issued to *our* add-on
(the audience), and that the user is on the allow-list. Nothing secret is
stored in the add-on, so there is nothing to leak from the public repo.
"""
import os

from fastapi import Header, HTTPException, status
from google.auth.exceptions import TransportError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

# Local development only: skips token checks and enables /docs.
# Never set on Cloud Run, so the deployed service is locked by default.
DEV_MODE = os.environ.get("PHISHLENS_DEV") == "1"

_google_request = google_requests.Request()


def _allowed_emails() -> set[str]:
    raw = os.environ.get("ALLOWED_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def require_user(authorization: str = Header(default="")) -> str:
    if DEV_MODE:
        return "dev@localhost"

    audience = os.environ.get("OAUTH_CLIENT_ID")
    allowed = _allowed_emails()
    if not audience or not allowed:
        # Misconfigured server: refuse everyone rather than accept everyone.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Server auth is not configured")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")

    try:
        claims = id_token.verify_oauth2_token(token, _google_request, audience=audience)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from None
    except TransportError:
        # Could not fetch Google's signing keys, so we cannot verify anyone.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Cannot verify token right now") from None

    email = str(claims.get("email", "")).lower()
    if not claims.get("email_verified") or email not in allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User not allowed")
    return email