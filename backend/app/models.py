"""The shape of the data that crosses the trust boundary.

Everything the add-on sends is written by an unknown email sender, so the
backend accepts only these fields, with a length limit on every string and
list. Pydantic checks all of it before any analyzer runs; anything else is
rejected with 422. extra="forbid" rejects fields we did not define.
"""
import html
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Link(BaseModel):
    """A link as it appears in the email's HTML, entities still encoded.

    Browsers decode every HTML entity before following a link, so
    "paypa1&period;com" opens paypa1.com. Decoding happens here, once, with
    Python's full HTML5 entity table, so every check sees what a browser would.
    """
    model_config = ConfigDict(extra="forbid")
    href: str = Field(max_length=2_048)  # where a click really goes
    text: str = Field(default="", max_length=500)  # what the user sees

    @field_validator("href", "text")
    @classmethod
    def _decode_entities(cls, value: str) -> str:
        return html.unescape(value)


class Attachment(BaseModel):
    """File metadata only. The contents never leave Gmail."""
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(max_length=255)
    content_type: str = Field(default="", max_length=255)  # declared by the sender, not verified
    size: int = Field(default=0, ge=0)
    # 64 lowercase hex characters, or empty when the file was too large to hash.
    sha256: str = Field(default="", pattern=r"^([a-f0-9]{64})?$")


class EmailPayload(BaseModel):
    """What the add-on extracts from one opened message."""
    model_config = ConfigDict(extra="forbid")
    from_header: str = Field(max_length=4_000)
    reply_to: str = Field(default="", max_length=4_000)
    subject: str = Field(default="", max_length=4_000)
    # The add-on sends at most the first 1,500 characters; the limit here is a ceiling.
    body_text: str = Field(default="", max_length=50_000)
    # Raw Authentication-Results headers, topmost first. Only Google's is trusted.
    authentication_results: list[str] = Field(default_factory=list, max_length=10)
    links: list[Link] = Field(default_factory=list, max_length=100)
    attachments: list[Attachment] = Field(default_factory=list, max_length=20)


class Severity(str, Enum):
    """How serious one finding is. It sets a floor on the verdict (see scoring.py)."""
    INFO = "info"          # a note, e.g. a check that could not run; never adds points
    LOW = "low"            # often harmless on its own; matters only when signals add up
    MEDIUM = "medium"      # enough on its own to ask the user to check
    HIGH = "high"          # a strong sign of phishing
    CRITICAL = "critical"  # near-certain: the message is malicious whatever the score


class Finding(BaseModel):
    """One reason shown on the card. Every point of the score comes from one of these."""
    analyzer: str   # which check produced it
    title: str      # one line, shown in bold
    detail: str     # the evidence, in words the user can act on
    severity: Severity
    points: int     # added to the 0-100 risk score
