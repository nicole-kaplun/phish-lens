from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Link(BaseModel):
    model_config = ConfigDict(extra="forbid")

    href: str = Field(max_length=2_048)
    text: str = Field(default="", max_length=500)


class EmailPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_header: str = Field(max_length=4_000)
    subject: str = Field(default="", max_length=4_000)
    body_text: str = Field(default="", max_length=50_000)
    authentication_results: list[str] = Field(default_factory=list, max_length=10)
    links: list[Link] = Field(default_factory=list, max_length=100)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    analyzer: str
    title: str
    detail: str
    severity: Severity
    points: int