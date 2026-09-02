"""Pydantic models for parser, detector, and API results."""

from enum import Enum

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Supported SSH authentication event types."""

    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"


class SSHEvent(BaseModel):
    """An SSH event extracted from a log line."""

    line_number: int
    raw_line: str
    timestamp: str | None = None
    hostname: str | None = None
    event_type: EventType
    ip_address: str
    username: str | None = None
    authentication_method: str | None = None


class DetectionFinding(BaseModel):
    """A single finding triggered by a rule."""

    rule_id: str
    title: str
    description: str
    severity: str
    points: int = Field(ge=0)
    line_numbers: list[int] = Field(default_factory=list)
    ip_address: str | None = None
    username: str | None = None


class EntitySummary(BaseModel):
    """Summary of activity for an IP address or username."""

    value: str
    attempts: int
    failed_attempts: int
    successful_attempts: int
    reasons: list[str] = Field(default_factory=list)


class MarkedLogLine(BaseModel):
    """Original line with the reasons why it was marked."""

    line_number: int
    content: str
    reasons: list[str]


class RiskBreakdown(BaseModel):
    """Point contribution for one triggered detection rule."""

    rule_id: str
    label: str
    points: int


class AnalysisResult(BaseModel):
    """Complete result of a log file analysis."""

    filename: str
    total_lines: int
    parsed_events: int
    failed_logins: int
    successful_logins: int
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    alert: bool
    suspicious_ips: list[EntitySummary] = Field(default_factory=list)
    suspicious_users: list[EntitySummary] = Field(default_factory=list)
    findings: list[DetectionFinding] = Field(default_factory=list)
    score_breakdown: list[RiskBreakdown] = Field(default_factory=list)
    marked_lines: list[MarkedLogLine] = Field(default_factory=list)
