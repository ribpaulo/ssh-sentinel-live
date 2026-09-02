"""API-Modelle für das Live-Dashboard und die Alarmverwaltung."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from database import AlertStatus
from models.analysis import EventType


class DashboardEvent(BaseModel):
    id: int
    event_timestamp: str | None
    hostname: str | None
    event_type: EventType
    ip_address: str
    username: str | None
    auth_method: str | None
    source: str


class DashboardAlert(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: str
    score: int
    ip_address: str | None
    username: str | None
    event_count: int
    window_start: str
    window_end: str
    status: AlertStatus
    created_at: str
    updated_at: str


class DashboardAlertDetail(DashboardAlert):
    description: str
    note: str | None
    events: list[DashboardEvent]


class DashboardAlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("note")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None
