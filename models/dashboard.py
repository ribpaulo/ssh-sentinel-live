"""API-Modelle für das read-only Live-Dashboard."""

from pydantic import BaseModel

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
    events: list[DashboardEvent]
