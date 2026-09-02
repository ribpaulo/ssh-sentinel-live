"""Time-based detection rule for SSH brute-force activity."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from database import (
    AlertData,
    AlertMutation,
    AlertStatus,
    Database,
)
from models.analysis import EventType


class DetectionOutcome(str, Enum):
    NO_ALERT = "NO_ALERT"
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    ALREADY_PROCESSED = "ALREADY_PROCESSED"


@dataclass(frozen=True, slots=True)
class BruteForceDetectionResult:
    outcome: DetectionOutcome
    event_id: int | None
    alert_id: int | None = None
    event_count: int = 0


class SSHBruteForceDetector:
    RULE_ID = "SSH_BRUTE_FORCE"
    TITLE = "SSH brute-force activity detected"
    SEVERITY = "HIGH"
    SCORE = 70
    DEFAULT_THRESHOLD = 5
    DEFAULT_WINDOW_SECONDS = 60.0

    def __init__(
        self,
        database: Database,
        *,
        threshold: int = DEFAULT_THRESHOLD,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 2:
            raise ValueError("threshold must be an integer greater than or equal to 2")
        if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool):
            raise ValueError("window_seconds must be a positive finite number")
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be a positive finite number")

        self.database = database
        self.threshold = threshold
        self.window_seconds = float(window_seconds)

    @staticmethod
    def _event_timestamp(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("event_timestamp must include a timezone")
        return parsed.astimezone(timezone.utc)

    def evaluate(self, event_id: int) -> BruteForceDetectionResult:
        event = self.database.get_event(event_id)
        if event is None:
            raise LookupError(f"Event {event_id} does not exist")
        if event["event_type"] != EventType.FAILED_LOGIN.value:
            return BruteForceDetectionResult(DetectionOutcome.NO_ALERT, event_id)
        if not event["ip_address"] or not event["event_timestamp"]:
            return BruteForceDetectionResult(DetectionOutcome.NO_ALERT, event_id)

        event_timestamp = self._event_timestamp(event["event_timestamp"])
        earliest_timestamp = event_timestamp - timedelta(seconds=self.window_seconds)
        window_events = self.database.get_events_in_window(
            event_type=EventType.FAILED_LOGIN,
            ip_address=event["ip_address"],
            window_start=earliest_timestamp,
            window_end=event_timestamp,
        )
        if len(window_events) < self.threshold:
            return BruteForceDetectionResult(DetectionOutcome.NO_ALERT, event_id)

        timestamps = [self._event_timestamp(row["event_timestamp"]) for row in window_events]
        usernames = [row["username"] for row in window_events]
        username = (
            usernames[0]
            if usernames and all(item == usernames[0] for item in usernames)
            else None
        )
        window_label = f"{self.window_seconds:g}"
        alert = AlertData(
            rule_id=self.RULE_ID,
            title=self.TITLE,
            description=(
                f"At least {self.threshold} failed SSH login attempts from "
                f"{event['ip_address']} occurred within {window_label} seconds."
            ),
            severity=self.SEVERITY,
            score=self.SCORE,
            ip_address=event["ip_address"],
            username=username,
            event_count=len(window_events),
            window_start=min(timestamps),
            window_end=max(timestamps),
            status=AlertStatus.OPEN,
        )
        mutation = self.database.save_or_extend_active_alert(
            alert,
            (row["id"] for row in window_events),
            evaluated_event_id=event_id,
        )
        outcomes = {
            AlertMutation.CREATED: DetectionOutcome.CREATED,
            AlertMutation.UPDATED: DetectionOutcome.UPDATED,
            AlertMutation.ALREADY_PROCESSED: DetectionOutcome.ALREADY_PROCESSED,
        }
        return BruteForceDetectionResult(
            outcome=outcomes[mutation.action],
            event_id=event_id,
            alert_id=mutation.alert_id,
            event_count=mutation.event_count,
        )
