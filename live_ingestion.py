"""Überführt neue SSH-Logzeilen über den bestehenden Parser in SQLite."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from brute_force_detection import (
    BruteForceDetectionResult,
    DetectionOutcome,
    SSHBruteForceDetector,
)
from database import Database, EventData
from parser import parse_line


SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})$",
    re.IGNORECASE,
)
MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@dataclass(frozen=True, slots=True)
class LiveIngestionResult:
    event_id: int | None
    detection: BruteForceDetectionResult


def _as_local(value: datetime, local_timezone: tzinfo | None) -> datetime:
    if local_timezone is None:
        return value.astimezone()
    if value.tzinfo is None:
        return value.replace(tzinfo=local_timezone)
    return value.astimezone(local_timezone)


def _localize(value: datetime, local_timezone: tzinfo | None) -> datetime:
    if value.tzinfo is not None:
        return value
    if local_timezone is None:
        return value.astimezone()
    return value.replace(tzinfo=local_timezone)


def normalize_live_timestamp(
    value: str | None,
    *,
    reference_time: datetime | None = None,
    local_timezone: tzinfo | None = None,
) -> datetime | None:
    """Normalisiert Parser-Zeitstempel anhand eines Referenzzeitpunkts nach UTC."""

    if value is None:
        return None

    syslog_match = SYSLOG_TIMESTAMP.fullmatch(value)
    if syslog_match is None:
        iso_value = f"{value[:-1]}+00:00" if value.lower().endswith("z") else value
        try:
            parsed = datetime.fromisoformat(iso_value)
        except ValueError as exc:
            raise ValueError(f"Unsupported event timestamp: {value}") from exc
        return _localize(parsed, local_timezone).astimezone(timezone.utc)

    reference = reference_time or datetime.now(timezone.utc)
    local_reference = _as_local(reference, local_timezone)
    month = MONTHS[syslog_match.group("month").lower()]

    def build(year: int) -> datetime:
        naive = datetime(
            year,
            month,
            int(syslog_match.group("day")),
            int(syslog_match.group("hour")),
            int(syslog_match.group("minute")),
            int(syslog_match.group("second")),
        )
        return _localize(naive, local_timezone)

    event_time = build(local_reference.year)
    if event_time > local_reference + timedelta(days=1):
        event_time = build(local_reference.year - 1)
    return event_time.astimezone(timezone.utc)


class LiveIngestionService:
    """Parst einzelne Live-Zeilen und speichert unterstützte SSH-Ereignisse."""

    def __init__(
        self,
        database: Database,
        source: str | Path,
        *,
        local_timezone: tzinfo | None = None,
        now: Callable[[], datetime] | None = None,
        detector: SSHBruteForceDetector | None = None,
    ) -> None:
        self.database = database
        self.source = str(Path(source))
        self.local_timezone = local_timezone
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._line_number = 0
        self.detector = detector or SSHBruteForceDetector(database)

    def ingest_line(self, line: str) -> int | None:
        """Speichert eine unterstützte Zeile und liefert deren Datenbank-ID."""

        return self.ingest_line_with_detection(line).event_id

    def ingest_line_with_detection(self, line: str) -> LiveIngestionResult:
        """Speichert eine Zeile und wertet das neue Event anschliessend aus."""

        self._line_number += 1
        event = parse_line(line, self._line_number)
        if event is None:
            return LiveIngestionResult(
                event_id=None,
                detection=BruteForceDetectionResult(DetectionOutcome.NO_ALERT, None),
            )

        timestamp = normalize_live_timestamp(
            event.timestamp,
            reference_time=self._now(),
            local_timezone=self.local_timezone,
        )
        event_id = self.database.save_event(
            EventData(
                event_timestamp=timestamp,
                hostname=event.hostname,
                event_type=event.event_type,
                ip_address=event.ip_address,
                username=event.username,
                auth_method=event.authentication_method,
                raw_line=event.raw_line,
                source=self.source,
            )
        )
        return LiveIngestionResult(
            event_id=event_id,
            detection=self.detector.evaluate(event_id),
        )
