"""SQLite-Persistenz für SSH-Ereignisse und Alarme."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from models.analysis import EventType


DEFAULT_DATABASE_PATH = Path("data/ssh_sentinel.db")


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class EventData:
    event_timestamp: datetime | str | None
    hostname: str | None
    event_type: EventType | str
    ip_address: str
    username: str | None
    auth_method: str | None
    raw_line: str
    source: str


@dataclass(frozen=True, slots=True)
class AlertData:
    rule_id: str
    title: str
    description: str
    severity: str
    score: int
    ip_address: str | None
    username: str | None
    event_count: int
    window_start: datetime | str
    window_end: datetime | str
    status: AlertStatus | str = AlertStatus.OPEN
    note: str | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    event_timestamp TEXT,
    hostname TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    username TEXT,
    auth_method TEXT,
    raw_line TEXT NOT NULL,
    source TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0),
    ip_address TEXT,
    username TEXT,
    event_count INTEGER NOT NULL CHECK (event_count >= 0),
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('OPEN', 'ACKNOWLEDGED', 'FALSE_POSITIVE', 'CLOSED')
    ),
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_event_timestamp
    ON events(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip_address
    ON events(ip_address);
CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_address
    ON alerts(ip_address);
CREATE INDEX IF NOT EXISTS idx_alert_events_event_id
    ON alert_events(event_id);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso8601(value: datetime | str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a datetime, ISO-8601 string, or None")

    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    return parsed.isoformat()


def _event_type_value(event_type: EventType | str) -> str:
    if isinstance(event_type, EventType):
        return event_type.value
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("event_type must not be empty")
    return event_type


def _status_value(status: AlertStatus | str) -> str:
    try:
        return AlertStatus(status).value
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in AlertStatus)
        raise ValueError(f"Invalid alert status. Allowed values: {allowed}") from exc


def _limit_value(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    return limit


class Database:
    """Database access without retaining a global SQLite connection."""

    def __init__(self, path: str | Path = DEFAULT_DATABASE_PATH) -> None:
        self.path = Path(path)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create tables and indexes when they do not yet exist."""

        with self._connection() as connection:
            connection.executescript(f"BEGIN;\n{SCHEMA}\nCOMMIT;")

    @staticmethod
    def _event_values(event: EventData, ingested_at: str) -> tuple[object, ...]:
        return (
            _iso8601(event.event_timestamp, "event_timestamp"),
            event.hostname,
            _event_type_value(event.event_type),
            event.ip_address,
            event.username,
            event.auth_method,
            event.raw_line,
            event.source,
            ingested_at,
        )

    def save_event(self, event: EventData) -> int:
        ingested_at = _utc_now()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    event_timestamp, hostname, event_type, ip_address, username,
                    auth_method, raw_line, source, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._event_values(event, ingested_at),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an event ID")
            return cursor.lastrowid

    def save_events(self, events: Iterable[EventData]) -> int:
        event_list = list(events)
        if not event_list:
            return 0

        ingested_at = _utc_now()
        values = [self._event_values(event, ingested_at) for event in event_list]
        with self._connection() as connection:
            connection.executemany(
                """
                INSERT INTO events (
                    event_timestamp, hostname, event_type, ip_address, username,
                    auth_method, raw_line, source, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        return len(event_list)

    def get_event(self, event_id: int) -> sqlite3.Row | None:
        with self._connection() as connection:
            return connection.execute(
                "SELECT * FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()

    def get_recent_events(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._connection() as connection:
            return connection.execute(
                """
                SELECT * FROM events
                ORDER BY event_timestamp DESC, id DESC
                LIMIT ?
                """,
                (_limit_value(limit),),
            ).fetchall()

    @staticmethod
    def _alert_values(alert: AlertData, now: str) -> tuple[object, ...]:
        return (
            alert.rule_id,
            alert.title,
            alert.description,
            alert.severity,
            alert.score,
            alert.ip_address,
            alert.username,
            alert.event_count,
            _iso8601(alert.window_start, "window_start"),
            _iso8601(alert.window_end, "window_end"),
            _status_value(alert.status),
            alert.note,
            now,
            now,
        )

    @staticmethod
    def _link_events(
        connection: sqlite3.Connection,
        alert_id: int,
        event_ids: Iterable[int],
    ) -> None:
        unique_event_ids = list(dict.fromkeys(event_ids))
        connection.executemany(
            "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
            ((alert_id, event_id) for event_id in unique_event_ids),
        )

    def save_alert(self, alert: AlertData, event_ids: Iterable[int] = ()) -> int:
        now = _utc_now()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO alerts (
                    rule_id, title, description, severity, score, ip_address,
                    username, event_count, window_start, window_end, status,
                    note, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._alert_values(alert, now),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an alert ID")
            alert_id = cursor.lastrowid
            self._link_events(connection, alert_id, event_ids)
            return alert_id

    def link_alert_events(self, alert_id: int, event_ids: Iterable[int]) -> None:
        with self._connection() as connection:
            self._link_events(connection, alert_id, event_ids)

    def get_alert_with_events(self, alert_id: int) -> dict[str, Any] | None:
        with self._connection() as connection:
            alert = connection.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()
            if alert is None:
                return None

            events = connection.execute(
                """
                SELECT events.*
                FROM events
                JOIN alert_events ON alert_events.event_id = events.id
                WHERE alert_events.alert_id = ?
                ORDER BY events.event_timestamp, events.id
                """,
                (alert_id,),
            ).fetchall()
            return {**dict(alert), "events": events}

    def get_alerts(
        self,
        status: AlertStatus | str,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        with self._connection() as connection:
            return connection.execute(
                """
                SELECT * FROM alerts
                WHERE status = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (_status_value(status), _limit_value(limit)),
            ).fetchall()

    def update_alert_status(
        self,
        alert_id: int,
        status: AlertStatus | str,
        note: str | None = None,
    ) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE alerts
                SET status = ?, note = ?, updated_at = ?
                WHERE id = ?
                """,
                (_status_value(status), note, _utc_now(), alert_id),
            )
            if cursor.rowcount != 1:
                raise LookupError(f"Alert {alert_id} does not exist")
