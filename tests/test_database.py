import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from database import (
    AlertData,
    AlertMutation,
    AlertStatus,
    Database,
    EventData,
)
from models.analysis import EventType


@pytest.fixture
def database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "nested" / "ssh_sentinel.db")
    database.initialize()
    return database


def event_data(
    timestamp: str = "2026-08-25T10:00:00+00:00",
    ip_address: str = "203.0.113.10",
) -> EventData:
    return EventData(
        event_timestamp=timestamp,
        hostname="server-01",
        event_type=EventType.FAILED_LOGIN,
        ip_address=ip_address,
        username="root",
        auth_method="password",
        raw_line=f"Failed password for root from {ip_address}",
        source="test/auth.log",
    )


def alert_data(status: AlertStatus | str = AlertStatus.OPEN) -> AlertData:
    return AlertData(
        rule_id="FAILED_LOGINS_BY_IP",
        title="Repeated failed logins",
        description="Several failed SSH logins in a short period.",
        severity="high",
        score=35,
        ip_address="203.0.113.10",
        username="root",
        event_count=2,
        window_start="2026-08-25T10:00:00Z",
        window_end="2026-08-25T10:05:00Z",
        status=status,
    )


def test_initialize_creates_parent_directory_tables_and_indexes(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "data" / "ssh_sentinel.db"
    database = Database(path)

    database.initialize()

    assert path.is_file()
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
    assert {"events", "alerts", "alert_events"} <= tables
    assert {
        "idx_events_event_timestamp",
        "idx_events_timestamp_jd",
        "idx_events_ip_address",
        "idx_events_type_ip_timestamp_jd",
        "idx_alerts_status",
        "idx_alerts_rule_ip_status_window_jd",
    } <= indexes


def test_save_and_load_event(database: Database) -> None:
    event_id = database.save_event(event_data())

    stored = database.get_event(event_id)

    assert isinstance(stored, sqlite3.Row)
    assert stored["id"] == event_id
    assert stored["event_timestamp"] == "2026-08-25T10:00:00+00:00"
    assert stored["event_type"] == "failed_login"
    assert stored["auth_method"] == "password"
    assert stored["source"] == "test/auth.log"
    ingested_at = datetime.fromisoformat(stored["ingested_at"])
    assert ingested_at.tzinfo == timezone.utc


def test_save_multiple_events_and_load_recent_with_limit(database: Database) -> None:
    events = [
        event_data("2026-08-25T10:00:00Z", "203.0.113.10"),
        event_data("2026-08-25T10:01:00Z", "203.0.113.11"),
        event_data("2026-08-25T10:02:00Z", "203.0.113.12"),
    ]

    inserted = database.save_events(events)
    recent = database.get_recent_events(limit=2)

    assert inserted == 3
    assert [row["ip_address"] for row in recent] == [
        "203.0.113.12",
        "203.0.113.11",
    ]


def test_save_alert_with_linked_events(database: Database) -> None:
    event_ids = database.save_event(event_data()), database.save_event(
        event_data("2026-08-25T10:01:00Z")
    )

    alert_id = database.save_alert(alert_data(), event_ids)
    stored = database.get_alert_with_events(alert_id)

    assert stored is not None
    assert stored["status"] == AlertStatus.OPEN.value
    assert stored["event_count"] == 2
    assert [event["id"] for event in stored["events"]] == list(event_ids)
    assert datetime.fromisoformat(stored["created_at"]).tzinfo == timezone.utc
    assert stored["created_at"] == stored["updated_at"]


def test_link_events_to_existing_alert(database: Database) -> None:
    first_event_id = database.save_event(event_data())
    second_event_id = database.save_event(event_data("2026-08-25T10:01:00Z"))
    alert_id = database.save_alert(alert_data(), [first_event_id])

    database.link_alert_events(alert_id, [second_event_id])

    stored = database.get_alert_with_events(alert_id)
    assert stored is not None
    assert [event["id"] for event in stored["events"]] == [
        first_event_id,
        second_event_id,
    ]


def test_filter_alerts_by_status_and_limit(database: Database) -> None:
    database.save_alert(alert_data(AlertStatus.OPEN))
    database.save_alert(alert_data(AlertStatus.CLOSED))
    newest_open_id = database.save_alert(alert_data(AlertStatus.OPEN))

    open_alerts = database.get_alerts(AlertStatus.OPEN, limit=1)
    closed_alerts = database.get_alerts("CLOSED")

    assert [row["id"] for row in open_alerts] == [newest_open_id]
    assert len(closed_alerts) == 1
    assert closed_alerts[0]["status"] == "CLOSED"


def test_update_alert_status_and_note(database: Database) -> None:
    alert_id = database.save_alert(alert_data())

    database.update_alert_status(
        alert_id,
        AlertStatus.ACKNOWLEDGED,
        note="Checked by analyst",
    )

    stored = database.get_alert_with_events(alert_id)
    assert stored is not None
    assert stored["status"] == "ACKNOWLEDGED"
    assert stored["note"] == "Checked by analyst"
    assert datetime.fromisoformat(stored["updated_at"]).tzinfo == timezone.utc


def test_reject_invalid_alert_status(database: Database) -> None:
    with pytest.raises(ValueError, match="Invalid alert status"):
        database.save_alert(alert_data("INVALID"))

    alert_id = database.save_alert(alert_data())
    with pytest.raises(ValueError, match="Invalid alert status"):
        database.update_alert_status(alert_id, "IGNORED")

    stored = database.get_alert_with_events(alert_id)
    assert stored is not None
    assert stored["status"] == "OPEN"


def test_foreign_keys_cascade_links_and_rollback_invalid_alert(database: Database) -> None:
    event_id = database.save_event(event_data())
    alert_id = database.save_alert(alert_data(), [event_id])

    with sqlite3.connect(database.path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        linked_rows = connection.execute(
            "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()[0]
        event_rows = connection.execute(
            "SELECT COUNT(*) FROM events WHERE id = ?",
            (event_id,),
        ).fetchone()[0]

    assert linked_rows == 0
    assert event_rows == 1

    with pytest.raises(sqlite3.IntegrityError):
        database.save_alert(alert_data(), [999_999])
    assert len(database.get_alerts(AlertStatus.OPEN)) == 0


def test_data_persists_across_database_instances(tmp_path: Path) -> None:
    path = tmp_path / "persistent.db"
    writer = Database(path)
    writer.initialize()
    event_id = writer.save_event(event_data())

    reader = Database(path)
    stored = reader.get_event(event_id)

    assert stored is not None
    assert stored["ip_address"] == "203.0.113.10"


def test_active_alert_creation_counts_unique_linked_events(database: Database) -> None:
    first_event_id = database.save_event(event_data())
    second_event_id = database.save_event(event_data("2026-08-25T10:01:00Z"))
    alert = replace(alert_data(), event_count=99)

    result = database.save_or_extend_active_alert(
        alert,
        [first_event_id, first_event_id, second_event_id],
        evaluated_event_id=second_event_id,
    )
    stored = database.get_alert_with_events(result.alert_id)

    assert result.action == AlertMutation.CREATED
    assert result.event_count == 2
    assert stored is not None
    assert stored["event_count"] == 2
    assert [event["id"] for event in stored["events"]] == [
        first_event_id,
        second_event_id,
    ]


def test_active_alert_extension_rolls_back_if_event_linking_fails(
    database: Database,
) -> None:
    first_event_id = database.save_event(event_data())
    initial = database.save_or_extend_active_alert(
        alert_data(),
        [first_event_id],
        evaluated_event_id=first_event_id,
    )
    before = database.get_alert_with_events(initial.alert_id)
    second_event_id = database.save_event(event_data("2026-08-25T10:01:00Z"))

    with pytest.raises(sqlite3.IntegrityError):
        database.save_or_extend_active_alert(
            alert_data(),
            [second_event_id, 999_999],
            evaluated_event_id=second_event_id,
        )

    after = database.get_alert_with_events(initial.alert_id)
    assert before is not None
    assert after is not None
    assert after["event_count"] == before["event_count"] == 1
    assert after["window_start"] == before["window_start"]
    assert after["window_end"] == before["window_end"]
    assert after["updated_at"] == before["updated_at"]
    assert [event["id"] for event in after["events"]] == [first_event_id]


def test_active_alert_overlap_compares_mixed_utc_offsets_chronologically(
    database: Database,
) -> None:
    first_event_id = database.save_event(event_data("2026-08-25T13:00:00+02:00"))
    initial_alert = replace(
        alert_data(),
        event_count=1,
        window_start="2026-08-25T13:00:00+02:00",
        window_end="2026-08-25T13:01:00+02:00",
    )
    initial = database.save_or_extend_active_alert(
        initial_alert,
        [first_event_id],
        evaluated_event_id=first_event_id,
    )
    second_event_id = database.save_event(event_data("2026-08-25T11:01:00+00:00"))
    candidate = replace(
        alert_data(),
        event_count=1,
        window_start="2026-08-25T11:01:00+00:00",
        window_end="2026-08-25T11:01:00+00:00",
    )

    result = database.save_or_extend_active_alert(
        candidate,
        [second_event_id],
        evaluated_event_id=second_event_id,
    )
    stored = database.get_alert_with_events(initial.alert_id)

    assert result.action == AlertMutation.UPDATED
    assert result.alert_id == initial.alert_id
    assert stored is not None
    assert stored["event_count"] == 2
    assert stored["window_start"] == "2026-08-25T11:00:00+00:00"
    assert stored["window_end"] == "2026-08-25T11:01:00+00:00"
