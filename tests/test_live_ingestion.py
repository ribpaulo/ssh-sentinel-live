import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from database import Database
from live_ingest import _positive_float
from live_ingestion import LiveIngestionService, normalize_live_timestamp


def test_ignores_unsupported_log_line(tmp_path: Path) -> None:
    database = Database(tmp_path / "events.db")
    database.initialize()
    service = LiveIngestionService(database, tmp_path / "auth.log")

    event_id = service.ingest_line("Aug 25 18:30:12 host CRON[1]: unrelated")

    assert event_id is None
    assert database.get_recent_events() == []


def test_parses_and_saves_event_with_source_and_current_year(tmp_path: Path) -> None:
    database = Database(tmp_path / "events.db")
    database.initialize()
    log_path = tmp_path / "auth.log"
    local_timezone = timezone(timedelta(hours=2))
    service = LiveIngestionService(
        database,
        log_path,
        local_timezone=local_timezone,
        now=lambda: datetime(2026, 8, 25, 18, 31, tzinfo=local_timezone),
    )
    line = (
        "Aug 25 18:30:12 server-01 sshd[1]: "
        "Failed password for root from 203.0.113.10 port 41000 ssh2"
    )

    event_id = service.ingest_line(line)
    stored = database.get_event(event_id) if event_id is not None else None

    assert stored is not None
    assert stored["event_timestamp"] == "2026-08-25T16:30:12+00:00"
    assert stored["hostname"] == "server-01"
    assert stored["event_type"] == "failed_login"
    assert stored["ip_address"] == "203.0.113.10"
    assert stored["username"] == "root"
    assert stored["auth_method"] == "password"
    assert stored["raw_line"] == line
    assert stored["source"] == str(log_path)


def test_assigns_december_event_to_previous_year_on_january_first(tmp_path: Path) -> None:
    database = Database(tmp_path / "events.db")
    database.initialize()
    local_timezone = timezone(timedelta(hours=1))
    service = LiveIngestionService(
        database,
        tmp_path / "auth.log",
        local_timezone=local_timezone,
        now=lambda: datetime(2027, 1, 1, 0, 5, tzinfo=local_timezone),
    )
    line = (
        "Dec 31 23:59:30 server-01 sshd[2]: "
        "Accepted publickey for deploy from 2001:db8::10 port 41001 ssh2"
    )

    event_id = service.ingest_line(line)
    stored = database.get_event(event_id) if event_id is not None else None

    assert stored is not None
    assert stored["event_timestamp"] == "2026-12-31T22:59:30+00:00"


def test_preserves_instant_of_complete_iso_timestamp() -> None:
    normalized = normalize_live_timestamp(
        "2026-08-25T18:30:12+02:00",
        reference_time=datetime(2030, 1, 1, tzinfo=timezone.utc),
        local_timezone=timezone(timedelta(hours=-5)),
    )

    assert normalized == datetime(2026, 8, 25, 16, 30, 12, tzinfo=timezone.utc)


def test_interprets_naive_iso_timestamp_in_configured_local_timezone() -> None:
    normalized = normalize_live_timestamp(
        "2026-08-25T18:30:12",
        local_timezone=timezone(timedelta(hours=2)),
    )

    assert normalized == datetime(2026, 8, 25, 16, 30, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf"])
def test_rejects_invalid_poll_intervals(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _positive_float(value)
