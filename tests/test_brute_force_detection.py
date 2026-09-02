from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import database as database_module
from brute_force_detection import DetectionOutcome, SSHBruteForceDetector
from database import AlertStatus, Database, EventData
from models.analysis import EventType


BASE_TIME = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
SOURCE_IP = "203.0.113.40"


@pytest.fixture
def database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "detection.db")
    database.initialize()
    return database


def save_event(
    database: Database,
    offset_seconds: float,
    *,
    ip_address: str = SOURCE_IP,
    username: str | None = "root",
    event_type: EventType = EventType.FAILED_LOGIN,
) -> int:
    return database.save_event(
        EventData(
            event_timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
            hostname="server-01",
            event_type=event_type,
            ip_address=ip_address,
            username=username,
            auth_method="password",
            raw_line=f"event at {offset_seconds}",
            source="test/auth.log",
        )
    )


def save_failures(
    database: Database,
    offsets: list[float],
    *,
    ip_address: str = SOURCE_IP,
    usernames: list[str | None] | None = None,
) -> list[int]:
    names = usernames or ["root"] * len(offsets)
    return [
        save_event(database, offset, ip_address=ip_address, username=username)
        for offset, username in zip(offsets, names, strict=True)
    ]


def test_below_threshold_creates_no_alert(database: Database) -> None:
    event_ids = save_failures(database, [0, 10, 20, 30])

    result = SSHBruteForceDetector(database).evaluate(event_ids[-1])

    assert result.outcome == DetectionOutcome.NO_ALERT
    assert database.get_alerts(AlertStatus.OPEN) == []


def test_fifth_failure_at_inclusive_window_boundary_creates_alert(
    database: Database,
) -> None:
    event_ids = save_failures(database, [0, 15, 30, 45, 60])

    result = SSHBruteForceDetector(database).evaluate(event_ids[-1])
    alert = database.get_alert_with_events(result.alert_id) if result.alert_id else None

    assert result.outcome == DetectionOutcome.CREATED
    assert alert is not None
    assert alert["rule_id"] == "SSH_BRUTE_FORCE"
    assert alert["title"] == "SSH brute-force activity detected"
    assert alert["severity"] == "HIGH"
    assert alert["score"] == 70
    assert alert["status"] == "OPEN"
    assert alert["event_count"] == 5
    assert alert["window_start"] == BASE_TIME.isoformat()
    assert alert["window_end"] == (BASE_TIME + timedelta(seconds=60)).isoformat()
    assert alert["username"] == "root"
    assert [event["id"] for event in alert["events"]] == event_ids
    assert "5" in alert["description"]
    assert "60" in alert["description"]
    assert SOURCE_IP in alert["description"]


def test_event_just_outside_window_is_excluded(database: Database) -> None:
    event_ids = save_failures(database, [0, 15, 30, 45, 60.001])

    result = SSHBruteForceDetector(database).evaluate(event_ids[-1])

    assert result.outcome == DetectionOutcome.NO_ALERT


def test_window_compares_mixed_utc_offsets_chronologically(database: Database) -> None:
    timestamps = [
        "2026-08-31T13:00:00+02:00",
        "2026-08-31T06:00:15-05:00",
        "2026-08-31T11:00:30+00:00",
        "2026-08-31T12:00:45+01:00",
        "2026-08-31T13:01:00+02:00",
    ]
    event_ids = [
        database.save_event(
            EventData(
                event_timestamp=timestamp,
                hostname="server-01",
                event_type=EventType.FAILED_LOGIN,
                ip_address=SOURCE_IP,
                username="root",
                auth_method="password",
                raw_line=f"event at {timestamp}",
                source="test/auth.log",
            )
        )
        for timestamp in timestamps
    ]

    result = SSHBruteForceDetector(database).evaluate(event_ids[-1])
    alert = database.get_alert_with_events(result.alert_id) if result.alert_id else None

    assert result.outcome == DetectionOutcome.CREATED
    assert alert is not None
    assert alert["event_count"] == 5
    assert alert["window_start"] == "2026-08-31T11:00:00+00:00"
    assert alert["window_end"] == "2026-08-31T11:01:00+00:00"
    assert [event["id"] for event in alert["events"]] == event_ids


def test_only_failures_from_same_ip_are_grouped(database: Database) -> None:
    save_failures(database, [0, 10, 20, 30], ip_address=SOURCE_IP)
    other_event = save_event(database, 40, ip_address="198.51.100.20")

    result = SSHBruteForceDetector(database).evaluate(other_event)

    assert result.outcome == DetectionOutcome.NO_ALERT
    assert database.get_alerts(AlertStatus.OPEN) == []


def test_successful_login_does_not_trigger_rule(database: Database) -> None:
    save_failures(database, [0, 10, 20, 30])
    successful_event = save_event(
        database,
        40,
        event_type=EventType.SUCCESSFUL_LOGIN,
    )

    result = SSHBruteForceDetector(database).evaluate(successful_event)

    assert result.outcome == DetectionOutcome.NO_ALERT


def test_event_without_ip_does_not_trigger_rule(database: Database) -> None:
    event_id = save_event(database, 0, ip_address="")

    result = SSHBruteForceDetector(database, threshold=2).evaluate(event_id)

    assert result.outcome == DetectionOutcome.NO_ALERT


def test_different_usernames_produce_null_username(database: Database) -> None:
    event_ids = save_failures(
        database,
        [0, 1],
        usernames=["root", "admin"],
    )

    result = SSHBruteForceDetector(database, threshold=2).evaluate(event_ids[-1])
    alert = database.get_alert_with_events(result.alert_id) if result.alert_id else None

    assert alert is not None
    assert alert["username"] is None

    additional_event = save_event(database, 2, username="root")
    updated = SSHBruteForceDetector(database, threshold=2).evaluate(additional_event)
    alert = database.get_alert_with_events(result.alert_id) if result.alert_id else None

    assert updated.outcome == DetectionOutcome.UPDATED
    assert alert is not None
    assert alert["username"] is None


def test_additional_failure_extends_open_alert(
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_ids = save_failures(database, [0, 10, 20, 30, 40])
    detector = SSHBruteForceDetector(database)
    created = detector.evaluate(event_ids[-1])
    assert created.alert_id is not None
    before = database.get_alert_with_events(created.alert_id)
    assert before is not None
    updated_at = "2030-01-01T00:00:00+00:00"
    monkeypatch.setattr(database_module, "_utc_now", lambda: updated_at)
    additional_event = save_event(database, 50)

    updated = detector.evaluate(additional_event)
    alert = database.get_alert_with_events(created.alert_id)

    assert updated.outcome == DetectionOutcome.UPDATED
    assert updated.alert_id == created.alert_id
    assert alert is not None
    assert alert["event_count"] == 6
    assert alert["window_start"] == BASE_TIME.isoformat()
    assert alert["window_end"] == (BASE_TIME + timedelta(seconds=50)).isoformat()
    assert alert["updated_at"] == updated_at
    assert alert["updated_at"] != before["updated_at"]
    assert {event["id"] for event in alert["events"]} == {*event_ids, additional_event}


def test_acknowledged_alert_is_extended(database: Database) -> None:
    event_ids = save_failures(database, [0, 1])
    detector = SSHBruteForceDetector(database, threshold=2)
    created = detector.evaluate(event_ids[-1])
    assert created.alert_id is not None
    database.update_alert_status(created.alert_id, AlertStatus.ACKNOWLEDGED)
    additional_event = save_event(database, 2)

    updated = detector.evaluate(additional_event)
    alert = database.get_alert_with_events(created.alert_id)

    assert updated.outcome == DetectionOutcome.UPDATED
    assert alert is not None
    assert alert["status"] == "ACKNOWLEDGED"
    assert alert["event_count"] == 3


@pytest.mark.parametrize(
    "terminal_status",
    [AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE],
)
def test_terminal_alert_is_not_extended(
    database: Database,
    terminal_status: AlertStatus,
) -> None:
    event_ids = save_failures(database, [0, 1])
    detector = SSHBruteForceDetector(database, threshold=2)
    original = detector.evaluate(event_ids[-1])
    assert original.alert_id is not None
    database.update_alert_status(original.alert_id, terminal_status)
    additional_event = save_event(database, 2)

    result = detector.evaluate(additional_event)
    old_alert = database.get_alert_with_events(original.alert_id)

    assert result.outcome == DetectionOutcome.CREATED
    assert result.alert_id != original.alert_id
    assert old_alert is not None
    assert old_alert["status"] == terminal_status.value
    assert old_alert["event_count"] == 2


def test_new_attack_after_window_creates_new_alert(database: Database) -> None:
    detector = SSHBruteForceDetector(database, threshold=2)
    first_attack = save_failures(database, [0, 1])
    first_result = detector.evaluate(first_attack[-1])
    second_attack = save_failures(database, [100, 101])

    second_result = detector.evaluate(second_attack[-1])

    assert first_result.outcome == DetectionOutcome.CREATED
    assert second_result.outcome == DetectionOutcome.CREATED
    assert second_result.alert_id != first_result.alert_id
    assert len(database.get_alerts(AlertStatus.OPEN)) == 2


def test_repeated_evaluation_is_idempotent(
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_ids = save_failures(database, [0, 1])
    detector = SSHBruteForceDetector(database, threshold=2)
    first = detector.evaluate(event_ids[-1])
    before = database.get_alert_with_events(first.alert_id) if first.alert_id else None
    assert before is not None
    monkeypatch.setattr(
        database_module,
        "_utc_now",
        lambda: "2030-01-01T00:00:00+00:00",
    )

    repeated = detector.evaluate(event_ids[-1])
    alert = database.get_alert_with_events(first.alert_id) if first.alert_id else None

    assert repeated.outcome == DetectionOutcome.ALREADY_PROCESSED
    assert repeated.alert_id == first.alert_id
    assert alert is not None
    assert alert["event_count"] == 2
    assert len(alert["events"]) == 2
    assert alert["updated_at"] == before["updated_at"]
    assert len(database.get_alerts(AlertStatus.OPEN)) == 1


@pytest.mark.parametrize("threshold", [1, 0, -1, 2.5, True])
def test_rejects_invalid_threshold(database: Database, threshold: object) -> None:
    with pytest.raises(ValueError, match="threshold"):
        SSHBruteForceDetector(database, threshold=threshold)  # type: ignore[arg-type]


@pytest.mark.parametrize("window", [0, -1, float("nan"), float("inf"), "60", True])
def test_rejects_invalid_window(database: Database, window: object) -> None:
    with pytest.raises(ValueError, match="window_seconds"):
        SSHBruteForceDetector(database, window_seconds=window)  # type: ignore[arg-type]


def test_detection_works_across_database_instances(tmp_path: Path) -> None:
    path = tmp_path / "shared.db"
    writer = Database(path)
    writer.initialize()
    event_ids = save_failures(writer, [0, 1])

    result = SSHBruteForceDetector(Database(path), threshold=2).evaluate(event_ids[-1])
    alert = Database(path).get_alert_with_events(result.alert_id) if result.alert_id else None

    assert result.outcome == DetectionOutcome.CREATED
    assert alert is not None
    assert alert["event_count"] == 2


def test_parallel_evaluation_does_not_create_duplicate_active_alerts(
    database: Database,
) -> None:
    event_ids = save_failures(database, [0, 1, 2, 3, 4, 5])

    def evaluate(event_id: int) -> DetectionOutcome:
        return SSHBruteForceDetector(database).evaluate(event_id).outcome

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(evaluate, event_ids[-2:]))

    alerts = database.get_alerts(AlertStatus.OPEN)
    assert DetectionOutcome.CREATED in outcomes
    assert all(
        outcome in {
            DetectionOutcome.CREATED,
            DetectionOutcome.UPDATED,
            DetectionOutcome.ALREADY_PROCESSED,
        }
        for outcome in outcomes
    )
    assert len(alerts) == 1
    alert = database.get_alert_with_events(alerts[0]["id"])
    assert alert is not None
    assert alert["event_count"] == 6
