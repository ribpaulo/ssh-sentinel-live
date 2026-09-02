import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

import database as database_module
from database import AlertData, AlertStatus, EventData
from main import create_app
from models.analysis import EventType


BASE_TIME = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def alert_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setattr(database_module, "_utc_now", lambda: BASE_TIME.isoformat())
    return create_app(tmp_path / "alerts.db")


async def _request(app: FastAPI, method: str, url: str, **kwargs: object) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.request(method, url, **kwargs)


def event_data(offset_seconds: int, username: str = "root") -> EventData:
    return EventData(
        event_timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        hostname="server-01",
        event_type=EventType.FAILED_LOGIN,
        ip_address="203.0.113.80",
        username=username,
        auth_method="password",
        raw_line=f"failed event {offset_seconds}",
        source="test/auth.log",
    )


def alert_data(
    status: AlertStatus = AlertStatus.OPEN,
    *,
    note: str | None = None,
    event_count: int = 0,
) -> AlertData:
    return AlertData(
        rule_id="SSH_BRUTE_FORCE",
        title="SSH brute-force activity detected",
        description="Repeated failed SSH logins detected.",
        severity="HIGH",
        score=70,
        ip_address="203.0.113.80",
        username="root",
        event_count=event_count,
        window_start=BASE_TIME,
        window_end=BASE_TIME + timedelta(seconds=60),
        status=status,
        note=note,
    )


@pytest.mark.parametrize(
    ("initial_status", "new_status"),
    [
        (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED),
        (AlertStatus.ACKNOWLEDGED, AlertStatus.CLOSED),
        (AlertStatus.OPEN, AlertStatus.FALSE_POSITIVE),
    ],
)
def test_patch_updates_allowed_alert_statuses(
    alert_app: FastAPI,
    initial_status: AlertStatus,
    new_status: AlertStatus,
) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data(initial_status))

    response = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": new_status.value, "note": None},
        )
    )

    assert response.status_code == 200
    assert response.json()["status"] == new_status.value
    stored = database.get_alert_with_events(alert_id)
    assert stored is not None
    assert stored["status"] == new_status.value


def test_patch_saves_updates_and_clears_note(alert_app: FastAPI) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data(note="Initial note"))

    saved = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "ACKNOWLEDGED", "note": "  Investigation started  "},
        )
    )
    loaded = asyncio.run(_request(alert_app, "GET", f"/api/alerts/{alert_id}"))
    cleared = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "ACKNOWLEDGED", "note": "   "},
        )
    )

    assert saved.status_code == 200
    assert saved.json()["note"] == "Investigation started"
    assert loaded.json()["note"] == "Investigation started"
    assert cleared.status_code == 200
    assert cleared.json()["note"] is None
    stored = database.get_alert_with_events(alert_id)
    assert stored is not None
    assert stored["note"] is None


def test_patch_updates_timestamp_without_changing_detection_data(
    alert_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = alert_app.state.database
    event_ids = [database.save_event(event_data(0)), database.save_event(event_data(30))]
    alert_id = database.save_alert(alert_data(event_count=2), event_ids)
    before = database.get_alert_with_events(alert_id)
    assert before is not None
    changed_at = (BASE_TIME + timedelta(minutes=5)).isoformat()
    monkeypatch.setattr(database_module, "_utc_now", lambda: changed_at)

    response = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "ACKNOWLEDGED", "note": "Being investigated"},
        )
    )
    after = database.get_alert_with_events(alert_id)

    assert response.status_code == 200
    assert response.json()["updated_at"] == changed_at
    assert response.json()["note"] == "Being investigated"
    assert after is not None
    assert after["updated_at"] == changed_at
    assert after["event_count"] == before["event_count"] == 2
    assert after["window_start"] == before["window_start"]
    assert after["window_end"] == before["window_end"]
    assert [event["id"] for event in after["events"]] == event_ids


def test_identical_patch_does_not_change_updated_at(
    alert_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data())
    monkeypatch.setattr(
        database_module,
        "_utc_now",
        lambda: (BASE_TIME + timedelta(hours=1)).isoformat(),
    )

    response = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "OPEN", "note": None},
        )
    )

    assert response.status_code == 200
    assert response.json()["updated_at"] == BASE_TIME.isoformat()


def test_patch_rejects_unknown_alert_invalid_payloads_and_long_note(
    alert_app: FastAPI,
) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data())

    missing = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            "/api/alerts/999999",
            json={"status": "CLOSED", "note": None},
        )
    )
    invalid_status = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "IGNORED", "note": None},
        )
    )
    too_long = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "OPEN", "note": "x" * 2001},
        )
    )
    empty = asyncio.run(
        _request(alert_app, "PATCH", f"/api/alerts/{alert_id}", json={})
    )

    assert missing.status_code == 404
    assert invalid_status.status_code == 422
    assert too_long.status_code == 422
    assert empty.status_code == 422


def test_status_filter_reflects_patch_immediately(alert_app: FastAPI) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data())

    changed = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "ACKNOWLEDGED", "note": "Triaged"},
        )
    )
    open_alerts = asyncio.run(
        _request(alert_app, "GET", "/api/alerts?status=OPEN")
    )
    acknowledged_alerts = asyncio.run(
        _request(alert_app, "GET", "/api/alerts?status=ACKNOWLEDGED")
    )

    assert changed.status_code == 200
    assert open_alerts.json() == []
    assert [alert["id"] for alert in acknowledged_alerts.json()] == [alert_id]


def test_database_errors_return_generic_message(
    alert_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = alert_app.state.database
    alert_id = database.save_alert(alert_data())

    def fail_update(*args: object) -> None:
        raise sqlite3.OperationalError("sensitive database detail")

    monkeypatch.setattr(database, "update_alert_status_and_note", fail_update)
    response = asyncio.run(
        _request(
            alert_app,
            "PATCH",
            f"/api/alerts/{alert_id}",
            json={"status": "CLOSED", "note": None},
        )
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Alarm konnte nicht gespeichert werden."}
    assert "sensitive" not in response.text


def test_dashboard_contains_filter_and_alert_edit_fields(alert_app: FastAPI) -> None:
    response = asyncio.run(_request(alert_app, "GET", "/dashboard"))

    assert response.status_code == 200
    assert 'id="alert-status-filter"' in response.text
    assert 'id="alert-status"' in response.text
    assert 'id="alert-note"' in response.text
    assert 'maxlength="2000"' in response.text
    assert 'id="alert-save"' in response.text
