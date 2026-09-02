import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from database import AlertData, AlertStatus, EventData
from main import create_app
from models.analysis import EventType


BASE_TIME = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def dashboard_app(tmp_path: Path) -> FastAPI:
    return create_app(tmp_path / "dashboard.db")


async def _request(app: FastAPI, method: str, url: str, **kwargs: object) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.request(method, url, **kwargs)


def event_data(
    offset_seconds: int,
    *,
    hostname: str | None = "server-01",
    username: str | None = "root",
    auth_method: str | None = "password",
) -> EventData:
    return EventData(
        event_timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        hostname=hostname,
        event_type=EventType.FAILED_LOGIN,
        ip_address="203.0.113.70",
        username=username,
        auth_method=auth_method,
        raw_line=f"failed event {offset_seconds}",
        source="examples/live_auth.log",
    )


def alert_data(status: AlertStatus, *, ip_address: str | None = "203.0.113.70") -> AlertData:
    return AlertData(
        rule_id="SSH_BRUTE_FORCE",
        title="SSH brute-force activity detected",
        description="Five failed logins occurred within 60 seconds.",
        severity="HIGH",
        score=70,
        ip_address=ip_address,
        username=None,
        event_count=1,
        window_start=BASE_TIME,
        window_end=BASE_TIME + timedelta(seconds=60),
        status=status,
    )


def test_dashboard_and_existing_upload_page_are_available(dashboard_app: FastAPI) -> None:
    dashboard = asyncio.run(_request(dashboard_app, "GET", "/dashboard"))
    upload = asyncio.run(_request(dashboard_app, "GET", "/"))

    assert dashboard.status_code == 200
    assert "Live dashboard" in dashboard.text
    assert "Status filter" in dashboard.text
    assert "Investigation note" in dashboard.text
    assert "Close alert details" in dashboard.text
    assert bytes.fromhex("416c61726d65").decode() not in dashboard.text
    assert bytes.fromhex("556e74657273756368756e67736e6f74697a").decode() not in dashboard.text
    assert "/static/dashboard.js" in dashboard.text
    assert upload.status_code == 200
    assert "Upload SSH log file" in upload.text
    assert bytes.fromhex("5353482d4c6f67646174656920686f63686c6164656e").decode() not in upload.text
    assert 'href="/dashboard"' in upload.text


def test_empty_database_returns_empty_api_lists(dashboard_app: FastAPI) -> None:
    events = asyncio.run(_request(dashboard_app, "GET", "/api/events"))
    alerts = asyncio.run(_request(dashboard_app, "GET", "/api/alerts"))

    assert events.status_code == 200
    assert events.json() == []
    assert alerts.status_code == 200
    assert alerts.json() == []


def test_events_are_newest_first_limited_and_have_stable_json(
    dashboard_app: FastAPI,
) -> None:
    database = dashboard_app.state.database
    first_id = database.save_event(event_data(0))
    second_id = database.save_event(event_data(10))
    newest_id = database.save_event(
        event_data(20, hostname=None, username=None, auth_method=None)
    )

    response = asyncio.run(_request(dashboard_app, "GET", "/api/events?limit=2"))
    payload = response.json()

    assert response.status_code == 200
    assert [event["id"] for event in payload] == [newest_id, second_id]
    assert first_id not in {event["id"] for event in payload}
    assert set(payload[0]) == {
        "id",
        "event_timestamp",
        "hostname",
        "event_type",
        "ip_address",
        "username",
        "auth_method",
        "source",
    }
    assert payload[0]["hostname"] is None
    assert payload[0]["username"] is None
    assert payload[0]["auth_method"] is None
    assert payload[0]["source"] == "examples/live_auth.log"
    assert payload[0]["event_type"] == "failed_login"


@pytest.mark.parametrize("limit", [0, 201])
def test_invalid_event_limit_is_rejected(dashboard_app: FastAPI, limit: int) -> None:
    response = asyncio.run(_request(dashboard_app, "GET", f"/api/events?limit={limit}"))

    assert response.status_code == 422


def test_alerts_are_newest_first_and_filter_by_active_statuses(
    dashboard_app: FastAPI,
) -> None:
    database = dashboard_app.state.database
    open_id = database.save_alert(alert_data(AlertStatus.OPEN))
    acknowledged_id = database.save_alert(alert_data(AlertStatus.ACKNOWLEDGED))
    closed_id = database.save_alert(alert_data(AlertStatus.CLOSED))

    all_alerts = asyncio.run(_request(dashboard_app, "GET", "/api/alerts"))
    limited_alerts = asyncio.run(_request(dashboard_app, "GET", "/api/alerts?limit=1"))
    open_alerts = asyncio.run(_request(dashboard_app, "GET", "/api/alerts?status=OPEN"))
    acknowledged_alerts = asyncio.run(
        _request(dashboard_app, "GET", "/api/alerts?status=ACKNOWLEDGED")
    )

    assert all_alerts.status_code == 200
    assert [alert["id"] for alert in all_alerts.json()] == [
        closed_id,
        acknowledged_id,
        open_id,
    ]
    assert [alert["id"] for alert in limited_alerts.json()] == [closed_id]
    assert [alert["id"] for alert in open_alerts.json()] == [open_id]
    assert [alert["id"] for alert in acknowledged_alerts.json()] == [acknowledged_id]
    assert acknowledged_alerts.json()[0]["username"] is None


def test_invalid_alert_status_and_limit_are_rejected(dashboard_app: FastAPI) -> None:
    invalid_status = asyncio.run(
        _request(dashboard_app, "GET", "/api/alerts?status=IGNORED")
    )
    invalid_limit = asyncio.run(_request(dashboard_app, "GET", "/api/alerts?limit=201"))

    assert invalid_status.status_code == 422
    assert invalid_limit.status_code == 422


def test_alert_detail_contains_linked_events_and_unknown_id_is_404(
    dashboard_app: FastAPI,
) -> None:
    database = dashboard_app.state.database
    first_event = database.save_event(event_data(0))
    second_event = database.save_event(event_data(10, username="admin"))
    alert_id = database.save_alert(
        alert_data(AlertStatus.OPEN, ip_address=None),
        [first_event, second_event],
    )

    response = asyncio.run(_request(dashboard_app, "GET", f"/api/alerts/{alert_id}"))
    missing = asyncio.run(_request(dashboard_app, "GET", "/api/alerts/999999"))
    payload = response.json()

    assert response.status_code == 200
    assert payload["id"] == alert_id
    assert payload["description"] == "Five failed logins occurred within 60 seconds."
    assert payload["ip_address"] is None
    assert [event["id"] for event in payload["events"]] == [first_event, second_event]
    assert "raw_line" not in payload["events"][0]
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Alert not found."}


def test_temporary_database_path_and_dashboard_static_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nested" / "temporary.db"
    monkeypatch.setenv("SSH_SENTINEL_DATABASE", str(path))
    app = create_app()
    script_path = Path(__file__).parents[1] / "static" / "dashboard.js"

    events = asyncio.run(_request(app, "GET", "/api/events"))

    assert path.is_file()
    assert app.state.database.path == path
    assert str(app.url_path_for("static", path="/dashboard.js")) == "/static/dashboard.js"
    assert "refreshDashboard" in script_path.read_text(encoding="utf-8")
    assert events.status_code == 200
    assert events.json() == []


def test_dashboard_badge_cells_do_not_prepend_fallback_text() -> None:
    script_path = Path(__file__).parents[1] / "static" / "dashboard.js"
    script = script_path.read_text(encoding="utf-8")

    assert 'appendCell(row, "")' not in script
    assert "appendBadgeCell(row, event.event_type, \"event\")" in script
    assert "appendBadgeCell(row, alert.severity, \"severity\")" in script
    assert "appendBadgeCell(row, alert.status, \"status\")" in script
    assert 'titleCell.textContent = "—"' in script
    assert "detailButton.append(title)" in script
    assert "detailButton.append(rule)" in script
