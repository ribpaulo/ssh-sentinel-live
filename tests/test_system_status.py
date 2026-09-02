import asyncio
import threading
from pathlib import Path

import httpx
from fastapi import FastAPI

import run_live
from main import app as default_app
from main import create_app
from runtime_status import LiveIngestionState, LiveSystemStatus


async def _get(app: FastAPI, url: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(url)


def test_normal_app_reports_stable_inactive_status(tmp_path: Path) -> None:
    app = create_app(tmp_path / "normal.db")

    response = asyncio.run(_get(app, "/api/system/status"))

    assert response.status_code == 200
    assert response.json() == {
        "database_ready": True,
        "live_ingestion": "inactive",
        "log_file": None,
        "started_at": response.json()["started_at"],
        "last_event_id": None,
        "last_event_at": None,
        "last_error": None,
    }
    assert response.json()["started_at"].endswith("+00:00")


def test_default_main_app_does_not_activate_live_ingestion() -> None:
    response = asyncio.run(_get(default_app, "/api/system/status"))

    assert response.status_code == 200
    assert response.json()["live_ingestion"] == "inactive"
    assert response.json()["log_file"] is None


def test_active_live_status_is_exposed_without_database_path(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    status = LiveSystemStatus(log_file)
    status.mark_active()
    app = create_app(tmp_path / "private" / "sentinel.db", system_status=status)

    payload = asyncio.run(_get(app, "/api/system/status")).json()

    assert payload["live_ingestion"] == "active"
    assert payload["log_file"] == str(log_file)
    assert payload["database_ready"] is True
    assert "database" not in payload
    assert "sentinel.db" not in str(payload)


def test_background_error_is_visible_without_message_or_stacktrace(tmp_path: Path) -> None:
    class FailingTailer:
        def follow(self):
            if False:
                yield ""
            raise RuntimeError("secret detail\nTraceback (most recent call last): ...")

        def stop(self) -> None:
            pass

        def close(self) -> None:
            pass

    status = LiveSystemStatus(tmp_path / "auth.log")
    database = run_live.Database(tmp_path / "status.db")
    database.initialize()
    worker = run_live.LiveIngestionWorker(
        database,
        FailingTailer(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        status,
        on_error=lambda error: None,
    )
    app = create_app(database.path, system_status=status)

    worker.start()
    worker.join(1)
    response = asyncio.run(_get(app, "/api/system/status"))
    payload = response.json()

    assert not worker.is_alive
    assert payload["live_ingestion"] == "error"
    assert payload["last_error"] == "Live ingestion failed (RuntimeError)."
    assert "secret detail" not in response.text
    assert "Traceback" not in response.text


def test_dashboard_contains_operating_status_without_breaking_existing_controls(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path / "dashboard.db")

    response = asyncio.run(_get(app, "/dashboard"))

    assert response.status_code == 200
    assert 'id="monitoring-state"' in response.text
    assert 'id="monitoring-detail"' in response.text
    assert 'id="alert-status-filter"' in response.text
    assert 'id="alert-edit-form"' in response.text
    assert all(thread.name != run_live.THREAD_NAME for thread in threading.enumerate())
