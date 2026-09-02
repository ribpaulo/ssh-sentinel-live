"""HTTP routes for the HTML interface and JSON API."""

import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Path as ApiPath,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from database import AlertStatus, Database
from models.analysis import AnalysisResult
from models.dashboard import (
    DashboardAlert,
    DashboardAlertDetail,
    DashboardAlertUpdate,
    DashboardEvent,
    SystemStatusResponse,
)
from service import analyze_log


BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter()

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_SUFFIXES = {".log", ".txt"}


async def get_database(request: Request) -> Database:
    return request.app.state.database


def _event_payload(row: object) -> dict[str, object]:
    values = dict(row)  # type: ignore[arg-type]
    return {
        key: values[key]
        for key in (
            "id",
            "event_timestamp",
            "hostname",
            "event_type",
            "ip_address",
            "username",
            "auth_method",
            "source",
        )
    }


def _alert_payload(row: object) -> dict[str, object]:
    values = dict(row)  # type: ignore[arg-type]
    return {
        key: values[key]
        for key in (
            "id",
            "rule_id",
            "title",
            "severity",
            "score",
            "ip_address",
            "username",
            "event_count",
            "window_start",
            "window_end",
            "status",
            "created_at",
            "updated_at",
        )
    }


def _alert_detail_payload(alert: dict[str, object]) -> dict[str, object]:
    payload = _alert_payload(alert)
    payload["description"] = alert["description"]
    payload["note"] = alert["note"]
    payload["events"] = [_event_payload(event) for event in alert["events"]]  # type: ignore[union-attr]
    return payload


async def _read_log_file(upload: UploadFile) -> tuple[str, str]:
    """Validate and safely read a small text log file."""

    filename = Path(upload.filename or "upload.log").name
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail="Only .log and .txt files are allowed.")

    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    await upload.close()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The file must not exceed 2 MB.")
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if b"\x00" in data:
        raise HTTPException(status_code=400, detail="The file does not appear to be a text file.")

    try:
        return data.decode("utf-8"), filename
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="The file must be UTF-8 encoded text.",
        ) from exc


@router.get("/", response_class=HTMLResponse)
async def start_page(request: Request) -> HTMLResponse:
    """Display the upload page."""

    return templates.TemplateResponse(request=request, name="index.html")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> HTMLResponse:
    """Display the live dashboard."""

    return templates.TemplateResponse(request=request, name="dashboard.html")


@router.post("/analyze", response_class=HTMLResponse)
async def analyze_page(request: Request, log_file: UploadFile = File(...)) -> HTMLResponse:
    """Analyze a file and render the result as HTML."""

    try:
        content, filename = await _read_log_file(log_file)
    except HTTPException as exc:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": exc.detail},
            status_code=exc.status_code,
        )

    result = analyze_log(content, filename)
    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={"result": result},
    )


@router.post("/api/analyze", response_model=AnalysisResult)
async def analyze_api(log_file: UploadFile = File(...)) -> AnalysisResult:
    """Return the same analysis result as structured JSON."""

    content, filename = await _read_log_file(log_file)
    return analyze_log(content, filename)


@router.get("/api/health")
async def health() -> dict[str, str]:
    """Simple health check for development and deployment."""

    return {"status": "ok"}


@router.get("/api/system/status", response_model=SystemStatusResponse)
async def system_status(request: Request) -> dict[str, object]:
    """Return concise operating status without internal error details."""

    database: Database = request.app.state.database
    latest_event = None
    try:
        latest_event = database.get_last_ingested_event()
        database_ready = True
    except sqlite3.Error:
        database_ready = False

    snapshot = request.app.state.system_status.snapshot()
    last_event_id = snapshot.last_event_id
    last_event_at = snapshot.last_event_at
    if last_event_id is None and latest_event is not None:
        last_event_id = latest_event["id"]
        last_event_at = latest_event["ingested_at"]

    return {
        "database_ready": database_ready,
        "live_ingestion": snapshot.live_ingestion,
        "log_file": snapshot.log_file,
        "started_at": snapshot.started_at,
        "last_event_id": last_event_id,
        "last_event_at": last_event_at,
        "last_error": snapshot.last_error,
    }


@router.get("/api/events", response_model=list[DashboardEvent])
async def recent_events(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    database: Database = Depends(get_database),
) -> list[dict[str, object]]:
    """Return the most recent persistent SSH events."""

    return [_event_payload(row) for row in database.get_recent_events(limit)]


@router.get("/api/alerts", response_model=list[DashboardAlert])
async def recent_alerts(
    status: Annotated[AlertStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    database: Database = Depends(get_database),
) -> list[dict[str, object]]:
    """Return the latest alerts, optionally filtered by status."""

    return [_alert_payload(row) for row in database.get_alerts(status, limit)]


@router.get("/api/alerts/{alert_id}", response_model=DashboardAlertDetail)
async def alert_detail(
    alert_id: Annotated[int, ApiPath(ge=1)],
    database: Database = Depends(get_database),
) -> dict[str, object]:
    """Return an alert including its linked events."""

    alert = database.get_alert_with_events(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_detail_payload(alert)


@router.patch("/api/alerts/{alert_id}", response_model=DashboardAlertDetail)
async def update_alert(
    alert_id: Annotated[int, ApiPath(ge=1)],
    update: DashboardAlertUpdate,
    database: Database = Depends(get_database),
) -> dict[str, object]:
    """Update an alert's status and investigation note."""

    try:
        database.update_alert_status_and_note(alert_id, update.status, update.note)
        alert = database.get_alert_with_events(alert_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Alert not found.") from exc
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=500,
            detail="Alert could not be saved.",
        ) from exc

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_detail_payload(alert)
