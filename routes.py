"""HTTP-Routen für die HTML-Oberfläche und die JSON-API."""

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
    """Validiert und liest eine kleine Text-Logdatei sicher ein."""

    filename = Path(upload.filename or "upload.log").name
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail="Erlaubt sind nur .log- und .txt-Dateien.")

    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    await upload.close()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Die Datei darf maximal 2 MB gross sein.")
    if not data:
        raise HTTPException(status_code=400, detail="Die hochgeladene Datei ist leer.")
    if b"\x00" in data:
        raise HTTPException(status_code=400, detail="Die Datei scheint keine Textdatei zu sein.")

    try:
        return data.decode("utf-8"), filename
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Die Datei muss UTF-8-kodierter Text sein.",
        ) from exc


@router.get("/", response_class=HTMLResponse)
async def start_page(request: Request) -> HTMLResponse:
    """Zeigt die Upload-Seite."""

    return templates.TemplateResponse(request=request, name="index.html")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> HTMLResponse:
    """Zeigt das Live-Dashboard."""

    return templates.TemplateResponse(request=request, name="dashboard.html")


@router.post("/analyze", response_class=HTMLResponse)
async def analyze_page(request: Request, log_file: UploadFile = File(...)) -> HTMLResponse:
    """Analysiert eine Datei und rendert das Resultat als HTML."""

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
    """Liefert dasselbe Analyseergebnis als strukturiertes JSON."""

    content, filename = await _read_log_file(log_file)
    return analyze_log(content, filename)


@router.get("/api/health")
async def health() -> dict[str, str]:
    """Einfacher Health-Check für Entwicklung und Deployment."""

    return {"status": "ok"}


@router.get("/api/events", response_model=list[DashboardEvent])
async def recent_events(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    database: Database = Depends(get_database),
) -> list[dict[str, object]]:
    """Liefert die neuesten persistenten SSH-Ereignisse."""

    return [_event_payload(row) for row in database.get_recent_events(limit)]


@router.get("/api/alerts", response_model=list[DashboardAlert])
async def recent_alerts(
    status: Annotated[AlertStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    database: Database = Depends(get_database),
) -> list[dict[str, object]]:
    """Liefert die neuesten Alarme, optional nach Status gefiltert."""

    return [_alert_payload(row) for row in database.get_alerts(status, limit)]


@router.get("/api/alerts/{alert_id}", response_model=DashboardAlertDetail)
async def alert_detail(
    alert_id: Annotated[int, ApiPath(ge=1)],
    database: Database = Depends(get_database),
) -> dict[str, object]:
    """Liefert einen Alarm inklusive seiner verknüpften Events."""

    alert = database.get_alert_with_events(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alarm nicht gefunden.")
    return _alert_detail_payload(alert)


@router.patch("/api/alerts/{alert_id}", response_model=DashboardAlertDetail)
async def update_alert(
    alert_id: Annotated[int, ApiPath(ge=1)],
    update: DashboardAlertUpdate,
    database: Database = Depends(get_database),
) -> dict[str, object]:
    """Aktualisiert Status und Untersuchungsnotiz eines Alarms."""

    try:
        database.update_alert_status_and_note(alert_id, update.status, update.note)
        alert = database.get_alert_with_events(alert_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Alarm nicht gefunden.") from exc
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=500,
            detail="Alarm konnte nicht gespeichert werden.",
        ) from exc

    if alert is None:
        raise HTTPException(status_code=404, detail="Alarm nicht gefunden.")
    return _alert_detail_payload(alert)
