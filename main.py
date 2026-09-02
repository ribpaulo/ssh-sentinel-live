"""FastAPI application entry point."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from database import DEFAULT_DATABASE_PATH, Database
from routes import router
from runtime_status import LiveSystemStatus


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH_ENV = "SSH_SENTINEL_DATABASE"


def create_app(
    database_path: str | Path | None = None,
    *,
    system_status: LiveSystemStatus | None = None,
) -> FastAPI:
    """Create the application with a configurable SQLite database."""

    configured_path = database_path or os.environ.get(DATABASE_PATH_ENV) or DEFAULT_DATABASE_PATH
    database = Database(configured_path)
    database.initialize()

    application = FastAPI(
        title="SSH Sentinel Mini-SIEM",
        description="Demo analysis of SSH authentication logs for an educational project.",
        version="1.0.0",
    )
    application.state.database = database
    application.state.system_status = system_status or LiveSystemStatus()
    application.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static",
    )
    application.include_router(router)
    return application


app = create_app()
