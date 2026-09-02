"""Einstiegspunkt der FastAPI-Anwendung."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from database import DEFAULT_DATABASE_PATH, Database
from routes import router


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH_ENV = "SSH_SENTINEL_DATABASE"


def create_app(database_path: str | Path | None = None) -> FastAPI:
    """Erstellt die Anwendung mit einer konfigurierbaren SQLite-Datenbank."""

    configured_path = database_path or os.environ.get(DATABASE_PATH_ENV) or DEFAULT_DATABASE_PATH
    database = Database(configured_path)
    database.initialize()

    application = FastAPI(
        title="SSH Sentinel Mini-SIEM",
        description="Demo-Analyse von SSH-Authentifizierungslogs für eine Modularbeit.",
        version="1.0.0",
    )
    application.state.database = database
    application.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static",
    )
    application.include_router(router)
    return application


app = create_app()
