"""Thread-sicherer Betriebsstatus für den integrierten Live-Modus."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class LiveIngestionState(str, Enum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class LiveSystemSnapshot:
    live_ingestion: LiveIngestionState
    log_file: str | None
    started_at: str
    last_event_id: int | None
    last_event_at: str | None
    last_error: str | None


class LiveSystemStatus:
    """Hält wenige Laufzeitinformationen ohne globale mutable Daten."""

    def __init__(
        self,
        log_file: str | Path | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._state = LiveIngestionState.INACTIVE
        self._log_file = str(Path(log_file)) if log_file is not None else None
        self._started_at = self._utc_now()
        self._last_event_id: int | None = None
        self._last_event_at: str | None = None
        self._last_error: str | None = None

    def _utc_now(self) -> str:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("status clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc).isoformat()

    def mark_active(self) -> None:
        with self._lock:
            self._state = LiveIngestionState.ACTIVE
            self._last_error = None

    def mark_inactive(self) -> None:
        with self._lock:
            if self._state != LiveIngestionState.ERROR:
                self._state = LiveIngestionState.INACTIVE

    def record_event(self, event_id: int) -> None:
        occurred_at = self._utc_now()
        with self._lock:
            self._last_event_id = event_id
            self._last_event_at = occurred_at

    def record_error(self, error: BaseException) -> None:
        # Die API nennt nur die Fehlerklasse. Details bleiben in der lokalen
        # Konsolenausgabe und können so keine internen Informationen offenlegen.
        safe_message = f"Live-Ingestion fehlgeschlagen ({type(error).__name__})."
        with self._lock:
            self._state = LiveIngestionState.ERROR
            self._last_error = safe_message

    def snapshot(self) -> LiveSystemSnapshot:
        with self._lock:
            return LiveSystemSnapshot(
                live_ingestion=self._state,
                log_file=self._log_file,
                started_at=self._started_at,
                last_event_id=self._last_event_id,
                last_event_at=self._last_event_at,
                last_error=self._last_error,
            )
