"""Unified startup for the FastAPI dashboard and live ingestion."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from brute_force_detection import DetectionOutcome, SSHBruteForceDetector
from database import DEFAULT_DATABASE_PATH, Database
from file_tailer import FileTailer
from launcher import DEFAULT_HOST, DEFAULT_PORT, port_is_available
from live_ingest import _minimum_two_int, _positive_float
from live_ingestion import LiveIngestionResult, LiveIngestionService
from main import create_app
from runtime_status import LiveSystemStatus


THREAD_NAME = "ssh-sentinel-live-ingestion"
DEFAULT_JOIN_TIMEOUT = 5.0


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def _readable_log_file(value: str) -> Path:
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Log file does not exist: {path}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Log path is not a regular file: {path}")
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        raise argparse.ArgumentTypeError(f"Log file is not readable: {path}") from exc
    return path


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Start SSH Sentinel with the dashboard and live ingestion.",
    )
    parser.add_argument(
        "--log-file",
        required=True,
        type=_readable_log_file,
        help="Regular, readable log file to monitor",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE_PATH,
        help=f"SQLite file (default: {DEFAULT_DATABASE_PATH})",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"HTTP host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT, help=f"HTTP port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--poll-interval",
        type=_positive_float,
        default=0.5,
        help="Polling interval in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Also read existing file content at startup",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=_minimum_two_int,
        default=SSHBruteForceDetector.DEFAULT_THRESHOLD,
        help="Failed attempts required for an alert (default: 5)",
    )
    parser.add_argument(
        "--brute-force-window",
        type=_positive_float,
        default=SSHBruteForceDetector.DEFAULT_WINDOW_SECONDS,
        help="Detection window in seconds (default: 60)",
    )
    return parser


class LiveIngestionWorker:
    """Run the existing ingestion in exactly one controlled thread."""

    def __init__(
        self,
        database: Database,
        tailer: FileTailer,
        service: LiveIngestionService,
        status: LiveSystemStatus,
        *,
        on_result: Callable[[LiveIngestionResult], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self.database = database
        self.tailer = tailer
        self.service = service
        self.status = status
        self._on_result = on_result
        self._on_error = on_error or self._print_error
        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None

    @staticmethod
    def _print_error(error: BaseException) -> None:
        print(f"Live ingestion error: {error}", file=sys.stderr)

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("Live ingestion has already been started")
        self.status.mark_active()
        self._thread = threading.Thread(
            target=self._run,
            name=THREAD_NAME,
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception as exc:
            self._thread = None
            self.error = exc
            self.status.record_error(exc)
            raise

    def _run(self) -> None:
        try:
            for line in self.tailer.follow():
                result = self.service.ingest_line_with_detection(line)
                if result.event_id is not None:
                    self.status.record_event(result.event_id)
                if self._on_result is not None:
                    self._on_result(result)
            if not self._stop_requested.is_set():
                raise RuntimeError("Live ingestion stopped unexpectedly")
        except Exception as exc:
            self.error = exc
            self.status.record_error(exc)
            self._on_error(exc)
        finally:
            self.tailer.close()
            if self.error is None:
                self.status.mark_inactive()

    def stop(self, timeout: float = DEFAULT_JOIN_TIMEOUT) -> bool:
        self._stop_requested.set()
        self.tailer.stop()
        thread = self._thread
        if thread is None:
            self.tailer.close()
            self.status.mark_inactive()
            return True
        thread.join(timeout)
        if thread.is_alive():
            error = RuntimeError("Live ingestion did not stop within the timeout")
            self.error = error
            self.status.record_error(error)
            self._on_error(error)
            return False
        return True

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)


@dataclass(frozen=True, slots=True)
class LiveApplication:
    app: FastAPI
    database: Database
    status: LiveSystemStatus
    worker: LiveIngestionWorker
    dashboard_url: str


def _display_result(database: Database, result: LiveIngestionResult) -> None:
    if result.event_id is None:
        return
    event = database.get_event(result.event_id)
    if event is None:
        raise RuntimeError(f"Stored event {result.event_id} was not found")
    print(
        f"Event {result.event_id}: {event['event_type']} "
        f"{event['ip_address']} ({event['event_timestamp']})"
    )
    if result.detection.outcome == DetectionOutcome.CREATED:
        print(f"Alert {result.detection.alert_id} created: SSH_BRUTE_FORCE")
    elif result.detection.outcome == DetectionOutcome.UPDATED:
        print(f"Alert {result.detection.alert_id} updated: SSH_BRUTE_FORCE")


def build_live_application(args: argparse.Namespace) -> LiveApplication:
    status = LiveSystemStatus(args.log_file)
    app = create_app(args.database, system_status=status)
    database: Database = app.state.database
    detector = SSHBruteForceDetector(
        database,
        threshold=args.brute_force_threshold,
        window_seconds=args.brute_force_window,
    )
    service = LiveIngestionService(database, args.log_file, detector=detector)
    tailer = FileTailer(
        args.log_file,
        poll_interval=args.poll_interval,
        from_start=args.from_start,
    )
    worker = LiveIngestionWorker(
        database,
        tailer,
        service,
        status,
        on_result=lambda result: _display_result(database, result),
    )
    browser_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    return LiveApplication(
        app=app,
        database=database,
        status=status,
        worker=worker,
        dashboard_url=f"http://{browser_host}:{args.port}/dashboard",
    )


def run(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    if not port_is_available(args.host, args.port):
        print(
            f"Error: port {args.port} on host {args.host} is unavailable.",
            file=sys.stderr,
        )
        return 1

    try:
        live = build_live_application(args)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"Error while initializing SSH Sentinel: {exc}", file=sys.stderr)
        return 1

    print(f"Log file: {args.log_file}")
    print(f"Database: {args.database}")
    print(f"Dashboard: {live.dashboard_url}")
    print("Live operation is running. Press Ctrl+C to stop.")

    exit_code = 0
    try:
        live.worker.start()
        uvicorn.run(
            live.app,
            host=args.host,
            port=args.port,
            loop="asyncio",
            http="h11",
            lifespan="off",
            reload=False,
            workers=1,
        )
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError) as exc:
        print(f"Unified live operation error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        if not live.worker.stop():
            exit_code = 1

    if live.worker.error is not None:
        exit_code = 1
    print("SSH Sentinel stopped.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run())
