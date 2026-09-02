import argparse
import threading
from pathlib import Path

import pytest

import run_live
from brute_force_detection import BruteForceDetectionResult, DetectionOutcome
from live_ingestion import LiveIngestionResult
from runtime_status import LiveIngestionState, LiveSystemStatus


class BlockingTailer:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.stopped = threading.Event()
        self.closed = threading.Event()

    def follow(self):
        self.started.set()
        while not self.stopped.wait(0.05):
            if False:
                yield ""

    def stop(self) -> None:
        self.stopped.set()

    def close(self) -> None:
        self.closed.set()


class NoopService:
    def ingest_line_with_detection(self, line: str) -> LiveIngestionResult:
        raise AssertionError(f"unexpected line: {line}")


def _arguments(tmp_path: Path) -> argparse.Namespace:
    log_file = tmp_path / "auth.log"
    log_file.touch()
    return run_live.build_argument_parser().parse_args(
        ["--log-file", str(log_file), "--database", str(tmp_path / "sentinel.db")]
    )


def test_import_does_not_start_live_ingestion_thread() -> None:
    assert all(thread.name != run_live.THREAD_NAME for thread in threading.enumerate())


def test_web_and_ingestion_share_the_same_database(tmp_path: Path) -> None:
    live = run_live.build_live_application(_arguments(tmp_path))

    assert live.database is live.app.state.database
    assert live.worker.database is live.database
    assert live.worker.service.database is live.database
    assert live.database.path == tmp_path / "sentinel.db"
    assert not live.worker.is_alive


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--port", "0"),
        ("--port", "65536"),
        ("--poll-interval", "0"),
        ("--poll-interval", "nan"),
        ("--brute-force-threshold", "1"),
        ("--brute-force-window", "inf"),
        ("--brute-force-window", "-1"),
    ],
)
def test_cli_rejects_invalid_numeric_options(
    tmp_path: Path,
    option: str,
    value: str,
) -> None:
    log_file = tmp_path / "auth.log"
    log_file.touch()

    with pytest.raises(SystemExit) as exc_info:
        run_live.build_argument_parser().parse_args(
            ["--log-file", str(log_file), option, value]
        )

    assert exc_info.value.code == 2


def test_cli_defaults_match_existing_components(tmp_path: Path) -> None:
    args = _arguments(tmp_path)

    assert args.host == "127.0.0.1"
    assert args.port == 8000
    assert args.poll_interval == 0.5
    assert args.brute_force_threshold == 5
    assert args.brute_force_window == 60.0
    assert args.from_start is False


def test_cli_rejects_missing_and_non_regular_log_file(tmp_path: Path) -> None:
    parser = run_live.build_argument_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--log-file", str(tmp_path / "missing.log")])
    with pytest.raises(SystemExit):
        parser.parse_args(["--log-file", str(tmp_path)])


def test_worker_starts_and_stops_with_bounded_join(tmp_path: Path) -> None:
    tailer = BlockingTailer()
    status = LiveSystemStatus(tmp_path / "auth.log")
    database = run_live.Database(tmp_path / "events.db")
    worker = run_live.LiveIngestionWorker(
        database,
        tailer,  # type: ignore[arg-type]
        NoopService(),  # type: ignore[arg-type]
        status,
    )

    worker.start()
    assert tailer.started.wait(1)
    assert worker.is_alive
    assert status.snapshot().live_ingestion == LiveIngestionState.ACTIVE

    assert worker.stop(timeout=1)
    assert not worker.is_alive
    assert tailer.closed.is_set()
    assert status.snapshot().live_ingestion == LiveIngestionState.INACTIVE


def test_worker_cleanup_is_safe_when_thread_cannot_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnstartableThread:
        def __init__(self, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("thread unavailable")

    tailer = BlockingTailer()
    status = LiveSystemStatus(tmp_path / "auth.log")
    worker = run_live.LiveIngestionWorker(
        run_live.Database(tmp_path / "events.db"),
        tailer,  # type: ignore[arg-type]
        NoopService(),  # type: ignore[arg-type]
        status,
    )
    monkeypatch.setattr(run_live.threading, "Thread", UnstartableThread)

    with pytest.raises(RuntimeError, match="thread unavailable"):
        worker.start()

    assert worker.stop(timeout=0.01)
    assert tailer.closed.is_set()
    assert status.snapshot().live_ingestion == LiveIngestionState.ERROR


def test_unified_run_uses_no_reload_and_stops_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _arguments(tmp_path)
    captured: dict[str, object] = {}

    monkeypatch.setattr(run_live, "port_is_available", lambda host, port: True)

    def fake_uvicorn_run(application, **options):
        captured.update(app=application, **options)

    monkeypatch.setattr(run_live.uvicorn, "run", fake_uvicorn_run)

    result = run_live.run(
        ["--log-file", str(args.log_file), "--database", str(args.database)]
    )

    assert result == 0
    assert captured["reload"] is False
    assert captured["workers"] == 1
    assert captured["lifespan"] == "off"
    assert all(thread.name != run_live.THREAD_NAME for thread in threading.enumerate())


def test_occupied_port_is_reported_before_ingestion_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _arguments(tmp_path)
    monkeypatch.setattr(run_live, "port_is_available", lambda host, port: False)

    result = run_live.run(["--log-file", str(args.log_file)])

    assert result == 1
    assert "unavailable" in capsys.readouterr().err
    assert all(thread.name != run_live.THREAD_NAME for thread in threading.enumerate())


def test_worker_records_successful_event() -> None:
    class OneLineTailer:
        def follow(self):
            yield "supported"

        def stop(self) -> None:
            pass

        def close(self) -> None:
            pass

    class OneEventService:
        def ingest_line_with_detection(self, line: str) -> LiveIngestionResult:
            return LiveIngestionResult(
                event_id=42,
                detection=BruteForceDetectionResult(DetectionOutcome.NO_ALERT, 42),
            )

    status = LiveSystemStatus("auth.log")
    worker = run_live.LiveIngestionWorker(
        run_live.Database(":memory:"),
        OneLineTailer(),  # type: ignore[arg-type]
        OneEventService(),  # type: ignore[arg-type]
        status,
        on_error=lambda error: None,
    )

    worker.start()
    worker.join(1)
    snapshot = status.snapshot()

    assert snapshot.last_event_id == 42
    assert snapshot.last_event_at is not None
    assert snapshot.live_ingestion == LiveIngestionState.ERROR
    assert snapshot.last_error == "Live ingestion failed (RuntimeError)."
