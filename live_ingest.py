"""Command-line entry point for continuous SSH log ingestion."""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Sequence
from pathlib import Path

from brute_force_detection import DetectionOutcome, SSHBruteForceDetector
from database import DEFAULT_DATABASE_PATH, Database
from file_tailer import FileTailer
from live_ingestion import LiveIngestionService


def _positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return number


def _minimum_two_int(value: str) -> int:
    number = int(value)
    if number < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return number


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor a local SSH log file and store new events.",
    )
    parser.add_argument("--log-file", required=True, type=Path, help="Log file to monitor")
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE_PATH,
        help=f"SQLite file (default: {DEFAULT_DATABASE_PATH})",
    )
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


def run(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    database = Database(args.database)
    database.initialize()
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

    print(f"Log file: {args.log_file}")
    print(f"Database: {args.database}")
    print("Monitoring is running. Press Ctrl+C to stop.")

    try:
        for line in tailer.follow():
            result = service.ingest_line_with_detection(line)
            if result.event_id is None:
                continue
            event = database.get_event(result.event_id)
            assert event is not None
            print(
                f"Event {result.event_id}: {event['event_type']} "
                f"{event['ip_address']} ({event['event_timestamp']})"
            )
            if result.detection.outcome == DetectionOutcome.CREATED:
                print(f"Alert {result.detection.alert_id} created: SSH_BRUTE_FORCE")
            elif result.detection.outcome == DetectionOutcome.UPDATED:
                print(f"Alert {result.detection.alert_id} updated: SSH_BRUTE_FORCE")
    except KeyboardInterrupt:
        tailer.stop()
        print("\nMonitoring stopped.")
        return 0
    except OSError as exc:
        print(f"Error while monitoring the log file: {exc}", file=sys.stderr)
        return 1
    finally:
        tailer.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
