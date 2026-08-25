"""Kommandozeilenstart für die fortlaufende SSH-Log-Ingestion."""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Sequence
from pathlib import Path

from database import DEFAULT_DATABASE_PATH, Database
from file_tailer import FileTailer
from live_ingestion import LiveIngestionService


def _positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("muss endlich und grösser als null sein")
    return number


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Überwacht eine lokale SSH-Logdatei und speichert neue Events.",
    )
    parser.add_argument("--log-file", required=True, type=Path, help="Zu überwachende Logdatei")
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE_PATH,
        help=f"SQLite-Datei (Standard: {DEFAULT_DATABASE_PATH})",
    )
    parser.add_argument(
        "--poll-interval",
        type=_positive_float,
        default=0.5,
        help="Polling-Intervall in Sekunden (Standard: 0.5)",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Vorhandene Dateiinhalte beim Start ebenfalls einlesen",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    database = Database(args.database)
    database.initialize()
    service = LiveIngestionService(database, args.log_file)
    tailer = FileTailer(
        args.log_file,
        poll_interval=args.poll_interval,
        from_start=args.from_start,
    )

    print(f"Logdatei: {args.log_file}")
    print(f"Datenbank: {args.database}")
    print("Überwachung läuft. Zum Beenden Ctrl+C drücken.")

    try:
        for line in tailer.follow():
            event_id = service.ingest_line(line)
            if event_id is None:
                continue
            event = database.get_event(event_id)
            assert event is not None
            print(
                f"Event {event_id}: {event['event_type']} "
                f"{event['ip_address']} ({event['event_timestamp']})"
            )
    except KeyboardInterrupt:
        tailer.stop()
        print("\nÜberwachung beendet.")
        return 0
    except OSError as exc:
        print(f"Fehler beim Überwachen der Logdatei: {exc}", file=sys.stderr)
        return 1
    finally:
        tailer.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
