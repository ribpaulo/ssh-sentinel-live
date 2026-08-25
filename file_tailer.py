"""Polling-basierter Tailer für fortlaufend ergänzte Logdateien."""

from __future__ import annotations

import math
import os
import threading
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Iterator


FileIdentity = tuple[int, int]


class FileTailer:
    """Liest ausschliesslich neu verfügbare, vollständige Zeilen einer Datei."""

    def __init__(
        self,
        path: str | Path,
        poll_interval: float = 0.5,
        *,
        from_start: bool = False,
    ) -> None:
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be finite and greater than zero")

        self.path = Path(path)
        self.poll_interval = poll_interval
        self.from_start = from_start
        self._file: BinaryIO | None = None
        self._identity: FileIdentity | None = None
        self._buffer = b""
        self._checkpoint: tuple[int, bytes] = (0, b"")
        self._stop_event = threading.Event()
        self._rotation_pending = False

    @staticmethod
    def _file_identity(stat_result: os.stat_result) -> FileIdentity:
        return stat_result.st_dev, stat_result.st_ino

    def _open(self, *, at_end: bool) -> None:
        handle = self.path.open("rb")
        try:
            if at_end:
                handle.seek(0, os.SEEK_END)
            identity = self._file_identity(os.fstat(handle.fileno()))
            self._file = handle
            self._identity = identity
            self._update_checkpoint()
        except Exception:
            self._file = None
            self._identity = None
            self._checkpoint = (0, b"")
            handle.close()
            raise

    def start(self) -> None:
        """Öffnet die Datei und legt die initiale Leseposition fest."""

        if self._file is not None:
            return
        self._buffer = b""
        self._open(at_end=not self.from_start and not self._rotation_pending)
        self._rotation_pending = False

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._identity = None
        self._buffer = b""
        self._checkpoint = (0, b"")

    def __enter__(self) -> FileTailer:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _read_complete_lines(self) -> list[str]:
        if self._file is None:
            return []

        data = self._buffer + self._file.read()
        self._update_checkpoint()
        chunks = data.split(b"\n")
        self._buffer = chunks.pop()
        return [chunk.removesuffix(b"\r").decode("utf-8") for chunk in chunks]

    def _update_checkpoint(self) -> None:
        if self._file is None:
            self._checkpoint = (0, b"")
            return

        position = self._file.tell()
        start = max(0, position - 64)
        self._file.seek(start)
        data = self._file.read(position - start)
        self._file.seek(position)
        self._checkpoint = start, data

    def _checkpoint_changed(self) -> bool:
        if self._file is None:
            return False

        start, expected = self._checkpoint
        if not expected:
            return False
        position = self._file.tell()
        self._file.seek(start)
        current = self._file.read(len(expected))
        self._file.seek(position)
        return current != expected

    def _switch_to_rotated_file(self) -> list[str]:
        try:
            lines = self._read_complete_lines()
        finally:
            self.close()
        self._rotation_pending = True
        try:
            self._open(at_end=False)
        except FileNotFoundError:
            return lines
        self._rotation_pending = False
        return [*lines, *self._read_complete_lines()]

    def poll(self) -> list[str]:
        """Gibt alle seit dem letzten Aufruf vervollständigten Zeilen zurück."""

        if self._file is None:
            self.start()
        assert self._file is not None

        try:
            path_stat = self.path.stat()
        except FileNotFoundError:
            # Nach einem Rename kann der alte Handle noch letzte Daten enthalten.
            return self._read_complete_lines()

        if self._file_identity(path_stat) != self._identity:
            return self._switch_to_rotated_file()

        if path_stat.st_size < self._file.tell() or self._checkpoint_changed():
            self._file.seek(0)
            self._buffer = b""
            self._checkpoint = (0, b"")

        return self._read_complete_lines()

    def stop(self) -> None:
        """Beendet eine laufende follow-Schleife und weckt deren Wartephase auf."""

        self._stop_event.set()

    def follow(self) -> Iterator[str]:
        """Liefert Zeilen bis stop aufgerufen oder die Iteration abgebrochen wird."""

        self.start()
        try:
            while not self._stop_event.is_set():
                yield from self.poll()
                self._stop_event.wait(self.poll_interval)
        finally:
            self.close()
