import threading
from pathlib import Path

import pytest

from file_tailer import FileTailer


def append(path: Path, content: str) -> None:
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(content)


def append_bytes(path: Path, content: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(content)


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_rejects_invalid_poll_interval(tmp_path: Path, interval: float) -> None:
    with pytest.raises(ValueError):
        FileTailer(tmp_path / "auth.log", poll_interval=interval)


def test_starts_at_end(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("existing line\n", encoding="utf-8")

    with FileTailer(path) as tailer:
        assert tailer.poll() == []


def test_reads_newly_appended_complete_line(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()

    with FileTailer(path) as tailer:
        append(path, "new line\n")
        assert tailer.poll() == ["new line"]
        assert tailer.poll() == []


def test_reopening_does_not_replay_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("existing\n", encoding="utf-8")
    tailer = FileTailer(path)

    tailer.start()
    append(path, "first new line\n")
    assert tailer.poll() == ["first new line"]
    tailer.close()

    tailer.start()
    assert tailer.poll() == []
    tailer.close()


def test_can_start_at_beginning(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("first\nsecond\n", encoding="utf-8")

    with FileTailer(path, from_start=True) as tailer:
        assert tailer.poll() == ["first", "second"]


def test_buffers_incomplete_line_until_newline_arrives(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()

    with FileTailer(path) as tailer:
        append(path, "incomplete")
        assert tailer.poll() == []

        append(path, " line\n")
        assert tailer.poll() == ["incomplete line"]


def test_buffers_split_multibyte_utf8_character(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()
    encoded = "Grüsse".encode("utf-8")
    split_at = encoded.index(b"\xc3") + 1

    with FileTailer(path) as tailer:
        append_bytes(path, encoded[:split_at])
        assert tailer.poll() == []
        append_bytes(path, encoded[split_at:] + b"\n")
        assert tailer.poll() == ["Grüsse"]


def test_invalid_utf8_is_reported_and_handle_is_closed(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_bytes(b"\xff\n")
    tailer = FileTailer(path, from_start=True)

    with pytest.raises(UnicodeDecodeError), tailer:
        tailer.poll()

    assert tailer._file is None


def test_reads_multiple_lines_and_preserves_empty_lines(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()

    with FileTailer(path) as tailer:
        append(path, "first\n\nthird\n")
        assert tailer.poll() == ["first", "", "third"]


def test_detects_truncation_and_reads_rewritten_file(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("old\n", encoding="utf-8")

    with FileTailer(path) as tailer:
        path.write_text("a longer replacement line\n", encoding="utf-8")
        assert tailer.poll() == ["a longer replacement line"]

        path.write_text("", encoding="utf-8")
        assert tailer.poll() == []
        append(path, "after clear\n")
        assert tailer.poll() == ["after clear"]


def test_detects_rotation_and_reads_old_remainder_then_new_file(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    rotated_path = tmp_path / "auth.log.1"
    path.write_text("existing\n", encoding="utf-8")

    with FileTailer(path) as tailer:
        append(path, "last old line\n")
        path.rename(rotated_path)
        path.write_text("first new line\n", encoding="utf-8")

        assert tailer.poll() == ["last old line", "first new line"]


def test_stop_wakes_follow_loop_and_closes_file(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()
    tailer = FileTailer(path, poll_interval=30)
    tailer.start()
    collected: list[str] = []
    thread = threading.Thread(target=lambda: collected.extend(tailer.follow()))

    thread.start()
    tailer.stop()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert collected == []
    assert tailer._file is None


def test_stop_before_follow_is_not_lost(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.touch()
    tailer = FileTailer(path, poll_interval=30)
    tailer.stop()
    thread = threading.Thread(target=lambda: list(tailer.follow()))

    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert tailer._file is None
