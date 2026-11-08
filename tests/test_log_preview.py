from pathlib import Path
from typing import Any

import pytest

from opsgate.log_preview import (
    LINE_BYTE_LIMIT,
    STEP_LOG_BYTE_LIMIT,
    STEP_LOG_TRUNCATION_MARKER,
    TAIL_BYTE_LIMIT,
    TRUNCATION_MARKER,
    read_step_log,
    read_tail_lines,
)
from opsgate.runner import _tail_lines


@pytest.mark.parametrize("reader", [read_tail_lines, _tail_lines, read_step_log])
def test_large_log_reads_only_bounded_tail(tmp_path: Path, monkeypatch: Any, reader: Any) -> None:
    path = tmp_path / "session.log"
    budget = STEP_LOG_BYTE_LIMIT if reader is read_step_log else TAIL_BYTE_LIMIT
    path.write_bytes(b"x" * (budget * 3) + b"\nlast line\n")
    from opsgate.log_preview import open_regular
    original_open = open_regular
    reads: list[int] = []

    class GuardedFile:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: Any) -> None:
            self.handle.close()

        def seek(self, offset: int, whence: int = 0) -> int:
            return int(self.handle.seek(offset, whence))

        def read(self, size: int = -1) -> bytes:
            assert 0 <= size <= budget
            reads.append(size)
            return bytes(self.handle.read(size))

    def guarded_open(path: Path) -> Any:
        return GuardedFile(original_open(path))

    monkeypatch.setattr("opsgate.log_preview.open_regular", guarded_open)
    lines = reader(path)
    assert reads == [budget]
    if reader is read_step_log:
        assert lines.startswith(STEP_LOG_TRUNCATION_MARKER + "\n")
        assert lines.endswith("last line\n")
        return
    assert lines[0] == TRUNCATION_MARKER
    assert lines[-1] == "last line"
    assert len(lines[1]) == LINE_BYTE_LIMIT


@pytest.mark.parametrize("reader", [read_tail_lines, _tail_lines])
def test_normal_final_40_lines(tmp_path: Path, reader: Any) -> None:
    path = tmp_path / "session.log"
    path.write_text("".join(f"line {i}\n" for i in range(45)))
    assert reader(path) == [TRUNCATION_MARKER] + [f"line {i}" for i in range(5, 45)]


def test_utf8_fragments_and_huge_single_line(tmp_path: Path) -> None:
    path = tmp_path / "session.log"
    path.write_bytes("€".encode() * TAIL_BYTE_LIMIT)
    lines = read_tail_lines(path)
    assert lines[0] == TRUNCATION_MARKER
    assert lines[1].startswith("\ufffd")
    assert lines[1].endswith("€")
    assert len(lines[1]) <= LINE_BYTE_LIMIT


@pytest.mark.parametrize("content, expected", [(b"", []), (b"a\r\nb\rc\n", ["a", "b", "c"]), (b"a\n\n", ["a", ""])])
def test_small_logs(tmp_path: Path, content: bytes, expected: list[str]) -> None:
    path = tmp_path / "session.log"
    assert read_tail_lines(path) == []
    path.write_bytes(content)
    assert read_tail_lines(path) == expected
    assert read_tail_lines(path, max_lines=0) == []


def test_tail_window_splits_utf8_character(tmp_path: Path, monkeypatch: Any) -> None:
    path = tmp_path / "session.log"
    path.write_bytes(b"xx" + "€".encode() + b"\nend!\n")
    monkeypatch.setattr("opsgate.log_preview.TAIL_BYTE_LIMIT", 8)
    assert read_tail_lines(path) == [TRUNCATION_MARKER, "\ufffd\ufffd", "end!"]


@pytest.mark.parametrize(
    "content, expected",
    [(b"12345678", "12345678"), (b"012345678", "[step log truncated]\n12345678"),
     (b"a\r\nb\rc", "a\nb\nc"), (b"xx" + "€".encode() + b"abcdef", "[step log truncated]\n\ufffd\ufffdabcdef")],
)
def test_step_log_boundaries(tmp_path: Path, monkeypatch: Any, content: bytes, expected: str) -> None:
    path = tmp_path / "session.log"
    path.write_bytes(content)
    monkeypatch.setattr("opsgate.log_preview.STEP_LOG_BYTE_LIMIT", 8)
    assert read_step_log(path) == expected


@pytest.mark.parametrize("swap_parent", [False, True])
def test_opened_log_survives_alias_swap(tmp_path: Path, swap_parent: bool) -> None:
    from opsgate.log_preview import open_beneath

    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "log").write_text("admitted")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "log").write_text("outside secret")
    with open_beneath(tmp_path, Path("inside/log")) as handle:
        if swap_parent:
            inside.rename(tmp_path / "retained")
            inside.symlink_to(outside, target_is_directory=True)
        else:
            (inside / "log").unlink()
            (inside / "log").symlink_to(outside / "log")
        assert read_step_log(handle) == "admitted"
        with pytest.raises(OSError):
            open_beneath(tmp_path, Path("inside/log"))


def test_special_log_admission_is_nonblocking(tmp_path: Path) -> None:
    import os

    from opsgate.log_preview import open_beneath

    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(OSError):
        open_beneath(tmp_path, Path("fifo"))
    (tmp_path / "alias").symlink_to(tmp_path / "fifo")
    with pytest.raises(OSError):
        read_step_log(tmp_path / "alias")
