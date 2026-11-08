"""Finite checksum work over synthetic logs and readers."""
from __future__ import annotations

import io
import threading
from pathlib import Path
from typing import Any

import pytest

from opsgate import runner

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_admitted_length_and_independent_digest(tmp_path: Path) -> None:
    path = tmp_path / "log"
    path.write_bytes(b"abc")
    assert runner._sha256(path, deadline=float("inf"), stop_event=threading.Event()) == (3, ABC_SHA256)


@pytest.mark.parametrize("budget", ["bytes", "deadline", "cancellation", "short_read"])
def test_no_partial_checksum(budget: str, monkeypatch: pytest.MonkeyPatch) -> None:
    event = threading.Event()
    source = io.BytesIO(b"abc")
    deadline = float("inf")
    if budget == "bytes":
        monkeypatch.setattr(runner, "LOG_CHECKSUM_MAX_BYTES", 2)
    elif budget == "deadline":
        # Expire after the first read, before publishing a complete digest.
        ticks = iter([0.0, 2.0])
        monkeypatch.setattr(runner.time, "monotonic", lambda: next(ticks))
        deadline = 1.0
    elif budget == "cancellation":
        event.set()
    else:
        source = io.BytesIO(b"ab")
    assert runner._hash_snapshot(source, 3, deadline=deadline, stop_event=event) is None


def test_growing_reader_stops_at_admitted_length() -> None:
    class GrowingReader:
        consumed = 0

        def read(self, size: int) -> bytes:
            assert size > 0
            self.consumed += size
            assert self.consumed <= 3
            return b"abc"[:size]

    source = GrowingReader()
    assert runner._hash_snapshot(source, 3, deadline=float("inf"), stop_event=threading.Event()) == ABC_SHA256
    assert source.consumed == 3


def test_changed_log_has_no_full_checksum(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "log"
    path.write_bytes(b"abc")
    original_open = runner.open_regular

    class GrowingFile:
        def __enter__(self) -> Any:
            self.handle = original_open(path)
            return self

        def __exit__(self, *args: Any) -> None:
            self.handle.close()

        def fileno(self) -> int:
            return self.handle.fileno()

        def read(self, size: int) -> bytes:
            with path.open("ab") as append:
                append.write(b"more")
            return bytes(self.handle.read(size))

    monkeypatch.setattr(runner, "open_regular", lambda _: GrowingFile())
    assert runner._sha256(path, deadline=float("inf"), stop_event=threading.Event()) == (3, None)
