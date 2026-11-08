"""Bounded previews of retained UTF-8 logs; step log views."""

import os
import stat
from contextlib import nullcontext
from pathlib import Path
from typing import BinaryIO

TAIL_BYTE_LIMIT = 64 * 1024
LINE_BYTE_LIMIT = 2048
TRUNCATION_MARKER = "[log preview truncated]"


def open_regular(path: Path) -> BinaryIO:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    handle = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        handle.close()
        raise OSError("log is not a regular file")
    return handle


def open_beneath(root: Path, relative: Path) -> BinaryIO:
    """Pin every directory and reject aliases while opening an admitted log."""
    parts = relative.parts
    if not parts or relative.is_absolute() or any(part in (".", "..") for part in parts):
        raise OSError("invalid log path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        handle = os.fdopen(fd, "rb")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            handle.close()
            raise OSError("log is not a regular file")
        return handle
    finally:
        os.close(directory)


def read_tail_lines(path: Path | BinaryIO, max_lines: int = 40) -> list[str]:
    if max_lines <= 0:
        return []
    try:
        with open_regular(path) if isinstance(path, Path) else nullcontext(path) as handle:
            size = handle.seek(0, 2)
            start = max(0, size - TAIL_BYTE_LIMIT)
            handle.seek(start)
            data = handle.read(TAIL_BYTE_LIMIT)
    except FileNotFoundError:
        return []

    # Normalize the same newline forms as a text-mode log reader.
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    truncated = start > 0 or len(lines) > max_lines
    result = []
    for line in lines[-max_lines:]:
        if len(line) > LINE_BYTE_LIMIT:
            line = line[-LINE_BYTE_LIMIT:]
            truncated = True
        # A byte-window or line boundary may split a UTF-8 character.
        result.append(line.decode("utf-8", errors="replace"))
    if truncated:
        result.insert(0, TRUNCATION_MARKER)
    return result


STEP_LOG_BYTE_LIMIT = 2 * 1024 * 1024
STEP_LOG_TRUNCATION_MARKER = "[step log truncated]"


def read_step_log(path: Path | BinaryIO) -> str:
    """Read at most the final 2 MiB, preserving small logs in full."""
    with open_regular(path) if isinstance(path, Path) else nullcontext(path) as handle:
        size = handle.seek(0, 2)
        start = max(0, size - STEP_LOG_BYTE_LIMIT)
        handle.seek(start)
        data = handle.read(STEP_LOG_BYTE_LIMIT)
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return f"{STEP_LOG_TRUNCATION_MARKER}\n{text}" if start else text
