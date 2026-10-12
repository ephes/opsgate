"""Bounded previews of retained UTF-8 logs; full log views remain separate."""

from pathlib import Path

TAIL_BYTE_LIMIT = 64 * 1024
LINE_BYTE_LIMIT = 2048
TRUNCATION_MARKER = "[log preview truncated]"


def read_tail_lines(path: Path, max_lines: int = 40) -> list[str]:
    if max_lines <= 0:
        return []
    try:
        with path.open("rb") as handle:
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
