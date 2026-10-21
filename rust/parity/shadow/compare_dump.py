"""Compare the data-parity records of Python and Rust (rust/PLAN.md 11.2 step 1).

Usage::

    python3 rust/parity/shadow/compare_dump.py python.jsonl rust.jsonl

``python.jsonl`` comes from ``serialize_python.py``, ``rust.jsonl`` from ``opsgate check-db --db <copy> --dump``
(record keys: ``serialize_python.py``). Records are paired by position and must name the same ``rowid`` and ``id``;
every key is compared by its canonical JSON text (``json.dumps(sort_keys=True)`` of the decoded value, so number
formatting does not matter but ``1``, ``1.0`` and ``true`` differ). Differences name the row and the key, never a
value. Exit status 0 when there are none, which includes "every approval checksum that matched in Python matches in
Rust"; 1 otherwise. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

KEYS = (
    "rowid",
    "id",
    "ticket",
    "ticket_error",
    "approval_checksum",
    "approval_checksum_error",
    "approved_payload_checksum",
    "approval_checksum_matches",
)
MAX_LISTED = 50


def load(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as lines:
        return [json.loads(line) for line in lines if line.strip()]


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def compare(python: list[dict[str, Any]], rust: list[dict[str, Any]]) -> list[str]:
    differences = []
    if len(python) != len(rust):
        differences.append(f"record count: python {len(python)}, rust {len(rust)}")
    for python_record, rust_record in zip(python, rust, strict=False):
        name = f"rowid {python_record.get('rowid')} id {python_record.get('id')}"
        for key in KEYS:
            if key not in python_record or key not in rust_record:
                differences.append(f"{name}: {key} missing")
            elif canonical(python_record[key]) != canonical(rust_record[key]):
                differences.append(f"{name}: {key} differs")
    return differences


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("python", type=Path)
    parser.add_argument("rust", type=Path)
    args = parser.parse_args(argv)
    python, rust = load(args.python), load(args.rust)
    differences = compare(python, rust)
    print(f"tickets: python {len(python)}, rust {len(rust)}")
    for name, records in (("python", python), ("rust", rust)):
        approved = sum(1 for record in records if record.get("approved_payload_checksum"))
        matching = sum(1 for record in records if record.get("approval_checksum_matches") is True)
        print(f"approval checksums ({name}): {approved} stored, {matching} matching")
    print(f"differences: {len(differences)}")
    for difference in differences[:MAX_LISTED]:
        print(f"  {difference}")
    if len(differences) > MAX_LISTED:
        print(f"  ... and {len(differences) - MAX_LISTED} more")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
