"""Write the data-parity records of an OpsGate database with the Python service (rust/PLAN.md 11.2 step 1).

Usage (with the interpreter of the deployed venv, which can import ``opsgate``)::

    .venv/bin/python rust/parity/shadow/serialize_python.py --db COPY.sqlite3 --out python.jsonl

``opsgate check-db --db COPY.sqlite3 --dump rust.jsonl`` writes the same records with the Rust store, and
``compare_dump.py python.jsonl rust.jsonl`` compares both. One JSON line per ``tickets`` row, in rowid order:

- ``rowid``, ``id``;
- ``ticket``: ``_serialize_ticket`` of the row (what ``GET /api/v1/tickets/<id>`` returns), or ``null`` with
  ``ticket_error``;
- ``approval_checksum``: the payload checksum ``approve_ticket`` computes from the stored fields, or ``null`` with
  ``approval_checksum_error`` (the ``ServiceError`` code, ``"unhandled"`` for any other exception);
- ``approved_payload_checksum`` as stored, and ``approval_checksum_matches``: the stored checksum is non-empty and
  equals the recomputed one (what the claim's tamper check requires).

The database is opened read-only and ``OpsGateService.__init__`` (which initialises the database) is never run. The
output contains prompts and contexts: it is created new (never overwriting a file) with mode 0600.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from opsgate.service import (
    OpsGateService,
    ServiceError,
    compute_payload_checksum,
    enforce_policy_against_plan,
    parse_execution_plan,
)


def approval_checksum(service: OpsGateService, row: sqlite3.Row) -> str:
    """The statements of ``OpsGateService.approve_ticket`` that compute ``approved_payload_checksum``."""
    execution_plan = parse_execution_plan(json.loads(row["execution_plan_json"]))
    policy_requirements = json.loads(row["policy_requirements_json"])
    enforce_policy_against_plan(policy_requirements, execution_plan)
    payload_for_checksum = service._ticket_payload_from_fields(
        source=row["source"],
        task_ref=row["task_ref"],
        title=row["title"],
        summary=row["summary"],
        execution_plan=execution_plan,
        policy_requirements=policy_requirements,
        context=json.loads(row["context_json"]),
        expires_at=row["expires_at"],
        max_duration_seconds=int(row["max_duration_seconds"]),
    )
    return compute_payload_checksum(payload_for_checksum)


def error_kind(exc: Exception) -> str:
    return exc.error_code if isinstance(exc, ServiceError) else "unhandled"


def record(service: OpsGateService, row: sqlite3.Row) -> dict[str, Any]:
    result: dict[str, Any] = {"rowid": row["_rowid"], "id": row["id"]}
    try:
        result["ticket"] = service._serialize_ticket(row)
        result["ticket_error"] = None
    except Exception as exc:  # noqa: BLE001 - the API answers 500
        result["ticket"] = None
        result["ticket_error"] = error_kind(exc)
    stored = row["approved_payload_checksum"]
    try:
        checksum = approval_checksum(service, row)
    except Exception as exc:  # noqa: BLE001 - the API answers 500
        result["approval_checksum"] = None
        result["approval_checksum_error"] = error_kind(exc)
        matches = False
    else:
        result["approval_checksum"] = checksum
        result["approval_checksum_error"] = None
        matches = bool(stored) and stored == checksum
    result["approved_payload_checksum"] = stored
    result["approval_checksum_matches"] = matches
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--db", required=True, type=Path, help="the database (opened read-only)")
    parser.add_argument("--out", required=True, type=Path, help="the new JSON-lines file")
    args = parser.parse_args(argv)

    connection = sqlite3.connect(f"{args.db.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    # `__init__` would create and migrate the database; the two methods used need no state.
    service = OpsGateService.__new__(OpsGateService)
    tickets = approved = matching = 0
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as out:
            for row in connection.execute("SELECT rowid AS _rowid, * FROM tickets ORDER BY rowid"):
                line = record(service, row)
                tickets += 1
                approved += bool(line["approved_payload_checksum"])
                matching += line["approval_checksum_matches"]
                out.write(json.dumps(line, sort_keys=True) + "\n")
    finally:
        connection.close()
    print(f"dump: {args.out} ({tickets} tickets, {approved} with an approval checksum, {matching} matching)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
