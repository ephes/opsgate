"""Concurrency tests for ticket state transitions.

Each mutating service method reads a ticket, checks its state in Python and then
writes. These tests interleave a second writer between that read and the write
and check that the second writer can no longer be silently overwritten.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import bcrypt
import pytest

from opsgate.config import OpsGateSettings
from opsgate.service import OpsGateService, ServiceError, SubmitterContext

APPROVER = "opsgate-admin"
RUNNER_HOST = "runner-a"

# How long the first writer pauses between its read and its write while the
# second writer runs. Without serialization the second writer finishes well
# inside this window; with serialization it blocks until the first commits.
INTERLEAVE_WINDOW_SECONDS = 0.5


def _build_service(tmp_path: Path) -> OpsGateService:
    password_hash = bcrypt.hashpw(b"secret-password", bcrypt.gensalt(rounds=4)).decode("utf-8")
    settings = OpsGateSettings(
        service_name="opsgate",
        bind_host="127.0.0.1",
        bind_port=8711,
        db_path=str(tmp_path / "opsgate.sqlite3"),
        session_secret="x" * 32,
        trust_proxy_headers=False,
        session_cookie_secure=False,
        session_timeout_seconds=3600,
        ui_username=APPROVER,
        ui_password_bcrypt=password_hash,
        max_duration_seconds_default=3600,
        policy_floor_require_reviewer_step=False,
        runner_token="runner-token-000000000000",
        submitter_policies=(),
        require_tailscale_context=True,
        allowed_cidrs=("127.0.0.1/32",),
        execution_data_dir=str(tmp_path / "data"),
        disable_file_path=str(tmp_path / "opsgate.disabled"),
    )
    return OpsGateService(settings)


@pytest.fixture
def service(tmp_path: Path) -> OpsGateService:
    return _build_service(tmp_path)


def _create(service: OpsGateService, task_ref: str = "race-1") -> str:
    ticket = service.create_ticket(
        {
            "title": "Race",
            "summary": "Concurrent transition test",
            "task_ref": task_ref,
            "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}],
        },
        SubmitterContext(source="nyxmon", token="unused", require_reviewer_step_floor=False),
        source_ip="127.0.0.1",
        user_agent="pytest",
    )
    return str(ticket["id"])


def _approve(service: OpsGateService, ticket_id: str) -> dict[str, Any]:
    return service.approve_ticket(ticket_id, approver=APPROVER, source_ip=None, user_agent=None)


def _cancel(service: OpsGateService, ticket_id: str) -> dict[str, Any]:
    return service.cancel_ticket(ticket_id, approver=APPROVER, reason="stop", source_ip=None, user_agent=None)


def _reject(service: OpsGateService, ticket_id: str) -> dict[str, Any]:
    return service.reject_ticket(ticket_id, approver=APPROVER, reason="no", source_ip=None, user_agent=None)


def _runner_finish(service: OpsGateService, ticket_id: str, state: str = "succeeded") -> dict[str, Any]:
    return service.update_runner_status(
        ticket_id,
        runner_host=RUNNER_HOST,
        payload={"event": "ticket_succeeded", "state": state},
        source_ip=None,
        user_agent=None,
    )


def _claim(service: OpsGateService) -> dict[str, Any] | None:
    return service.claim_ticket(runner_host=RUNNER_HOST, source_ip=None, user_agent=None)


def _state(service: OpsGateService, ticket_id: str) -> str:
    return str(service.get_ticket(ticket_id)["state"])


def _audit(service: OpsGateService, ticket_id: str) -> list[tuple[str, str | None, str | None]]:
    with sqlite3.connect(service.settings.db_path) as conn:
        rows = conn.execute(
            "SELECT event_type, previous_state, new_state FROM audit_events WHERE ticket_id = ? ORDER BY id ASC",
            (ticket_id,),
        ).fetchall()
    return [(str(row[0]), row[1], row[2]) for row in rows]


Outcome = dict[str, Any] | ServiceError


def _run(fn: Callable[[], dict[str, Any]]) -> Outcome:
    try:
        return fn()
    except ServiceError as error:
        return error


def _interleave(
    monkeypatch: pytest.MonkeyPatch,
    first: Callable[[], dict[str, Any]],
    second: Callable[[], dict[str, Any]],
) -> tuple[Outcome, Outcome]:
    """Run ``second`` in another thread right after ``first`` has read the ticket.

    ``first`` pauses after its first ``_select_ticket`` call until ``second``
    finishes or the interleave window runs out, whichever comes first.
    """
    original_select = OpsGateService._select_ticket
    first_thread_id: list[int] = []
    first_has_read = threading.Event()
    second_done = threading.Event()

    def hooked_select(self: OpsGateService, conn: sqlite3.Connection, ticket_id: str) -> sqlite3.Row | None:
        row = original_select(self, conn, ticket_id)
        if first_thread_id and threading.get_ident() == first_thread_id[0] and not first_has_read.is_set():
            first_has_read.set()
            second_done.wait(timeout=INTERLEAVE_WINDOW_SECONDS)
        return row

    monkeypatch.setattr(OpsGateService, "_select_ticket", hooked_select)

    results: dict[str, Outcome] = {}

    def run_first() -> None:
        first_thread_id.append(threading.get_ident())
        results["first"] = _run(first)

    def run_second() -> None:
        assert first_has_read.wait(timeout=5)
        try:
            results["second"] = _run(second)
        finally:
            second_done.set()

    threads = [threading.Thread(target=run_first), threading.Thread(target=run_second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    monkeypatch.setattr(OpsGateService, "_select_ticket", original_select)
    return results["first"], results["second"]


def _stale_first_read(monkeypatch: pytest.MonkeyPatch, stale_row: sqlite3.Row) -> None:
    """Make the next ``_select_ticket`` call return a row read before a concurrent change."""
    original_select = OpsGateService._select_ticket
    used = threading.Event()

    def stale_select(self: OpsGateService, conn: sqlite3.Connection, ticket_id: str) -> sqlite3.Row | None:
        if not used.is_set():
            used.set()
            return stale_row
        return original_select(self, conn, ticket_id)

    monkeypatch.setattr(OpsGateService, "_select_ticket", stale_select)


def _snapshot(service: OpsGateService, ticket_id: str) -> sqlite3.Row:
    conn = sqlite3.connect(service.settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    finally:
        conn.close()
    assert row is not None
    return row


def _assert_error(outcome: Outcome, error_code: str) -> None:
    assert isinstance(outcome, ServiceError), outcome
    assert outcome.status_code == 409
    assert outcome.error_code == error_code


# --- Interleaved writers -------------------------------------------------------


def test_cancel_during_approve_is_not_overwritten(service: OpsGateService, monkeypatch: pytest.MonkeyPatch) -> None:
    ticket_id = _create(service)

    approved, canceled = _interleave(
        monkeypatch,
        lambda: _approve(service, ticket_id),
        lambda: _cancel(service, ticket_id),
    )

    # The approve read pending_approval first; the cancel must not be lost.
    assert isinstance(approved, dict)
    assert isinstance(canceled, dict)
    assert _state(service, ticket_id) == "canceled"
    assert _claim(service) is None
    # The cancel replaced the approved state, and the audit trail says so.
    assert _audit(service, ticket_id)[-2:] == [
        ("ticket_approved", "pending_approval", "approved"),
        ("ticket_canceled", "approved", "canceled"),
    ]


def test_cancel_during_runner_completion_is_reported(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticket_id = _create(service)
    _approve(service, ticket_id)
    claimed = _claim(service)
    assert claimed is not None and claimed["id"] == ticket_id

    finished, canceled = _interleave(
        monkeypatch,
        lambda: _runner_finish(service, ticket_id),
        lambda: _cancel(service, ticket_id),
    )

    # The runner read running first and wins; the cancel then sees a terminal
    # ticket and is told so instead of reporting success.
    assert isinstance(finished, dict) and finished["state"] == "succeeded"
    _assert_error(canceled, "invalid_state")
    assert _state(service, ticket_id) == "succeeded"
    events = [event for event, _, _ in _audit(service, ticket_id)]
    assert "ticket_canceled" not in events


def test_double_approve_has_one_winner(service: OpsGateService, monkeypatch: pytest.MonkeyPatch) -> None:
    ticket_id = _create(service)

    first, second = _interleave(
        monkeypatch,
        lambda: _approve(service, ticket_id),
        lambda: _approve(service, ticket_id),
    )

    assert isinstance(first, dict)
    _assert_error(second, "invalid_state")
    events = [event for event, _, _ in _audit(service, ticket_id)]
    assert events.count("ticket_approved") == 1


def test_reject_during_approve_is_not_overwritten(service: OpsGateService, monkeypatch: pytest.MonkeyPatch) -> None:
    ticket_id = _create(service)

    approved, rejected = _interleave(
        monkeypatch,
        lambda: _approve(service, ticket_id),
        lambda: _reject(service, ticket_id),
    )

    assert isinstance(approved, dict)
    _assert_error(rejected, "invalid_state")
    assert _state(service, ticket_id) == "approved"


# --- Compare-and-set on a stale read -------------------------------------------


def test_approve_with_stale_read_after_cancel_returns_state_changed(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticket_id = _create(service)
    stale = _snapshot(service, ticket_id)
    _cancel(service, ticket_id)

    _stale_first_read(monkeypatch, stale)
    outcome = _run(lambda: _approve(service, ticket_id))

    _assert_error(outcome, "state_changed")
    monkeypatch.undo()
    assert _state(service, ticket_id) == "canceled"
    assert _claim(service) is None
    events = [event for event, _, _ in _audit(service, ticket_id)]
    assert "ticket_approved" not in events


def test_runner_completion_with_stale_read_after_cancel_returns_state_changed(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticket_id = _create(service)
    _approve(service, ticket_id)
    assert _claim(service) is not None
    stale = _snapshot(service, ticket_id)
    _cancel(service, ticket_id)

    _stale_first_read(monkeypatch, stale)
    outcome = _run(lambda: _runner_finish(service, ticket_id))

    _assert_error(outcome, "state_changed")
    monkeypatch.undo()
    ticket = service.get_ticket(ticket_id)
    assert ticket["state"] == "canceled"
    assert ticket["result"] == "canceled"


@pytest.mark.parametrize("action", ["reject", "cancel"])
def test_lifecycle_action_with_stale_read_returns_state_changed(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    ticket_id = _create(service)
    stale = _snapshot(service, ticket_id)
    _approve(service, ticket_id)

    _stale_first_read(monkeypatch, stale)
    fn = _reject if action == "reject" else _cancel
    outcome = _run(lambda: fn(service, ticket_id))

    # The stale read saw pending_approval; the ticket is approved now. Even
    # where the action is valid from approved (cancel), it must not commit
    # against a state it did not read.
    _assert_error(outcome, "state_changed")
    monkeypatch.undo()
    assert _state(service, ticket_id) == "approved"


def test_archive_with_stale_read_returns_state_changed(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticket_id = _create(service)
    stale = _snapshot(service, ticket_id)
    _approve(service, ticket_id)

    _stale_first_read(monkeypatch, stale)
    outcome = _run(
        lambda: service.archive_ticket(ticket_id, approver=APPROVER, source_ip=None, user_agent=None)
    )

    _assert_error(outcome, "state_changed")
    monkeypatch.undo()
    ticket = service.get_ticket(ticket_id)
    assert ticket["state"] == "approved"
    assert not ticket.get("archived_at")
    # The approved ticket stays claimable.
    claimed = _claim(service)
    assert claimed is not None and claimed["id"] == ticket_id


def test_unarchive_with_stale_read_returns_state_changed(
    service: OpsGateService, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticket_id = _create(service)
    service.archive_ticket(ticket_id, approver=APPROVER, source_ip=None, user_agent=None)
    stale = _snapshot(service, ticket_id)
    service.unarchive_ticket(ticket_id, approver=APPROVER, source_ip=None, user_agent=None)
    service.archive_ticket(ticket_id, approver="other-approver", source_ip=None, user_agent=None)

    _stale_first_read(monkeypatch, stale)
    outcome = _run(
        lambda: service.unarchive_ticket(ticket_id, approver=APPROVER, source_ip=None, user_agent=None)
    )

    _assert_error(outcome, "state_changed")
    monkeypatch.undo()
    assert service.get_ticket(ticket_id)["archived_by"] == "other-approver"
