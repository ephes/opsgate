"""Approver transitions through the cookie API: approve, reject, cancel, archive, unarchive (PLAN.md 4.7.2).

Ported from tests/test_api.py (names kept) plus the body rules of 4.6.
"""

from __future__ import annotations

from typing import Any

import pytest
from harness import (
    FUTURE,
    JSON_NULL,
    PAST,
    REVIEW_PLAN,
    Browser,
    Database,
    Recorder,
    claim,
    create_ticket,
    get_ticket,
    runner_status,
)

S4B = pytest.mark.rust("S4a", "S4b")
REVIEWED: dict[str, Any] = {"execution_plan": REVIEW_PLAN, "policy_requirements": {"require_reviewer_step": True}}


@S4B
def test_approve_and_reject_flow(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-approve-1", **REVIEWED)
    approved = approver.api_action(ticket_id, "approve")
    assert approved.status == 200
    body = approved.json()
    assert (body["state"], body["approved_by"]) == ("approved", approver.target.username)
    assert body["approved_payload_checksum"] == body["payload_checksum"]

    second = create_ticket(anon, task_ref="parity-reject-1")
    rejected = approver.api_action(second, "reject", {"reason": "not-needed"})
    assert rejected.status == 200
    assert (rejected.json()["state"], rejected.json()["result"], rejected.json()["result_detail"]) == (
        "rejected",
        "failure",
        "not-needed",
    )


@S4B
def test_cancel_flow(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-cancel-1")
    body = approver.api_action(ticket_id, "cancel", {"reason": "operator canceled"}).json()
    assert (body["state"], body["result"], body["result_detail"]) == ("canceled", "canceled", "operator canceled")


@S4B
@pytest.mark.local
@pytest.mark.parametrize("state", ["approved", "running"])
def test_cancel_from_approved_and_running(anon: Browser, approver: Browser, state: str) -> None:
    ticket_id = create_ticket(anon, task_ref=f"parity-cancel-{state}")
    assert approver.api_action(ticket_id, "approve").status == 200
    if state == "running":
        assert claim(anon).json()["ticket"]["id"] == ticket_id
    body = approver.api_action(ticket_id, "cancel").json()
    assert (body["state"], body["result_detail"]) == ("canceled", "canceled_by_approver")
    again = approver.api_action(ticket_id, "cancel")
    assert (again.status, again.error) == (409, "invalid_state")


@S4B
@pytest.mark.parametrize("action", ["reject", "cancel"])
@pytest.mark.parametrize(
    "body", [None, JSON_NULL, {}, [], 0, "", False, {"reason": None}, {"reason": 7}, {"reason": "  why  "}]
)
def test_reason_body_rules(anon: Browser, approver: Browser, action: str, body: Any) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.api_action(ticket_id, action, body)
    assert resp.status == 200
    default = "rejected_by_approver" if action == "reject" else "canceled_by_approver"
    expected = (
        {None: "None", 7: "7", "  why  ": "why"}.get(body.get("reason", "-"), default)
        if isinstance(body, dict)
        else default
    )
    assert resp.json()["result_detail"] == expected


@S4B
@pytest.mark.parametrize("action", ["reject", "cancel"])
@pytest.mark.parametrize("body", [[1], "x", 1, True, {"reason": [1]}])
def test_reason_body_truthy_non_objects(
    anon: Browser, approver: Browser, rec: Recorder, impl: str, action: str, body: Any
) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.api_action(ticket_id, action, body)
    if isinstance(body, dict):
        rec.divergence("D-3")  # Python stores str([1]); Rust answers invalid_json.
        assert resp.status == (200 if impl == "python" else 400)
    else:
        rec.divergence("D-4")  # Python fails with AttributeError (500); Rust answers invalid_json.
        assert resp.status == (500 if impl == "python" else 400)
    if impl == "rust":
        assert resp.error == "invalid_json"
    assert get_ticket(anon, ticket_id)["state"] == (
        "pending_approval" if resp.status != 200 else ("rejected" if action == "reject" else "canceled")
    )


@S4B
@pytest.mark.parametrize("action", ["approve", "reject", "cancel", "archive", "unarchive"])
def test_actions_on_missing_ticket(approver: Browser, action: str) -> None:
    resp = approver.api_action("missing-ticket", action)
    assert (resp.status, resp.error) == (404, "ticket_not_found")


@S4B
def test_lazy_expiry_blocks_approval(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-old-1", expires_at=PAST, **REVIEWED)
    approve = approver.api_action(ticket_id, "approve")
    assert (approve.status, approve.error) == (409, "ticket_expired")
    assert get_ticket(anon, ticket_id)["state"] == "expired"
    assert db.audit_types(ticket_id) == ["ticket_created", "ticket_expired"]
    again = approver.api_action(ticket_id, "approve")
    assert (again.status, again.error) == (409, "invalid_state")


@S4B
def test_dedupe_ignores_archived_pending_ticket(anon: Browser, approver: Browser) -> None:
    first = create_ticket(anon, "openclaw", task_ref="parity-same-ref-archived")
    assert approver.api_action(first, "archive").json()["is_archived"] is True
    create_ticket(anon, "openclaw", task_ref="parity-same-ref-archived")


@S4B
def test_dedupe_expires_stale_approved_ticket_before_replacement_submit(
    anon: Browser, approver: Browser, db: Database
) -> None:
    original = create_ticket(anon, task_ref="parity-expired-approved", expires_at=FUTURE, **REVIEWED)
    assert approver.api_action(original, "approve").json()["state"] == "approved"
    db.set_ticket(original, expires_at=PAST)
    replacement = create_ticket(anon, task_ref="parity-expired-approved", expires_at=FUTURE, **REVIEWED)
    assert replacement != original
    assert get_ticket(anon, original)["state"] == "expired"
    assert db.audit_types(original)[-1] == "ticket_expired"


@S4B
def test_approval_revalidates_stored_agent_allowlist(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-approve-bad-agent-1")
    db.set_ticket(
        ticket_id, execution_plan_json='[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]'
    )
    resp = approver.api_action(ticket_id, "approve")
    assert (resp.status, resp.error) == (400, "invalid_execution_plan")


@S4B
def test_approval_revalidates_stored_reviewer_requirement(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon, "operator", task_ref="parity-approve-missing-reviewer-1", **REVIEWED)
    db.set_ticket(
        ticket_id, execution_plan_json='[{"role":"investigator","agent":"codex","prompt_markdown":"Inspect state"}]'
    )
    resp = approver.api_action(ticket_id, "approve")
    assert (resp.status, resp.error) == (400, "missing_reviewer_step")


@S4B
def test_api_archive_and_unarchive_preserve_ticket_access_and_audit(
    anon: Browser, approver: Browser, db: Database
) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-archive-api-1")
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    archived = approver.api_action(ticket_id, "archive").json()
    assert (archived["state"], archived["is_archived"], archived["archived_by"]) == (
        "rejected",
        True,
        approver.target.username,
    )
    assert isinstance(archived["archived_at"], str)
    assert get_ticket(anon, ticket_id)["is_archived"] is True
    restored = approver.api_action(ticket_id, "unarchive").json()
    assert (restored["state"], restored["is_archived"], restored["archived_at"], restored["archived_by"]) == (
        "rejected",
        False,
        None,
        None,
    )
    assert db.audit_types(ticket_id)[-2:] == ["ticket_archived", "ticket_unarchived"]


@S4B
@pytest.mark.local
@pytest.mark.parametrize("state", ["approved", "running"])
def test_archive_rejects_non_archivable_active_states(anon: Browser, approver: Browser, state: str) -> None:
    ticket_id = create_ticket(anon, task_ref=f"parity-archive-api-{state}")
    assert approver.api_action(ticket_id, "approve").status == 200
    if state == "running":
        assert claim(anon).json()["ticket"]["id"] == ticket_id
        heartbeat = {"runner_host": "runner-a", "event": "heartbeat", "state": "running"}
        assert runner_status(anon, ticket_id, heartbeat).status == 200
    resp = approver.api_action(ticket_id, "archive")
    assert (resp.status, resp.error) == (409, "invalid_state")


@S4B
@pytest.mark.parametrize(
    ("state", "result"),
    [
        ("succeeded", "success"),
        ("failed", "failure"),
        ("rejected", "failure"),
        ("canceled", "canceled"),
        ("expired", "failure"),
    ],
)
def test_archive_allowed_for_all_terminal_states(
    anon: Browser, approver: Browser, db: Database, state: str, result: str
) -> None:
    ticket_id = create_ticket(anon, task_ref=f"parity-archive-terminal-{state}")
    db.set_ticket(ticket_id, state=state, result=result, result_detail=f"{state}_for_test", finished_at=PAST)
    body = approver.api_action(ticket_id, "archive").json()
    assert (body["state"], body["result"], body["is_terminal"], body["is_archived"]) == (state, result, True, True)
    for action in ("approve", "reject", "cancel"):
        assert approver.api_action(ticket_id, action).status == 409


@S4B
def test_archive_allowed_for_pending_approval_state(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-archive-pending-approval-1")
    body = approver.api_action(ticket_id, "archive").json()
    assert (body["state"], body["is_terminal"], body["is_archived"], body["is_archivable"]) == (
        "pending_approval",
        False,
        True,
        False,
    )


@S4B
def test_archive_rejects_double_archive(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-archive-api-3")
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    assert approver.api_action(ticket_id, "archive").status == 200
    resp = approver.api_action(ticket_id, "archive")
    assert (resp.status, resp.error) == (409, "already_archived")


@S4B
def test_unarchive_rejects_non_archived_ticket(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-archive-api-4")
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    resp = approver.api_action(ticket_id, "unarchive")
    assert (resp.status, resp.error) == (409, "not_archived")


@S4B
def test_unarchive_rejects_when_replacement_open_ticket_exists(anon: Browser, approver: Browser) -> None:
    original = create_ticket(anon, task_ref="parity-archive-restore-conflict")
    assert approver.api_action(original, "archive").status == 200
    create_ticket(anon, task_ref="parity-archive-restore-conflict")
    resp = approver.api_action(original, "unarchive")
    assert (resp.status, resp.error) == (409, "duplicate_open_ticket")
    assert get_ticket(anon, original)["is_archived"] is True


@S4B
@pytest.mark.parametrize("action", ["approve", "reject", "cancel"])
def test_archived_pending_ticket_blocks_lifecycle_actions(anon: Browser, approver: Browser, action: str) -> None:
    ticket_id = create_ticket(anon, "openclaw", task_ref=f"parity-archive-pending-{action}")
    assert approver.api_action(ticket_id, "archive").status == 200
    resp = approver.api_action(ticket_id, action, {"reason": "nope"} if action != "approve" else None)
    assert (resp.status, resp.error) == (409, "archived_ticket")


@S4B
def test_ticket_reads_with_approver_session(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, "openclaw")
    assert approver.get(f"/api/v1/tickets/{ticket_id}").json()["source"] == "openclaw"
    # A submit token of another source still wins over the session cookie (4.3).
    resp = approver.get(f"/api/v1/tickets/{ticket_id}", bearer=anon.target.submit_tokens["nyxmon"])
    assert (resp.status, resp.error) == (403, "forbidden")


@S4B
@pytest.mark.parametrize("action", ["reject", "cancel"])
@pytest.mark.parametrize(
    "body", ['{"context":' + "[" * 2000 + "0" + "]" * 2000 + "}", '{"reason": ' + "[" * 64 + "]" * 64 + "}"]
)
def test_json_decode_errors_are_domain_responses(anon: Browser, approver: Browser, action: str, body: str) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.post(
        f"/api/v1/tickets/{ticket_id}/{action}",
        content=body,
        content_type="application/json",
        headers={"X-CSRF-Token": approver.csrf()},
    )
    assert (resp.status, resp.error) == (400, "invalid_json")
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"
