"""Runner API: claim, stored-JSON validation, tamper check, heartbeats, status updates (PLAN.md 4.7.3, 4.7.4).

Ported from tests/test_api.py (names kept) plus the explicit-value cases the plan requires.
Every scenario here owns its queue (claims take the oldest approved ticket), so all are ``local``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from harness import (
    JSON_NULL,
    PAST,
    REVIEW_PLAN,
    Browser,
    Database,
    Recorder,
    Target,
    claim,
    create_ticket,
    get_ticket,
    runner_status,
)

S4A = pytest.mark.rust("S4a")
S4B = pytest.mark.rust("S4a", "S4b")
pytestmark = pytest.mark.local
REVIEWED: dict[str, Any] = {"execution_plan": REVIEW_PLAN, "policy_requirements": {"require_reviewer_step": True}}


def running_ticket(anon: Browser, approver: Browser, **fields: Any) -> str:
    ticket_id = create_ticket(anon, **(fields or REVIEWED))
    assert approver.api_action(ticket_id, "approve").status == 200
    claimed = claim(anon).json()["ticket"]
    assert claimed["id"] == ticket_id and claimed["state"] == "running" and claimed["runner_host"] == "runner-a"
    return ticket_id


@S4B
def test_runner_claim_happy_path(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = running_ticket(anon, approver)
    assert db.audit_types(ticket_id) == ["ticket_created", "ticket_approved", "runner_claimed"]
    assert claim(anon).json() == {"ticket": None}


@S4B
def test_claim_order_is_approval_order(anon: Browser, approver: Browser, db: Database) -> None:
    first, second, third = (create_ticket(anon, task_ref=f"parity-order-{n}") for n in range(3))
    for ticket_id in (second, first, third):
        assert approver.api_action(ticket_id, "approve").status == 200
    # Equal approval stamps fall back to created_at (4.7.3).
    db.set_ticket(first, approved_at=PAST)
    db.set_ticket(third, approved_at=PAST)
    assert [claim(anon).json()["ticket"]["id"] for _ in range(3)] == [first, third, second]


@S4B
def test_runner_claim_detects_checksum_tamper(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-claim-tamper-1", **REVIEWED)
    assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(ticket_id, execution_plan_json='[{"role":"reviewer","agent":"codex","prompt_markdown":"tampered"}]')
    assert claim(anon).json() == {"ticket": None}
    body = get_ticket(anon, ticket_id)
    assert (body["state"], body["result"], body["result_detail"]) == ("failed", "failure", "prompt_tampered")


@S4B
def test_claim_of_missing_approval_checksum_is_tamper(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon)
    assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(ticket_id, approved_payload_checksum=None)
    assert claim(anon).json() == {"ticket": None}
    assert get_ticket(anon, ticket_id)["result_detail"] == "prompt_tampered"


@S4B
def test_claim_skips_expired_approved_ticket(anon: Browser, approver: Browser, db: Database) -> None:
    expired = create_ticket(anon, task_ref="parity-claim-expired")
    fresh = create_ticket(anon, task_ref="parity-claim-fresh")
    for ticket_id in (expired, fresh):
        assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(expired, expires_at=PAST)
    assert claim(anon).json()["ticket"]["id"] == fresh
    assert get_ticket(anon, expired)["state"] == "expired"


@S4B
def test_runner_does_not_claim_archived_approved_ticket(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon, "openclaw", task_ref="parity-archive-runner-1")
    assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(ticket_id, archived_at="2026-03-11T10:00:00Z", archived_by="opsgate-admin")
    assert claim(anon).json() == {"ticket": None}


@S4B
def test_runner_claim_fails_invalid_stored_agent_and_moves_on(anon: Browser, approver: Browser, db: Database) -> None:
    bad = create_ticket(anon, task_ref="parity-claim-bad-agent-1")
    good = create_ticket(anon, task_ref="parity-claim-bad-agent-2")
    for ticket_id in (bad, good):
        assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(
        bad, execution_plan_json='[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]'
    )
    claimed = claim(anon).json()["ticket"]
    assert (claimed["id"], claimed["state"]) == (good, "running")
    detail = get_ticket(anon, bad)
    assert (detail["state"], detail["result"], detail["result_detail"]) == ("failed", "failure", "invalid_stored_plan")


CORRUPT = [
    ("execution_plan_json", "{broken", "invalid_stored_json"),
    ("execution_plan_json", "[42]", "invalid_execution_plan"),
    ("policy_requirements_json", "{broken", "invalid_stored_json"),
    ("policy_requirements_json", "[]", "invalid_policy_requirements"),
    ("policy_requirements_json", "null", "invalid_policy_requirements"),
    ("policy_requirements_json", '{"require_reviewer_step": "false"}', "invalid_policy_requirements"),
    ("context_json", "{broken", "invalid_stored_json"),
    ("context_json", "[]", "invalid_ticket"),
    ("context_json", "null", "invalid_ticket"),
    ("context_json", '{"nested":' + "[" * 100000 + "0" + "]" * 100000 + "}", "invalid_stored_json"),
    ("tmux_sessions_json", "{broken", "invalid_stored_json"),
    ("tmux_sessions_json", "null", "invalid_tmux_sessions"),
    ("context_json", '{"nested":' + "[" * 64 + "0" + "]" * 64 + "}", "invalid_stored_json"),
    ("tmux_sessions_json", "[" * 65 + "0" + "]" * 65, "invalid_stored_json"),
]


@S4B
@pytest.mark.parametrize(
    ("column", "stored_json", "error_code"),
    CORRUPT,
    ids=[f"{column}-{code}-{len(raw)}" for column, raw, code in CORRUPT],
)
@pytest.mark.parametrize("with_successor", [True, False])
def test_runner_claim_isolates_corrupt_stored_json(
    anon: Browser, approver: Browser, db: Database, column: str, stored_json: str, error_code: str, with_successor: bool
) -> None:
    bad = create_ticket(anon, task_ref="parity-corrupt-oldest")
    good = create_ticket(anon, task_ref="parity-valid-successor") if with_successor else None
    for ticket_id in [bad, *([good] if good else [])]:
        assert approver.api_action(ticket_id, "approve").status == 200
    db.set_ticket(bad, **{column: stored_json, "approved_at": PAST})
    claimed = claim(anon).json()["ticket"]
    assert (claimed and claimed["id"]) == (good if good else None)
    row = db.rows("SELECT * FROM tickets WHERE id = ?", (bad,))[0]
    assert (row["state"], row["result"], row["result_detail"], row["runner_host"], row["started_at"]) == (
        "failed",
        "failure",
        "invalid_stored_plan",
        None,
        None,
    )
    events = db.rows(
        "SELECT * FROM audit_events WHERE ticket_id = ? AND event_type IN ('ticket_failed', 'runner_claimed')", (bad,)
    )
    assert [(e["event_type"], e["actor"], e["previous_state"], e["new_state"]) for e in events] == [
        ("ticket_failed", "runner:runner-a", "approved", "failed")
    ]
    assert json.loads(events[0]["metadata_json"]) == {"reason": "invalid_stored_plan", "error": error_code}
    # A later idle poll must not fail or audit the corrupt row again.
    assert claim(anon).json() == {"ticket": None}
    assert db.audit_types(bad).count("ticket_failed") == 1


@S4B
@pytest.mark.parametrize(
    ("column", "stored_json", "response_field"),
    [
        ("context_json", '{"nested":' + "[" * 63 + "0" + "]" * 63 + "}", "context"),
        ("tmux_sessions_json", "[" * 64 + "0" + "]" * 64, "tmux_sessions"),
    ],
    ids=["context", "tmux_sessions"],
)
def test_runner_claim_accepts_stored_json_at_depth_limit(
    anon: Browser, approver: Browser, db: Database, column: str, stored_json: str, response_field: str
) -> None:
    ticket_id = create_ticket(anon)
    db.set_ticket(ticket_id, **{column: stored_json})
    assert approver.api_action(ticket_id, "approve").status == 200
    claimed = claim(anon).json()["ticket"]
    assert (claimed["id"], claimed["state"]) == (ticket_id, "running")
    assert claimed[response_field] == json.loads(stored_json)
    assert "ticket_failed" not in db.audit_types(ticket_id)


@S4B
@pytest.mark.parametrize("field", ["role", "agent", "prompt_markdown"])
def test_claim_rejects_non_text_stored_plan(anon: Browser, approver: Browser, db: Database, field: str) -> None:
    ticket_id = create_ticket(anon)
    assert approver.api_action(ticket_id, "approve").status == 200
    step: dict[str, Any] = {"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}
    step[field] = None
    db.set_ticket(ticket_id, execution_plan_json=json.dumps([step]))
    assert claim(anon).json() == {"ticket": None}
    detail = get_ticket(anon, ticket_id)
    assert (detail["state"], detail["result_detail"]) == ("failed", "invalid_stored_plan")


@S4B
def test_ticket_unicode_text_persists_and_passes_checksum_validation(anon: Browser, approver: Browser) -> None:
    text = "Grüße aus Köln 🛠️"
    plan = [{"role": "investigator", "agent": "codex", "prompt_markdown": text}]
    context = {"score": 0.95, "count": 3.0, "ratio": 1e-05, "big": 1e16, "ints": [10**20, -7], "text": text}
    ticket_id = create_ticket(anon, title=text, summary=text, task_ref=text, execution_plan=plan, context=context)
    ticket = anon.get(f"/api/v1/tickets/{ticket_id}", bearer=anon.target.runner_token).json()
    approved = approver.api_action(ticket_id, "approve")
    assert approved.json()["approved_payload_checksum"] == ticket["payload_checksum"]
    claimed = claim(anon, "test").json()["ticket"]
    assert (claimed["id"], claimed["state"], claimed["context"]) == (ticket_id, "running", context)


# ------------------------------------------------------------------ heartbeats and claim bodies


@S4A
def test_idle_runner_claim_poll_records_heartbeat(anon: Browser, db: Database) -> None:
    create_ticket(anon, task_ref="parity-idle-heartbeat-1")
    assert claim(anon, "runner-idle").json() == {"ticket": None}
    first = anon.get("/api/v1/health").json()
    assert first["runner_host"] == "runner-idle" and first["runner_last_heartbeat"] is not None
    assert first["ticket_counters"] == {"pending_approval": 1}
    assert claim(anon, "runner-idle").status == 200
    second = anon.get("/api/v1/health").json()
    assert second["runner_last_heartbeat"] >= first["runner_last_heartbeat"]
    assert [row["runner_host"] for row in db.rows("SELECT runner_host FROM runner_heartbeats")] == ["runner-idle"]
    assert db.scalar("SELECT COUNT(*) FROM audit_events WHERE actor = 'runner:runner-idle'") == 0


@S4A
def test_runner_claim_without_token_records_no_heartbeat(anon: Browser) -> None:
    resp = anon.post("/api/v1/runner/claim", json_body={"runner_host": "runner-anon"})
    assert (resp.status, resp.error) == (401, "invalid_runner_token")
    assert anon.get("/api/v1/health").json()["runner_last_heartbeat"] is None


@S4A
def test_claim_with_disable_file_touches_nothing(anon: Browser, api: Target, db: Database) -> None:
    assert api.exec_dir is not None
    (api.exec_dir / ".disabled").write_text("", encoding="utf-8")
    assert claim(anon).json() == {"ticket": None}
    assert anon.get("/api/v1/health").json()["runner_last_heartbeat"] is None
    (api.exec_dir / ".disabled").unlink()
    assert claim(anon).json() == {"ticket": None}
    assert db.scalar("SELECT runner_host FROM runner_heartbeats") == "runner-a"


@S4A
@pytest.mark.parametrize(
    ("body", "host"),
    [
        (None, "127.0.0.1"),
        (JSON_NULL, "127.0.0.1"),
        ({}, "127.0.0.1"),
        ([], "127.0.0.1"),
        (0, "127.0.0.1"),
        ("", "127.0.0.1"),
        ({"runner_host": ""}, "127.0.0.1"),
        ({"runner_host": "  studio  "}, "studio"),
        ({"runner_host": None}, "None"),
        ({"runner_host": False}, "False"),
        ({"runner_host": 0}, "0"),
    ],
    ids=lambda value: json.dumps(value) if not isinstance(value, object) or value is not JSON_NULL else "null",
)
def test_claim_runner_host_rules(anon: Browser, db: Database, body: Any, host: str) -> None:
    resp = anon.post("/api/v1/runner/claim", json_body=body, bearer=anon.target.runner_token)
    assert resp.json() == {"ticket": None}
    assert db.scalar("SELECT runner_host FROM runner_heartbeats") == host


@S4A
@pytest.mark.parametrize("body", [[1], "x", 1, True, {"runner_host": [1]}])
def test_claim_truthy_non_object_bodies(anon: Browser, rec: Recorder, impl: str, body: Any) -> None:
    resp = anon.post("/api/v1/runner/claim", json_body=body, bearer=anon.target.runner_token)
    if isinstance(body, dict):
        rec.divergence("D-3")  # Python uses str([1]) as the host; Rust answers invalid_json.
        assert resp.status == (200 if impl == "python" else 400)
    else:
        rec.divergence("D-4")  # Python 500 (AttributeError); Rust invalid_json.
        assert resp.status == (500 if impl == "python" else 400)


# ------------------------------------------------------------------ runner status


@S4B
def test_runner_status_rejects_terminal_state_regression(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-status-1", **REVIEWED)
    assert approver.api_action(ticket_id, "approve").status == 200
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-a"})
    assert (resp.status, resp.error) == (409, "invalid_state")
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-a", "state": "succeeded"})
    assert (resp.status, resp.error) == (409, "invalid_state")
    assert claim(anon).json()["ticket"]["state"] == "running"
    succeed = runner_status(anon, ticket_id, {"runner_host": "runner-a", "state": "succeeded"})
    assert (succeed.status, succeed.json()["state"], succeed.json()["result"]) == (200, "succeeded", "success")
    for body in ({"runner_host": "runner-a", "state": "running"}, {"runner_host": "runner-a"}):
        resp = runner_status(anon, ticket_id, body)
        assert (resp.status, resp.error) == (409, "invalid_state")


@S4B
def test_runner_status_on_pending_and_missing_tickets(anon: Browser) -> None:
    ticket_id = create_ticket(anon)
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-a", "state": "running"})
    assert (resp.status, resp.error) == (409, "invalid_state")
    resp = runner_status(anon, "missing-ticket", {"runner_host": "runner-a"})
    assert (resp.status, resp.error) == (404, "ticket_not_found")
    resp = runner_status(anon, "missing-ticket", {"event": "bogus"})
    assert (resp.status, resp.error) == (400, "invalid_runner_event")


@S4B
def test_approved_ticket_may_be_started_by_status(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon)
    assert approver.api_action(ticket_id, "approve").status == 200
    body = runner_status(
        anon, ticket_id, {"runner_host": "runner-b", "state": "running", "event": "step_started"}
    ).json()
    assert (body["state"], body["runner_host"], body["started_at"]) == ("running", "runner-b", None)


@S4B
def test_runner_status_accepts_timeout_result_and_tmux_sessions(anon: Browser, approver: Browser) -> None:
    ticket_id = running_ticket(anon, approver)
    sessions = [
        {
            "step_index": 0,
            "role": "reviewer",
            "agent": "codex",
            "session_name": "job-1",
            "status": "timeout",
            "attach_command": (
                "sudo -u ops env TMUX_TMPDIR=/Users/ops/remediation/tmux tmux -L remediation attach -t job-1"
            ),
        }
    ]
    body = runner_status(
        anon,
        ticket_id,
        {
            "runner_host": "runner-a",
            "event": "timeout",
            "state": "failed",
            "result": "timeout",
            "result_detail": "max_duration_seconds_exceeded",
            "tmux_sessions": sessions,
        },
    ).json()
    assert (body["state"], body["result"], body["tmux_sessions"]) == ("failed", "timeout", sessions)


@S4B
@pytest.mark.parametrize("value", [{"bad": "value"}, "x", 7])
def test_runner_status_rejects_invalid_tmux_sessions_payload(anon: Browser, approver: Browser, value: Any) -> None:
    ticket_id = running_ticket(anon, approver)
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-a", "tmux_sessions": value})
    assert (resp.status, resp.error) == (400, "invalid_tmux_sessions")


@S4B
def test_runner_status_rejects_runner_host_mismatch(anon: Browser, approver: Browser) -> None:
    ticket_id = running_ticket(anon, approver)
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-b", "event": "heartbeat"})
    assert (resp.status, resp.error) == (409, "runner_host_mismatch")


@S4B
@pytest.mark.parametrize(
    "event", ["ticket_approved", "bogus", " HEARTBEAT ", "", "   ", "Step_Started", "invalid_plan"]
)
def test_runner_status_event_values(anon: Browser, approver: Browser, db: Database, event: str) -> None:
    ticket_id = running_ticket(anon, approver)
    resp = runner_status(anon, ticket_id, {"runner_host": "runner-a", "event": event})
    if event in {"ticket_approved", "bogus"}:
        assert (resp.status, resp.error) == (400, "invalid_runner_event")
    else:
        assert resp.status == 200
        expected = event.strip().lower() or "heartbeat"
        assert db.audit_types(ticket_id)[-1] == f"runner_{expected}"


@S4B
def test_runner_status_accepts_step_failed_event(anon: Browser, approver: Browser) -> None:
    ticket_id = running_ticket(anon, approver)
    body = runner_status(
        anon,
        ticket_id,
        {
            "runner_host": "runner-a",
            "event": "step_failed",
            "state": "failed",
            "result": "failure",
            "result_detail": "step_1_exit_code_7",
        },
    ).json()
    assert (body["state"], body["result"], body["result_detail"]) == ("failed", "failure", "step_1_exit_code_7")


@S4B
@pytest.mark.parametrize("state", [None, "running", "succeeded", "failed", "canceled", " FAILED "])
@pytest.mark.parametrize("result", [None, "success", "failure", "timeout", "canceled"])
def test_runner_state_result_matrix(
    anon: Browser, approver: Browser, db: Database, state: str | None, result: str | None
) -> None:
    ticket_id = running_ticket(anon, approver)
    before = db.rows("SELECT * FROM tickets")
    payload: dict[str, Any] = {"runner_host": "runner-a"}
    if state is not None:
        payload["state"] = state
    if result is not None:
        payload["result"] = result
    effective = (state or "running").strip().lower()
    compatible = {"succeeded": {"success"}, "failed": {"failure", "timeout"}, "canceled": {"canceled"}}
    resp = runner_status(anon, ticket_id, payload)
    if result is None or result in compatible.get(effective, set()):
        defaults = {"succeeded": "success", "failed": "failure", "canceled": "canceled"}
        assert (resp.status, resp.json()["state"], resp.json()["result"]) == (
            200,
            effective,
            result or defaults.get(effective),
        )
        assert (resp.json()["finished_at"] is not None) is (effective != "running")
    else:
        assert (resp.status, resp.error) == (400, "invalid_runner_result")
        assert db.rows("SELECT * FROM tickets") == before


EXPLICIT_VALUES: list[tuple[str, Any, int, str | None]] = [
    ("event", None, 400, "invalid_runner_event"),
    ("event", False, 400, "invalid_runner_event"),
    ("event", 0, 400, "invalid_runner_event"),
    ("state", None, 200, None),
    ("state", False, 400, "invalid_runner_state"),
    ("state", 0, 400, "invalid_runner_state"),
    ("result", None, 200, None),
    ("result", False, 400, "invalid_runner_result"),
    ("result", 0, 400, "invalid_runner_result"),
    ("result_detail", None, 200, None),
    ("result_detail", False, 200, None),
    ("result_detail", 0, 200, None),
    ("tmux_sessions", None, 200, None),
    ("tmux_sessions", False, 400, "invalid_tmux_sessions"),
    ("tmux_sessions", 0, 400, "invalid_tmux_sessions"),
    ("runner_host", None, 409, "runner_host_mismatch"),
    ("runner_host", False, 409, "runner_host_mismatch"),
    ("runner_host", 0, 409, "runner_host_mismatch"),
]


@S4B
@pytest.mark.parametrize(
    ("field", "value", "status", "error"),
    EXPLICIT_VALUES,
    ids=[f"{f}-{json.dumps(v)}" for f, v, _, _ in EXPLICIT_VALUES],
)
def test_runner_status_explicit_null_false_zero(
    anon: Browser, approver: Browser, field: str, value: Any, status: int, error: str | None
) -> None:
    # PLAN.md 4.7.4: only a missing key takes the default; str() of the JSON scalar decides otherwise.
    ticket_id = running_ticket(anon, approver)
    payload: dict[str, Any] = {"runner_host": "runner-a", "tmux_sessions": [{"step_index": 0}]}
    payload[field] = value
    resp = runner_status(anon, ticket_id, payload)
    assert (resp.status, resp.error) == (status, error)
    if status == 200:
        body = resp.json()
        assert body["tmux_sessions"] == ([] if field == "tmux_sessions" else [{"step_index": 0}])
        if field == "result_detail":
            assert body["result_detail"] == str(value)


@S4B
@pytest.mark.parametrize(
    ("field", "value"), [("event", [1]), ("state", {"a": 1}), ("result", [1]), ("result_detail", [1])]
)
def test_runner_status_container_values(
    anon: Browser, approver: Browser, rec: Recorder, impl: str, field: str, value: Any
) -> None:
    rec.divergence("D-3")
    ticket_id = running_ticket(anon, approver)
    payload: dict[str, Any] = {"runner_host": "runner-a", "state": "failed", field: value}
    resp = runner_status(anon, ticket_id, payload)
    expected = {
        "event": "invalid_runner_event",
        "state": "invalid_runner_state",
        "result": "invalid_runner_result",
        "result_detail": None if impl == "python" else "invalid_json",
    }[field]
    assert resp.error == expected
