"""Cross-implementation database scenarios and races observable over HTTP (PLAN.md 7.3, 4.7, 4.8, 4.10).

``peer`` is the implementation that takes over the database between steps;
a run with ``--impl python`` covers python→python and python→rust, a run with
``--impl rust`` the other two (the rust peer waits for its slices).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import pytest
from conftest import Stack
from harness import (
    IMPLS,
    PLAN,
    Browser,
    Database,
    Recorder,
    claim,
    create_ticket,
    get_ticket,
    runner_status,
)

S4B = pytest.mark.rust("S4a", "S4b")
pytestmark = pytest.mark.local

# Production-shaped payloads (PLAN.md section 1): nyxmon contexts carry JSON floats.
CONTEXTS: list[dict[str, Any]] = [
    {"check_id": 17, "result": {"score": 0.95, "threshold": 3.0, "latency_ms": 14.0, "ratio": 1e-05}},
    {"big": 10**30, "neg": -0.0, "tiny": 5e-324, "e16": 1e16, "text": 'Grüße   🛠️ \x7f "q" \\'},
    {"nested": {"list": [1, 2.5, None, True, False, "x"], "empty": {}, "arr": []}},
]


@S4B
@pytest.mark.parametrize("peer", IMPLS)
def test_cross_implementation_create_approve_claim(stack: Stack, impl: str, peer: str, rec: Recorder) -> None:
    """Create in one, approve in the other, claim in the first, and the reverse (checksum, 4.8)."""
    first = stack.server(impl=impl)
    anon = stack.browser(first, "anon")
    created = [create_ticket(anon, task_ref=f"parity-cross-a{n}", context=ctx) for n, ctx in enumerate(CONTEXTS)]

    second = stack.restart(first, impl=peer)
    approver = stack.approver(second)
    for ticket_id in created:
        body = approver.api_action(ticket_id, "approve").json()
        assert body["approved_payload_checksum"] == body["payload_checksum"]
    created_by_peer = [
        create_ticket(anon, task_ref=f"parity-cross-b{n}", context=ctx) for n, ctx in enumerate(CONTEXTS)
    ]

    third = stack.restart(second, impl=impl)
    claimed = [claim(anon).json()["ticket"] for _ in created]
    assert [ticket["id"] for ticket in claimed] == created
    assert all(ticket["state"] == "running" for ticket in claimed)
    assert [ticket["context"] for ticket in claimed] == CONTEXTS
    approver = stack.approver(third, "approver-again")
    for ticket_id in created_by_peer:
        assert approver.api_action(ticket_id, "approve").status == 200

    stack.restart(third, impl=peer)
    claimed = [claim(anon).json()["ticket"] for _ in created_by_peer]
    assert [ticket["id"] for ticket in claimed] == created_by_peer
    assert claim(anon).json() == {"ticket": None}
    rec.note("peer", peer)


@S4B
@pytest.mark.parametrize("peer", IMPLS)
def test_restart_on_other_implementation_database(stack: Stack, impl: str, peer: str) -> None:
    """Schema is a no-op on the other implementation's database and the generation is kept (4.10, 4.5.2)."""
    first = stack.server(impl=impl)
    anon = stack.browser(first, "anon")
    ticket_id = create_ticket(anon)
    approver = stack.approver(first)
    assert approver.post("/logout", data={"csrf_token": approver.csrf()}).status == 302
    db = stack.db(first)
    schema = db.schema()
    session_state = db.rows("SELECT * FROM ui_session_state")
    assert session_state[0]["session_generation"] == 2

    second = stack.restart(first, impl=peer)
    assert db.schema() == schema
    assert db.rows("SELECT * FROM ui_session_state") == session_state
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"
    assert stack.approver(second, "approver-peer").api_action(ticket_id, "approve").status == 200


@S4B
@pytest.mark.parametrize("peer", IMPLS)
def test_running_ticket_survives_api_switch(stack: Stack, impl: str, peer: str) -> None:
    """A runner keeps reporting to the other implementation after an API cutover (PLAN.md 3.1)."""
    first = stack.server(impl=impl)
    anon = stack.browser(first, "anon")
    ticket_id = create_ticket(anon, execution_plan=PLAN * 2)
    assert stack.approver(first).api_action(ticket_id, "approve").status == 200
    assert claim(anon).json()["ticket"]["id"] == ticket_id
    stack.restart(first, impl=peer)
    sessions = [{"step_index": 0, "status": "running", "session_name": "job-x-01-investigator"}]
    assert (
        runner_status(
            anon, ticket_id, {"runner_host": "runner-a", "event": "step_started", "tmux_sessions": sessions}
        ).status
        == 200
    )
    done = runner_status(
        anon,
        ticket_id,
        {
            "runner_host": "runner-a",
            "event": "ticket_succeeded",
            "state": "succeeded",
            "result_detail": "completed_2_steps",
        },
    )
    assert (done.json()["state"], done.json()["result"]) == ("succeeded", "success")


# ------------------------------------------------------------------ races (tests/test_ticket_transition_races.py)


def race(*calls: Callable[[], Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))
    results: list[Any] = [None] * len(calls)

    def run(index: int, call: Callable[[], Any]) -> None:
        barrier.wait()
        results[index] = call()

    threads = [threading.Thread(target=run, args=(index, call)) for index, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return results


def outcome(resp: Any) -> str:
    """200, or the conflict class: invalid_state and state_changed are both legal for a loser."""
    if resp.status == 200:
        return "ok"
    assert resp.status == 409 and resp.error in {"invalid_state", "state_changed"}, (resp.status, resp.error)
    return "conflict"


def stop_recording(rec: Recorder, *browsers: Browser) -> None:
    """After a race the exchanges and rows depend on the winner; the scenario records its invariants instead."""
    rec.snapshot_enabled = False
    for browser in browsers:
        browser.recorder = None


def raced_browsers(stack: Stack, anon: Browser, count: int) -> list[Browser]:
    browsers = [stack.approver(anon.target, f"racer-{n}") for n in range(count)]
    for browser in browsers:
        browser.recorder = None  # racing exchanges arrive in any order; the scenario records the invariants
    return browsers


@S4B
@pytest.mark.parametrize("attempt", range(3))
def test_double_approve_has_one_winner(stack: Stack, anon: Browser, db: Database, rec: Recorder, attempt: int) -> None:
    ticket_id = create_ticket(anon)
    one, two = raced_browsers(stack, anon, 2)
    tokens = [one.csrf(), two.csrf()]
    results = race(
        lambda: one.api_action(ticket_id, "approve", headers={"X-CSRF-Token": tokens[0]}),
        lambda: two.api_action(ticket_id, "approve", headers={"X-CSRF-Token": tokens[1]}),
    )
    assert sorted(outcome(resp) for resp in results) == ["conflict", "ok"]
    assert db.audit_types(ticket_id) == ["ticket_created", "ticket_approved"]
    rec.note("outcomes", sorted(outcome(resp) for resp in results))


@S4B
@pytest.mark.parametrize("attempt", range(3))
def test_cancel_during_approve_is_not_overwritten(
    stack: Stack, anon: Browser, db: Database, rec: Recorder, attempt: int
) -> None:
    ticket_id = create_ticket(anon)
    one, two = raced_browsers(stack, anon, 2)
    tokens = [one.csrf(), two.csrf()]
    approve, cancel = race(
        lambda: one.api_action(ticket_id, "approve", headers={"X-CSRF-Token": tokens[0]}),
        lambda: two.api_action(ticket_id, "cancel", headers={"X-CSRF-Token": tokens[1]}),
    )
    stop_recording(rec, anon)
    assert outcome(cancel) == "ok"  # cancel is legal from pending and from approved
    assert get_ticket(anon, ticket_id)["state"] == "canceled"
    expected = (
        ["ticket_created", "ticket_approved", "ticket_canceled"]
        if outcome(approve) == "ok"
        else ["ticket_created", "ticket_canceled"]
    )
    assert db.audit_types(ticket_id) == expected
    rec.note("final state", "canceled")


@S4B
@pytest.mark.parametrize("attempt", range(3))
def test_reject_during_approve_is_not_overwritten(
    stack: Stack, anon: Browser, db: Database, rec: Recorder, attempt: int
) -> None:
    ticket_id = create_ticket(anon)
    one, two = raced_browsers(stack, anon, 2)
    tokens = [one.csrf(), two.csrf()]
    approve, reject = race(
        lambda: one.api_action(ticket_id, "approve", headers={"X-CSRF-Token": tokens[0]}),
        lambda: two.api_action(ticket_id, "reject", headers={"X-CSRF-Token": tokens[1]}),
    )
    stop_recording(rec, anon)
    assert sorted([outcome(approve), outcome(reject)]) == ["conflict", "ok"]
    final = get_ticket(anon, ticket_id)["state"]
    assert final == ("approved" if outcome(approve) == "ok" else "rejected")
    assert len(db.audit_types(ticket_id)) == 2
    rec.note("one winner", True)


@S4B
@pytest.mark.parametrize("attempt", range(3))
def test_cancel_during_runner_completion_is_reported(
    stack: Stack, anon: Browser, db: Database, rec: Recorder, attempt: int
) -> None:
    ticket_id = create_ticket(anon)
    (one,) = raced_browsers(stack, anon, 1)
    assert one.api_action(ticket_id, "approve").status == 200
    assert claim(anon).json()["ticket"]["id"] == ticket_id
    token = one.csrf()
    runner = Browser(anon.target, None, "runner")
    try:
        finish, cancel = race(
            lambda: runner_status(
                runner, ticket_id, {"runner_host": "runner-a", "event": "ticket_succeeded", "state": "succeeded"}
            ),
            lambda: one.api_action(ticket_id, "cancel", headers={"X-CSRF-Token": token}),
        )
    finally:
        runner.close()
    stop_recording(rec, anon)
    assert sorted([outcome(finish), outcome(cancel)]) == ["conflict", "ok"]
    final = get_ticket(anon, ticket_id)["state"]
    assert final == ("succeeded" if outcome(finish) == "ok" else "canceled")
    rec.note("one winner", True)


@S4B
@pytest.mark.parametrize("attempt", range(3))
def test_concurrent_claims_hand_out_a_ticket_once(
    stack: Stack, anon: Browser, db: Database, rec: Recorder, attempt: int
) -> None:
    ticket_id = create_ticket(anon)
    assert stack.approver(anon.target).api_action(ticket_id, "approve").status == 200
    runners = [Browser(anon.target, None, f"runner-{n}") for n in range(4)]
    try:
        results = race(*[lambda r=r, n=n: claim(r, f"runner-{n}") for n, r in enumerate(runners)])
    finally:
        for runner in runners:
            runner.close()
    stop_recording(rec, anon)
    claimed = [resp.json()["ticket"] for resp in results]
    assert all(resp.status == 200 for resp in results)
    assert sum(ticket is not None for ticket in claimed) == 1
    assert db.audit_types(ticket_id).count("runner_claimed") == 1
    rec.note("claimed once", True)
