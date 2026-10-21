"""Supervisor scenarios: disable file, `--once`, recovery housekeeping (rust/PLAN.md 4.1, 4.13.6, 7.4)."""

from __future__ import annotations

import json
import time

from conftest import Rig
from runner_harness import step, wait_until

# Matches the tmux name pattern of 4.13.6 but is not a UUID: never a recovery candidate.
BOGUS = "job-" + "a" * 36 + "-01-x"


def test_disable_file_with_once_claims_nothing(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    (rig.ws.exec_dir / ".disabled").touch()
    runner = rig.runner(once=True)
    assert runner.wait(30) == 0
    assert rig.api.calls() == []
    assert rig.api.ticket(tid)["state"] == "approved"
    rig.observe("calls", len(rig.api.calls()))


def test_disable_file_pauses_claims(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    disabled = rig.ws.root / "custom.disabled"
    disabled.touch()
    runner = rig.runner(OPSGATE_DISABLE_FILE_PATH=str(disabled))
    time.sleep(3)
    assert runner.alive()
    assert rig.api.calls("claim") == []
    disabled.unlink()
    wait_until(lambda: rig.api.ticket(tid)["state"] == "succeeded", timeout=60, what="ticket succeeded")
    assert runner.stop() == 0
    rig.observe_statuses(tid)


def test_once_without_work_claims_once(rig: Rig) -> None:
    runner = rig.runner(once=True)
    assert runner.wait(30) == 0
    assert [(c.kind, c.response) for c in rig.api.calls()] == [("claim", 200)]
    assert list((rig.ws.exec_dir / "runner-state").iterdir()) == []
    rig.observe("calls", [(c.kind, c.response) for c in rig.api.calls()])


def test_recovery_housekeeping(rig: Rig) -> None:
    terminal = rig.api.add_ticket([step("investigator")], state="succeeded", claimable=False)
    terminal_tmux_only = rig.api.add_ticket([step("investigator")], state="canceled", claimable=False)
    not_running = rig.api.add_ticket([step("investigator")], state="approved", claimable=False)
    unknown = "bbbbbbbb-0000-4000-8000-000000000001"
    running = rig.api.add_ticket(
        [step("investigator", lines=1)], state="running", runner_host="runner-parity", claimable=False
    )

    state_dir = rig.ws.exec_dir / "runner-state"
    state_dir.mkdir(parents=True)

    def state_file(name: str, content: object) -> None:
        text = content if isinstance(content, str) else json.dumps(content)
        (state_dir / name).write_text(text, encoding="utf-8")

    state_file("broken.json", "{not json")
    state_file("list.json", [1])
    state_file("no-id.json", {"runner_host": "x"})
    state_file("ignored.txt", "not a state file")
    for tid in (terminal, not_running, unknown, running):
        state_file(f"{tid}.json", {"ticket_id": tid, "runner_host": "runner-parity", "updated_at": "x"})
    rig.ws.start_dummy_session(f"job-{terminal}-01-old")
    rig.ws.start_dummy_session(f"job-{terminal}-02-older")
    rig.ws.start_dummy_session(f"job-{terminal_tmux_only}-01-old")
    rig.ws.start_dummy_session(f"job-{not_running}-01-old")
    rig.ws.start_dummy_session(f"job-{unknown}-01-old")
    rig.ws.start_dummy_session(BOGUS)
    rig.ws.start_dummy_session("unrelated")

    runner = rig.runner(once=True)
    assert runner.wait(60) == 0

    assert sorted(p.name for p in state_dir.iterdir()) == sorted(["ignored.txt", f"{unknown}.json"])
    # The running ticket's finished session stays (remain-on-exit) because --once exits first.
    assert rig.ws.sessions() == sorted([f"job-{unknown}-01-old", BOGUS, "unrelated", f"job-{running}-01-investigator"])
    # The running ticket without artifacts starts fresh (nothing says a step was ever started).
    assert rig.api.events(running) == ["step_started", "step_finished", "ticket_succeeded"]
    for tid in (terminal, terminal_tmux_only, not_running, unknown):
        assert rig.api.calls("status", tid) == []
    gets = {c.ticket for c in rig.api.calls("get")}
    assert {terminal, terminal_tmux_only, not_running, unknown, running} <= gets
    rig.observe("state_files", sorted(rig.norm.text(p.name) for p in state_dir.iterdir()))
    rig.observe_sessions()
    rig.observe_statuses(running)


def write_state(rig: Rig, tid: str) -> None:
    state_dir = rig.ws.exec_dir / "runner-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = {"ticket_id": tid, "runner_host": "runner-parity", "updated_at": "2026-01-01T00:00:00Z"}
    (state_dir / f"{tid}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_recovery_without_tmux_server(rig: Rig) -> None:
    terminal = rig.api.add_ticket([step("investigator")], state="failed", claimable=False)
    write_state(rig, terminal)
    runner = rig.runner(once=True)
    assert runner.wait(30) == 0
    # "no server running" (or a missing socket) counts as no sessions: cleanup verified, state removed.
    assert list((rig.ws.exec_dir / "runner-state").iterdir()) == []
    assert rig.ws.sessions() == []
    rig.observe("state_files", [])


def test_recovery_without_tmux_binary(rig: Rig) -> None:
    terminal = rig.api.add_ticket([step("investigator")], state="succeeded", claimable=False)
    write_state(rig, terminal)
    runner = rig.runner(once=True, without_tmux=True)
    assert runner.wait(30) == 0
    # Discovery through tmux finds nothing, but cleanup cannot be verified: the state file stays.
    assert [p.name for p in (rig.ws.exec_dir / "runner-state").iterdir()] == [f"{terminal}.json"]
    assert [(c.kind, c.ticket, c.response) for c in rig.api.calls()][-1] == ("claim", None, 200)
    assert {c.ticket for c in rig.api.calls("get")} == {terminal}
    rig.observe("state_files", [rig.norm.text(p.name) for p in (rig.ws.exec_dir / "runner-state").iterdir()])


def test_recovery_get_outage_is_isolated(rig: Rig) -> None:
    unavailable = rig.api.add_ticket([step("investigator")], state="succeeded", claimable=False)
    terminal = rig.api.add_ticket([step("investigator")], state="succeeded", claimable=False)
    write_state(rig, unavailable)
    write_state(rig, terminal)
    rig.api.fail("get", ticket=unavailable, times=1000, status=503, body={"error": "x", "message": "x"})
    rig.api.fail("get", ticket=terminal, times=1, drop=True)
    runner = rig.runner(once=True)
    assert runner.wait(30) == 0
    # The first pass skips both (503, transport failure); the loop's pass cleans up the reachable one.
    assert [p.name for p in (rig.ws.exec_dir / "runner-state").iterdir()] == [f"{unavailable}.json"]
    assert [c.response for c in rig.api.calls("get", terminal)] == ["dropped", 200]
    assert runner.p1_log_lines() == []
    rig.observe("state_files", [rig.norm.text(p.name) for p in (rig.ws.exec_dir / "runner-state").iterdir()])
