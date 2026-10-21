"""Shutdown, restart and cross-implementation recovery (rust/PLAN.md 4.1, 4.13.4, 4.13.5, 7.4).

The cross-implementation scenarios start one implementation, SIGKILL it in the
middle of a step and continue with the other one on the same artifact tree,
state files and tmux server (Python then Rust and the reverse; the all-Python
and all-Rust stacks are the baselines).
"""

from __future__ import annotations

import json
import signal

import pytest
from conftest import Rig
from runner_harness import RUNNER_HOST, session_name, step, step_files, wait_until

PAIRS = [("python", "python"), ("python", "rust"), ("rust", "python"), ("rust", "rust")]


def test_sigterm_marks_running_step_interrupted(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started")])
    runner = rig.runner()
    rig.ws.wait_marker("started")
    runner.signal(signal.SIGTERM)
    assert runner.wait(30) == 0

    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "interrupted" and "finished_at" in files.metadata
    assert rig.api.events(tid) == ["step_started"]
    assert rig.ws.sessions() == []
    assert rig.api.ticket(tid)["state"] == "running"
    # The worker returned normally, so its state file is gone; the artifact directory remains.
    assert list((rig.ws.exec_dir / "runner-state").iterdir()) == []
    rig.observe("tree_after_sigterm", rig.norm.tree(rig.ws.exec_dir))

    # A restarted runner finds the ticket through its artifact directory and fails the step.
    again = rig.runner(once=True)
    assert again.wait(60) == 0
    assert rig.api.events(tid) == ["step_started", "step_failed"]
    assert rig.api.status_payloads(tid)[-1]["result_detail"] == "step_1_interrupted"
    assert len(rig.ws.agent_calls()) == 1
    rig.observe_statuses(tid)
    rig.observe_tree()


@pytest.mark.stacks
@pytest.mark.parametrize("runners", PAIRS, ids=["-".join(p) for p in PAIRS])
@pytest.mark.parametrize("variant", ["adopt_exit_code", "reattach_live_session", "interrupted"])
def test_sigkill_and_restart(rig: Rig, runners: tuple[str, str], variant: str) -> None:
    first_impl, second_impl = runners
    plan = [step("investigator", lines=2, wait="release-1", marker="started-1"), step("reviewer", "claude", lines=1)]
    tid = rig.api.add_ticket(plan)
    first = rig.runner(first_impl)
    rig.ws.wait_marker("started-1")
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    original_started_at = files.metadata["started_at"]
    first.kill()
    assert (rig.ws.exec_dir / "runner-state" / f"{tid}.json").exists()
    rig.observe("tree_after_kill", rig.norm.tree(rig.ws.exec_dir))

    if variant == "adopt_exit_code":
        rig.ws.release("release-1")
        wait_until(lambda: files.exists("exit_code"), what="exit code of the orphaned step")
    elif variant == "interrupted":
        rig.ws.kill_session(session_name(tid, 1, "investigator"))
        assert not files.exists("exit_code")
    else:
        assert rig.ws.sessions() == [session_name(tid, 1, "investigator")]

    second = rig.runner(second_impl)
    if variant == "reattach_live_session":
        wait_until(
            lambda: "step_1_resumed" in [p.get("result_detail") for p in rig.api.status_payloads(tid)],
            what="step_1_resumed",
        )
        assert rig.ws.sessions() == [session_name(tid, 1, "investigator")]
        rig.ws.release("release-1")
    wait_until(lambda: rig.api.ticket(tid)["state"] in {"succeeded", "failed"}, timeout=60, what="terminal ticket")
    wait_until(lambda: not list((rig.ws.exec_dir / "runner-state").iterdir()), what="state file removed")
    wait_until(lambda: rig.ws.sessions() == [], what="finished sessions killed by recovery")
    assert second.stop() == 0

    payloads = rig.api.status_payloads(tid)
    meta = files.metadata
    assert meta["started_at"] == original_started_at
    assert "resumed_at" in meta
    if variant == "interrupted":
        assert [p["event"] for p in payloads] == ["step_started", "step_failed"]
        assert payloads[-1]["result_detail"] == "step_1_interrupted"
        assert (payloads[-1]["state"], payloads[-1]["result"]) == ("failed", "failure")
        assert meta["status"] == "interrupted"
        assert [c["agent"] for c in rig.ws.agent_calls()] == ["codex"]
    else:
        assert [(p["event"], p.get("result_detail")) for p in payloads if p["event"] != "heartbeat"] == [
            ("step_started", "step_1_started"),
            ("step_started", "step_1_resumed"),
            ("step_finished", "step_1_finished"),
            ("step_started", "step_2_started"),
            ("step_finished", "step_2_finished"),
            ("ticket_succeeded", "completed_2_steps"),
        ]
        assert all(p["runner_host"] == RUNNER_HOST for p in payloads)
        assert meta["status"] == "succeeded"
        # Never relaunched: one agent run per step.
        assert [c["agent"] for c in rig.ws.agent_calls()] == ["codex", "claude"]
        reviewer = step_files(rig.ws.exec_dir, tid, 2, "reviewer")
        assert json.loads(reviewer.text("previous_step_summary.md")) == files.summary
        context = json.loads((rig.ws.exec_dir / "jobs" / tid / "context.json").read_text())
        assert context["prior_step_summaries"] == [files.summary]
    assert rig.ws.sessions() == []
    rig.observe_statuses(tid)
    rig.observe_tree()


@pytest.mark.stacks
@pytest.mark.parametrize("runners", PAIRS, ids=["-".join(p) for p in PAIRS])
def test_sigkill_in_later_step_skips_finished_steps(rig: Rig, runners: tuple[str, str]) -> None:
    first_impl, second_impl = runners
    plan = [
        step("investigator", lines=1),
        step("implementer", "claude", lines=2, wait="release-2", marker="started-2"),
        step("reviewer", lines=1),
    ]
    tid = rig.api.add_ticket(plan)
    first = rig.runner(first_impl)
    rig.ws.wait_marker("started-2")
    first.kill()
    one = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    two = step_files(rig.ws.exec_dir, tid, 2, "implementer")
    three = step_files(rig.ws.exec_dir, tid, 3, "reviewer")
    step_one_metadata = one.metadata

    second = rig.runner(second_impl)
    wait_until(
        lambda: "step_2_resumed" in [p.get("result_detail") for p in rig.api.status_payloads(tid)],
        what="step_2_resumed",
    )
    rig.ws.release("release-2")
    wait_until(lambda: rig.api.ticket(tid)["state"] in {"succeeded", "failed"}, timeout=60, what="terminal ticket")
    wait_until(lambda: rig.ws.sessions() == [], what="finished sessions killed by recovery")
    assert second.stop() == 0

    # The succeeded first step is skipped (its summary collected once), the second re-attached.
    assert [p.get("result_detail") for p in rig.api.status_payloads(tid) if p["event"] != "heartbeat"] == [
        "step_1_started",
        "step_1_finished",
        "step_2_started",
        "step_2_resumed",
        "step_2_finished",
        "step_3_started",
        "step_3_finished",
        "completed_3_steps",
    ]
    assert one.metadata == step_one_metadata
    assert "resumed_at" in two.metadata and two.metadata["status"] == "succeeded"
    assert [c["agent"] for c in rig.ws.agent_calls()] == ["codex", "claude", "codex"]
    assert json.loads(three.text("previous_step_summary.md")) == two.summary
    context = json.loads((rig.ws.exec_dir / "sessions" / tid / "context.json").read_text())
    assert context["step_index"] == 2
    assert context["prior_step_summaries"] == [one.summary, two.summary]
    rig.observe_statuses(tid)
    rig.observe_tree()


@pytest.mark.parametrize("content", ["{broken", "[]", "\udcff"], ids=["invalid-json", "not-an-object", "undecodable"])
def test_unreadable_metadata_fails_closed(rig: Rig, content: str) -> None:
    tid = rig.api.add_ticket([step("investigator")], state="running", runner_host=RUNNER_HOST, claimable=False)
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    files.step_dir.mkdir(parents=True)
    (files.step_dir / "session_metadata.json").write_bytes(content.encode("utf-8", "surrogateescape"))
    runner = rig.runner(once=True)
    assert runner.wait(60) == 0

    # Found through its artifact directory; the step counts as started and is never launched.
    assert rig.api.events(tid) == ["step_failed"]
    failed = rig.api.status_payloads(tid)[-1]
    assert failed["result_detail"] == "step_1_interrupted"
    assert [e["status"] for e in failed["tmux_sessions"]] == ["interrupted"]
    assert files.metadata["status"] == "interrupted"
    assert rig.ws.agent_calls() == [] and rig.ws.sessions() == []
    rig.observe_statuses(tid)
    rig.observe_tree()
