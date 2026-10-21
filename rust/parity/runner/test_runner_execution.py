"""Executor scenarios over a fake API (rust/PLAN.md 4.13.2-4.13.4, 4.13.7, 4.13.8, 7.4)."""

from __future__ import annotations

import json
import time

from conftest import Rig
from runner_harness import RUNNER_HOST, RUNNER_TOKEN, session_name, step, step_files, wait_until


def run_once(rig: Rig, timeout: float = 60.0, **settings: str) -> int:
    runner = rig.runner(once=True, settings=settings)
    code = runner.wait(timeout)
    rig.observe("exit_code", code)
    rig.observe("log_lines", runner.p1_log_lines())
    return code


def test_single_step_success(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", lines=3)])
    assert run_once(rig) == 0

    assert rig.api.ticket(tid)["state"] == "succeeded"
    assert rig.api.events(tid) == ["step_started", "step_finished", "ticket_succeeded"]
    started, finished, done = rig.api.status_payloads(tid)
    assert started["runner_host"] == RUNNER_HOST
    assert started["result_detail"] == "step_1_started" and "state" not in started and "result" not in started
    assert finished["result_detail"] == "step_1_finished"
    assert (done["state"], done["result"], done["result_detail"]) == ("succeeded", "success", "completed_1_steps")
    assert [entry["status"] for entry in done["tmux_sessions"]] == ["succeeded"]

    # One claim that returns the ticket, one that returns none; JSON bodies with the runner host (4.13.1).
    claims = rig.api.calls("claim")
    assert [c.body for c in claims] == [{"runner_host": RUNNER_HOST}] * 2
    for call in rig.api.calls():
        assert call.authorized, call
        assert call.content_type == ("application/json" if call.method == "POST" else None), call
    rig.observe("claims", len(claims))

    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    meta = files.metadata
    assert meta["status"] == "succeeded"
    assert meta["session_name"] == session_name(tid, 1, "investigator")
    assert meta["summary_path"] == str(files.step_dir / "summary.json")
    assert meta["log_size_bytes"] == len(files.text("session.log").encode())
    assert files.text("session.log") == "".join(
        f"{line}\n" for line in ["codex output line 1", "codex output line 2", "codex output line 3", "codex done"]
    )
    assert files.text("exit_code") == "0\n"
    assert files.summary["status"] == "succeeded" and files.summary["exit_code"] == 0
    assert files.summary["summary_markdown"] == files.text("session.log").rstrip("\n")
    assert files.mode("run_step.sh") == 0o750
    assert files.mode("summary.json") == files.mode("session_metadata.json") == 0o600
    assert not files.exists("previous_step_summary.md")
    assert files.text("prompt.md") == rig.api.ticket(tid)["execution_plan"][0]["prompt_markdown"] + "\n"

    context = json.loads((rig.ws.exec_dir / "jobs" / tid / "context.json").read_text())
    assert context == {
        "ticket_id": tid,
        "step_index": 0,
        "step_role": "investigator",
        "step_agent": "codex",
        "prior_step_summaries": [],
    }
    assert not list((rig.ws.exec_dir / "runner-state").iterdir())

    (agent_call,) = rig.ws.agent_calls()
    assert agent_call["agent"] == "codex"
    assert agent_call["args"] == ["exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox", "-"]
    assert agent_call["prompt"] == files.text("prompt.md")
    # Every key of the env file reaches the agents and wins over the process environment (4.2, 4.13.8).
    assert agent_call["env"]["OPSGATE_PARITY_ENV_MARKER"] == "from-env-file"
    assert agent_call["env"]["OPSGATE_PARITY_OVERRIDE"] == "env-file-wins"
    assert agent_call["env"]["OPSGATE_PARITY_PROCESS_MARKER"] == "from-process"
    assert agent_call["env"]["OPSGATE_RUNNER_TOKEN"] == RUNNER_TOKEN
    # The harness passes no shell start-up hooks of its caller to the step scripts.
    assert agent_call["env"]["BASH_ENV"] is None
    assert agent_call["cwd"] in {str(rig.ws.cwd), str(rig.ws.cwd.resolve())}

    # remain-on-exit (production tmux.conf): the finished session stays until a recovery pass of a
    # long-running runner kills it; --once exits first.
    assert rig.ws.sessions() == [session_name(tid, 1, "investigator")]
    rig.observe_sessions()
    rig.observe_statuses(tid)
    rig.observe_tree()
    rig.observe_agents()


def test_multi_step_success(rig: Rig) -> None:
    plan = [
        step("Investigator", "codex", lines=2),
        step("implementer", "claude", lines=4),
        step("Reviewer #2", "CODEX", lines=1),
    ]
    tid = rig.api.add_ticket(plan)
    assert run_once(rig) == 0

    assert rig.api.events(tid) == ["step_started", "step_finished"] * 3 + ["ticket_succeeded"]
    done = rig.api.status_payloads(tid)[-1]
    assert done["result_detail"] == "completed_3_steps"
    entries = done["tmux_sessions"]
    assert [e["step_index"] for e in entries] == [0, 1, 2]
    assert [e["session_name"] for e in entries] == [
        session_name(tid, 1, "investigator"),
        session_name(tid, 2, "implementer"),
        session_name(tid, 3, "reviewer-2"),
    ]
    assert [e["role"] for e in entries] == ["Investigator", "implementer", "Reviewer #2"]
    assert [e["agent"] for e in entries] == ["codex", "claude", "CODEX"]

    first = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    second = step_files(rig.ws.exec_dir, tid, 2, "implementer")
    third = step_files(rig.ws.exec_dir, tid, 3, "reviewer-2")
    assert json.loads(second.text("previous_step_summary.md")) == first.summary
    assert json.loads(third.text("previous_step_summary.md")) == second.summary
    context = json.loads((rig.ws.exec_dir / "sessions" / tid / "context.json").read_text())
    assert context["step_index"] == 2 and context["step_role"] == "Reviewer #2" and context["step_agent"] == "CODEX"
    assert context["prior_step_summaries"] == [first.summary, second.summary]

    calls = rig.ws.agent_calls()
    assert [c["agent"] for c in calls] == ["codex", "claude", "codex"]
    assert calls[1]["args"] == ["-p", "--dangerously-skip-permissions"]
    rig.observe_statuses(tid)
    rig.observe_tree()
    rig.observe_agents()


def test_step_failure_exit_code(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", exit=3), step("reviewer")])
    assert run_once(rig) == 0

    assert rig.api.events(tid) == ["step_started", "step_failed"]
    failed = rig.api.status_payloads(tid)[-1]
    assert (failed["state"], failed["result"], failed["result_detail"]) == ("failed", "failure", "step_1_exit_code_3")
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "failed"
    assert files.summary["status"] == "failed" and files.summary["exit_code"] == 3
    assert not (rig.ws.exec_dir / "sessions" / tid / "steps" / "02-reviewer").exists()
    assert len(rig.ws.agent_calls()) == 1
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_unsupported_agent(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", "Gemini Pro")])
    assert run_once(rig) == 0

    assert rig.api.events(tid) == ["step_started", "step_failed"]
    failed = rig.api.status_payloads(tid)[-1]
    assert failed["result_detail"] == "unsupported_agent_gemini-pro"
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "failed"
    assert not files.exists("run_step.sh") and not files.exists("session.log")
    assert rig.ws.agent_calls() == [] and rig.ws.sessions() == []
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_invalid_plan(rig: Rig) -> None:
    empty = rig.api.add_ticket([])
    not_a_list = rig.api.add_ticket({"role": "investigator"})
    assert run_once(rig) == 0
    for tid in (empty, not_a_list):
        assert rig.api.status_payloads(tid) == [
            {
                "runner_host": RUNNER_HOST,
                "event": "invalid_plan",
                "state": "failed",
                "result": "failure",
                "result_detail": "invalid_execution_plan",
                "tmux_sessions": [],
            }
        ]
        rig.observe_statuses(tid)
    rig.observe_tree()


def test_ticket_timeout(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started")], max_duration_seconds=3)
    assert run_once(rig) == 0

    assert rig.api.events(tid) == ["step_started", "timeout"]
    timeout = rig.api.status_payloads(tid)[-1]
    assert (timeout["state"], timeout["result"], timeout["result_detail"]) == (
        "failed",
        "timeout",
        "max_duration_seconds_exceeded",
    )
    assert [e["status"] for e in timeout["tmux_sessions"]] == ["timeout"]
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "timeout" and "finished_at" in files.metadata
    assert not files.exists("exit_code") and not files.exists("summary.json")
    assert rig.ws.sessions() == []
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_cancel_during_step(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started"), step("reviewer")])
    runner = rig.runner(once=True)
    rig.ws.wait_marker("started")
    rig.api.set_state(tid, "canceled")
    assert runner.wait(30) == 0

    # The canceled ticket gets no further status update (4.13.4).
    assert rig.api.events(tid) == ["step_started"]
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "canceled" and "finished_at" in files.metadata
    assert rig.ws.sessions() == []
    assert len(rig.ws.agent_calls()) == 1
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_terminal_state_during_step(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started")])
    runner = rig.runner(once=True)
    rig.ws.wait_marker("started")
    rig.api.set_state(tid, "expired")
    assert runner.wait(30) == 0

    # The failure report meets a terminal ticket: 409 invalid_state is accepted silently.
    calls = rig.api.calls("status", tid)
    assert [(c.body["event"], c.response) for c in calls] == [("step_started", 200), ("step_failed", 409)]
    assert calls[-1].body["result_detail"] == "ticket_entered_expired"
    assert step_files(rig.ws.exec_dir, tid, 1, "investigator").metadata["status"] == "running"
    assert rig.ws.sessions() == []
    assert runner.p1_log_lines() == []
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_session_killed_externally(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started")])
    runner = rig.runner(once=True)
    rig.ws.wait_marker("started")
    rig.ws.kill_session(session_name(tid, 1, "investigator"))
    assert runner.wait(30) == 0

    assert rig.api.events(tid) == ["step_started", "step_failed"]
    assert rig.api.status_payloads(tid)[-1]["result_detail"] == "session_terminated_without_exit_code"
    assert step_files(rig.ws.exec_dir, tid, 1, "investigator").metadata["status"] == "running"
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_heartbeat_cadence(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", sleep=4.5), step("reviewer", sleep=2)])
    assert run_once(rig, OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS="1") == 0

    payloads = rig.api.status_payloads(tid)
    heartbeats = [p for p in payloads if p["event"] == "heartbeat"]
    first_step = [p["result_detail"] for p in heartbeats if p["result_detail"].endswith("_of_2")]
    assert {p["result_detail"] for p in heartbeats} <= {"running_step_1_of_2", "running_step_2_of_2"}
    assert first_step.count("running_step_1_of_2") >= 2
    assert all(p["tmux_sessions"][-1]["status"] == "running" for p in heartbeats)
    times = [c.at for c in rig.api.calls("status", tid) if c.body["event"] == "heartbeat"]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    # One heartbeat per interval at most (the poll loop sleeps 1 s between checks).
    assert all(gap >= 0.8 for gap in gaps), gaps
    assert [e for e in rig.api.events(tid) if e != "heartbeat"] == [
        "step_started",
        "step_finished",
        "step_started",
        "step_finished",
        "ticket_succeeded",
    ]
    rig.observe_statuses(tid)


def test_no_heartbeat_before_interval(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", sleep=3)])
    assert run_once(rig) == 0
    assert "heartbeat" not in rig.api.events(tid)
    assert len(rig.api.calls("get", tid)) >= 3
    rig.observe_statuses(tid)


def test_parallel_tickets_and_limit(rig: Rig) -> None:
    tids = [rig.api.add_ticket([step(f"worker {n}", wait=f"release-{n}", marker=f"started-{n}")]) for n in (1, 2, 3)]
    runner = rig.runner(OPSGATE_MAX_PARALLEL_JOBS="2")
    rig.ws.wait_marker("started-1")
    rig.ws.wait_marker("started-2")
    # Two workers fill the limit: the third ticket is not claimed while both run.
    time.sleep(3)
    assert rig.api.ticket(tids[2])["state"] == "approved"
    assert len([c for c in rig.api.calls("claim") if c.response == 200]) == 2
    running = sorted(session_name(t, 1, f"worker-{n}") for n, t in zip((1, 2), tids[:2], strict=True))
    assert rig.ws.sessions() == running
    state_files = sorted(p.name for p in (rig.ws.exec_dir / "runner-state").iterdir())
    assert state_files == sorted(f"{t}.json" for t in tids[:2])
    state = json.loads((rig.ws.exec_dir / "runner-state" / f"{tids[0]}.json").read_text())
    assert set(state) == {"ticket_id", "runner_host", "updated_at"}
    assert (state["ticket_id"], state["runner_host"]) == (tids[0], RUNNER_HOST)

    rig.ws.release("release-1")
    rig.ws.wait_marker("started-3")
    rig.ws.release("release-2")
    rig.ws.release("release-3")
    wait_until(lambda: all(rig.api.ticket(t)["state"] == "succeeded" for t in tids), what="all tickets succeeded")
    wait_until(lambda: not list((rig.ws.exec_dir / "runner-state").iterdir()), what="state files reaped")
    # Recovery passes find the finished (remain-on-exit) sessions of terminal tickets and kill them.
    wait_until(lambda: rig.ws.sessions() == [], what="finished sessions killed by recovery")
    assert runner.stop() == 0
    for tid in tids:
        rig.observe_statuses(tid)
    rig.observe_tree()
