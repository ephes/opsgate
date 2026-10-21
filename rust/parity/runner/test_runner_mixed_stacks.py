"""Mixed stacks: a real API and a real runner of either implementation (rust/PLAN.md 3.1, 7.4).

One multi-step ticket goes through the whole life cycle (create with a submit
token, approve in an approver session, claim, two steps, success) for every
combination of Python/Rust API and Python/Rust runner, so the order of the API
and runner cutovers does not matter. The API's step log page reads the
artifacts the runner wrote.
"""

from __future__ import annotations

import pytest
from conftest import Rig
from runner_harness import RUNNER_HOST, step, wait_until

STACKS = [("python", "python"), ("python", "rust"), ("rust", "python"), ("rust", "rust")]


def collapse(events: list[dict[str, object]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for event in events:
        if out and event == out[-1] and event.get("event_type") == "runner_heartbeat":
            continue
        out.append(event)
    return out


@pytest.mark.stacks
@pytest.mark.parametrize(
    ("api", "runners"), [(a, (r,)) for a, r in STACKS], ids=[f"api_{a}-runner_{r}" for a, r in STACKS]
)
def test_mixed_stack_runs_multi_step_ticket(rig: Rig, api: str, runners: tuple[str]) -> None:
    server = rig.server(api)
    plan = [step("investigator", "codex", lines=3), step("reviewer", "claude", lines=2)]
    tid = server.create_ticket(plan, task_ref="mixed-stack-1", max_duration_seconds=600)
    assert server.get_ticket(tid)["state"] == "pending_approval"
    approver = server.approver()
    server.approve(approver, tid)

    runner = rig.runner(runners[0], base_url=server.base_url)
    wait_until(lambda: server.get_ticket(tid)["state"] in {"succeeded", "failed"}, timeout=90, what="ticket finished")
    wait_until(lambda: not list((rig.ws.exec_dir / "runner-state").iterdir()), what="state file removed")
    assert runner.stop() == 0

    ticket = server.get_ticket(tid)
    assert (ticket["state"], ticket["result"], ticket["result_detail"]) == ("succeeded", "success", "completed_2_steps")
    assert ticket["runner_host"] == RUNNER_HOST
    sessions = ticket["tmux_sessions"]
    assert [s["status"] for s in sessions] == ["succeeded", "succeeded"]
    assert [s["session_name"] for s in sessions] == [f"job-{tid}-01-investigator", f"job-{tid}-02-reviewer"]
    assert [c["agent"] for c in rig.ws.agent_calls()] == ["codex", "claude"]

    # The API's step log view reads the runner's artifacts (shared tree, 4.12/4.13.2).
    for number, expected in ((1, "codex output line 3"), (2, "claude output line 2")):
        page = approver.request("GET", f"/tickets/{tid}/steps/{number}/log")
        assert page.status == 200 and expected.encode() in page.body

    audit = server.audit_events(tid)
    types = [e["event_type"] for e in audit]
    assert types[:3] == ["ticket_created", "ticket_approved", "runner_claimed"]
    assert types[-1] == "runner_ticket_succeeded"
    rig.observe(
        "ticket",
        rig.norm.value(
            {
                key: ticket.get(key)
                for key in ("state", "result", "result_detail", "runner_host", "tmux_sessions", "started_at")
            }
        ),
    )
    rig.observe("audit", collapse([rig.norm.value(e) for e in audit]))
    rig.observe_tree()
    rig.observe_agents()
