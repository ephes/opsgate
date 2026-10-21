"""API error, retry and outage scenarios (rust/PLAN.md 4.13.1, 4.13.4 `_post_status`, 4.13.6, 4.15, 7.4)."""

from __future__ import annotations

import json

import pytest
from conftest import Rig
from runner_harness import session_name, step, step_files, wait_until

UNAVAILABLE = {"error": "unavailable", "message": "scripted outage"}


def test_status_retry_recovers(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    rig.api.fail("status", event="step_started", times=1, status=503, body=UNAVAILABLE)
    rig.api.fail("status", event="step_started", times=1, drop=True)
    runner = rig.runner(once=True)
    assert runner.wait(60) == 0

    calls = rig.api.calls("status", tid)
    assert [(c.body["event"], c.response) for c in calls] == [
        ("step_started", 503),
        ("step_started", "dropped"),
        ("step_started", 200),
        ("step_finished", 200),
        ("ticket_succeeded", 200),
    ]
    # Up to three attempts, one second apart (stop-aware wait).
    assert calls[1].at - calls[0].at >= 0.9 and calls[2].at - calls[1].at >= 0.9
    assert calls[0].body == calls[1].body == calls[2].body
    assert runner.p1_log_lines() == []
    rig.observe("log_lines", runner.p1_log_lines())
    rig.observe_statuses(tid)


def test_status_outage_keeps_state_for_recovery(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    rig.api.fail("status", event="step_started", times=3, status=503, body=UNAVAILABLE)
    first = rig.runner(once=True)
    assert first.wait(60) == 0

    # Three failed attempts: the worker gives up without failing the ticket and keeps its state file.
    assert [(c.body["event"], c.response) for c in rig.api.calls("status", tid)] == [("step_started", 503)] * 3
    assert first.p1_log_lines() == ["Runner API unavailable 503 http_error"]
    assert (rig.ws.exec_dir / "runner-state" / f"{tid}.json").exists()
    files = step_files(rig.ws.exec_dir, tid, 1, "investigator")
    assert files.metadata["status"] == "running"
    assert rig.ws.agent_calls() == [] and rig.ws.sessions() == []
    rig.observe("first_log_lines", first.p1_log_lines())
    rig.observe("tree_after_outage", rig.norm.tree(rig.ws.exec_dir))

    # The next runner recovers the ticket from the state file; the step was started and never ran,
    # so it is failed as interrupted instead of being launched again (4.13.5).
    second = rig.runner(once=True)
    assert second.wait(60) == 0
    assert rig.api.events(tid) == ["step_started"] * 3 + ["step_failed"]
    assert rig.api.status_payloads(tid)[-1]["result_detail"] == "step_1_interrupted"
    assert files.metadata["status"] == "interrupted"
    assert rig.ws.agent_calls() == []
    assert not (rig.ws.exec_dir / "runner-state" / f"{tid}.json").exists()
    rig.observe_statuses(tid)
    rig.observe_tree()


def test_heartbeat_outage_reattaches_live_session(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="release", marker="started")])
    rig.api.fail("status", event="heartbeat", times=3, status=503, body=UNAVAILABLE)
    runner = rig.runner(OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS="1")
    rig.ws.wait_marker("started")

    def resumed() -> bool:
        return any(p.get("result_detail") == "step_1_resumed" for p in rig.api.status_payloads(tid))

    wait_until(resumed, timeout=60, what="step_1_resumed")
    # The live session was never killed or relaunched.
    assert rig.ws.sessions() == [session_name(tid, 1, "investigator")]
    rig.ws.release("release")
    wait_until(lambda: rig.api.ticket(tid)["state"] == "succeeded", timeout=60, what="ticket succeeded")
    assert runner.stop() == 0

    calls = rig.api.calls("status", tid)
    assert [(c.body["event"], c.response) for c in calls[:4]] == [("step_started", 200)] + [("heartbeat", 503)] * 3
    assert calls[4].body["event"] == "step_started" and calls[4].body["result_detail"] == "step_1_resumed"
    assert [c.body["event"] for c in calls[-2:]] == ["step_finished", "ticket_succeeded"]
    assert len(rig.ws.agent_calls()) == 1
    meta = step_files(rig.ws.exec_dir, tid, 1, "investigator").metadata
    assert meta["status"] == "succeeded" and "resumed_at" in meta
    assert runner.p1_log_lines() == ["Runner API unavailable 503 http_error"]
    rig.observe("log_lines", runner.p1_log_lines())
    rig.observe_statuses(tid)
    rig.observe_tree()


@pytest.mark.parametrize("status", [400, 404, 409])
def test_permanent_status_error_stops_session_and_fails(rig: Rig, status: int) -> None:
    tid = rig.api.add_ticket([step("investigator", wait="never", marker="started")])
    rig.api.fail("status", event="heartbeat", times=1, status=status, body={"error": "rejected", "message": "no"})
    runner = rig.runner(once=True, OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS="1")
    assert runner.wait(60) == 0

    calls = rig.api.calls("status", tid)
    assert [(c.body["event"], c.response) for c in calls] == [
        ("step_started", 200),
        ("heartbeat", status),
        ("failed", 200),
    ]
    failed = calls[-1].body
    assert set(failed) == {"runner_host", "event", "state", "result", "result_detail"}
    assert (failed["state"], failed["result"]) == ("failed", "failure")
    assert failed["result_detail"].startswith("runner_unhandled_exception:")
    # The session is gone (killed and verified) before the failure is reported.
    assert rig.ws.sessions() == []
    assert not list((rig.ws.exec_dir / "runner-state").iterdir())
    assert runner.p1_log_lines() == []
    rig.observe_statuses(tid)
    rig.observe_tree()


@pytest.mark.parametrize("code", ["invalid_state", "state_changed"])
def test_conflict_after_ticket_moved_on_is_silent(rig: Rig, code: str) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    rig.api.fail("status", event="step_finished", times=1, status=409, body={"error": code, "message": "moved"})
    runner = rig.runner(once=True)
    assert runner.wait(60) == 0
    assert [(c.body["event"], c.response) for c in rig.api.calls("status", tid)] == [
        ("step_started", 200),
        ("step_finished", 409),
        ("ticket_succeeded", 200),
    ]
    assert runner.p1_log_lines() == []
    rig.observe_statuses(tid)


def test_other_conflict_is_permanent(rig: Rig) -> None:
    tid = rig.api.add_ticket([step("investigator")])
    rig.api.fail(
        "status", event="step_finished", times=1, status=409, body={"error": "runner_host_mismatch", "message": "x"}
    )
    runner = rig.runner(once=True)
    assert runner.wait(60) == 0
    calls = rig.api.calls("status", tid)
    assert [(c.body["event"], c.response) for c in calls] == [
        ("step_started", 200),
        ("step_finished", 409),
        ("failed", 200),
    ]
    assert calls[-1].body["result_detail"].startswith("runner_unhandled_exception:")
    rig.observe_statuses(tid)


def test_claim_failures_are_logged_and_skipped(rig: Rig) -> None:
    rig.api.fail("claim", times=1, status=503, body=UNAVAILABLE)
    rig.api.fail("claim", times=1, drop=True)
    rig.api.fail("claim", times=1, status=409, body={"error": "runner_host_mismatch", "message": "x"})
    rig.api.fail("claim", times=1, status=418, body={"error": "teapot", "message": "x"})
    rig.api.fail("claim", times=1, status=200, raw=b"not json")
    rig.api.fail("claim", times=1, status=200, raw=b"[1]")
    rig.api.fail("claim", times=1, status=200, raw=json.dumps({"ticket": "bad"}).encode())
    # A ticket without id is skipped and the runner claims again in the same round.
    rig.api.fail("claim", times=1, status=200, raw=json.dumps({"ticket": {"state": "running"}}).encode())
    tid = rig.api.add_ticket([step("investigator")])
    runner = rig.runner()
    wait_until(lambda: rig.api.ticket(tid)["state"] == "succeeded", timeout=90, what="ticket succeeded")
    assert runner.stop() == 0

    assert runner.p1_log_lines() == [
        "Runner claim failed 503 http_error",
        "Runner claim failed 503 transport_error",
        "Runner claim failed 409 runner_host_mismatch",
        "Runner claim failed 418 http_error",
        "Runner claim failed 502 invalid_response",
        "Runner claim failed 500 invalid_response",
        "Runner claim failed 500 invalid_ticket",
    ]
    claims = rig.api.calls("claim")
    # Each failure ends its claim round; the id-less ticket does not.
    assert [c.response for c in claims[7:9]] == [200, 200]
    assert claims[8].at - claims[7].at < 0.9
    rig.observe("log_lines", runner.p1_log_lines())
    rig.observe_statuses(tid)
