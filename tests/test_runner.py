from __future__ import annotations

import json
import shlex
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from opsgate.config import RunnerSettings
from opsgate.runner import OpsGateRunner, RunnerApiError, TicketExecutor, _build_agent_command, _build_attach_command


class FakeApi:
    def __init__(self, ticket: dict[str, Any]) -> None:
        self.ticket = ticket
        self.updates: list[dict[str, Any]] = []

    def get_ticket(self, _: str) -> dict[str, Any]:
        return self.ticket

    def update_status(self, _: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.updates.append(payload)
        if "state" in payload:
            self.ticket["state"] = payload["state"]
        if "result" in payload:
            self.ticket["result"] = payload["result"]
        if "result_detail" in payload:
            self.ticket["result_detail"] = payload["result_detail"]
        if "tmux_sessions" in payload:
            self.ticket["tmux_sessions"] = payload["tmux_sessions"]
        return self.ticket


class StubTicketExecutor(TicketExecutor):
    def __init__(
        self,
        *,
        has_session: bool,
        auto_complete_exit_code: int | None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._has_session = has_session
        self._auto_complete_exit_code = auto_complete_exit_code
        self.killed_sessions: list[str] = []

    def _tmux_has_session(self, session_name: str) -> bool:
        del session_name
        return self._has_session

    def _tmux_new_session(self, *, session_name: str, script_path: Path) -> None:
        del session_name
        if self._auto_complete_exit_code is None:
            return
        step_dir = script_path.parent
        (step_dir / "session.log").write_text("ok\n", encoding="utf-8")
        (step_dir / "exit_code").write_text(f"{self._auto_complete_exit_code}\n", encoding="utf-8")

    def _tmux_kill_session(self, session_name: str) -> None:
        self.killed_sessions.append(session_name)


def _runner_settings(tmp_path: Path) -> RunnerSettings:
    execution_data_dir = tmp_path / "execution"
    tickets_dir = execution_data_dir / "jobs"
    session_artifacts_dir = execution_data_dir / "sessions"
    return RunnerSettings(
        service_name="opsgate",
        runner_token="runner-token-000000000000",
        runner_host="runner-a",
        runner_api_base_url="http://127.0.0.1:8711",
        runner_poll_interval_seconds=1,
        runner_heartbeat_interval_seconds=1,
        max_parallel_jobs=2,
        max_duration_seconds_default=3600,
        execution_data_dir=str(execution_data_dir),
        tickets_dir=str(tickets_dir),
        session_artifacts_dir=str(session_artifacts_dir),
        tmux_socket_label="remediation",
        tmux_tmpdir=str(execution_data_dir / "tmux"),
        disable_file_path=str(execution_data_dir / ".disabled"),
    )


def test_ticket_executor_runs_steps_sequentially(tmp_path: Path) -> None:
    now = datetime.now(tz=UTC)
    ticket_id = "aaaaaaaa-1111-4111-8111-111111111111"
    ticket: dict[str, Any] = {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 120,
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "echo step-1"},
            {"role": "reviewer", "agent": "claude", "prompt_markdown": "echo step-2"},
        ],
        "tmux_sessions": [],
    }
    api = FakeApi(ticket)
    executor = StubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    executor.run(initial_ticket=ticket)

    assert ticket["state"] == "succeeded"
    assert ticket["result"] == "success"

    summaries = sorted((tmp_path / "execution" / "sessions" / ticket_id / "steps").glob("*/summary.json"))
    assert len(summaries) == 2

    details = [str(update.get("result_detail", "")) for update in api.updates]
    assert "step_1_started" in details
    assert "step_2_started" in details


def test_ticket_executor_reports_timeout_result(tmp_path: Path) -> None:
    now = datetime.now(tz=UTC)
    ticket_id = "bbbbbbbb-2222-4222-8222-222222222222"
    ticket: dict[str, Any] = {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 1,
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "sleep 10"},
        ],
        "tmux_sessions": [],
    }
    api = FakeApi(ticket)
    executor = StubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=True,
        auto_complete_exit_code=None,
    )
    executor.run(initial_ticket=ticket)

    assert ticket["state"] == "failed"
    assert ticket["result"] == "timeout"
    assert ticket["result_detail"] == "max_duration_seconds_exceeded"
    assert len(executor.killed_sessions) >= 1


def test_ticket_executor_reports_step_failure_detail(tmp_path: Path) -> None:
    now = datetime.now(tz=UTC)
    ticket_id = "dddddddd-4444-4444-8444-444444444444"
    ticket: dict[str, Any] = {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 120,
        "execution_plan": [
            {"role": "reviewer", "agent": "claude", "prompt_markdown": "exit 7"},
        ],
        "tmux_sessions": [],
    }
    api = FakeApi(ticket)
    executor = StubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=7,
    )
    executor.run(initial_ticket=ticket)

    assert ticket["state"] == "failed"
    assert ticket["result"] == "failure"
    assert ticket["result_detail"] == "step_1_exit_code_7"
    assert any(update.get("event") == "step_failed" for update in api.updates)


def test_ticket_executor_resumes_from_existing_step_summary(tmp_path: Path) -> None:
    now = datetime.now(tz=UTC)
    ticket_id = "cccccccc-3333-4333-8333-333333333333"
    ticket: dict[str, Any] = {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 120,
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "echo step-1"},
            {"role": "reviewer", "agent": "claude", "prompt_markdown": "echo step-2"},
        ],
        "tmux_sessions": [],
    }
    api = FakeApi(ticket)
    executor = StubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )

    first_step_paths = executor._prepare_step_paths(0, ticket["execution_plan"][0])
    first_step_paths.step_dir.mkdir(parents=True, exist_ok=True)
    first_step_paths.summary_path.write_text(
        '{"status":"succeeded","summary_markdown":"already done"}\n',
        encoding="utf-8",
    )

    executor.run(initial_ticket=ticket)

    details = [str(update.get("result_detail", "")) for update in api.updates]
    assert "step_1_started" not in details
    assert "step_2_started" in details
    assert ticket["state"] == "succeeded"


def test_worker_keeps_state_file_when_status_update_unavailable(tmp_path: Path, monkeypatch) -> None:
    ticket_id = "11111111-2222-4333-8444-555555555555"
    runner = OpsGateRunner(_runner_settings(tmp_path))
    runner._write_state_file(ticket_id)

    class FailingApi:
        def update_status(self, _: str, __: dict[str, Any]) -> dict[str, Any]:
            raise RunnerApiError("down", status_code=503, error_code="unavailable")

        def get_ticket(self, _: str) -> dict[str, Any]:
            raise RunnerApiError("down", status_code=503, error_code="unavailable")

    class ExplodingExecutor:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self, *, initial_ticket: dict[str, Any] | None) -> None:
            del initial_ticket
            raise RuntimeError("boom")

    runner.api = FailingApi()  # type: ignore[assignment]
    monkeypatch.setattr("opsgate.runner.TicketExecutor", ExplodingExecutor)
    runner._run_worker(ticket_id=ticket_id, initial_ticket={"id": ticket_id})

    assert runner._worker_state_path(ticket_id).exists()


def test_worker_exception_report_includes_runner_host(tmp_path: Path, monkeypatch) -> None:
    ticket_id = "66666666-6666-4666-8666-666666666666"
    runner = OpsGateRunner(_runner_settings(tmp_path))

    class CaptureApi:
        def __init__(self) -> None:
            self.updates: list[dict[str, Any]] = []

        def update_status(self, _: str, payload: dict[str, Any]) -> dict[str, Any]:
            self.updates.append(payload)
            return {"state": "failed"}

        def get_ticket(self, _: str) -> dict[str, Any]:
            return {"state": "failed"}

    class ExplodingExecutor:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self, *, initial_ticket: dict[str, Any] | None) -> None:
            del initial_ticket
            raise RuntimeError("boom")

    capture_api = CaptureApi()
    runner.api = capture_api  # type: ignore[assignment]
    monkeypatch.setattr("opsgate.runner.TicketExecutor", ExplodingExecutor)

    runner._run_worker(ticket_id=ticket_id, initial_ticket={"id": ticket_id, "state": "running"})

    assert len(capture_api.updates) == 1
    assert capture_api.updates[0]["runner_host"] == "runner-a"
    assert capture_api.updates[0]["event"] == "failed"
    assert capture_api.updates[0]["state"] == "failed"


def test_worker_success_marks_state_for_cleanup(tmp_path: Path, monkeypatch) -> None:
    ticket_id = "44444444-4444-4444-8444-444444444444"
    runner = OpsGateRunner(_runner_settings(tmp_path))
    runner._write_state_file(ticket_id)

    class NoopExecutor:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self, *, initial_ticket: dict[str, Any] | None) -> None:
            del initial_ticket

    monkeypatch.setattr("opsgate.runner.TicketExecutor", NoopExecutor)
    runner._run_worker(ticket_id=ticket_id, initial_ticket={"id": ticket_id, "state": "running"})

    assert runner._worker_state_path(ticket_id).exists()
    assert runner._worker_cleanup[ticket_id] is True


def test_reap_finished_workers_cleans_state_files(tmp_path: Path) -> None:
    ticket_id = "55555555-5555-4555-8555-555555555555"
    runner = OpsGateRunner(_runner_settings(tmp_path))
    runner._write_state_file(ticket_id)
    runner._worker_cleanup[ticket_id] = True

    worker = threading.Thread(target=lambda: None)
    worker.start()
    worker.join()
    runner.workers[ticket_id] = worker

    runner._reap_finished_workers()

    assert ticket_id not in runner.workers
    assert ticket_id not in runner._worker_cleanup
    assert not runner._worker_state_path(ticket_id).exists()


def test_recovery_restarts_only_running_tickets(tmp_path: Path, monkeypatch) -> None:
    running_ticket_id = "11111111-1111-4111-8111-111111111111"
    approved_ticket_id = "22222222-2222-4222-8222-222222222222"
    terminal_ticket_id = "33333333-3333-4333-8333-333333333333"
    runner = OpsGateRunner(_runner_settings(tmp_path))
    for ticket_id in (running_ticket_id, approved_ticket_id, terminal_ticket_id):
        runner._write_state_file(ticket_id)

    class RecoveryApi:
        def get_ticket(self, ticket_id: str) -> dict[str, Any]:
            states = {
                running_ticket_id: "running",
                approved_ticket_id: "approved",
                terminal_ticket_id: "succeeded",
            }
            return {"id": ticket_id, "state": states[ticket_id]}

    runner.api = RecoveryApi()  # type: ignore[assignment]

    started_workers: list[tuple[str, dict[str, Any] | None]] = []
    killed_terminal_sessions: list[str] = []

    def _record_worker_start(*, ticket_id: str, initial_ticket: dict[str, Any] | None = None) -> None:
        started_workers.append((ticket_id, initial_ticket))

    monkeypatch.setattr(runner, "_start_worker", _record_worker_start)
    monkeypatch.setattr(runner, "_kill_tmux_sessions_for_ticket", killed_terminal_sessions.append)
    monkeypatch.setattr(
        runner,
        "_discover_ticket_ids_from_tmux",
        lambda: {running_ticket_id, approved_ticket_id, terminal_ticket_id},
    )
    monkeypatch.setattr(runner, "_discover_ticket_ids_from_artifacts", lambda: set())

    runner._recover_inflight_tickets(include_artifacts=True)

    assert [ticket_id for ticket_id, _ in started_workers] == [running_ticket_id]
    assert started_workers[0][1] is not None
    assert started_workers[0][1]["state"] == "running"
    assert killed_terminal_sessions == [approved_ticket_id, terminal_ticket_id]
    assert runner._worker_state_path(running_ticket_id).exists()
    assert not runner._worker_state_path(approved_ticket_id).exists()
    assert not runner._worker_state_path(terminal_ticket_id).exists()


def test_discover_ticket_ids_from_tmux_handles_missing_binary(tmp_path: Path, monkeypatch) -> None:
    runner = OpsGateRunner(_runner_settings(tmp_path))

    def _raise_file_not_found(*_: Any, **__: Any) -> Any:
        raise FileNotFoundError("tmux")

    monkeypatch.setattr("opsgate.runner.subprocess.run", _raise_file_not_found)
    assert runner._discover_ticket_ids_from_tmux() == set()


def test_build_agent_command_rejects_unsupported_agent(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported agent"):
        _build_agent_command("custom-agent --flag '; rm -rf /'", prompt_path)


def test_build_agent_command_uses_codex_exec_with_stdin(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    command = _build_agent_command("codex", prompt_path)

    assert command == (
        "codex exec --skip-git-repo-check "
        "--dangerously-bypass-approvals-and-sandbox "
        f"- < {shlex.quote(str(prompt_path))}"
    )


def test_build_agent_command_uses_claude_print_with_bypass_permissions(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    command = _build_agent_command("claude", prompt_path)

    assert command == f"claude -p --dangerously-skip-permissions < {shlex.quote(str(prompt_path))}"


def test_build_attach_command_includes_tmux_tmpdir() -> None:
    command = _build_attach_command(
        tmux_socket_label="remediation",
        session_name="job-1",
        tmux_tmpdir="/Users/ops/remediation/tmux",
    )

    assert command == (
        "sudo -u ops env TMUX_TMPDIR=/Users/ops/remediation/tmux "
        "tmux -L remediation attach -t job-1"
    )


def test_ticket_executor_rejects_unsupported_agent(tmp_path: Path) -> None:
    now = datetime.now(tz=UTC)
    ticket_id = "eeeeeeee-5555-4555-8555-555555555555"
    ticket: dict[str, Any] = {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 120,
        "execution_plan": [
            {"role": "investigator", "agent": "shell", "prompt_markdown": "Inspect the service"},
        ],
        "tmux_sessions": [],
    }
    api = FakeApi(ticket)
    executor = StubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )

    executor.run(initial_ticket=ticket)

    assert ticket["state"] == "failed"
    assert ticket["result"] == "failure"
    assert ticket["result_detail"] == "unsupported_agent_shell"


class RecordingStubTicketExecutor(StubTicketExecutor):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.launched_sessions: list[str] = []

    def _tmux_new_session(self, *, session_name: str, script_path: Path) -> None:
        self.launched_sessions.append(session_name)
        super()._tmux_new_session(session_name=session_name, script_path=script_path)


def _resume_ticket(ticket_id: str, plan: list[dict[str, str]]) -> dict[str, Any]:
    now = datetime.now(tz=UTC)
    return {
        "id": ticket_id,
        "state": "running",
        "started_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "max_duration_seconds": 120,
        "execution_plan": plan,
        "tmux_sessions": [],
    }


def _write_interrupted_step(
    executor: TicketExecutor,
    step_index: int,
    step: dict[str, str],
    *,
    exit_code: int | None,
) -> Any:
    step_paths = executor._prepare_step_paths(step_index, step)
    step_paths.step_dir.mkdir(parents=True, exist_ok=True)
    step_paths.metadata_path.write_text(
        json.dumps(
            {
                "step_index": step_index,
                "role": step["role"],
                "agent": step["agent"],
                "session_name": f"job-{executor.ticket_id}-{step_index + 1:02d}-{step['role']}",
                "status": "running",
                "started_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    step_paths.prompt_path.write_text(step["prompt_markdown"] + "\n", encoding="utf-8")
    step_paths.log_path.write_text("original run output\n", encoding="utf-8")
    if exit_code is not None:
        step_paths.exit_code_path.write_text(f"{exit_code}\n", encoding="utf-8")
    return step_paths


@pytest.mark.parametrize(
    ("exit_code", "expected_state", "expected_detail"),
    [(0, "succeeded", "completed_1_steps"), (3, "failed", "step_1_exit_code_3")],
)
def test_resume_adopts_existing_exit_code_without_relaunch(
    tmp_path: Path, exit_code: int, expected_state: str, expected_detail: str
) -> None:
    ticket_id = "77777777-7777-4777-8777-777777777777"
    plan = [{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)
    executor = RecordingStubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    step_paths = _write_interrupted_step(executor, 0, plan[0], exit_code=exit_code)

    executor.run(initial_ticket=ticket)

    assert executor.launched_sessions == []
    assert not step_paths.script_path.exists()
    assert ticket["state"] == expected_state
    assert ticket["result_detail"] == expected_detail
    summary = json.loads(step_paths.summary_path.read_text(encoding="utf-8"))
    assert summary["exit_code"] == exit_code
    assert summary["started_at"] == "2026-01-01T00:00:00Z"
    assert summary["summary_markdown"] == "original run output"


def test_resume_fails_interrupted_step_without_relaunch(tmp_path: Path) -> None:
    ticket_id = "88888888-8888-4888-8888-888888888888"
    plan = [
        {"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "review"},
    ]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)
    executor = RecordingStubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    step_paths = _write_interrupted_step(executor, 0, plan[0], exit_code=None)

    executor.run(initial_ticket=ticket)

    assert executor.launched_sessions == []
    assert not step_paths.script_path.exists()
    assert not step_paths.summary_path.exists()
    assert ticket["state"] == "failed"
    assert ticket["result"] == "failure"
    assert ticket["result_detail"] == "step_1_interrupted"
    metadata = json.loads(step_paths.metadata_path.read_text(encoding="utf-8"))
    assert metadata["status"] == "interrupted"
    assert metadata["started_at"] == "2026-01-01T00:00:00Z"
    assert "finished_at" in metadata
    details = [str(update.get("result_detail", "")) for update in api.updates]
    assert "step_2_started" not in details
    assert ticket["tmux_sessions"][0]["status"] == "interrupted"


def test_resume_reattaches_live_session_without_relaunch(tmp_path: Path) -> None:
    ticket_id = "99999999-9999-4999-8999-999999999999"
    plan = [{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)

    class FinishingExecutor(RecordingStubTicketExecutor):
        def _tmux_has_session(self, session_name: str) -> bool:
            del session_name
            # The live session finishes while the resumed runner polls it.
            step_paths = self._prepare_step_paths(0, plan[0])
            step_paths.exit_code_path.write_text("0\n", encoding="utf-8")
            return True

    executor = FinishingExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=True,
        auto_complete_exit_code=0,
    )
    _write_interrupted_step(executor, 0, plan[0], exit_code=None)

    executor.run(initial_ticket=ticket)

    assert executor.launched_sessions == []
    assert ticket["state"] == "succeeded"


def test_resumed_summary_appears_once_in_next_step_context(tmp_path: Path) -> None:
    ticket_id = "abababab-abab-4bab-8bab-abababababab"
    plan = [
        {"role": "investigator", "agent": "codex", "prompt_markdown": "inspect"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "review"},
    ]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)
    executor = RecordingStubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    first_step_paths = executor._prepare_step_paths(0, plan[0])
    first_step_paths.step_dir.mkdir(parents=True, exist_ok=True)
    first_step_paths.summary_path.write_text(
        '{"status":"succeeded","summary_markdown":"already done"}\n',
        encoding="utf-8",
    )

    executor.run(initial_ticket=ticket)

    second_step_paths = executor._prepare_step_paths(1, plan[1])
    context = json.loads(second_step_paths.context_path.read_text(encoding="utf-8"))
    assert context["step_index"] == 1
    assert context["prior_step_summaries"] == [{"status": "succeeded", "summary_markdown": "already done"}]
    assert len(executor.launched_sessions) == 1
    assert ticket["state"] == "succeeded"


def test_runner_shutdown_marks_running_step_interrupted(tmp_path: Path) -> None:
    ticket_id = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd"
    plan = [{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)
    stop_event = threading.Event()

    class StoppingExecutor(RecordingStubTicketExecutor):
        def _tmux_new_session(self, *, session_name: str, script_path: Path) -> None:
            super()._tmux_new_session(session_name=session_name, script_path=script_path)
            self._has_session = True
            stop_event.set()

    executor = StoppingExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=stop_event,
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=None,
    )

    executor.run(initial_ticket=ticket)

    step_paths = executor._prepare_step_paths(0, plan[0])
    metadata = json.loads(step_paths.metadata_path.read_text(encoding="utf-8"))
    assert metadata["status"] == "interrupted"
    assert executor.killed_sessions == [executor.launched_sessions[0]]
    assert ticket["state"] == "running"


@pytest.mark.parametrize("failure", ["malformed_json", "invalid_utf8", "read_error"])
def test_resume_fails_closed_on_unreadable_metadata(tmp_path: Path, monkeypatch, failure: str) -> None:
    ticket_id = "efefefef-efef-4fef-8fef-efefefefefef"
    plan = [{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)
    executor = RecordingStubTicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    step_paths = _write_interrupted_step(executor, 0, plan[0], exit_code=None)
    if failure == "malformed_json":
        step_paths.metadata_path.write_text("{not json", encoding="utf-8")
    elif failure == "invalid_utf8":
        step_paths.metadata_path.write_bytes(b"\xff\xfe{")
    else:
        original_read_text = Path.read_text
        metadata_path = step_paths.metadata_path

        def _read_text(self: Path, *args: Any, **kwargs: Any) -> str:
            if self == metadata_path:
                raise PermissionError("denied")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _read_text)

    executor.run(initial_ticket=ticket)

    assert executor.launched_sessions == []
    assert ticket["state"] == "failed"
    assert ticket["result_detail"] == "step_1_interrupted"


def test_resume_adopts_exit_code_written_during_session_probe(tmp_path: Path) -> None:
    ticket_id = "fafafafa-fafa-4afa-8afa-fafafafafafa"
    plan = [{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]
    ticket = _resume_ticket(ticket_id, plan)
    api = FakeApi(ticket)

    class RacingExecutor(RecordingStubTicketExecutor):
        def _tmux_has_session(self, session_name: str) -> bool:
            del session_name
            # The session writes exit_code and exits right as the runner probes it.
            self._prepare_step_paths(0, plan[0]).exit_code_path.write_text("0\n", encoding="utf-8")
            return False

    executor = RacingExecutor(
        settings=_runner_settings(tmp_path),
        api=api,
        stop_event=threading.Event(),
        ticket_id=ticket_id,
        has_session=False,
        auto_complete_exit_code=0,
    )
    _write_interrupted_step(executor, 0, plan[0], exit_code=None)

    executor.run(initial_ticket=ticket)

    assert executor.launched_sessions == []
    assert ticket["state"] == "succeeded"


@pytest.mark.parametrize("error_code", ["invalid_state", "state_changed"])
def test_post_status_ignores_conflict_when_ticket_moved_on(tmp_path: Path, error_code: str) -> None:
    class ConflictApi:
        def __init__(self) -> None:
            self.calls = 0

        def update_status(self, _: str, __: dict[str, Any]) -> dict[str, Any]:
            self.calls += 1
            raise RunnerApiError("conflict", status_code=409, error_code=error_code)

    api = ConflictApi()
    executor = TicketExecutor(
        settings=_runner_settings(tmp_path),
        api=api,  # type: ignore[arg-type]
        stop_event=threading.Event(),
        ticket_id="77777777-7777-4777-8777-777777777777",
    )

    executor._post_status(event="ticket_succeeded", state="succeeded", result="success")

    assert api.calls == 1


def test_post_status_raises_other_conflicts(tmp_path: Path) -> None:
    class ConflictApi:
        def update_status(self, _: str, __: dict[str, Any]) -> dict[str, Any]:
            raise RunnerApiError("conflict", status_code=409, error_code="runner_host_mismatch")

    executor = TicketExecutor(
        settings=_runner_settings(tmp_path),
        api=ConflictApi(),  # type: ignore[arg-type]
        stop_event=threading.Event(),
        ticket_id="77777777-7777-4777-8777-777777777777",
    )

    with pytest.raises(RunnerApiError):
        executor._post_status(event="heartbeat")
