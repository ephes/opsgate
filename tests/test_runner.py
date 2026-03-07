from __future__ import annotations

import shlex
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from opsgate.config import RunnerSettings
from opsgate.runner import OpsGateRunner, RunnerApiError, TicketExecutor, _build_agent_command


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
            {"role": "investigator", "agent": "shell", "prompt_markdown": "echo step-1"},
            {"role": "reviewer", "agent": "shell", "prompt_markdown": "echo step-2"},
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
            {"role": "investigator", "agent": "shell", "prompt_markdown": "sleep 10"},
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
            {"role": "reviewer", "agent": "shell", "prompt_markdown": "exit 7"},
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
            {"role": "investigator", "agent": "shell", "prompt_markdown": "echo step-1"},
            {"role": "reviewer", "agent": "shell", "prompt_markdown": "echo step-2"},
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


def test_build_agent_command_quotes_fallback_agent(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    command = _build_agent_command("custom-agent --flag '; rm -rf /'", prompt_path)
    tokens = shlex.split(command)
    assert tokens[0] == "custom-agent"
    assert tokens[1] == "--flag"
    assert tokens[2] == "; rm -rf /"
    assert "--prompt-file" in tokens


def test_build_agent_command_uses_codex_exec_with_stdin(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    command = _build_agent_command("codex", prompt_path)

    assert command == (
        "codex exec --skip-git-repo-check "
        "--dangerously-bypass-approvals-and-sandbox "
        f"- < {shlex.quote(str(prompt_path))}"
    )


def test_build_agent_command_expands_prompt_placeholder_safely(tmp_path: Path) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("echo hi\n", encoding="utf-8")
    command = _build_agent_command("tool --input {prompt_file}", prompt_path)
    tokens = shlex.split(command)
    assert tokens[0] == "tool"
    assert tokens[1] == "--input"
    assert tokens[2] == str(prompt_path)
