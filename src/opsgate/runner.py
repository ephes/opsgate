from __future__ import annotations

import hashlib
import json
import re
import shlex
import signal
import subprocess
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .config import RunnerSettings, load_runner_settings
from .service import SUPPORTED_AGENTS, TERMINAL_STATES, isoformat_z, parse_iso_datetime, utc_now

TICKET_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TMUX_TICKET_RE = re.compile(r"^job-([0-9a-fA-F-]{36})-\d{2}-")


class RunnerApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: int, error_code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


@dataclass(frozen=True)
class StepPaths:
    step_dir: Path
    prompt_path: Path
    context_path: Path
    previous_summary_path: Path
    log_path: Path
    summary_path: Path
    metadata_path: Path
    script_path: Path
    exit_code_path: Path


@dataclass(frozen=True)
class StepOutcome:
    kind: str
    detail: str
    summary: dict[str, Any] | None = None


class RunnerApiClient:
    def __init__(self, settings: RunnerSettings) -> None:
        self._settings = settings

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self._settings.runner_api_base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._settings.runner_token}",
        }
        data: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, sort_keys=True).encode("utf-8")

        request = Request(url=url, method=method, headers=headers, data=data)
        try:
            with urlopen(request, timeout=15) as response:
                raw = response.read().decode("utf-8") or "{}"
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise RunnerApiError("Invalid JSON response", status_code=500, error_code="invalid_response")
                return parsed
        except HTTPError as error:
            body_text = error.read().decode("utf-8")
            try:
                body = json.loads(body_text) if body_text else {}
            except json.JSONDecodeError:
                body = {}
            if isinstance(body, dict):
                message = str(body.get("message", error.reason))
                error_code = str(body.get("error", "http_error"))
            else:
                message = str(error.reason)
                error_code = "http_error"
            raise RunnerApiError(message, status_code=error.code, error_code=error_code) from error

    def claim_ticket(self, runner_host: str) -> dict[str, Any] | None:
        payload = {"runner_host": runner_host}
        body = self._request("POST", "/api/v1/runner/claim", payload)
        ticket = body.get("ticket")
        if ticket is None:
            return None
        if not isinstance(ticket, dict):
            raise RunnerApiError(
                "runner claim returned invalid ticket payload",
                status_code=500,
                error_code="invalid_ticket",
            )
        return ticket

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        body = self._request("GET", f"/api/v1/tickets/{ticket_id}")
        return body

    def update_status(self, ticket_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/runner/{ticket_id}/status", payload)


def _slugify(value: str) -> str:
    lowered = value.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return slug or "step"


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, sort_keys=True, indent=2)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 64)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _tail_lines(path: Path, max_lines: int = 40) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for line in deque(handle, maxlen=max_lines)]


def _build_agent_command(agent: str, prompt_path: Path) -> str:
    normalized = agent.strip()
    lower = normalized.lower()
    prompt_value = str(prompt_path)
    quoted_prompt = shlex.quote(prompt_value)
    if lower == "codex":
        # OpsGate tickets are manually approved before execution, so the runner
        # uses non-interactive Codex with full local execution and no git-root
        # requirement. Prompt content is streamed on stdin via `-`.
        return (
            "codex exec --skip-git-repo-check "
            "--dangerously-bypass-approvals-and-sandbox "
            f"- < {quoted_prompt}"
        )
    if lower == "claude":
        return f"claude -p --dangerously-skip-permissions < {quoted_prompt}"
    allowed_agents = ", ".join(SUPPORTED_AGENTS)
    raise ValueError(f"unsupported agent: {normalized or '<empty>'}; allowed agents: {allowed_agents}")


def _build_attach_command(*, tmux_socket_label: str, session_name: str, tmux_tmpdir: str) -> str:
    if tmux_tmpdir:
        return (
            f"sudo -u ops env TMUX_TMPDIR={shlex.quote(tmux_tmpdir)} "
            f"tmux -L {shlex.quote(tmux_socket_label)} attach -t {shlex.quote(session_name)}"
        )
    return f"sudo -u ops tmux -L {shlex.quote(tmux_socket_label)} attach -t {shlex.quote(session_name)}"


class TicketExecutor:
    def __init__(
        self,
        *,
        settings: RunnerSettings,
        api: RunnerApiClient,
        stop_event: threading.Event,
        ticket_id: str,
    ) -> None:
        self.settings = settings
        self.api = api
        self.stop_event = stop_event
        self.ticket_id = ticket_id
        self._artifacts_root = Path(settings.session_artifacts_dir) / ticket_id
        self._ticket_root = Path(settings.tickets_dir) / ticket_id

    def run(self, initial_ticket: dict[str, Any] | None = None) -> None:
        ticket = initial_ticket or self.api.get_ticket(self.ticket_id)
        state = str(ticket.get("state", ""))
        if state in TERMINAL_STATES:
            return
        if state != "running":
            return

        started_at_raw = str(ticket.get("started_at", "")).strip()
        if started_at_raw:
            started_at = parse_iso_datetime(started_at_raw)
        else:
            started_at = utc_now()

        max_duration = int(ticket.get("max_duration_seconds") or self.settings.max_duration_seconds_default)
        if max_duration <= 0:
            max_duration = self.settings.max_duration_seconds_default
        deadline = started_at + timedelta(seconds=max_duration)

        execution_plan = ticket.get("execution_plan", [])
        if not isinstance(execution_plan, list) or len(execution_plan) == 0:
            self._post_status(
                event="invalid_plan",
                state="failed",
                result="failure",
                result_detail="invalid_execution_plan",
                tmux_sessions=[],
            )
            return

        tmux_sessions_raw = ticket.get("tmux_sessions", [])
        tmux_sessions = tmux_sessions_raw if isinstance(tmux_sessions_raw, list) else []
        prior_summaries = self._load_completed_summaries(execution_plan)

        for step_index, step in enumerate(execution_plan):
            if self.stop_event.is_set():
                return

            latest = self.api.get_ticket(self.ticket_id)
            latest_state = str(latest.get("state", ""))
            if latest_state in TERMINAL_STATES:
                self._kill_running_sessions(tmux_sessions)
                return

            step_paths = self._prepare_step_paths(step_index, step)
            existing_summary = self._load_summary(step_paths.summary_path)
            if existing_summary is not None and str(existing_summary.get("status", "")).lower() == "succeeded":
                prior_summaries.append(existing_summary)
                continue

            step_outcome = self._run_step(
                step_index=step_index,
                total_steps=len(execution_plan),
                step=step,
                prior_summaries=prior_summaries,
                tmux_sessions=tmux_sessions,
                deadline=deadline,
                step_paths=step_paths,
            )

            if step_outcome.kind == "succeeded":
                if step_outcome.summary is not None:
                    prior_summaries.append(step_outcome.summary)
                continue

            if step_outcome.kind == "canceled":
                return

            if step_outcome.kind == "timeout":
                self._kill_running_sessions(tmux_sessions)
                self._post_status(
                    event="timeout",
                    state="failed",
                    result="timeout",
                    result_detail=step_outcome.detail,
                    tmux_sessions=tmux_sessions,
                )
                return

            self._post_status(
                event="step_failed",
                state="failed",
                result="failure",
                result_detail=step_outcome.detail,
                tmux_sessions=tmux_sessions,
            )
            return

        self._post_status(
            event="ticket_succeeded",
            state="succeeded",
            result="success",
            result_detail=f"completed_{len(execution_plan)}_steps",
            tmux_sessions=tmux_sessions,
        )

    def _load_completed_summaries(self, execution_plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for step_index, step in enumerate(execution_plan):
            step_paths = self._prepare_step_paths(step_index, step)
            summary = self._load_summary(step_paths.summary_path)
            if summary is None:
                break
            if str(summary.get("status", "")).lower() != "succeeded":
                break
            summaries.append(summary)
        return summaries

    def _prepare_step_paths(self, step_index: int, step: dict[str, Any]) -> StepPaths:
        role_slug = _slugify(str(step.get("role", "step")))
        step_name = f"{step_index + 1:02d}-{role_slug}"
        step_dir = self._artifacts_root / "steps" / step_name
        prompt_path = step_dir / "prompt.md"
        context_path = self._artifacts_root / "context.json"
        previous_summary_path = step_dir / "previous_step_summary.md"
        log_path = step_dir / "session.log"
        summary_path = step_dir / "summary.json"
        metadata_path = step_dir / "session_metadata.json"
        script_path = step_dir / "run_step.sh"
        exit_code_path = step_dir / "exit_code"
        return StepPaths(
            step_dir=step_dir,
            prompt_path=prompt_path,
            context_path=context_path,
            previous_summary_path=previous_summary_path,
            log_path=log_path,
            summary_path=summary_path,
            metadata_path=metadata_path,
            script_path=script_path,
            exit_code_path=exit_code_path,
        )

    def _run_step(
        self,
        *,
        step_index: int,
        total_steps: int,
        step: dict[str, Any],
        prior_summaries: list[dict[str, Any]],
        tmux_sessions: list[dict[str, Any]],
        deadline,
        step_paths: StepPaths,
    ) -> StepOutcome:
        step_paths.step_dir.mkdir(parents=True, exist_ok=True)
        self._ticket_root.mkdir(parents=True, exist_ok=True)

        step_role = str(step.get("role", "step"))
        step_agent = str(step.get("agent", ""))
        prompt_markdown = str(step.get("prompt_markdown", ""))
        session_name = f"job-{self.ticket_id}-{step_index + 1:02d}-{_slugify(step_role)}"
        attach_command = _build_attach_command(
            tmux_socket_label=self.settings.tmux_socket_label,
            session_name=session_name,
            tmux_tmpdir=self.settings.tmux_tmpdir,
        )

        context_payload = {
            "ticket_id": self.ticket_id,
            "step_index": step_index,
            "step_role": step_role,
            "step_agent": step_agent,
            "prior_step_summaries": prior_summaries,
        }
        _atomic_write_json(step_paths.context_path, context_payload)
        _atomic_write_json(self._ticket_root / "context.json", context_payload)
        step_paths.prompt_path.write_text(prompt_markdown + "\n", encoding="utf-8")
        if prior_summaries:
            previous_summary = json.dumps(prior_summaries[-1], sort_keys=True, indent=2)
            step_paths.previous_summary_path.write_text(previous_summary + "\n", encoding="utf-8")

        session_meta = {
            "step_index": step_index,
            "role": step_role,
            "agent": step_agent,
            "session_name": session_name,
            "attach_command": attach_command,
            "prompt_path": str(step_paths.prompt_path),
            "context_path": str(step_paths.context_path),
            "log_path": str(step_paths.log_path),
            "summary_path": str(step_paths.summary_path),
            "status": "running",
            "started_at": isoformat_z(utc_now()),
        }
        _atomic_write_json(step_paths.metadata_path, session_meta)

        tmux_entry = self._upsert_tmux_session(tmux_sessions, session_meta)
        self._post_status(
            event="step_started",
            result_detail=f"step_{step_index + 1}_started",
            tmux_sessions=tmux_sessions,
        )

        if not self._tmux_has_session(session_name):
            try:
                self._create_step_script(
                    step_paths=step_paths,
                    step_agent=step_agent,
                    prompt_path=step_paths.prompt_path,
                )
            except ValueError:
                tmux_entry["status"] = "failed"
                tmux_entry["finished_at"] = isoformat_z(utc_now())
                _atomic_write_json(step_paths.metadata_path, tmux_entry)
                return StepOutcome(kind="failed", detail=f"unsupported_agent_{_slugify(step_agent)}")
            self._tmux_new_session(session_name=session_name, script_path=step_paths.script_path)

        heartbeat_interval = max(1, self.settings.runner_heartbeat_interval_seconds)
        next_heartbeat = time.monotonic() + heartbeat_interval

        while True:
            if self.stop_event.is_set():
                self._tmux_kill_session(session_name)
                tmux_entry["status"] = "canceled"
                return StepOutcome(kind="canceled", detail="runner_shutdown")

            if utc_now() >= deadline:
                self._tmux_kill_session(session_name)
                tmux_entry["status"] = "timeout"
                tmux_entry["finished_at"] = isoformat_z(utc_now())
                _atomic_write_json(step_paths.metadata_path, tmux_entry)
                return StepOutcome(kind="timeout", detail="max_duration_seconds_exceeded")

            try:
                latest = self.api.get_ticket(self.ticket_id)
            except RunnerApiError:
                latest = {"state": "running"}
            latest_state = str(latest.get("state", ""))
            if latest_state == "canceled":
                self._tmux_kill_session(session_name)
                tmux_entry["status"] = "canceled"
                tmux_entry["finished_at"] = isoformat_z(utc_now())
                _atomic_write_json(step_paths.metadata_path, tmux_entry)
                return StepOutcome(kind="canceled", detail="ticket_canceled")
            if latest_state in TERMINAL_STATES:
                self._tmux_kill_session(session_name)
                return StepOutcome(kind="failed", detail=f"ticket_entered_{latest_state}")

            if step_paths.exit_code_path.exists():
                break

            if not self._tmux_has_session(session_name):
                return StepOutcome(kind="failed", detail="session_terminated_without_exit_code")

            now_monotonic = time.monotonic()
            if now_monotonic >= next_heartbeat:
                self._post_status(
                    event="heartbeat",
                    result_detail=f"running_step_{step_index + 1}_of_{total_steps}",
                    tmux_sessions=tmux_sessions,
                )
                next_heartbeat = now_monotonic + heartbeat_interval

            time.sleep(1.0)

        try:
            exit_code = int(step_paths.exit_code_path.read_text(encoding="utf-8").strip())
        except ValueError:
            exit_code = 1

        finished_at = isoformat_z(utc_now())
        tmux_entry["finished_at"] = finished_at
        tmux_entry["log_path"] = str(step_paths.log_path)
        tmux_entry["log_size_bytes"] = step_paths.log_path.stat().st_size if step_paths.log_path.exists() else 0
        tmux_entry["log_sha256"] = _sha256(step_paths.log_path) if step_paths.log_path.exists() else None

        summary = {
            "ticket_id": self.ticket_id,
            "step_index": step_index,
            "role": step_role,
            "agent": step_agent,
            "session_name": session_name,
            "started_at": session_meta["started_at"],
            "finished_at": finished_at,
            "exit_code": exit_code,
            "status": "succeeded" if exit_code == 0 else "failed",
            "log_path": str(step_paths.log_path),
            "log_size_bytes": tmux_entry["log_size_bytes"],
            "log_sha256": tmux_entry["log_sha256"],
            "summary_markdown": "\n".join(_tail_lines(step_paths.log_path)),
        }
        _atomic_write_json(step_paths.summary_path, summary)

        if exit_code == 0:
            tmux_entry["status"] = "succeeded"
            tmux_entry["summary_path"] = str(step_paths.summary_path)
            _atomic_write_json(step_paths.metadata_path, tmux_entry)
            self._post_status(
                event="step_finished",
                result_detail=f"step_{step_index + 1}_finished",
                tmux_sessions=tmux_sessions,
            )
            return StepOutcome(kind="succeeded", detail="ok", summary=summary)

        tmux_entry["status"] = "failed"
        tmux_entry["summary_path"] = str(step_paths.summary_path)
        _atomic_write_json(step_paths.metadata_path, tmux_entry)
        return StepOutcome(kind="failed", detail=f"step_{step_index + 1}_exit_code_{exit_code}", summary=summary)

    def _create_step_script(self, *, step_paths: StepPaths, step_agent: str, prompt_path: Path) -> None:
        command = _build_agent_command(step_agent, prompt_path)
        quoted_log_path = shlex.quote(str(step_paths.log_path))
        quoted_exit_path = shlex.quote(str(step_paths.exit_code_path))
        script = "\n".join(
            (
                "#!/bin/bash",
                "set -uo pipefail",
                f"{command} 2>&1 | tee -a {quoted_log_path}",
                "cmd_rc=${PIPESTATUS[0]}",
                f"printf \"%s\\n\" \"$cmd_rc\" > {quoted_exit_path}",
                "exit \"$cmd_rc\"",
                "",
            )
        )
        step_paths.script_path.write_text(script, encoding="utf-8")
        step_paths.script_path.chmod(0o750)

    def _post_status(
        self,
        *,
        event: str,
        state: str | None = None,
        result: str | None = None,
        result_detail: str = "",
        tmux_sessions: list[dict[str, Any]] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "runner_host": self.settings.runner_host,
            "event": event,
        }
        if state:
            payload["state"] = state
        if result:
            payload["result"] = result
        if result_detail:
            payload["result_detail"] = result_detail
        if tmux_sessions is not None:
            payload["tmux_sessions"] = tmux_sessions
        try:
            self.api.update_status(self.ticket_id, payload)
        except RunnerApiError as error:
            if error.status_code == 409 and error.error_code == "invalid_state":
                return
            raise

    def _upsert_tmux_session(self, tmux_sessions: list[dict[str, Any]], entry: dict[str, Any]) -> dict[str, Any]:
        step_index = int(entry["step_index"])
        for existing in tmux_sessions:
            if int(existing.get("step_index", -1)) == step_index:
                existing.update(entry)
                return existing
        tmux_sessions.append(dict(entry))
        return tmux_sessions[-1]

    def _load_summary(self, summary_path: Path) -> dict[str, Any] | None:
        if not summary_path.exists():
            return None
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        if not isinstance(loaded, dict):
            return None
        return loaded

    def _kill_running_sessions(self, tmux_sessions: list[dict[str, Any]]) -> None:
        for entry in tmux_sessions:
            if str(entry.get("status", "")).lower() == "running":
                session_name = str(entry.get("session_name", "")).strip()
                if session_name:
                    self._tmux_kill_session(session_name)

    def _tmux_command(self, *args: str) -> list[str]:
        return ["tmux", "-L", self.settings.tmux_socket_label, *args]

    def _tmux_has_session(self, session_name: str) -> bool:
        result = subprocess.run(
            self._tmux_command("has-session", "-t", session_name),
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    def _tmux_new_session(self, *, session_name: str, script_path: Path) -> None:
        subprocess.run(
            self._tmux_command("new-session", "-d", "-s", session_name, f"/bin/bash {shlex.quote(str(script_path))}"),
            capture_output=True,
            text=True,
            check=True,
        )

    def _tmux_kill_session(self, session_name: str) -> None:
        subprocess.run(
            self._tmux_command("kill-session", "-t", session_name),
            capture_output=True,
            text=True,
            check=False,
        )


class OpsGateRunner:
    def __init__(self, settings: RunnerSettings) -> None:
        self.settings = settings
        self.api = RunnerApiClient(settings)
        self.stop_event = threading.Event()
        self.state_dir = Path(settings.execution_data_dir) / "runner-state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.workers: dict[str, threading.Thread] = {}
        self._worker_cleanup: dict[str, bool] = {}
        self._lock = threading.Lock()
        self._artifacts_bootstrap_scanned = False

    def install_signal_handlers(self) -> None:
        def _handle_signal(_: int, __) -> None:
            self.stop_event.set()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

    def run_forever(self, *, once: bool = False) -> None:
        self.install_signal_handlers()
        self._recover_inflight_tickets(include_artifacts=not self._artifacts_bootstrap_scanned)
        self._artifacts_bootstrap_scanned = True

        while not self.stop_event.is_set():
            self._reap_finished_workers()
            self._recover_inflight_tickets(include_artifacts=False)

            if Path(self.settings.disable_file_path).exists():
                if once:
                    break
                time.sleep(self.settings.runner_poll_interval_seconds)
                continue

            claimed_any = False
            while self._active_worker_count() < self.settings.max_parallel_jobs and not self.stop_event.is_set():
                claimed_ticket = self.api.claim_ticket(self.settings.runner_host)
                if claimed_ticket is None:
                    break
                claimed_any = True
                ticket_id = str(claimed_ticket.get("id", "")).strip()
                if not ticket_id:
                    continue
                self._write_state_file(ticket_id)
                self._start_worker(ticket_id=ticket_id, initial_ticket=claimed_ticket)

            if once and not claimed_any:
                break

            if once:
                self._wait_for_workers()
                break

            time.sleep(self.settings.runner_poll_interval_seconds)

        self._wait_for_workers()

    def _worker_state_path(self, ticket_id: str) -> Path:
        return self.state_dir / f"{ticket_id}.json"

    def _write_state_file(self, ticket_id: str) -> None:
        _atomic_write_json(
            self._worker_state_path(ticket_id),
            {
                "ticket_id": ticket_id,
                "runner_host": self.settings.runner_host,
                "updated_at": isoformat_z(utc_now()),
            },
        )

    def _remove_state_file(self, ticket_id: str) -> None:
        self._worker_state_path(ticket_id).unlink(missing_ok=True)

    def _start_worker(self, *, ticket_id: str, initial_ticket: dict[str, Any] | None = None) -> None:
        with self._lock:
            existing = self.workers.get(ticket_id)
            if existing is not None and existing.is_alive():
                return

            worker = threading.Thread(
                target=self._run_worker,
                kwargs={"ticket_id": ticket_id, "initial_ticket": initial_ticket},
                daemon=True,
                name=f"opsgate-ticket-{ticket_id}",
            )
            self.workers[ticket_id] = worker
            worker.start()

    def _run_worker(self, *, ticket_id: str, initial_ticket: dict[str, Any] | None) -> None:
        remove_state = False
        try:
            executor = TicketExecutor(
                settings=self.settings,
                api=self.api,
                stop_event=self.stop_event,
                ticket_id=ticket_id,
            )
            executor.run(initial_ticket=initial_ticket)
            remove_state = True
        except Exception as exc:  # pragma: no cover - exercised via monkeypatch test
            traceback.print_exc()
            try:
                self.api.update_status(
                    ticket_id,
                    {
                        "runner_host": self.settings.runner_host,
                        "event": "failed",
                        "state": "failed",
                        "result": "failure",
                        "result_detail": f"runner_unhandled_exception:{type(exc).__name__}",
                    },
                )
                remove_state = True
            except RunnerApiError:
                # API unavailable: keep state file so restart recovery can re-drive the ticket.
                remove_state = False
        finally:
            if not remove_state:
                try:
                    latest = self.api.get_ticket(ticket_id)
                    if str(latest.get("state", "")) in TERMINAL_STATES:
                        remove_state = True
                except RunnerApiError:
                    pass
            with self._lock:
                self._worker_cleanup[ticket_id] = remove_state

    def _recover_inflight_tickets(self, *, include_artifacts: bool) -> None:
        candidate_ticket_ids: set[str] = set()
        for state_file in sorted(self.state_dir.glob("*.json")):
            try:
                parsed = json.loads(state_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                state_file.unlink(missing_ok=True)
                continue
            if not isinstance(parsed, dict):
                state_file.unlink(missing_ok=True)
                continue
            ticket_id = str(parsed.get("ticket_id", "")).strip()
            if not ticket_id:
                state_file.unlink(missing_ok=True)
                continue
            candidate_ticket_ids.add(ticket_id)

        candidate_ticket_ids.update(self._discover_ticket_ids_from_tmux())
        if include_artifacts:
            candidate_ticket_ids.update(self._discover_ticket_ids_from_artifacts())

        for ticket_id in sorted(candidate_ticket_ids):
            if self._active_worker_count() >= self.settings.max_parallel_jobs:
                break
            try:
                ticket = self.api.get_ticket(ticket_id)
            except RunnerApiError:
                continue

            ticket_state = str(ticket.get("state", "")).strip().lower()
            if ticket_state in TERMINAL_STATES:
                self._remove_state_file(ticket_id)
                self._kill_tmux_sessions_for_ticket(ticket_id)
                continue
            if ticket_state != "running":
                self._remove_state_file(ticket_id)
                self._kill_tmux_sessions_for_ticket(ticket_id)
                continue

            self._write_state_file(ticket_id)
            self._start_worker(ticket_id=ticket_id, initial_ticket=ticket)

    def _tmux_command(self, *args: str) -> list[str]:
        return ["tmux", "-L", self.settings.tmux_socket_label, *args]

    def _discover_ticket_ids_from_tmux(self) -> set[str]:
        try:
            result = subprocess.run(
                self._tmux_command("ls"),
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return set()
        if result.returncode != 0:
            return set()

        discovered: set[str] = set()
        for line in result.stdout.splitlines():
            session_name = line.split(":", 1)[0].strip()
            match = TMUX_TICKET_RE.match(session_name)
            if match:
                candidate = match.group(1)
                if TICKET_ID_RE.match(candidate):
                    discovered.add(candidate)
        return discovered

    def _discover_ticket_ids_from_artifacts(self) -> set[str]:
        artifacts_root = Path(self.settings.session_artifacts_dir)
        if not artifacts_root.exists():
            return set()

        discovered: set[str] = set()
        for entry in artifacts_root.iterdir():
            if not entry.is_dir():
                continue
            if TICKET_ID_RE.match(entry.name):
                discovered.add(entry.name)
        return discovered

    def _tmux_sessions_for_ticket(self, ticket_id: str) -> list[str]:
        try:
            result = subprocess.run(
                self._tmux_command("ls"),
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return []
        if result.returncode != 0:
            return []

        session_prefix = f"job-{ticket_id}-"
        matches: list[str] = []
        for line in result.stdout.splitlines():
            session_name = line.split(":", 1)[0].strip()
            if session_name.startswith(session_prefix):
                matches.append(session_name)
        return matches

    def _kill_tmux_sessions_for_ticket(self, ticket_id: str) -> None:
        for session_name in self._tmux_sessions_for_ticket(ticket_id):
            subprocess.run(
                self._tmux_command("kill-session", "-t", session_name),
                capture_output=True,
                text=True,
                check=False,
            )

    def _active_worker_count(self) -> int:
        with self._lock:
            return sum(1 for worker in self.workers.values() if worker.is_alive())

    def _reap_finished_workers(self) -> None:
        state_files_to_remove: list[str] = []
        with self._lock:
            finished = [ticket_id for ticket_id, worker in self.workers.items() if not worker.is_alive()]
            for ticket_id in finished:
                del self.workers[ticket_id]
                if self._worker_cleanup.pop(ticket_id, False):
                    state_files_to_remove.append(ticket_id)
        for ticket_id in state_files_to_remove:
            self._remove_state_file(ticket_id)

    def _wait_for_workers(self) -> None:
        while True:
            self._reap_finished_workers()
            with self._lock:
                alive = [worker for worker in self.workers.values() if worker.is_alive()]
            if not alive:
                return
            for worker in alive:
                worker.join(timeout=0.5)


def run_runner(once: bool = False) -> None:
    settings = load_runner_settings()
    runner = OpsGateRunner(settings)
    runner.run_forever(once=once)
