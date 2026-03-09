from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import bcrypt
import pytest

from opsgate.app import create_app
from opsgate.config import OpsGateSettings, SubmitterPolicy
from opsgate.service import parse_iso_datetime


def _build_settings(db_path: str) -> OpsGateSettings:
    password_hash = bcrypt.hashpw(b"secret-password", bcrypt.gensalt()).decode("utf-8")
    return OpsGateSettings(
        service_name="opsgate",
        bind_host="127.0.0.1",
        bind_port=8711,
        db_path=db_path,
        session_secret="x" * 32,
        trust_proxy_headers=False,
        session_cookie_secure=False,
        session_timeout_seconds=3600,
        ui_username="opsgate-admin",
        ui_password_bcrypt=password_hash,
        max_duration_seconds_default=3600,
        policy_floor_require_reviewer_step=False,
        runner_token="runner-token-000000000000",
        submitter_policies=(
            SubmitterPolicy(
                source="openclaw",
                token="openclaw-token-0000000000",
                require_reviewer_step_floor=False,
            ),
            SubmitterPolicy(
                source="nyxmon",
                token="nyxmon-token-000000000000",
                require_reviewer_step_floor=False,
            ),
            SubmitterPolicy(
                source="operator",
                token="operator-token-00000000000",
                require_reviewer_step_floor=False,
            ),
        ),
        require_tailscale_context=True,
        allowed_cidrs=("127.0.0.1/32", "::1/128", "100.64.0.0/10"),
        execution_data_dir="/tmp",
        disable_file_path="/tmp/opsgate.disabled",
    )


def _build_client(tmp_path: Path, *, operator_require_reviewer_step_floor: bool = False) -> Any:
    db_file = str(tmp_path / "opsgate.sqlite3")
    settings = _build_settings(db_file)
    submitter_policies = tuple(
        SubmitterPolicy(
            source=policy.source,
            token=policy.token,
            require_reviewer_step_floor=(
                operator_require_reviewer_step_floor
                if policy.source == "operator"
                else policy.require_reviewer_step_floor
            ),
        )
        for policy in settings.submitter_policies
    )
    settings = OpsGateSettings(
        **{
            **settings.__dict__,
            "submitter_policies": submitter_policies,
        }
    )
    app = create_app(settings)
    app.config.update(TESTING=True)
    app.config["OPSGATE_TEST_DB_PATH"] = db_file
    return app.test_client()


@pytest.fixture
def client(tmp_path: Path) -> Any:
    return _build_client(tmp_path)


@pytest.fixture
def proxy_client(tmp_path: Path) -> Any:
    db_file = str(tmp_path / "opsgate-proxy.sqlite3")
    settings = _build_settings(db_file)
    settings = OpsGateSettings(
        **{
            **settings.__dict__,
            "trust_proxy_headers": True,
        }
    )
    app = create_app(settings)
    app.config.update(TESTING=True)
    app.config["OPSGATE_TEST_DB_PATH"] = db_file
    return app.test_client()


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def runner_headers() -> dict[str, str]:
    return auth_headers("runner-token-000000000000")


def session_csrf_token(client: Any) -> str:
    with client.session_transaction() as session:
        token = session.get("csrf_token")
    assert isinstance(token, str)
    return token


def login(client: Any, path: str = "/login") -> Any:
    page = client.get(path, follow_redirects=False)
    assert page.status_code == 200
    pre_login_token = session_csrf_token(client)
    response = client.post(
        path,
        data={
            "csrf_token": pre_login_token,
            "username": "opsgate-admin",
            "password": "secret-password",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert session_csrf_token(client) != pre_login_token
    return response


def create_ticket(
    client: Any,
    *,
    token: str,
    title: str,
    summary: str,
    task_ref: str | None = None,
    execution_plan: list[dict[str, str]] | None = None,
    policy_requirements: dict[str, bool] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "title": title,
        "summary": summary,
        "execution_plan": execution_plan
        or [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}],
    }
    if task_ref is not None:
        payload["task_ref"] = task_ref
    if policy_requirements is not None:
        payload["policy_requirements"] = policy_requirements

    response = client.post("/api/v1/tickets", headers=auth_headers(token), json=payload)
    assert response.status_code == 201
    return response.get_json()["id"]


def set_ticket_tmux_sessions(client: Any, ticket_id: str, tmux_sessions: list[dict[str, Any]]) -> None:
    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE tickets SET tmux_sessions_json = ? WHERE id = ?",
            (json.dumps(tmux_sessions, sort_keys=True), ticket_id),
        )
        conn.commit()


def write_ticket_log(ticket_id: str, *, relative_path: str, content: str) -> Path:
    log_path = Path("/tmp/sessions") / ticket_id / relative_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(content, encoding="utf-8")
    return log_path


def set_ticket_terminal_state(
    client: Any,
    ticket_id: str,
    *,
    state: str,
    result: str = "failure",
    result_detail: str = "terminal_state_for_test",
) -> None:
    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    finished_at = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE tickets
            SET state = ?, finished_at = ?, result = ?, result_detail = ?
            WHERE id = ?
            """,
            (state, finished_at, result, result_detail, ticket_id),
        )
        conn.commit()


def audit_event_types(client: Any, ticket_id: str) -> list[str]:
    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT event_type FROM audit_events WHERE ticket_id = ? ORDER BY id ASC",
            (ticket_id,),
        ).fetchall()
    return [str(row[0]) for row in rows]


def test_ui_ticket_detail_redirects_to_login_with_next(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Needs approval",
        summary="Redirect check",
        task_ref="ui-next-1",
    )
    response = client.get(f"/tickets/{ticket_id}", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/login?next=/tickets/{ticket_id}")


def test_login_redirects_to_requested_next_path(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Needs approval",
        summary="Redirect check",
        task_ref="ui-next-2",
    )
    redirect_to_login = client.get(f"/tickets/{ticket_id}", follow_redirects=False)
    assert redirect_to_login.status_code == 302
    login_path = redirect_to_login.headers["Location"]

    login_response = login(client, login_path)
    assert login_response.status_code == 302
    assert login_response.headers["Location"] == f"/tickets/{ticket_id}"


def test_manual_ticket_creation_from_ui(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Manual remediation",
            "summary": "Create through web UI",
            "task_ref": "ui-manual-1",
            "steps-0-role": "implementer",
            "steps-0-agent": "codex",
            "steps-0-prompt_markdown": "Inspect the target service and prepare a no-op patch.",
            "steps-1-role": "reviewer",
            "steps-1-agent": "claude",
            "steps-1-prompt_markdown": "Review the proposed change and confirm it stays a no-op.",
            "max_duration_seconds": "900",
            "context_json": '{"service": "opsgate", "host": "macstudio"}',
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    location = response.headers["Location"]
    assert location.startswith("/tickets/")
    ticket_id = location.rsplit("/", 1)[-1]

    api_detail = client.get(f"/api/v1/tickets/{ticket_id}")
    assert api_detail.status_code == 200
    ticket = api_detail.get_json()
    assert ticket["execution_plan"] == [
        {
            "role": "implementer",
            "agent": "codex",
            "prompt_markdown": "Inspect the target service and prepare a no-op patch.",
        },
        {
            "role": "reviewer",
            "agent": "claude",
            "prompt_markdown": "Review the proposed change and confirm it stays a no-op.",
        },
    ]
    assert ticket["policy_requirements"]["require_reviewer_step"] is False

    detail = client.get(location)
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)
    assert "Manual remediation" in body
    assert "approver:opsgate-admin" in body


def test_manual_ticket_form_defaults_investigator_to_codex(client: Any) -> None:
    login(client)

    response = client.get("/tickets")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'name="steps-0-role"' in body
    assert '<option value="investigator" selected>investigator</option>' in body
    assert 'name="steps-0-agent"' in body
    assert '<option value="codex" selected>codex</option>' in body
    assert '<option value="claude">claude</option>' in body


def test_manual_ticket_form_renders_role_scaffolding(client: Any) -> None:
    login(client)

    response = client.get("/tickets")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Role model" in body
    assert "OpsGate currently supports exactly three workflow roles." in body
    assert "Inspect-only investigation" in body
    assert "Repo-first implementation" in body
    assert "Independent review gate" in body
    assert "Use suggested prompt" in body


def test_ticket_list_renders_compact_created_at_timestamp(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Compact timestamp",
        summary="Recent tickets should use compact UTC timestamps",
        task_ref="ui-created-at-1",
    )
    login(client)

    raw_created_at = client.get(f"/api/v1/tickets/{ticket_id}").get_json()["created_at"]
    expected_created_at = parse_iso_datetime(raw_created_at).strftime("%Y-%m-%d %H:%M UTC")

    response = client.get("/tickets")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert expected_created_at in body
    assert raw_created_at not in body


def test_api_archive_and_unarchive_preserve_ticket_access_and_audit(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Archive via API",
        summary="Archive should preserve direct reads and audit events",
        task_ref="archive-api-1",
    )
    login(client)
    reject = client.post(f"/api/v1/tickets/{ticket_id}/reject", json={"reason": "done"})
    assert reject.status_code == 200

    archive = client.post(f"/api/v1/tickets/{ticket_id}/archive")
    assert archive.status_code == 200
    archived_ticket = archive.get_json()
    assert archived_ticket["state"] == "rejected"
    assert archived_ticket["is_archived"] is True
    assert archived_ticket["archived_by"] == "opsgate-admin"
    assert isinstance(archived_ticket["archived_at"], str)

    submitter_detail = client.get(
        f"/api/v1/tickets/{ticket_id}",
        headers=auth_headers("nyxmon-token-000000000000"),
    )
    assert submitter_detail.status_code == 200
    assert submitter_detail.get_json()["is_archived"] is True

    unarchive = client.post(f"/api/v1/tickets/{ticket_id}/unarchive")
    assert unarchive.status_code == 200
    restored_ticket = unarchive.get_json()
    assert restored_ticket["state"] == "rejected"
    assert restored_ticket["is_archived"] is False
    assert restored_ticket["archived_at"] is None
    assert restored_ticket["archived_by"] is None

    assert audit_event_types(client, ticket_id)[-2:] == ["ticket_archived", "ticket_unarchived"]


def test_archive_requires_terminal_state(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Archive blocked",
        summary="Pending tickets should not archive",
        task_ref="archive-api-2",
    )
    login(client)

    response = client.post(f"/api/v1/tickets/{ticket_id}/archive")
    assert response.status_code == 409
    assert response.get_json() == {
        "error": "invalid_state",
        "message": "Only terminal tickets can be archived",
    }


@pytest.mark.parametrize(
    ("state", "result"),
    [
        ("succeeded", "success"),
        ("failed", "failure"),
        ("rejected", "failure"),
        ("canceled", "canceled"),
        ("expired", "failure"),
    ],
)
def test_archive_allowed_for_all_terminal_states(client: Any, state: str, result: str) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title=f"Archive {state}",
        summary="All terminal states should archive cleanly",
        task_ref=f"archive-terminal-{state}",
    )
    set_ticket_terminal_state(client, ticket_id, state=state, result=result, result_detail=f"{state}_for_test")
    login(client)

    response = client.post(f"/api/v1/tickets/{ticket_id}/archive")
    assert response.status_code == 200
    archived_ticket = response.get_json()
    assert archived_ticket["state"] == state
    assert archived_ticket["result"] == result
    assert archived_ticket["is_terminal"] is True
    assert archived_ticket["is_archived"] is True


def test_archive_rejects_double_archive(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Archive twice",
        summary="Second archive should fail",
        task_ref="archive-api-3",
    )
    login(client)
    assert client.post(f"/api/v1/tickets/{ticket_id}/reject", json={"reason": "done"}).status_code == 200
    assert client.post(f"/api/v1/tickets/{ticket_id}/archive").status_code == 200

    second_archive = client.post(f"/api/v1/tickets/{ticket_id}/archive")
    assert second_archive.status_code == 409
    assert second_archive.get_json() == {
        "error": "already_archived",
        "message": "Ticket is already archived",
    }


def test_unarchive_rejects_non_archived_ticket(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Restore not archived",
        summary="Unarchive should fail if archive never happened",
        task_ref="archive-api-4",
    )
    login(client)
    assert client.post(f"/api/v1/tickets/{ticket_id}/reject", json={"reason": "done"}).status_code == 200

    response = client.post(f"/api/v1/tickets/{ticket_id}/unarchive")
    assert response.status_code == 409
    assert response.get_json() == {
        "error": "not_archived",
        "message": "Ticket is not archived",
    }


def test_ui_archive_and_restore_controls_manage_ticket_visibility(client: Any) -> None:
    title = "Archive through UI"
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title=title,
        summary="Terminal ticket should move out of the default queue",
        task_ref="archive-ui-1",
    )
    login(client)
    reject = client.post(f"/api/v1/tickets/{ticket_id}/reject", json={"reason": "done"})
    assert reject.status_code == 200

    before_archive = client.get(f"/tickets/{ticket_id}")
    assert before_archive.status_code == 200
    assert "Archive Ticket" in before_archive.get_data(as_text=True)
    assert "Restore Ticket" not in before_archive.get_data(as_text=True)

    archive = client.post(
        f"/tickets/{ticket_id}/archive",
        data={"csrf_token": session_csrf_token(client)},
        follow_redirects=False,
    )
    assert archive.status_code == 302
    assert archive.headers["Location"] == f"/tickets/{ticket_id}"

    archived_detail = client.get(f"/tickets/{ticket_id}")
    archived_body = archived_detail.get_data(as_text=True)
    assert archived_detail.status_code == 200
    assert "Restore Ticket" in archived_body
    assert "Archive Ticket" not in archived_body
    assert "archived" in archived_body
    assert "Archived At" in archived_body
    assert "Archived By" in archived_body

    active_list = client.get("/tickets")
    active_body = active_list.get_data(as_text=True)
    assert active_list.status_code == 200
    assert title not in active_body

    archived_list = client.get("/tickets?view=archived")
    archived_list_body = archived_list.get_data(as_text=True)
    assert archived_list.status_code == 200
    assert title in archived_list_body
    assert "Archived tickets stay readable and restorable" in archived_list_body

    restore = client.post(
        f"/tickets/{ticket_id}/unarchive",
        data={"csrf_token": session_csrf_token(client)},
        follow_redirects=False,
    )
    assert restore.status_code == 302
    assert restore.headers["Location"] == f"/tickets/{ticket_id}"

    restored_list = client.get("/tickets")
    assert restored_list.status_code == 200
    assert title in restored_list.get_data(as_text=True)

    restored_detail = client.get(f"/tickets/{ticket_id}")
    assert restored_detail.status_code == 200
    restored_body = restored_detail.get_data(as_text=True)
    assert "Archived At" not in restored_body
    assert "Archived By" not in restored_body


def test_ui_archive_routes_require_csrf_token(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Archive CSRF",
        summary="Archive and restore should require CSRF tokens",
        task_ref="archive-ui-csrf-1",
    )
    login(client)
    assert client.post(f"/api/v1/tickets/{ticket_id}/reject", json={"reason": "done"}).status_code == 200

    archive = client.post(f"/tickets/{ticket_id}/archive", data={}, follow_redirects=False)
    assert archive.status_code == 302
    assert archive.headers["Location"] == f"/tickets/{ticket_id}"
    archive_detail = client.get(archive.headers["Location"])
    assert "Invalid form token" in archive_detail.get_data(as_text=True)

    assert client.post(
        f"/tickets/{ticket_id}/archive",
        data={"csrf_token": session_csrf_token(client)},
        follow_redirects=False,
    ).status_code == 302

    unarchive = client.post(f"/tickets/{ticket_id}/unarchive", data={}, follow_redirects=False)
    assert unarchive.status_code == 302
    assert unarchive.headers["Location"] == f"/tickets/{ticket_id}"
    unarchive_detail = client.get(unarchive.headers["Location"])
    assert "Invalid form token" in unarchive_detail.get_data(as_text=True)


def test_ticket_detail_renders_log_preview_and_full_log_link(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Preview logs",
        summary="Ticket detail should show log previews",
    )
    log_path = write_ticket_log(
        ticket_id,
        relative_path="steps/01-reviewer-claude/session.log",
        content="\n".join(f"line-{index:03d}" for index in range(1, 46)) + "\n",
    )
    set_ticket_tmux_sessions(
        client,
        ticket_id,
        [
            {
                "step_index": 0,
                "role": "reviewer",
                "agent": "claude",
                "status": "succeeded",
                "session_name": "job-preview-01",
                "attach_command": "tmux attach -t job-preview-01",
                "log_path": str(log_path),
            }
        ],
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Open full log" in body
    assert f"/tickets/{ticket_id}/steps/1/log" in body
    assert "line-045" in body
    assert "line-001" not in body


def test_ticket_step_log_view_renders_full_log(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Full log",
        summary="Operators should be able to read step logs in the UI",
    )
    log_path = write_ticket_log(
        ticket_id,
        relative_path="steps/01-reviewer-claude/session.log",
        content="first line\nsecond line\nthird line\n",
    )
    set_ticket_tmux_sessions(
        client,
        ticket_id,
        [
            {
                "step_index": 0,
                "role": "reviewer",
                "agent": "claude",
                "status": "succeeded",
                "session_name": "job-full-01",
                "attach_command": "tmux attach -t job-full-01",
                "log_path": str(log_path),
            }
        ],
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}/steps/1/log")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Step 1 Log" in body
    assert "first line" in body
    assert "third line" in body
    assert str(log_path) in body


def test_ticket_step_log_view_rejects_paths_outside_ticket_artifacts(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Bad log path",
        summary="Tampered log path should not be readable",
    )
    set_ticket_tmux_sessions(
        client,
        ticket_id,
        [
            {
                "step_index": 0,
                "role": "reviewer",
                "agent": "claude",
                "status": "failed",
                "session_name": "job-bad-path-01",
                "attach_command": "tmux attach -t job-bad-path-01",
                "log_path": "/etc/passwd",
            }
        ],
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}/steps/1/log", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == f"/tickets/{ticket_id}"

    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert "outside the ticket artifact root" in detail.get_data(as_text=True)


def test_ticket_detail_hides_full_log_link_for_session_without_numeric_step_index(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Malformed step index",
        summary="Broken full-log links should not render",
    )
    log_path = write_ticket_log(
        ticket_id,
        relative_path="steps/unknown/session.log",
        content="preview line\n",
    )
    set_ticket_tmux_sessions(
        client,
        ticket_id,
        [
            {
                "step_index": "abc",
                "role": "reviewer",
                "agent": "claude",
                "status": "failed",
                "session_name": "job-malformed-01",
                "attach_command": "tmux attach -t job-malformed-01",
                "log_path": str(log_path),
            }
        ],
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "preview line" in body
    assert "Open full log" not in body


def test_ticket_step_log_view_rejects_missing_step_number(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Missing step",
        summary="Missing step logs should redirect back to detail",
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}/steps/99/log", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == f"/tickets/{ticket_id}"

    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert "Step log does not exist" in detail.get_data(as_text=True)


def test_ticket_detail_shows_log_unavailable_message_for_missing_file(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Missing log file",
        summary="UI should show when a log is not available yet",
    )
    set_ticket_tmux_sessions(
        client,
        ticket_id,
        [
            {
                "step_index": 0,
                "role": "reviewer",
                "agent": "claude",
                "status": "running",
                "session_name": "job-missing-log-01",
                "attach_command": "tmux attach -t job-missing-log-01",
                "log_path": f"/tmp/sessions/{ticket_id}/steps/01-reviewer-claude/session.log",
            }
        ],
    )

    login(client)
    response = client.get(f"/tickets/{ticket_id}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Log preview is not available yet for this step." in body


def test_manual_ticket_creation_defaults_agent_from_role(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Role-based defaults",
            "summary": "Agent values should default from step role",
            "steps-0-role": "implementer",
            "steps-0-prompt_markdown": "Prepare the implementation plan.",
            "steps-1-role": "reviewer",
            "steps-1-prompt_markdown": "Review the implementation plan.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    ticket_id = response.headers["Location"].rsplit("/", 1)[-1]
    api_detail = client.get(f"/api/v1/tickets/{ticket_id}")
    assert api_detail.status_code == 200
    ticket = api_detail.get_json()
    assert ticket["execution_plan"] == [
        {
            "role": "implementer",
            "agent": "codex",
            "prompt_markdown": "Prepare the implementation plan.",
        },
        {
            "role": "reviewer",
            "agent": "claude",
            "prompt_markdown": "Review the implementation plan.",
        },
    ]


def test_manual_ticket_creation_supports_legacy_single_step_fields(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Legacy single step",
            "summary": "Old field names should still work",
            "step_role": "reviewer",
            "step_agent": "claude",
            "prompt_markdown": "Review the change set.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    ticket_id = response.headers["Location"].rsplit("/", 1)[-1]
    api_detail = client.get(f"/api/v1/tickets/{ticket_id}")
    assert api_detail.status_code == 200
    ticket = api_detail.get_json()
    assert ticket["execution_plan"] == [
        {
            "role": "reviewer",
            "agent": "claude",
            "prompt_markdown": "Review the change set.",
        }
    ]


def test_manual_ticket_creation_rejects_empty_execution_plan_from_ui(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "No steps",
            "summary": "Submitting without steps should fail",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "execution_plan must be a non-empty array" in body
    assert 'value="No steps"' in body
    assert ">Submitting without steps should fail</textarea>" in body
    assert "No workflow steps yet" in body


def test_manual_ticket_form_uses_implementer_guidance_for_legacy_implementor_role(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Legacy implementor guidance",
            "summary": "Guidance should still match implementer semantics",
            "steps-0-role": "implementor",
            "steps-0-agent": "codex",
            "steps-0-prompt_markdown": "Prepare the fix in source.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    ticket_id = response.headers["Location"].rsplit("/", 1)[-1]
    detail = client.get(f"/api/v1/tickets/{ticket_id}")
    assert detail.status_code == 200
    ticket = detail.get_json()
    assert ticket["execution_plan"] == [
        {
            "role": "implementor",
            "agent": "codex",
            "prompt_markdown": "Prepare the fix in source.",
        }
    ]

    response = client.get("/tickets")
    body = response.get_data(as_text=True)
    assert "Repo-first implementation" in body
    assert "Do not patch production files ad hoc as the primary fix path." in body


def test_manual_ticket_creation_enforces_operator_reviewer_floor_when_enabled(tmp_path: Path) -> None:
    client = _build_client(tmp_path, operator_require_reviewer_step_floor=True)
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Needs reviewer",
            "summary": "Policy floor should reject this",
            "steps-0-role": "implementer",
            "steps-0-agent": "codex",
            "steps-0-prompt_markdown": "Make a change.",
            "steps-1-role": "investigator",
            "steps-1-agent": "claude",
            "steps-1-prompt_markdown": "Collect logs.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "requires at least one reviewer step" in body
    assert "Operator policy floor" in body


def test_manual_ticket_creation_rejects_invalid_context_json(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Bad context",
            "summary": "This should fail",
            "steps-0-role": "reviewer",
            "steps-0-agent": "codex",
            "steps-0-prompt_markdown": "Inspect state.",
            "steps-1-role": "implementer",
            "steps-1-agent": "claude",
            "steps-1-prompt_markdown": "Prepare a no-op fix.",
            "context_json": "[1, 2, 3]",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "context_json must decode to an object" in body
    assert ">[1, 2, 3]</textarea>" in body
    assert ">Inspect state.</textarea>" in body
    assert ">Prepare a no-op fix.</textarea>" in body


def test_manual_ticket_creation_rejects_unsupported_agent_from_ui(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Bad agent",
            "summary": "Unsupported agents should be rejected",
            "steps-0-role": "reviewer",
            "steps-0-agent": "shell",
            "steps-0-prompt_markdown": "Review the proposed change.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "agent must be one of: codex, claude" in body
    assert 'value="Bad agent"' in body
    assert '>shell (unsupported)</option>' in body
    assert ">Review the proposed change.</textarea>" in body


def test_manual_ticket_creation_requires_csrf_token(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "title": "Missing token",
            "summary": "This should be rejected",
            "step_role": "reviewer",
            "step_agent": "codex",
            "prompt_markdown": "Do nothing.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"

    page = client.get("/tickets")
    assert "Invalid form token" in page.get_data(as_text=True)


def test_manual_ticket_creation_rejects_tampered_csrf_token(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": "tampered-token",
            "title": "Bad token",
            "summary": "This should be rejected",
            "step_role": "reviewer",
            "step_agent": "codex",
            "prompt_markdown": "Do nothing.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"

    page = client.get("/tickets")
    assert "Invalid form token" in page.get_data(as_text=True)


def test_ui_ticket_action_failure_redirects_back_to_ticket_detail(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Already approved",
        summary="Second approval should preserve detail context",
        task_ref="ui-action-failure-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )
    login(client)

    first_approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert first_approve.status_code == 200

    second_approve = client.post(
        f"/tickets/{ticket_id}/approve",
        data={"csrf_token": session_csrf_token(client)},
        follow_redirects=False,
    )
    assert second_approve.status_code == 302
    assert second_approve.headers["Location"] == f"/tickets/{ticket_id}"

    detail = client.get(second_approve.headers["Location"])
    assert detail.status_code == 200
    assert "Ticket is not pending approval" in detail.get_data(as_text=True)


def test_api_ticket_creation_rejects_unsupported_agent(client: Any) -> None:
    response = client.post(
        "/api/v1/tickets",
        headers=auth_headers("nyxmon-token-000000000000"),
        json={
            "title": "Bad API agent",
            "summary": "Unsupported agents should be rejected",
            "execution_plan": [
                {"role": "investigator", "agent": "shell", "prompt_markdown": "Inspect the service"}
            ],
        },
    )
    assert response.status_code == 400
    assert response.get_json() == {
        "error": "invalid_execution_plan",
        "message": "agent must be one of: codex, claude",
    }


def test_approval_revalidates_stored_agent_allowlist(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Stored bad agent",
        summary="Approval should reject unsupported stored agents",
        task_ref="approve-bad-agent-1",
    )

    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
            ('[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]', ticket_id),
        )
        conn.commit()

    login(client)
    response = client.post(f"/api/v1/tickets/{ticket_id}/approve")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "invalid_execution_plan",
        "message": "agent must be one of: codex, claude",
    }


def test_approval_revalidates_stored_reviewer_requirement(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="operator-token-00000000000",
        title="Stored missing reviewer",
        summary="Approval should reject a stored plan that no longer satisfies reviewer policy",
        task_ref="approve-missing-reviewer-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
            ('[{"role":"investigator","agent":"codex","prompt_markdown":"Inspect state"}]', ticket_id),
        )
        conn.commit()

    login(client)
    response = client.post(f"/api/v1/tickets/{ticket_id}/approve")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "missing_reviewer_step",
        "message": "policy_requirements.require_reviewer_step=true requires at least one reviewer step",
    }


def test_api_ticket_creation_normalizes_agent_case(client: Any) -> None:
    response = client.post(
        "/api/v1/tickets",
        headers=auth_headers("nyxmon-token-000000000000"),
        json={
            "title": "Mixed case agent",
            "summary": "Agent values should normalize to lowercase",
            "execution_plan": [
                {"role": "reviewer", "agent": "CLAUDE", "prompt_markdown": "Review the change"}
            ],
        },
    )
    assert response.status_code == 201

    ticket_id = response.get_json()["id"]
    detail = client.get(f"/api/v1/tickets/{ticket_id}", headers=auth_headers("nyxmon-token-000000000000"))
    assert detail.status_code == 200
    assert detail.get_json()["execution_plan"] == [
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "Review the change"}
    ]


def test_runner_claim_fails_invalid_stored_agent_and_moves_on(client: Any) -> None:
    bad_ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Invalid stored claim agent",
        summary="Claim should fail invalid stored plan and continue",
        task_ref="claim-bad-agent-1",
    )
    good_ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Valid follow-up ticket",
        summary="Claim should proceed to the next valid ticket",
        task_ref="claim-bad-agent-2",
    )

    login(client)
    assert client.post(f"/api/v1/tickets/{bad_ticket_id}/approve").status_code == 200
    assert client.post(f"/api/v1/tickets/{good_ticket_id}/approve").status_code == 200

    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
            ('[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]', bad_ticket_id),
        )
        conn.commit()

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})

    assert claim.status_code == 200
    claimed_ticket = claim.get_json()["ticket"]
    assert claimed_ticket is not None
    assert claimed_ticket["id"] == good_ticket_id
    assert claimed_ticket["state"] == "running"

    bad_ticket_detail = client.get(f"/api/v1/tickets/{bad_ticket_id}")
    assert bad_ticket_detail.status_code == 200
    bad_ticket = bad_ticket_detail.get_json()
    assert bad_ticket["state"] == "failed"
    assert bad_ticket["result"] == "failure"
    assert bad_ticket["result_detail"] == "invalid_stored_plan"


@pytest.mark.parametrize(
    ("route_name", "path_builder", "data_builder"),
    [
        ("logout", lambda ticket_id: "/logout", lambda _ticket_id: {}),
        ("approve", lambda ticket_id: f"/tickets/{ticket_id}/approve", lambda _ticket_id: {}),
        ("reject", lambda ticket_id: f"/tickets/{ticket_id}/reject", lambda _ticket_id: {"reason": "nope"}),
        ("cancel", lambda ticket_id: f"/tickets/{ticket_id}/cancel", lambda _ticket_id: {"reason": "stop"}),
    ],
)
def test_ui_post_routes_require_csrf_token(
    client: Any,
    route_name: str,
    path_builder: Any,
    data_builder: Any,
) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Needs approval",
        summary="CSRF route coverage",
        task_ref=f"ui-csrf-{route_name}",
    )
    login(client)

    response = client.post(
        path_builder(ticket_id),
        data=data_builder(ticket_id),
        follow_redirects=False,
    )
    assert response.status_code == 302
    expected_location = "/tickets" if route_name == "logout" else f"/tickets/{ticket_id}"
    assert response.headers["Location"] == expected_location

    page = client.get(expected_location)
    assert "Invalid form token" in page.get_data(as_text=True)


def test_trusted_proxy_headers_restore_client_ip_for_access_and_audit(proxy_client: Any) -> None:
    payload = {
        "title": "Proxy path",
        "summary": "Audit real client IP",
        "task_ref": "proxy-audit-1",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect proxy behavior"}
        ],
    }

    response = proxy_client.post(
        "/api/v1/tickets",
        headers={
            **auth_headers("nyxmon-token-000000000000"),
            "X-Forwarded-For": "100.100.100.42",
        },
        json=payload,
        environ_base={"REMOTE_ADDR": "203.0.113.8"},
    )
    assert response.status_code == 201

    ticket_id = response.get_json()["id"]
    db_path = proxy_client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT source_ip FROM audit_events WHERE ticket_id = ? AND event_type = 'ticket_created'",
            (ticket_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == "100.100.100.42"


def test_login_ignores_external_next_path(client: Any) -> None:
    response = login(client, "/login?next=https://example.com/steal")
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"


def test_login_form_uses_autofill_friendly_fields(client: Any) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<form method="post" action="/login" autocomplete="on">' in body
    assert 'name="username"' in body
    assert 'autocomplete="username"' in body
    assert 'autocapitalize="none"' in body
    assert 'autocorrect="off"' in body
    assert 'spellcheck="false"' in body
    assert 'name="password"' in body
    assert 'autocomplete="current-password"' in body


def test_login_ignores_protocol_relative_next_path(client: Any) -> None:
    response = login(client, "/login?next=//evil.example/steal")
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"


def test_login_ignores_javascript_next_path(client: Any) -> None:
    response = login(client, "/login?next=javascript:alert(1)")
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"


def test_login_ignores_control_chars_in_next_path(client: Any) -> None:
    response = login(client, "/login?next=/tickets/test%0D%0Ainvalid")
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"


def test_create_and_get_ticket_submit_token(client: Any) -> None:
    payload = {
        "title": "Investigate disk alert",
        "summary": "Disk usage crossed threshold",
        "task_ref": "alert-123",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Investigate issue"}
        ],
    }
    create_response = client.post(
        "/api/v1/tickets",
        headers=auth_headers("nyxmon-token-000000000000"),
        json=payload,
    )
    assert create_response.status_code == 201

    created = create_response.get_json()
    assert created["state"] == "pending_approval"
    assert created["source"] == "nyxmon"

    ticket_response = client.get(
        f"/api/v1/tickets/{created['id']}",
        headers=auth_headers("nyxmon-token-000000000000"),
    )
    assert ticket_response.status_code == 200
    fetched = ticket_response.get_json()
    assert fetched["id"] == created["id"]


def test_dedupe_enforced_for_open_task_ref(client: Any) -> None:
    payload = {
        "title": "Investigate alert",
        "summary": "Same task ref",
        "task_ref": "same-ref",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}
        ],
    }
    first = client.post("/api/v1/tickets", headers=auth_headers("openclaw-token-0000000000"), json=payload)
    assert first.status_code == 201

    second = client.post("/api/v1/tickets", headers=auth_headers("openclaw-token-0000000000"), json=payload)
    assert second.status_code == 409
    body = second.get_json()
    assert body["error"] == "duplicate_open_ticket"


def test_dedupe_not_applied_when_task_ref_missing(client: Any) -> None:
    payload = {
        "title": "Investigate alert",
        "summary": "No task ref",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}
        ],
    }
    first = client.post("/api/v1/tickets", headers=auth_headers("openclaw-token-0000000000"), json=payload)
    second = client.post("/api/v1/tickets", headers=auth_headers("openclaw-token-0000000000"), json=payload)
    assert first.status_code == 201
    assert second.status_code == 201


def test_operator_submitter_may_explicitly_require_reviewer_step(client: Any) -> None:
    payload = {
        "title": "Operator task",
        "summary": "Operator may opt into reviewer requirement",
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
        "policy_requirements": {"require_reviewer_step": True},
    }
    response = client.post("/api/v1/tickets", headers=auth_headers("operator-token-00000000000"), json=payload)
    assert response.status_code == 201
    body = response.get_json()
    assert body["policy_requirements"]["require_reviewer_step"] is True


def test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor(client: Any) -> None:
    payload = {
        "title": "Operator task with omitted policy",
        "summary": "Should default to no reviewer floor",
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
    }
    response = client.post("/api/v1/tickets", headers=auth_headers("operator-token-00000000000"), json=payload)
    assert response.status_code == 201
    body = response.get_json()
    assert body["policy_requirements"]["require_reviewer_step"] is False


def test_lazy_expiry_blocks_approval(client: Any) -> None:
    past = datetime.now(tz=UTC) - timedelta(hours=1)
    payload = {
        "title": "Old ticket",
        "summary": "Should expire before approval",
        "task_ref": "old-1",
        "expires_at": past.isoformat().replace("+00:00", "Z"),
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
        "policy_requirements": {"require_reviewer_step": True},
    }
    create_response = client.post("/api/v1/tickets", headers=auth_headers("nyxmon-token-000000000000"), json=payload)
    assert create_response.status_code == 201
    ticket_id = create_response.get_json()["id"]

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 409
    assert approve.get_json()["error"] == "ticket_expired"

    read_back = client.get(f"/api/v1/tickets/{ticket_id}", headers=auth_headers("nyxmon-token-000000000000"))
    assert read_back.status_code == 200
    assert read_back.get_json()["state"] == "expired"


def test_approve_and_reject_flow(client: Any) -> None:
    payload = {
        "title": "Approve me",
        "summary": "Ticket one",
        "task_ref": "approve-1",
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
        "policy_requirements": {"require_reviewer_step": True},
    }
    pending = client.post("/api/v1/tickets", headers=auth_headers("nyxmon-token-000000000000"), json=payload)
    assert pending.status_code == 201
    ticket_id = pending.get_json()["id"]

    login(client)

    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200
    approved = approve.get_json()
    assert approved["state"] == "approved"
    assert isinstance(approved["approved_payload_checksum"], str)
    assert len(approved["approved_payload_checksum"]) == 64

    second_payload = {
        "title": "Reject me",
        "summary": "Ticket two",
        "task_ref": "reject-1",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Investigate"}
        ],
    }
    second_pending = client.post(
        "/api/v1/tickets",
        headers=auth_headers("nyxmon-token-000000000000"),
        json=second_payload,
    )
    second_ticket_id = second_pending.get_json()["id"]

    reject = client.post(
        f"/api/v1/tickets/{second_ticket_id}/reject",
        json={"reason": "not-needed"},
    )
    assert reject.status_code == 200
    rejected = reject.get_json()
    assert rejected["state"] == "rejected"


def test_cancel_flow(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Cancel me",
        summary="Cancel flow test",
        task_ref="cancel-1",
    )
    login(client)
    cancel = client.post(f"/api/v1/tickets/{ticket_id}/cancel", json={"reason": "operator canceled"})
    assert cancel.status_code == 200
    body = cancel.get_json()
    assert body["state"] == "canceled"
    assert body["result"] == "canceled"


def test_runner_claim_happy_path(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner claim",
        summary="Claim test",
        task_ref="claim-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post(
        "/api/v1/runner/claim",
        headers=runner_headers(),
        json={"runner_host": "runner-a"},
    )
    assert claim.status_code == 200
    claimed_ticket = claim.get_json()["ticket"]
    assert claimed_ticket is not None
    assert claimed_ticket["id"] == ticket_id
    assert claimed_ticket["state"] == "running"
    assert claimed_ticket["runner_host"] == "runner-a"


def test_runner_claim_detects_checksum_tamper(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner tamper",
        summary="Tamper test",
        task_ref="claim-tamper-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    db_path = client.application.config["OPSGATE_TEST_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE tickets
            SET execution_plan_json = ?
            WHERE id = ?
            """,
            ('[{"role":"reviewer","agent":"codex","prompt_markdown":"tampered"}]', ticket_id),
        )
        conn.commit()

    claim = client.post(
        "/api/v1/runner/claim",
        headers=runner_headers(),
        json={"runner_host": "runner-a"},
    )
    assert claim.status_code == 200
    assert claim.get_json()["ticket"] is None

    read_back = client.get(f"/api/v1/tickets/{ticket_id}", headers=auth_headers("nyxmon-token-000000000000"))
    assert read_back.status_code == 200
    body = read_back.get_json()
    assert body["state"] == "failed"
    assert body["result_detail"] == "prompt_tampered"


def test_runner_status_rejects_terminal_state_regression(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner status",
        summary="Status transition test",
        task_ref="status-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    heartbeat_while_approved = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a"},
    )
    assert heartbeat_while_approved.status_code == 409
    assert heartbeat_while_approved.get_json()["error"] == "invalid_state"

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200
    assert claim.get_json()["ticket"]["state"] == "running"

    succeed = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a", "state": "succeeded"},
    )
    assert succeed.status_code == 200
    assert succeed.get_json()["state"] == "succeeded"

    regress = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a", "state": "running"},
    )
    assert regress.status_code == 409
    assert regress.get_json()["error"] == "invalid_state"

    heartbeat_after_terminal = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a"},
    )
    assert heartbeat_after_terminal.status_code == 409
    assert heartbeat_after_terminal.get_json()["error"] == "invalid_state"


def test_runner_status_accepts_timeout_result_and_tmux_sessions(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner timeout result",
        summary="Timeout result update",
        task_ref="status-timeout-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200
    assert claim.get_json()["ticket"]["state"] == "running"

    tmux_sessions = [
        {
            "step_index": 0,
            "role": "reviewer",
            "agent": "codex",
            "session_name": "job-1",
            "status": "timeout",
            "attach_command": (
                "sudo -u ops env TMUX_TMPDIR=/Users/ops/remediation/tmux "
                "tmux -L remediation attach -t job-1"
            ),
        }
    ]
    failed = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={
            "runner_host": "runner-a",
            "event": "timeout",
            "state": "failed",
            "result": "timeout",
            "result_detail": "max_duration_seconds_exceeded",
            "tmux_sessions": tmux_sessions,
        },
    )
    assert failed.status_code == 200
    body = failed.get_json()
    assert body["state"] == "failed"
    assert body["result"] == "timeout"
    assert body["tmux_sessions"] == tmux_sessions


def test_runner_status_rejects_invalid_tmux_sessions_payload(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner invalid tmux payload",
        summary="Invalid payload test",
        task_ref="status-invalid-tmux-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200

    invalid = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a", "tmux_sessions": {"bad": "value"}},
    )
    assert invalid.status_code == 400
    assert invalid.get_json()["error"] == "invalid_tmux_sessions"


def test_runner_status_rejects_runner_host_mismatch(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner host mismatch",
        summary="Host mismatch update",
        task_ref="status-host-mismatch-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200

    mismatch = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-b", "event": "heartbeat"},
    )
    assert mismatch.status_code == 409
    assert mismatch.get_json()["error"] == "runner_host_mismatch"


def test_runner_status_rejects_invalid_event_type(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner invalid event",
        summary="Invalid event update",
        task_ref="status-invalid-event-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200

    invalid_event = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={"runner_host": "runner-a", "event": "ticket_approved"},
    )
    assert invalid_event.status_code == 400
    assert invalid_event.get_json()["error"] == "invalid_runner_event"


def test_runner_status_accepts_step_failed_event(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Runner step failed event",
        summary="Step failed update",
        task_ref="status-step-failed-1",
        execution_plan=[{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        policy_requirements={"require_reviewer_step": True},
    )

    login(client)
    approve = client.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert approve.status_code == 200

    claim = client.post("/api/v1/runner/claim", headers=runner_headers(), json={"runner_host": "runner-a"})
    assert claim.status_code == 200

    step_failed = client.post(
        f"/api/v1/runner/{ticket_id}/status",
        headers=runner_headers(),
        json={
            "runner_host": "runner-a",
            "event": "step_failed",
            "state": "failed",
            "result": "failure",
            "result_detail": "step_1_exit_code_7",
        },
    )
    assert step_failed.status_code == 200
    body = step_failed.get_json()
    assert body["state"] == "failed"
    assert body["result"] == "failure"
    assert body["result_detail"] == "step_1_exit_code_7"


def test_get_ticket_forbidden_for_other_submitter_source(client: Any) -> None:
    ticket_id = create_ticket(
        client,
        token="nyxmon-token-000000000000",
        title="Cross source",
        summary="Forbidden read test",
        task_ref="cross-source-1",
    )
    response = client.get(f"/api/v1/tickets/{ticket_id}", headers=auth_headers("openclaw-token-0000000000"))
    assert response.status_code == 403
    assert response.get_json()["error"] == "forbidden"


def test_health_endpoint_reports_ok(client: Any) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"


def test_api_rejects_non_tailscale_source_ip(client: Any) -> None:
    payload = {
        "title": "Forbidden source",
        "summary": "CIDR enforcement",
        "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}],
    }
    response = client.post(
        "/api/v1/tickets",
        headers=auth_headers("nyxmon-token-000000000000"),
        environ_overrides={"REMOTE_ADDR": "8.8.8.8"},
        json=payload,
    )
    assert response.status_code == 403
