from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import bcrypt
import pytest

from opsgate.app import create_app
from opsgate.config import OpsGateSettings, SubmitterPolicy


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
                require_reviewer_step_floor=True,
            ),
        ),
        require_tailscale_context=True,
        allowed_cidrs=("127.0.0.1/32", "::1/128", "100.64.0.0/10"),
        execution_data_dir="/tmp",
        disable_file_path="/tmp/opsgate.disabled",
    )


@pytest.fixture
def client(tmp_path: Path) -> Any:
    db_file = str(tmp_path / "opsgate.sqlite3")
    app = create_app(_build_settings(db_file))
    app.config.update(TESTING=True)
    app.config["OPSGATE_TEST_DB_PATH"] = db_file
    return app.test_client()


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
            "step_role": "reviewer",
            "step_agent": "codex",
            "prompt_markdown": "Apply a safe no-op change and report findings.",
            "max_duration_seconds": "900",
            "context_json": '{"service": "opsgate", "host": "macstudio"}',
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    location = response.headers["Location"]
    assert location.startswith("/tickets/")

    detail = client.get(location)
    assert detail.status_code == 200
    body = detail.get_data(as_text=True)
    assert "Manual remediation" in body
    assert "approver:opsgate-admin" in body


def test_manual_ticket_creation_respects_operator_reviewer_floor(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Needs reviewer",
            "summary": "Policy floor should reject this",
            "step_role": "implementer",
            "step_agent": "codex",
            "prompt_markdown": "Make a change.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"

    page = client.get("/tickets")
    assert "requires at least one reviewer step" in page.get_data(as_text=True)


def test_manual_ticket_creation_rejects_invalid_context_json(client: Any) -> None:
    login(client)

    response = client.post(
        "/tickets",
        data={
            "csrf_token": session_csrf_token(client),
            "title": "Bad context",
            "summary": "This should fail",
            "step_role": "investigator",
            "step_agent": "codex",
            "prompt_markdown": "Inspect state.",
            "context_json": "[1, 2, 3]",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"

    page = client.get("/tickets")
    assert "context_json must decode to an object" in page.get_data(as_text=True)


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
    assert response.headers["Location"] == "/tickets"

    page = client.get("/tickets")
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


def test_policy_floor_cannot_be_weakened(client: Any) -> None:
    payload = {
        "title": "Operator task",
        "summary": "Should fail floor validation",
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
        "policy_requirements": {"require_reviewer_step": False},
    }
    response = client.post("/api/v1/tickets", headers=auth_headers("operator-token-00000000000"), json=payload)
    assert response.status_code == 400
    body = response.get_json()
    assert body["error"] == "policy_floor_violation"


def test_policy_floor_omitted_ticket_policy_uses_floor(client: Any) -> None:
    payload = {
        "title": "Operator task with omitted policy",
        "summary": "Should inherit floor",
        "execution_plan": [
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ],
    }
    response = client.post("/api/v1/tickets", headers=auth_headers("operator-token-00000000000"), json=payload)
    assert response.status_code == 201
    body = response.get_json()
    assert body["policy_requirements"]["require_reviewer_step"] is True


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
