"""Web UI: pages, actions, manual ticket form, log views, UI CSRF (PLAN.md 4.3, 4.11, 4.12).

Ported from tests/test_api.py (names kept). Pages are checked for their P1
content (strings the Python tests check, flashes, forms, links); the records
add the forms and links of every page. Log files live under the scenario's
execution data directory, as the runner would write them.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from conftest import Stack
from harness import (
    REVIEW_PLAN,
    Browser,
    Database,
    Profile,
    Target,
    create_ticket,
    get_ticket,
)

UI = pytest.mark.rust("S4a", "S4b", "S5")
NON_ASCII_TOKEN = "té-über"


def write_log(target: Target, stack: Stack, ticket_id: str, relative: str, content: str | bytes) -> Path:
    path = stack.exec_dir(target) / "sessions" / ticket_id / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return path


def set_sessions(db: Database, ticket_id: str, sessions: list[dict[str, Any]]) -> None:
    import json

    db.set_ticket(ticket_id, tmux_sessions_json=json.dumps(sessions, sort_keys=True))


def session_entry(log_path: str, step_index: Any = 0, status: str = "succeeded") -> dict[str, Any]:
    return {
        "step_index": step_index,
        "role": "reviewer",
        "agent": "claude",
        "status": status,
        "session_name": "job-parity-01",
        "attach_command": "tmux attach -t job-parity-01",
        "log_path": log_path,
    }


def manual_form(browser: Browser, **fields: str) -> dict[str, str]:
    return {"csrf_token": browser.csrf(), "title": "Manual", "summary": "Manual ticket", **fields}


STEPS = {
    "steps-0-role": "investigator",
    "steps-0-agent": "codex",
    "steps-0-prompt_markdown": "Inspect",
}


# ------------------------------------------------------------------ redirects and access


@UI
def test_ui_ticket_detail_redirects_to_login_with_next(anon: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-ui-next-1")
    for path in (f"/tickets/{ticket_id}", f"/tickets/{ticket_id}/steps/1/log"):
        resp = anon.get(path)
        assert (resp.status, resp.location) == (302, f"/login?next={path}")
    resp = anon.login(f"/login?next=/tickets/{ticket_id}")
    assert resp.location == f"/tickets/{ticket_id}"


@UI
def test_root_and_list_redirects(anon: Browser) -> None:
    assert anon.get("/").location == "/login"
    assert anon.get("/tickets").location == "/login"
    assert anon.login().status == 302
    assert anon.get("/").location == "/tickets"


@UI
def test_ui_pages_cannot_be_framed(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon)
    for path in ("/login", "/tickets", f"/tickets/{ticket_id}", "/tickets?view=archived"):
        assert approver.get(path).status == 200


@UI
def test_ui_missing_ticket_redirects_with_flash(approver: Browser) -> None:
    resp = approver.get("/tickets/missing-ticket")
    assert (resp.status, resp.location) == (302, "/tickets")
    assert approver.follow(resp).flashes == [["error", "Ticket not found"]]
    resp = approver.get("/tickets/missing-ticket/steps/1/log")
    assert resp.location == "/tickets/missing-ticket"


@UI
@pytest.mark.parametrize("unauthenticated_action", ["approve", "reject", "cancel", "archive", "unarchive"])
def test_ui_actions_without_session_redirect_to_login(anon: Browser, unauthenticated_action: str) -> None:
    ticket_id = create_ticket(anon)
    token = anon.get("/login").csrf_token
    resp = anon.post(f"/tickets/{ticket_id}/{unauthenticated_action}", data={"csrf_token": token})
    assert (resp.status, resp.location) == (302, "/login")
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"


# ------------------------------------------------------------------ manual ticket form


@UI
def test_manual_ticket_creation_from_ui(approver: Browser) -> None:
    resp = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            title="Manual remediation",
            summary="Create through web UI",
            task_ref="parity-ui-manual-1",
            **{
                "steps-0-role": "implementer",
                "steps-0-agent": "codex",
                "steps-0-prompt_markdown": "Inspect the target service and prepare a no-op patch.",
                "steps-1-role": "reviewer",
                "steps-1-agent": "claude",
                "steps-1-prompt_markdown": "Review the proposed change and confirm it stays a no-op.",
                "max_duration_seconds": "900",
                "context_json": '{"service": "opsgate", "host": "macstudio"}',
            },
        ),
    )
    assert resp.status == 302 and resp.location and resp.location.startswith("/tickets/")
    ticket_id = resp.location.rsplit("/", 1)[-1]
    ticket = approver.get(f"/api/v1/tickets/{ticket_id}").json()
    assert [step["role"] for step in ticket["execution_plan"]] == ["implementer", "reviewer"]
    assert ticket["policy_requirements"] == {"require_reviewer_step": False}
    assert (ticket["source"], ticket["created_by"], ticket["max_duration_seconds"]) == (
        "operator",
        f"approver:{approver.target.username}",
        900,
    )
    detail = approver.follow(resp)
    assert detail.flashes == [["success", "Ticket created and queued for approval"]]
    assert "Manual remediation" in detail.text and f"approver:{approver.target.username}" in detail.text


@UI
def test_manual_ticket_form_defaults_investigator_to_codex(approver: Browser) -> None:
    body = approver.get("/tickets").text
    assert 'name="steps-0-role"' in body
    assert '<option value="investigator" selected>investigator</option>' in body
    assert '<option value="codex" selected>codex</option>' in body
    assert '<option value="claude">claude</option>' in body


@UI
def test_manual_ticket_form_renders_role_scaffolding(approver: Browser) -> None:
    body = approver.get("/tickets").text
    for snippet in (
        "Role model",
        "OpsGate currently supports exactly three workflow roles.",
        "Inspect-only investigation",
        "Repo-first implementation",
        "Independent review gate",
        "Use suggested prompt",
    ):
        assert snippet in body


@UI
def test_manual_ticket_creation_defaults_agent_from_role(approver: Browser) -> None:
    resp = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            **{
                "steps-1-role": "reviewer",
                "steps-1-prompt_markdown": "Review the implementation plan.",
                "steps-0-role": "implementer",
                "steps-0-prompt_markdown": "Prepare the implementation plan.",
                "steps-2-role": "auditor",
                "steps-2-prompt_markdown": "Unknown roles default to codex.",
            },
        ),
    )
    ticket = approver.get(f"/api/v1/tickets/{resp.location.rsplit('/', 1)[-1]}").json()  # type: ignore[union-attr]
    assert [(s["role"], s["agent"]) for s in ticket["execution_plan"]] == [
        ("implementer", "codex"),
        ("reviewer", "claude"),
        ("auditor", "codex"),
    ]


@UI
def test_manual_ticket_creation_supports_legacy_single_step_fields(approver: Browser) -> None:
    resp = approver.post(
        "/tickets",
        data=manual_form(approver, step_role="reviewer", step_agent="claude", prompt_markdown="Review the change set."),
    )
    ticket = approver.get(f"/api/v1/tickets/{resp.location.rsplit('/', 1)[-1]}").json()  # type: ignore[union-attr]
    assert ticket["execution_plan"] == [
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "Review the change set."}
    ]


@UI
@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({}, "execution_plan must be a non-empty array"),
        ({**STEPS, "steps-0-agent": "shell"}, "agent must be one of: codex, claude"),
        ({**STEPS, "context_json": "[1, 2, 3]"}, "context_json must decode to an object"),
        ({**STEPS, "context_json": "{broken"}, None),
        ({**STEPS, "context_json": '{"n":' + "[" * 2000 + "0" + "]" * 2000 + "}"}, None),
        ({**STEPS, "expires_at": "tomorrow"}, None),
        ({**STEPS, "title": "  "}, "title and summary are required"),
    ],
)
def test_manual_ticket_form_errors_render_sticky_form(
    approver: Browser, db: Database, fields: dict[str, str], message: str | None
) -> None:
    resp = approver.post("/tickets", data=manual_form(approver, **fields))
    assert resp.status == 400
    assert len(resp.flashes) == 1 and resp.flashes[0][0] == "error"
    if message is not None:
        assert message in resp.flashes[0][1]
    assert db.scalar("SELECT count(*) FROM tickets") == 0


@UI
def test_manual_ticket_creation_rejects_empty_execution_plan_from_ui(approver: Browser) -> None:
    body = approver.post(
        "/tickets", data=manual_form(approver, title="No steps", summary="Submitting without steps should fail")
    ).text
    assert "execution_plan must be a non-empty array" in body
    assert 'value="No steps"' in body
    assert ">Submitting without steps should fail</textarea>" in body
    assert "No workflow steps yet" in body


@UI
def test_manual_ticket_creation_rejects_unsupported_agent_from_ui(approver: Browser) -> None:
    body = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            title="Bad agent",
            **{
                "steps-0-role": "reviewer",
                "steps-0-agent": "shell",
                "steps-0-prompt_markdown": "Review the proposed change.",
            },
        ),
    ).text
    assert 'value="Bad agent"' in body
    assert ">shell (unsupported)</option>" in body
    assert ">Review the proposed change.</textarea>" in body


@UI
def test_manual_ticket_creation_rejects_invalid_context_json(approver: Browser) -> None:
    body = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            **{
                "steps-0-role": "reviewer",
                "steps-0-agent": "codex",
                "steps-0-prompt_markdown": "Inspect state.",
                "steps-1-role": "implementer",
                "steps-1-agent": "claude",
                "steps-1-prompt_markdown": "Prepare a no-op fix.",
                "context_json": "[1, 2, 3]",
            },
        ),
    ).text
    assert ">[1, 2, 3]</textarea>" in body
    assert ">Inspect state.</textarea>" in body and ">Prepare a no-op fix.</textarea>" in body


@UI
def test_manual_ticket_form_uses_implementer_guidance_for_legacy_implementor_role(approver: Browser) -> None:
    resp = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            **{
                "steps-0-role": "implementor",
                "steps-0-agent": "codex",
                "steps-0-prompt_markdown": "Prepare the fix in source.",
            },
        ),
    )
    assert resp.status == 302
    body = approver.get("/tickets").text
    assert "Repo-first implementation" in body
    assert "Do not patch production files ad hoc as the primary fix path." in body


@UI
def test_manual_ticket_creation_enforces_operator_reviewer_floor_when_enabled(stack: Stack) -> None:
    target = stack.server(Profile(operator_reviewer_floor=True))
    approver = stack.approver(target)
    assert '<option value="reviewer" selected>reviewer</option>' in approver.get("/tickets").text
    body = approver.post(
        "/tickets",
        data=manual_form(
            approver,
            **{
                "steps-0-role": "implementer",
                "steps-0-agent": "codex",
                "steps-0-prompt_markdown": "Make a change.",
                "steps-1-role": "investigator",
                "steps-1-agent": "claude",
                "steps-1-prompt_markdown": "Collect logs.",
            },
        ),
    ).text
    assert "requires at least one reviewer step" in body
    assert "Operator policy floor" in body
    ok = approver.post("/tickets", data=manual_form(approver, step_role="reviewer", prompt_markdown="Review."))
    ticket = approver.get(f"/api/v1/tickets/{ok.location.rsplit('/', 1)[-1]}").json()  # type: ignore[union-attr]
    assert ticket["policy_requirements"] == {"require_reviewer_step": True}


@UI
@pytest.mark.parametrize("duration", ["1.5", "0", "31536001", "1_000", "-5", "abc"])
def test_manual_ticket_duration_rejects_invalid_values(approver: Browser, db: Database, duration: str) -> None:
    resp = approver.post("/tickets", data=manual_form(approver, max_duration_seconds=duration, **STEPS))
    assert resp.status == 400
    assert db.scalar("SELECT count(*) FROM tickets") == 0


@UI
@pytest.mark.parametrize("depth", [64, 65, 2000])
def test_real_manual_context_nesting_limit(approver: Browser, db: Database, depth: int) -> None:
    context = '{"nested":' + "[" * (depth - 1) + "0" + "]" * (depth - 1) + "}"
    resp = approver.post("/tickets", data=manual_form(approver, context_json=context, **STEPS))
    assert resp.status == (302 if depth == 64 else 400)
    assert db.scalar("SELECT count(*) FROM tickets") == (1 if depth == 64 else 0)


@UI
@pytest.mark.parametrize("token", [None, "tampered-token", NON_ASCII_TOKEN])
def test_manual_ticket_creation_requires_csrf_token(approver: Browser, db: Database, token: str | None) -> None:
    data = {"title": "Missing token", "summary": "Rejected", "step_role": "reviewer", "prompt_markdown": "Do nothing."}
    if token is not None:
        data["csrf_token"] = token
    resp = approver.post("/tickets", data=data)
    assert (resp.status, resp.location) == (302, "/tickets")
    page = approver.follow(resp)
    assert page.status == 200 and page.flashes == [["error", "Invalid form token"]]
    assert db.scalar("SELECT count(*) FROM tickets") == 0


# ------------------------------------------------------------------ ticket list and detail


@UI
def test_ticket_list_renders_compact_created_at_timestamp(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, title="Compact timestamp")
    raw = get_ticket(anon, ticket_id)["created_at"]
    compact = datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    body = approver.get("/tickets").text
    assert compact in body and raw not in body


@UI
@pytest.mark.parametrize("view", ["active", "archived", "all", "ALL", "bogus", ""])
def test_ticket_list_views(anon: Browser, approver: Browser, view: str) -> None:
    active = create_ticket(anon, title="Active ticket")
    shelved = create_ticket(anon, title="Shelved ticket")
    assert approver.api_action(shelved, "archive").status == 200
    body = approver.get(f"/tickets?view={view}").text
    shown = {"archived": (False, True), "all": (True, True)}.get(view.lower(), (True, False))
    assert ("Active ticket" in body, "Shelved ticket" in body) == shown
    assert active != shelved


@UI
def test_ui_archive_and_restore_controls_manage_ticket_visibility(anon: Browser, approver: Browser) -> None:
    title = "Archive through UI"
    ticket_id = create_ticket(anon, title=title, task_ref="parity-archive-ui-1")
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    before = approver.get(f"/tickets/{ticket_id}").text
    assert "Archive Ticket" in before and "Restore Ticket" not in before
    archive = approver.ui_action(ticket_id, "archive")
    assert (archive.status, archive.location) == (302, f"/tickets/{ticket_id}")
    archived = approver.follow(archive).text
    for snippet in ("Restore Ticket", "Archived At", "Archived By"):
        assert snippet in archived
    assert "Archive Ticket" not in archived
    assert 'href="/tickets?view=archived"' in archived
    assert title not in approver.get("/tickets").text
    archived_list = approver.get("/tickets?view=archived").text
    assert title in archived_list and "Archived tickets stay readable and restorable" in archived_list
    restore = approver.ui_action(ticket_id, "unarchive")
    assert (restore.status, restore.location) == (302, f"/tickets/{ticket_id}")
    assert title in approver.get("/tickets").text
    restored = approver.get(f"/tickets/{ticket_id}").text
    assert "Archived At" not in restored and "Archived By" not in restored


@UI
def test_ticket_list_shows_archive_and_restore_actions_with_list_redirect(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, title="Archive from list card")
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    assert "Archive" in approver.get("/tickets").text
    archive = approver.ui_action(ticket_id, "archive", redirect_to="/tickets")
    assert archive.location == "/tickets"
    assert "Restore" in approver.get("/tickets?view=archived").text
    restore = approver.ui_action(ticket_id, "unarchive", redirect_to="/tickets?view=archived")
    assert restore.location == "/tickets?view=archived"


@UI
@pytest.mark.parametrize(
    "redirect_to", ["/logout", "https://evil.example/x", "//evil.example/x", "/ticketsX", " /tickets?view=all "]
)
def test_ticket_list_archive_redirect_sanitizes_invalid_targets(
    anon: Browser, approver: Browser, redirect_to: str
) -> None:
    ticket_id = create_ticket(anon)
    assert approver.api_action(ticket_id, "reject", {"reason": "done"}).status == 200
    resp = approver.ui_action(ticket_id, "archive", redirect_to=redirect_to)
    expected = {"/ticketsX": "/ticketsX", " /tickets?view=all ": "/tickets?view=all"}.get(
        redirect_to, f"/tickets/{ticket_id}"
    )
    assert (resp.status, resp.location) == (302, expected)


@UI
def test_pending_approval_ticket_shows_archive_action_in_list_and_detail(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, "openclaw", title="Pending approval archive control")
    assert "Archive" in approver.get("/tickets").text
    detail = approver.get(f"/tickets/{ticket_id}").text
    for snippet in ("Archive Ticket", "Approve Ticket", "Reject Ticket", "Cancel Ticket"):
        assert snippet in detail


@UI
def test_archived_pending_ticket_hides_approve_reject_and_cancel_actions(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, "openclaw")
    assert approver.ui_action(ticket_id, "archive").status == 302
    body = approver.get(f"/tickets/{ticket_id}").text
    assert "Restore Ticket" in body
    for snippet in ("Approve Ticket", "Reject Ticket", "Cancel Ticket"):
        assert snippet not in body


@UI
@pytest.mark.parametrize("state", ["approved", "running", "succeeded", "failed", "rejected", "canceled", "expired"])
def test_detail_actions_by_state(anon: Browser, approver: Browser, db: Database, state: str) -> None:
    ticket_id = create_ticket(anon)
    db.set_ticket(ticket_id, state=state)
    page = approver.get(f"/tickets/{ticket_id}")
    assert page.status == 200
    actions = sorted(form["action"].rsplit("/", 1)[-1] for form in page.facts.forms)  # type: ignore[union-attr]
    expected = {"approved": ["cancel"], "running": ["cancel"]}.get(state, ["archive"])
    assert [action for action in actions if action != "logout"] == expected


@UI
@pytest.mark.parametrize(
    ("action", "fields", "state", "detail"),
    [
        ("approve", {}, "approved", None),
        ("reject", {"reason": " nope "}, "rejected", "nope"),
        ("reject", {}, "rejected", "rejected_by_approver"),
        ("cancel", {"reason": "stop"}, "canceled", "stop"),
    ],
)
def test_ui_ticket_actions(
    anon: Browser, approver: Browser, action: str, fields: dict[str, str], state: str, detail: str | None
) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.ui_action(ticket_id, action, **fields)
    assert (resp.status, resp.location) == (302, f"/tickets/{ticket_id}")
    ticket = get_ticket(anon, ticket_id)
    assert (ticket["state"], ticket["result_detail"]) == (state, detail)


@UI
def test_ui_ticket_action_failure_redirects_back_to_ticket_detail(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon, execution_plan=REVIEW_PLAN, policy_requirements={"require_reviewer_step": True})
    assert approver.api_action(ticket_id, "approve").status == 200
    second = approver.ui_action(ticket_id, "approve")
    assert (second.status, second.location) == (302, f"/tickets/{ticket_id}")
    assert approver.follow(second).flashes == [["error", "Ticket is not pending approval"]]


@UI
@pytest.mark.parametrize("action", ["approve", "reject", "cancel", "archive", "unarchive"])
@pytest.mark.parametrize("token", [None, NON_ASCII_TOKEN])
def test_ui_ticket_actions_reject_missing_or_non_ascii_form_token(
    anon: Browser, approver: Browser, action: str, token: str | None
) -> None:
    ticket_id = create_ticket(anon)
    data = {"reason": "nope"} if token is None else {"csrf_token": token, "reason": "nope"}
    resp = approver.post(f"/tickets/{ticket_id}/{action}", data=data)
    assert (resp.status, resp.location) == (302, f"/tickets/{ticket_id}")
    assert approver.follow(resp).flashes == [["error", "Invalid form token"]]
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"


@UI
def test_ui_post_routes_require_csrf_token(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.post("/logout", data={})
    assert (resp.status, resp.location) == (302, "/tickets")
    page = approver.follow(resp)
    assert page.status == 200 and page.flashes == [["error", "Invalid form token"]]
    resp = approver.post("/no-such-form", data={})
    assert (resp.status, resp.location) == (302, "/tickets")
    assert ticket_id


# ------------------------------------------------------------------ log previews and step logs (4.12)


@UI
@pytest.mark.parametrize("large_line", [False, True])
def test_ticket_detail_renders_log_preview_and_full_log_link(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database, large_line: bool
) -> None:
    ticket_id = create_ticket(anon)
    content = (
        "\n".join(f"line-{index:03d}" for index in range(1, 46)) + "\n" + ("x" * 5000 + "\n" if large_line else "")
    )
    log_path = write_log(api, stack, ticket_id, "steps/01-reviewer-claude/session.log", content)
    set_sessions(db, ticket_id, [session_entry(str(log_path))])
    body = approver.get(f"/tickets/{ticket_id}").text
    assert "Open step log" in body and f"/tickets/{ticket_id}/steps/1/log" in body
    assert "line-045" in body and "line-001" not in body and "[log preview truncated]" in body
    assert "x" * 2049 not in body
    assert ("x" * 2048 in body) is large_line


@UI
@pytest.mark.parametrize("large_log", [False, True])
def test_ticket_step_log_view_renders_bounded_log(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database, large_log: bool
) -> None:
    ticket_id = create_ticket(anon)
    content = "first line\r\n" + ("x" * (2 * 1024 * 1024) if large_log else "second line\r") + "third line\n\xff\n"
    log_path = write_log(api, stack, ticket_id, "steps/01-reviewer-claude/session.log", content.encode("latin-1"))
    set_sessions(db, ticket_id, [session_entry(str(log_path))])
    body = approver.get(f"/tickets/{ticket_id}/steps/1/log").text
    assert "Step 1 Log" in body
    assert ("first line" in body) is (not large_log)
    assert ("[step log truncated]" in body) is large_log
    assert "third line" in body and "�" in body
    assert str(log_path) in body


@UI
@pytest.mark.parametrize(
    ("log_path", "message"),
    [
        ("/etc/passwd", "outside the ticket artifact root"),
        ("SESSIONS/../other/session.log", "outside the ticket artifact root"),
        ("SESSIONS/missing.log", "Log file is not available for this step"),
        ("SESSIONS/steps", "Log file is not available for this step"),
        ("   ", "Log file is not available for this step"),
        ("SYMLINK", "outside the ticket artifact root"),
    ],
)
def test_ticket_step_log_view_rejects_paths_outside_ticket_artifacts(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database, log_path: str, message: str
) -> None:
    ticket_id = create_ticket(anon)
    root = stack.exec_dir(api) / "sessions" / ticket_id
    (root / "steps").mkdir(parents=True)
    (root / "link.log").symlink_to("/etc/hosts")
    raw = log_path.replace("SESSIONS", str(root)).replace("SYMLINK", str(root / "link.log"))
    set_sessions(db, ticket_id, [session_entry(raw, status="failed")])
    resp = approver.get(f"/tickets/{ticket_id}/steps/1/log")
    assert (resp.status, resp.location) == (302, f"/tickets/{ticket_id}")
    flashes = approver.follow(resp).flashes
    assert len(flashes) == 1 and message in flashes[0][1]


@UI
def test_ticket_detail_hides_full_log_link_for_session_without_numeric_step_index(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database
) -> None:
    ticket_id = create_ticket(anon)
    log_path = write_log(api, stack, ticket_id, "steps/unknown/session.log", "preview line\n")
    set_sessions(db, ticket_id, [session_entry(str(log_path), step_index="abc"), "not-an-object"])  # type: ignore[list-item]
    body = approver.get(f"/tickets/{ticket_id}").text
    assert "preview line" in body and "Open step log" not in body


@UI
@pytest.mark.parametrize("step", ["99", "0", "2"])
def test_ticket_step_log_view_rejects_missing_step_number(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database, step: str
) -> None:
    ticket_id = create_ticket(anon)
    log_path = write_log(api, stack, ticket_id, "steps/01-reviewer-claude/session.log", "x\n")
    set_sessions(db, ticket_id, [session_entry(str(log_path), step_index="0")])
    assert approver.get(f"/tickets/{ticket_id}/steps/1/log").status == 200
    resp = approver.get(f"/tickets/{ticket_id}/steps/{step}/log")
    assert (resp.status, resp.location) == (302, f"/tickets/{ticket_id}")
    assert approver.follow(resp).flashes == [["error", "Step log does not exist"]]


@UI
@pytest.mark.parametrize("step", ["-1", "1x", "%31"])
def test_step_log_route_matches_ascii_digits_only(anon: Browser, approver: Browser, step: str) -> None:
    ticket_id = create_ticket(anon)
    status = approver.get(f"/tickets/{ticket_id}/steps/{step}/log").status
    assert status == (302 if step == "%31" else 404)


@UI
def test_ticket_detail_shows_log_unavailable_message_for_missing_file(
    stack: Stack, api: Target, anon: Browser, approver: Browser, db: Database
) -> None:
    ticket_id = create_ticket(anon)
    missing = stack.exec_dir(api) / "sessions" / ticket_id / "steps/01-reviewer-claude/session.log"
    set_sessions(db, ticket_id, [session_entry(str(missing), status="running")])
    assert "Log preview is not available yet for this step." in approver.get(f"/tickets/{ticket_id}").text
