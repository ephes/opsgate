//! The approver's pages and form actions (`web::ui`, PLAN.md 4.3, 4.11,
//! 4.12; slice S5): the ticket list with its views, the detail page with
//! its actions and log previews, the step log page, and approve, reject,
//! cancel, archive and unarchive. Sessions come from the S4a test helper
//! (`TestApp::sign_in`), forms carry the session's CSRF token; pages are
//! read with an HTML tokenizer (`common::html`).

mod common;

use axum::http::{Method, StatusCode};
use common::{APPROVER, Call, NYXMON_TOKEN, OPENCLAW_TOKEN, TestApp, html};
use opsgate_core::time::parse_iso_datetime;
use serde_json::{Value, json};

/// `create_ticket` of `tests/test_api.py` with a task ref.
async fn ticket(app: &TestApp, token: &str, title: &str, task_ref: Option<&str>) -> String {
    let mut payload = common::ticket_payload(title, task_ref);
    payload["summary"] = json!(format!("{title} summary"));
    app.create_ticket(token, payload).await
}

/// Rejects through the store (Python's tests use the cookie API of S4b).
fn reject(app: &TestApp, ticket_id: &str) {
    app.state
        .store()
        .reject_ticket(ticket_id, APPROVER, "done", None, None)
        .unwrap();
}

/// The flash messages the detail page at `location` shows.
async fn flashes_at(app: &TestApp, location: &str) -> Vec<(String, String)> {
    let page = app.get(location).await;
    assert_eq!(page.status, StatusCode::OK, "{location}: {}", page.text());
    page.page().flashes
}

#[tokio::test]
async fn test_ui_ticket_detail_redirects_to_login_with_next() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Needs approval", Some("ui-next-1")).await;
    let response = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert!(
        response
            .location()
            .unwrap()
            .ends_with(&format!("/login?next=/tickets/{id}"))
    );
}

/// `test_login_redirects_to_requested_next_path` end to end: the detail
/// page (S5) sends the browser to the login page (S4b), which sends it back.
#[tokio::test]
async fn detail_page_login_round_trip() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Needs approval", Some("ui-next-2")).await;
    let to_login = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(to_login.status, StatusCode::FOUND);
    let login_path = to_login.location().unwrap().to_owned();
    let signed_in = app.login(&login_path).await;
    assert_eq!(signed_in.location(), Some(format!("/tickets/{id}").as_str()));
    assert_eq!(app.get(&format!("/tickets/{id}")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn test_ticket_list_renders_compact_created_at_timestamp() {
    let app = TestApp::new();
    let id = ticket(
        &app,
        NYXMON_TOKEN,
        "Compact timestamp",
        Some("ui-created-at-1"),
    )
    .await;
    app.sign_in();
    let raw = app.state.store().get_ticket(&id).unwrap()["created_at"]
        .as_str()
        .unwrap()
        .to_owned();
    let expected = parse_iso_datetime(&raw)
        .unwrap()
        .format("%Y-%m-%d %H:%M UTC")
        .to_string();
    let response = app.get("/tickets").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.text();
    assert!(body.contains(&expected));
    assert!(!body.contains(&raw));
}

#[tokio::test]
async fn test_ui_archive_and_restore_controls_manage_ticket_visibility() {
    let app = TestApp::new();
    let title = "Archive through UI";
    let id = ticket(&app, NYXMON_TOKEN, title, Some("archive-ui-1")).await;
    let token = app.sign_in();
    reject(&app, &id);

    let before = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(before.text().contains("Archive Ticket"));
    assert!(!before.text().contains("Restore Ticket"));

    let archive = app
        .post_form(&format!("/tickets/{id}/archive"), &token, &[])
        .await;
    assert_eq!(archive.status, StatusCode::FOUND);
    assert_eq!(archive.location(), Some(format!("/tickets/{id}").as_str()));

    let archived = app.get(&format!("/tickets/{id}")).await;
    let body = archived.text();
    assert_eq!(archived.status, StatusCode::OK);
    assert!(body.contains("Restore Ticket"));
    assert!(!body.contains("Archive Ticket"));
    assert!(body.contains("archived"));
    assert!(body.contains("Archived At"));
    assert!(body.contains("Archived By"));
    assert!(
        archived
            .page()
            .links
            .contains(&"/tickets?view=archived".to_owned())
    );

    let active = app.get("/tickets").await;
    assert_eq!(active.status, StatusCode::OK);
    assert!(!active.text().contains(title));

    let archived_list = app.get("/tickets?view=archived").await;
    assert_eq!(archived_list.status, StatusCode::OK);
    assert!(archived_list.text().contains(title));
    assert!(
        archived_list
            .text()
            .contains("Archived tickets stay readable and restorable")
    );

    let restore = app
        .post_form(&format!("/tickets/{id}/unarchive"), &token, &[])
        .await;
    assert_eq!(restore.status, StatusCode::FOUND);
    assert_eq!(restore.location(), Some(format!("/tickets/{id}").as_str()));

    let restored_list = app.get("/tickets").await;
    assert_eq!(restored_list.status, StatusCode::OK);
    assert!(restored_list.text().contains(title));

    let restored = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(restored.status, StatusCode::OK);
    assert!(!restored.text().contains("Archived At"));
    assert!(!restored.text().contains("Archived By"));
    assert!(
        restored
            .page()
            .links
            .contains(&"/tickets?view=active".to_owned())
    );
}

#[tokio::test]
async fn test_ticket_list_shows_archive_and_restore_actions_with_list_redirect() {
    let app = TestApp::new();
    let title = "Archive from list card";
    let id = ticket(&app, NYXMON_TOKEN, title, Some("archive-ui-list-1")).await;
    let token = app.sign_in();
    reject(&app, &id);

    let active = app.get("/tickets").await;
    assert_eq!(active.status, StatusCode::OK);
    let form = active
        .page()
        .form(&format!("/tickets/{id}/archive"))
        .cloned()
        .unwrap();
    assert_eq!(form.value("redirect_to"), Some("/tickets"));
    assert_eq!(form.value("csrf_token"), Some(token.as_str()));

    let archive = app
        .post_form(
            &format!("/tickets/{id}/archive"),
            &token,
            &[("redirect_to", "/tickets")],
        )
        .await;
    assert_eq!(archive.status, StatusCode::FOUND);
    assert_eq!(archive.location(), Some("/tickets"));

    let archived = app.get("/tickets?view=archived").await;
    assert_eq!(archived.status, StatusCode::OK);
    assert!(archived.text().contains(title));
    assert!(archived.text().contains("Restore"));
    let form = archived
        .page()
        .form(&format!("/tickets/{id}/unarchive"))
        .cloned()
        .unwrap();
    assert_eq!(form.value("redirect_to"), Some("/tickets?view=archived"));

    let restore = app
        .post_form(
            &format!("/tickets/{id}/unarchive"),
            &token,
            &[("redirect_to", "/tickets?view=archived")],
        )
        .await;
    assert_eq!(restore.status, StatusCode::FOUND);
    assert_eq!(restore.location(), Some("/tickets?view=archived"));

    // The `all` view keeps its own redirect target.
    let all = app.get("/tickets?view=all").await;
    let form = all
        .page()
        .form(&format!("/tickets/{id}/archive"))
        .cloned()
        .unwrap();
    assert_eq!(form.value("redirect_to"), Some("/tickets?view=all"));
}

#[tokio::test]
async fn test_pending_approval_ticket_shows_archive_action_in_list_and_detail() {
    let app = TestApp::new();
    let title = "Pending approval archive control";
    let id = ticket(&app, OPENCLAW_TOKEN, title, Some("archive-ui-pending-1")).await;
    app.sign_in();

    let active = app.get("/tickets").await;
    assert_eq!(active.status, StatusCode::OK);
    assert!(active.text().contains(title));
    assert!(active.page().has_form(&format!("/tickets/{id}/archive")));

    let detail = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.text().contains("Archive Ticket"));
}

#[tokio::test]
async fn test_archived_pending_ticket_hides_approve_reject_and_cancel_actions() {
    let app = TestApp::new();
    let id = ticket(
        &app,
        OPENCLAW_TOKEN,
        "Archived pending approval",
        Some("archive-ui-pending-2"),
    )
    .await;
    let token = app.sign_in();
    let archive = app
        .post_form(&format!("/tickets/{id}/archive"), &token, &[])
        .await;
    assert_eq!(archive.status, StatusCode::FOUND);

    let detail = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    let body = detail.text();
    assert!(body.contains("Restore Ticket"));
    for absent in ["Approve Ticket", "Reject Ticket", "Cancel Ticket"] {
        assert!(!body.contains(absent), "{absent}");
    }
}

#[tokio::test]
async fn test_ticket_list_archive_redirect_sanitizes_invalid_targets() {
    for redirect_to in [
        "/logout",
        "https://evil.example/x",
        "//evil.example/x",
        // Rust-only: values Python's `urlsplit` raises for (D-18) fall back
        // to the detail page.
        "http://[x",
        "/tickets\n/x",
        "tickets",
    ] {
        let app = TestApp::new();
        let id = ticket(
            &app,
            NYXMON_TOKEN,
            "Archive redirect validation",
            Some(&format!("archive-redirect-{redirect_to}")),
        )
        .await;
        let token = app.sign_in();
        reject(&app, &id);
        let response = app
            .post_form(
                &format!("/tickets/{id}/archive"),
                &token,
                &[("redirect_to", redirect_to)],
            )
            .await;
        assert_eq!(response.status, StatusCode::FOUND, "{redirect_to}");
        assert_eq!(
            response.location(),
            Some(format!("/tickets/{id}").as_str()),
            "{redirect_to}"
        );
    }
}

/// A `redirect_to` that passes is sent as Werkzeug sends a `Location`
/// (`iri_to_uri`): non-ASCII and unsafe characters quoted.
#[tokio::test]
async fn archive_redirect_target_is_sent_as_uri() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Redirect quoting", None).await;
    let token = app.sign_in();
    reject(&app, &id);
    let response = app
        .post_form(
            &format!("/tickets/{id}/archive"),
            &token,
            &[("redirect_to", " /tickets?view=all x&q=é#top ")],
        )
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response.location(),
        Some("/tickets?view=all%20x&q=%C3%A9#top")
    );
    response.assert_security_headers();
}

/// The sessions of `test_ticket_detail_renders_log_preview_and_full_log_link`.
fn reviewer_session(name: &str, status: &str, log_path: &str) -> Value {
    json!([{
        "step_index": 0,
        "role": "reviewer",
        "agent": "claude",
        "status": status,
        "session_name": name,
        "attach_command": format!("tmux attach -t {name}"),
        "log_path": log_path,
    }])
}

#[tokio::test]
async fn test_ticket_detail_renders_log_preview_and_full_log_link() {
    for large_line in [false, true] {
        let app = TestApp::new();
        let id = ticket(&app, NYXMON_TOKEN, "Preview logs", None).await;
        let mut content: String = (1..=45).map(|index| format!("line-{index:03}\n")).collect();
        if large_line {
            content.push_str(&"x".repeat(5000));
            content.push('\n');
        }
        let log = app.write_ticket_log(
            &id,
            "steps/01-reviewer-claude/session.log",
            content.as_bytes(),
        );
        app.set_tmux_sessions(
            &id,
            &reviewer_session("job-preview-01", "succeeded", log.to_str().unwrap()),
        );
        app.sign_in();
        let response = app.get(&format!("/tickets/{id}")).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = response.text();
        assert!(body.contains("Open step log"));
        assert!(
            response
                .page()
                .links
                .contains(&format!("/tickets/{id}/steps/1/log"))
        );
        assert!(body.contains("line-045"));
        assert!(!body.contains("line-001"));
        assert!(body.contains("[log preview truncated]"));
        assert!(!body.contains(&"x".repeat(2049)));
        if large_line {
            assert!(body.contains(&"x".repeat(2048)));
        }
        for shown in [
            "job-preview-01",
            "tmux attach -t job-preview-01",
            "succeeded",
        ] {
            assert!(body.contains(shown), "{shown}");
        }
    }
}

#[tokio::test]
async fn test_ticket_step_log_view_renders_bounded_log() {
    for large_log in [false, true] {
        let app = TestApp::new();
        let id = ticket(&app, NYXMON_TOKEN, "Full log", None).await;
        let middle = if large_log {
            "x".repeat(2 * 1024 * 1024)
        } else {
            "second line\n".to_owned()
        };
        let log = app.write_ticket_log(
            &id,
            "steps/01-reviewer-claude/session.log",
            format!("first line\n{middle}third line\n").as_bytes(),
        );
        app.set_tmux_sessions(
            &id,
            &reviewer_session("job-full-01", "succeeded", log.to_str().unwrap()),
        );
        app.sign_in();
        let response = app.get(&format!("/tickets/{id}/steps/1/log")).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = response.text();
        assert!(body.contains("Step 1 Log"));
        assert_eq!(body.contains("first line"), !large_log);
        assert_eq!(body.contains("[step log truncated]"), large_log);
        assert!(body.contains("third line"));
        assert!(body.contains(log.to_str().unwrap()));
        let page = response.page();
        assert!(page.links.contains(&format!("/tickets/{id}")));
        assert!(page.text.contains("job-full-01"));
        response.assert_security_headers();
    }
}

#[tokio::test]
async fn test_ticket_step_log_view_rejects_paths_outside_ticket_artifacts() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Bad log path", None).await;
    app.set_tmux_sessions(
        &id,
        &reviewer_session("job-bad-path-01", "failed", "/etc/passwd"),
    );
    app.sign_in();
    let response = app.get(&format!("/tickets/{id}/steps/1/log")).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some(format!("/tickets/{id}").as_str()));
    let flashes = flashes_at(&app, &format!("/tickets/{id}")).await;
    assert!(
        flashes.iter().any(|(category, message)| category == "error"
            && message.contains("outside the ticket artifact root")),
        "{flashes:?}"
    );
}

#[tokio::test]
async fn test_ticket_detail_hides_full_log_link_for_session_without_numeric_step_index() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Malformed step index", None).await;
    let log = app.write_ticket_log(&id, "steps/unknown/session.log", b"preview line\n");
    let mut sessions = reviewer_session("job-malformed-01", "failed", log.to_str().unwrap());
    sessions[0]["step_index"] = json!("abc");
    app.set_tmux_sessions(&id, &sessions);
    app.sign_in();
    let response = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.text();
    assert!(body.contains("preview line"));
    assert!(!body.contains("Open step log"));
}

#[tokio::test]
async fn test_ticket_step_log_view_rejects_missing_step_number() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Missing step", None).await;
    app.sign_in();
    for step in ["99", "0"] {
        let response = app.get(&format!("/tickets/{id}/steps/{step}/log")).await;
        assert_eq!(response.status, StatusCode::FOUND);
        assert_eq!(response.location(), Some(format!("/tickets/{id}").as_str()));
        let flashes = flashes_at(&app, &format!("/tickets/{id}")).await;
        assert_eq!(
            flashes,
            vec![("error".to_owned(), "Step log does not exist".to_owned())]
        );
    }
}

#[tokio::test]
async fn test_ticket_detail_shows_log_unavailable_message_for_missing_file() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Missing log file", None).await;
    let missing = app
        .execution_data_dir()
        .join("sessions")
        .join(&id)
        .join("steps/01-reviewer-claude/session.log");
    app.set_tmux_sessions(
        &id,
        &reviewer_session("job-missing-log-01", "running", missing.to_str().unwrap()),
    );
    app.sign_in();
    let response = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response
            .text()
            .contains("Log preview is not available yet for this step.")
    );
    // The step log page of a missing file: 404 `log_not_found`, flashed.
    let log = app.get(&format!("/tickets/{id}/steps/1/log")).await;
    assert_eq!(log.status, StatusCode::FOUND);
    let flashes = flashes_at(&app, &format!("/tickets/{id}")).await;
    assert_eq!(
        flashes,
        vec![(
            "error".to_owned(),
            "Log file is not available for this step".to_owned()
        )]
    );
}

#[tokio::test]
async fn test_ui_ticket_action_failure_redirects_back_to_ticket_detail() {
    let app = TestApp::new();
    let id = app
        .create_ticket(
            NYXMON_TOKEN,
            json!({
                "title": "Already approved",
                "summary": "Second approval should preserve detail context",
                "task_ref": "ui-action-failure-1",
                "execution_plan": [{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
                "policy_requirements": {"require_reviewer_step": true},
            }),
        )
        .await;
    let token = app.sign_in();
    let first = app
        .post_form(&format!("/tickets/{id}/approve"), &token, &[])
        .await;
    assert_eq!(first.status, StatusCode::FOUND);
    assert_eq!(first.location(), Some(format!("/tickets/{id}").as_str()));
    let second = app
        .post_form(&format!("/tickets/{id}/approve"), &token, &[])
        .await;
    assert_eq!(second.status, StatusCode::FOUND);
    assert_eq!(second.location(), Some(format!("/tickets/{id}").as_str()));
    let flashes = flashes_at(&app, &format!("/tickets/{id}")).await;
    assert_eq!(
        flashes,
        vec![(
            "error".to_owned(),
            "Ticket is not pending approval".to_owned()
        )]
    );
}

/// Without an approver session every page and action redirects to the
/// login page, the detail and step log pages with `next`; nothing changes.
#[tokio::test]
async fn pages_and_actions_need_an_approver_session() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Anonymous", None).await;
    for (path, location) in [
        ("/", "/login".to_owned()),
        ("/tickets", "/login".to_owned()),
        ("/tickets?view=all", "/login".to_owned()),
        (
            &format!("/tickets/{id}"),
            format!("/login?next=/tickets/{id}"),
        ),
        (
            &format!("/tickets/{id}/steps/1/log"),
            format!("/login?next=/tickets/{id}/steps/1/log"),
        ),
        ("/tickets/a%20b?x=1", "/login?next=/tickets/a+b".to_owned()),
    ] {
        let response = app.get(path).await;
        assert_eq!(response.status, StatusCode::FOUND, "{path}");
        assert_eq!(response.location(), Some(location.as_str()), "{path}");
        response.assert_security_headers();
    }
    // An anonymous session with a CSRF token (from the login page).
    assert_eq!(app.get("/login").await.status, StatusCode::OK);
    let token = app.session().csrf_token.unwrap();
    let before = app.snapshot();
    for action in ["approve", "reject", "cancel", "archive", "unarchive"] {
        let response = app
            .post_form(
                &format!("/tickets/{id}/{action}"),
                &token,
                &[("reason", "x")],
            )
            .await;
        assert_eq!(response.status, StatusCode::FOUND, "{action}");
        assert_eq!(response.location(), Some("/login"), "{action}");
    }
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "x"),
                ("summary", "y"),
                ("steps-0-role", "investigator"),
            ],
        )
        .await;
    assert_eq!(response.location(), Some("/login"));
    assert_eq!(app.snapshot(), before);

    app.sign_in();
    let root = app.get("/").await;
    assert_eq!(root.status, StatusCode::FOUND);
    assert_eq!(root.location(), Some("/tickets"));
}

const STATES: [&str; 8] = [
    "pending_approval",
    "approved",
    "running",
    "succeeded",
    "failed",
    "rejected",
    "canceled",
    "expired",
];

/// The actions of the detail page and the list by state and archive flag
/// (PLAN.md 4.11): every form posts the session's CSRF token.
#[tokio::test]
async fn actions_by_state_and_archive_flag() {
    let app = TestApp::new();
    let token = app.sign_in();
    for state in STATES {
        for archived in [false, true] {
            let id = ticket(&app, NYXMON_TOKEN, &format!("{state} {archived}"), None).await;
            app.set_state(&id, state, archived);
            let open = ["pending_approval", "approved", "running"].contains(&state);
            let archivable = !open || state == "pending_approval";
            let response = app.get(&format!("/tickets/{id}")).await;
            assert_eq!(response.status, StatusCode::OK);
            response.assert_security_headers();
            let page = response.page();
            let expected = [
                (
                    "approve",
                    !archived && state == "pending_approval",
                    vec!["csrf_token"],
                ),
                (
                    "reject",
                    !archived && state == "pending_approval",
                    vec!["csrf_token", "reason"],
                ),
                ("cancel", !archived && open, vec!["csrf_token", "reason"]),
                ("archive", !archived && archivable, vec!["csrf_token"]),
                ("unarchive", archived, vec!["csrf_token"]),
            ];
            for (action, offered, fields) in &expected {
                let path = format!("/tickets/{id}/{action}");
                assert_eq!(
                    page.has_form(&path),
                    *offered,
                    "{state} {archived} {action}"
                );
                if let Some(form) = page.form(&path) {
                    assert_eq!(form.method, "post");
                    assert_eq!(form.names(), *fields, "{action}");
                    assert_eq!(form.value("csrf_token"), Some(token.as_str()));
                }
            }
            let back = if archived {
                "/tickets?view=archived"
            } else {
                "/tickets?view=active"
            };
            assert!(page.links.contains(&back.to_owned()), "{state} {archived}");
            assert!(page.text.contains(state));

            let view = if archived { "archived" } else { "active" };
            let list = app.get(&format!("/tickets?view={view}")).await.page();
            assert!(list.links.contains(&format!("/tickets/{id}")));
            assert_eq!(
                list.has_form(&format!("/tickets/{id}/archive")),
                !archived && archivable,
                "{state} {archived}"
            );
            assert_eq!(list.has_form(&format!("/tickets/{id}/unarchive")), archived);
        }
    }
}

/// The list's views: `active` (default, also for unknown values), `archived`
/// and `all`, each with its filter links and the logout form.
#[tokio::test]
async fn list_views_filter_archived_tickets() {
    let app = TestApp::new();
    let token = app.sign_in();
    let active = ticket(&app, NYXMON_TOKEN, "Active one", None).await;
    let archived = ticket(&app, NYXMON_TOKEN, "Archived one", None).await;
    app.set_state(&archived, "pending_approval", true);
    for (query, shows_active, shows_archived) in [
        ("", true, false),
        ("?view=active", true, false),
        ("?view=bogus", true, false),
        ("?view=archived", false, true),
        ("?view=%20ARCHIVED%20", false, true),
        ("?view=all", true, true),
    ] {
        let response = app.get(&format!("/tickets{query}")).await;
        assert_eq!(response.status, StatusCode::OK, "{query}");
        let page = response.page();
        assert_eq!(
            page.links.contains(&format!("/tickets/{active}")),
            shows_active,
            "{query}"
        );
        assert_eq!(
            page.links.contains(&format!("/tickets/{archived}")),
            shows_archived,
            "{query}"
        );
        for link in ["/tickets", "/tickets?view=archived", "/tickets?view=all"] {
            assert!(page.links.contains(&link.to_owned()), "{query} {link}");
        }
        let logout = page.form("/logout").unwrap();
        assert_eq!(logout.value("csrf_token"), Some(token.as_str()));
    }
    let empty = TestApp::new();
    empty.sign_in();
    assert!(
        empty
            .get("/tickets?view=archived")
            .await
            .text()
            .contains("No archived tickets yet.")
    );
    assert!(
        empty
            .get("/tickets")
            .await
            .text()
            .contains("No tickets yet.")
    );
}

/// The list shows the 100 newest tickets by `created_at`.
#[tokio::test]
async fn list_shows_the_hundred_newest_tickets() {
    let app = TestApp::new();
    app.sign_in();
    let mut ids = Vec::new();
    for index in 0..101 {
        ids.push(ticket(&app, NYXMON_TOKEN, &format!("Ticket {index}"), None).await);
    }
    for (index, id) in ids.iter().enumerate() {
        app.connection()
            .execute(
                "UPDATE tickets SET created_at = ?1 WHERE id = ?2",
                rusqlite::params![
                    format!("2026-10-21T10:{:02}:{:02}.000001Z", index / 60, index % 60),
                    id
                ],
            )
            .unwrap();
    }
    let page = app.get("/tickets").await.page();
    assert!(!page.links.contains(&format!("/tickets/{}", ids[0])));
    for id in &ids[1..] {
        assert!(page.links.contains(&format!("/tickets/{id}")));
    }
}

/// Reject and cancel take the stripped form `reason` (empty: the default
/// reason); every action is audited as the approver with the request's
/// address and user agent.
#[tokio::test]
async fn actions_record_reason_and_audit() {
    let app = TestApp::new();
    let token = app.sign_in();
    let rejected = ticket(&app, NYXMON_TOKEN, "Reject me", None).await;
    let canceled = ticket(&app, NYXMON_TOKEN, "Cancel me", None).await;
    let response = app
        .send(
            Call::post(&format!("/tickets/{rejected}/reject"))
                .header("user-agent", "browser/1")
                .form(&[("csrf_token", &token), ("reason", "  not now \u{a0}")]),
        )
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response.location(),
        Some(format!("/tickets/{rejected}").as_str())
    );
    let response = app
        .post_form(
            &format!("/tickets/{canceled}/cancel"),
            &token,
            &[("reason", "  ")],
        )
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    let store = app.state.store();
    assert_eq!(store.get_ticket(&rejected).unwrap()["state"], "rejected");
    assert_eq!(
        store.get_ticket(&rejected).unwrap()["result_detail"],
        "not now"
    );
    assert_eq!(store.get_ticket(&canceled).unwrap()["state"], "canceled");
    assert_eq!(
        store.get_ticket(&canceled).unwrap()["result_detail"],
        "canceled_by_approver"
    );
    let (actor, source_ip, user_agent): (String, String, Option<String>) = app
        .connection()
        .query_row(
            "SELECT actor, source_ip, user_agent FROM audit_events \
             WHERE ticket_id = ?1 AND event_type = 'ticket_rejected'",
            [&rejected],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(actor, format!("approver:{APPROVER}"));
    assert_eq!(source_ip, "127.0.0.1");
    assert_eq!(user_agent.as_deref(), Some("browser/1"));
}

/// An action or page for an unknown ticket: the error is flashed and the
/// browser sent to the (missing) detail page, which sends it on to the list.
#[tokio::test]
async fn unknown_tickets_are_flashed() {
    let app = TestApp::new();
    let token = app.sign_in();
    for action in ["approve", "reject", "cancel", "archive", "unarchive"] {
        let response = app
            .post_form(&format!("/tickets/missing/{action}"), &token, &[])
            .await;
        assert_eq!(response.status, StatusCode::FOUND, "{action}");
        assert_eq!(response.location(), Some("/tickets/missing"), "{action}");
        let detail = app.get("/tickets/missing").await;
        assert_eq!(detail.status, StatusCode::FOUND);
        assert_eq!(detail.location(), Some("/tickets"));
        let flashes = app.get("/tickets").await.page().flashes;
        assert_eq!(
            flashes,
            vec![
                ("error".to_owned(), "Ticket not found".to_owned()),
                ("error".to_owned(), "Ticket not found".to_owned()),
            ],
            "{action}"
        );
    }
    let log = app.get("/tickets/missing/steps/1/log").await;
    assert_eq!(log.location(), Some("/tickets/missing"));
}

/// The step log route matches Werkzeug's `<int:step_number>`: any Unicode
/// decimal digits converted with `int()`; anything else is no route (404 for
/// every method, `OPTIONS` included).
#[tokio::test]
async fn step_log_route_takes_integers_only() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Step numbers", None).await;
    let log = app.write_ticket_log(&id, "steps/02/session.log", b"second step\n");
    let mut sessions = reviewer_session("job-02", "succeeded", log.to_str().unwrap());
    sessions[0]["step_index"] = json!(1);
    app.set_tmux_sessions(&id, &sessions);
    app.sign_in();
    for step in ["2", "02", "%D9%A2"] {
        let response = app.get(&format!("/tickets/{id}/steps/{step}/log")).await;
        assert_eq!(response.status, StatusCode::OK, "{step}");
        assert!(response.text().contains("second step"), "{step}");
        assert!(response.page().title.ends_with("Step 2"), "{step}");
    }
    for step in ["a", "-1", "1.0", "%201", &"1".repeat(4301)] {
        let path = format!("/tickets/{id}/steps/{step}/log");
        assert_eq!(app.get(&path).await.status, StatusCode::NOT_FOUND, "{step}");
        for method in [Method::OPTIONS, Method::PUT] {
            let response = app.send(Call::new(method.clone(), &path)).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{method} {step}");
        }
    }
    let huge = format!("/tickets/{id}/steps/{}/log", "1".repeat(4300));
    let response = app.get(&huge).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some(format!("/tickets/{id}").as_str()));
    let options = app
        .send(Call::new(
            Method::OPTIONS,
            &format!("/tickets/{id}/steps/1/log"),
        ))
        .await;
    assert_eq!(options.status, StatusCode::OK);
    let wrong = app
        .send(Call::new(
            Method::PUT,
            &format!("/tickets/{id}/steps/1/log"),
        ))
        .await;
    assert_eq!(wrong.status, StatusCode::METHOD_NOT_ALLOWED);
}

/// Session entries of every shape: the step number is `int(step_index) + 1`
/// when not negative (strings, floats and booleans converted as Python
/// does), non-object entries are skipped, the first matching entry is the
/// step's, and an infinite float is Python's unhandled error (500).
#[tokio::test]
async fn session_entries_of_every_shape() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Shapes", None).await;
    let log = app.write_ticket_log(&id, "steps/s.log", b"shared log\n");
    let path = log.to_str().unwrap();
    app.set_tmux_sessions(
        &id,
        &json!([
            "junk",
            {"step_index": " 2 ", "session_name": "text-index", "log_path": path},
            {"step_index": 1.9, "session_name": "float-index", "log_path": path},
            {"step_index": true, "session_name": "bool-index", "log_path": path},
            {"step_index": -1, "session_name": "negative", "log_path": path},
            {"session_name": "no-index", "log_path": 7},
        ]),
    );
    app.sign_in();
    let detail = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    let links = detail.page().links;
    assert!(links.contains(&format!("/tickets/{id}/steps/3/log")));
    assert!(links.contains(&format!("/tickets/{id}/steps/2/log")));
    assert_eq!(
        links.iter().filter(|link| link.contains("/steps/")).count(),
        3
    );
    let step2 = app.get(&format!("/tickets/{id}/steps/2/log")).await;
    assert_eq!(step2.status, StatusCode::OK);
    assert!(step2.text().contains("float-index"));
    assert!(!step2.text().contains("bool-index"));

    app.connection()
        .execute(
            "UPDATE tickets SET tmux_sessions_json = ?1 WHERE id = ?2",
            rusqlite::params![r#"[{"step_index": 1e400, "log_path": ""}]"#, id],
        )
        .unwrap();
    assert_eq!(
        app.get(&format!("/tickets/{id}")).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        app.get(&format!("/tickets/{id}/steps/1/log")).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// Log paths: a symbolic link out of the ticket's artifact root is outside
/// it (the preview is not shown); a path with a NUL character cannot be
/// resolved (Python's unhandled `ValueError`: 500).
#[tokio::test]
async fn log_paths_are_contained() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Containment", None).await;
    let outside = app.dir.path().join("secret.log");
    std::fs::write(&outside, "secret content\n").unwrap();
    let root = app.execution_data_dir().join("sessions").join(&id);
    std::fs::create_dir_all(&root).unwrap();
    let link = root.join("link.log");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    app.set_tmux_sessions(
        &id,
        &reviewer_session("job-link", "failed", link.to_str().unwrap()),
    );
    app.sign_in();
    let detail = app.get(&format!("/tickets/{id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(!detail.text().contains("secret content"));
    assert!(detail.text().contains("Log preview is not available yet"));
    let log = app.get(&format!("/tickets/{id}/steps/1/log")).await;
    assert_eq!(log.status, StatusCode::FOUND);
    let flashes = flashes_at(&app, &format!("/tickets/{id}")).await;
    assert_eq!(
        flashes[0].1,
        "Log file path is outside the ticket artifact root"
    );

    app.set_tmux_sessions(&id, &reviewer_session("job-nul", "failed", "/tmp/a\u{0}b"));
    assert_eq!(
        app.get(&format!("/tickets/{id}")).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        app.get(&format!("/tickets/{id}/steps/1/log")).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// `HEAD` of the pages answers like `GET` without a body; `OPTIONS` of
/// every route is 200.
#[tokio::test]
async fn head_and_options() {
    let app = TestApp::new();
    let id = ticket(&app, NYXMON_TOKEN, "Head", None).await;
    app.sign_in();
    for path in ["/tickets".to_owned(), format!("/tickets/{id}")] {
        let head = app.send(Call::new(Method::HEAD, &path)).await;
        assert_eq!(head.status, StatusCode::OK, "{path}");
        assert!(head.body.is_empty());
    }
    for path in [
        "/".to_owned(),
        "/tickets".to_owned(),
        format!("/tickets/{id}"),
        format!("/tickets/{id}/approve"),
        format!("/tickets/{id}/reject"),
        format!("/tickets/{id}/cancel"),
        format!("/tickets/{id}/archive"),
        format!("/tickets/{id}/unarchive"),
    ] {
        let response = app.send(Call::new(Method::OPTIONS, &path)).await;
        assert_eq!(response.status, StatusCode::OK, "{path}");
    }
    let wrong = app.get(&format!("/tickets/{id}/approve")).await;
    assert_eq!(wrong.status, StatusCode::METHOD_NOT_ALLOWED);
    let page = html::parse(&app.get("/tickets").await.text());
    assert_eq!(page.title.trim(), "OpsGate Tickets");
}
