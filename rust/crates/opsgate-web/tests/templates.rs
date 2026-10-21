//! Every template renders through the S4a environment (PLAN.md 6.3) with
//! the context `app.py` gives it, for each ticket state with and without
//! the archived flag. The pages and their P1 checks are slice S5's; this
//! test keeps the shared environment (globals, filters, value printing)
//! able to render them.

mod common;

use std::collections::BTreeMap;

use common::{NYXMON_TOKEN, TestApp};
use minijinja::value::Value as JinjaValue;
use opsgate_web::session::SessionHandle;
use opsgate_web::templates::{Context, to_template_value};
use serde_json::{Value, json};

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

fn scaffolding() -> Value {
    let role = json!({
        "title": "Role", "summary": "Summary", "dos": ["Do"], "donts": ["Don't"],
        "placeholder": "Placeholder", "suggested_prompt": "Prompt",
    });
    json!({"investigator": role, "implementer": role, "implementor": role, "reviewer": role})
}

async fn ticket(app: &TestApp, state: &str, archived: bool) -> Value {
    let id = app
        .create_ticket(
            NYXMON_TOKEN,
            json!({
                "title": format!("<{state}>"),
                "summary": "Summary",
                "task_ref": format!("render-{state}-{archived}"),
                "execution_plan": [
                    {"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"},
                    {"role": "reviewer", "agent": "claude", "prompt_markdown": "Review"},
                ],
                "context": {"ratio": 0.1, "big": 1e16, "nested": {"b": [1, null, true], "a": "<&>"}},
            }),
        )
        .await;
    app.connection()
        .execute(
            "UPDATE tickets SET state = ?1, archived_at = ?2, archived_by = ?3, \
             tmux_sessions_json = ?4 WHERE id = ?5",
            rusqlite::params![
                state,
                archived.then_some("2026-10-21T10:00:00Z"),
                archived.then_some("approver:opsgate-admin"),
                json!([{"step_index": 0, "session_name": "s", "log_path": "/nowhere"}, "junk"])
                    .to_string(),
                id,
            ],
        )
        .unwrap();
    serde_json::to_value(app.state.store().get_ticket(&id).unwrap()).unwrap()
}

fn context(entries: Vec<(&str, JinjaValue)>) -> Context {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

#[tokio::test]
async fn every_template_renders_for_every_state() {
    let app = TestApp::new();
    let templates = app.state.templates();
    let session = SessionHandle::default();
    session.flash("Flashed <message>", "error");
    let mut tickets = Vec::new();
    for state in STATES {
        for archived in [false, true] {
            let ticket = ticket(&app, state, archived).await;
            let id = ticket["id"].as_str().unwrap().to_owned();
            tickets.push(ticket.clone());
            let session_view = json!({
                "step_index": 0, "session_name": "s", "log_path": "/nowhere",
                "step_number": 1, "log_preview": "line <1>", "log_available": true,
                "log_url": format!("/tickets/{id}/steps/1/log"),
            });
            let detail = templates
                .render(
                    "ticket_detail.html",
                    &session,
                    context(vec![
                        ("ticket", to_template_value(&ticket)),
                        (
                            "tickets_back_href",
                            JinjaValue::from("/tickets?view=active"),
                        ),
                        ("session_views", to_template_value(&json!([session_view]))),
                    ]),
                )
                .unwrap();
            assert!(detail.contains("&lt;"), "{state}: titles are escaped");
            let approve = format!("action=\"/tickets/{id}/approve\"");
            assert_eq!(
                detail.contains(&approve),
                !archived && state == "pending_approval",
                "{state} {archived}"
            );
            let cancel = format!("action=\"/tickets/{id}/cancel\"");
            assert_eq!(
                detail.contains(&cancel),
                !archived && ["pending_approval", "approved", "running"].contains(&state),
                "{state} {archived}"
            );
            assert_eq!(
                detail.contains(&format!("action=\"/tickets/{id}/unarchive\"")),
                archived,
                "{state} {archived}"
            );

            let log = templates
                .render(
                    "ticket_log.html",
                    &session,
                    context(vec![
                        ("ticket", to_template_value(&ticket)),
                        (
                            "session",
                            to_template_value(&json!({"step_index": 0, "session_name": "s"})),
                        ),
                        ("step_number", JinjaValue::from(1)),
                        ("log_text", JinjaValue::from("[step log truncated]\n<x>")),
                        ("log_path", JinjaValue::from("/tmp/x.log")),
                    ]),
                )
                .unwrap();
            assert!(log.contains("&lt;x&gt;"));
        }
    }
    let scaffolding = scaffolding();
    let for_role = scaffolding.clone();
    for view in ["active", "archived", "all"] {
        for operator_requires_reviewer in [false, true] {
            let for_role = for_role.clone();
            let list = templates
                .render(
                    "tickets.html",
                    &session,
                    context(vec![
                        ("tickets", to_template_value(&Value::Array(tickets.clone()))),
                        ("ticket_view", JinjaValue::from(view)),
                        (
                            "form_data",
                            to_template_value(&json!({
                                "title": "", "summary": "", "task_ref": "",
                                "max_duration_seconds": "3600", "expires_at": "", "context_json": "",
                                "steps": [{"role": "investigator", "agent": "codex", "prompt_markdown": ""},
                                          {"role": "unknown", "agent": "gpt", "prompt_markdown": "x"}],
                            })),
                        ),
                        ("operator_requires_reviewer", JinjaValue::from(operator_requires_reviewer)),
                        ("max_duration_seconds_limit", JinjaValue::from(31_536_000)),
                        (
                            "role_agent_defaults",
                            to_template_value(&json!({"implementer": "codex", "reviewer": "claude"})),
                        ),
                        ("role_prompt_scaffolding", to_template_value(&scaffolding)),
                        ("supported_agents", to_template_value(&json!(["codex", "claude"]))),
                        (
                            "prompt_scaffolding_for_role",
                            JinjaValue::from_function(move |role: String| {
                                let role = role.trim().to_lowercase();
                                to_template_value(
                                    for_role.get(&role).unwrap_or(&for_role["investigator"]),
                                )
                            }),
                        ),
                    ]),
                )
                .unwrap();
            assert!(list.contains("action=\"/logout\""), "{view}");
            assert!(list.contains("href=\"/tickets?view=archived\""), "{view}");
            let ids: BTreeMap<String, ()> = tickets
                .iter()
                .map(|ticket| (ticket["id"].as_str().unwrap().to_owned(), ()))
                .collect();
            for id in ids.keys() {
                assert!(list.contains(&format!("href=\"/tickets/{id}\"")), "{view}");
            }
        }
    }
    let forbidden = templates
        .render("forbidden.html", &session, Context::new())
        .unwrap();
    assert!(forbidden.contains("Forbidden"));
}
