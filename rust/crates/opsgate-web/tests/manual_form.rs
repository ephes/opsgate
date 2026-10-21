//! The manual ticket form (`web::ui::manual_form`, PLAN.md 4.11; slice S5):
//! `GET /tickets` renders it, `POST /tickets` creates an operator ticket
//! created by the approver or renders the list again with status 400, the
//! error flashed and the form as sent.

mod common;

use axum::http::StatusCode;
use common::{APPROVER, Call, TestApp};
use serde_json::{Value, json};

/// The ticket the redirect of a created manual ticket points to.
async fn created(app: &TestApp, response: &common::TestResponse) -> Value {
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    let location = response.location().unwrap();
    assert!(location.starts_with("/tickets/"), "{location}");
    let id = location.rsplit('/').next().unwrap();
    let api = app.get(&format!("/api/v1/tickets/{id}")).await;
    assert_eq!(api.status, StatusCode::OK);
    api.json()
}

#[tokio::test]
async fn test_manual_ticket_creation_from_ui() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Manual remediation"),
                ("summary", "Create through web UI"),
                ("task_ref", "ui-manual-1"),
                ("steps-0-role", "implementer"),
                ("steps-0-agent", "codex"),
                (
                    "steps-0-prompt_markdown",
                    "Inspect the target service and prepare a no-op patch.",
                ),
                ("steps-1-role", "reviewer"),
                ("steps-1-agent", "claude"),
                (
                    "steps-1-prompt_markdown",
                    "Review the proposed change and confirm it stays a no-op.",
                ),
                ("max_duration_seconds", "900"),
                (
                    "context_json",
                    "{\"service\": \"opsgate\", \"host\": \"macstudio\"}",
                ),
            ],
        )
        .await;
    let ticket = created(&app, &response).await;
    assert_eq!(
        ticket["execution_plan"],
        json!([
            {"role": "implementer", "agent": "codex",
             "prompt_markdown": "Inspect the target service and prepare a no-op patch."},
            {"role": "reviewer", "agent": "claude",
             "prompt_markdown": "Review the proposed change and confirm it stays a no-op."},
        ])
    );
    assert_eq!(
        ticket["policy_requirements"]["require_reviewer_step"],
        json!(false)
    );
    // Rust-only: the other fields and who created it.
    assert_eq!(ticket["source"], "operator");
    assert_eq!(ticket["created_by"], format!("approver:{APPROVER}"));
    assert_eq!(ticket["task_ref"], "ui-manual-1");
    assert_eq!(ticket["max_duration_seconds"], json!(900));
    assert_eq!(
        ticket["context"],
        json!({"service": "opsgate", "host": "macstudio"})
    );

    let detail = app.get(response.location().unwrap()).await;
    assert_eq!(detail.status, StatusCode::OK);
    let body = detail.text();
    assert!(body.contains("Manual remediation"));
    assert!(body.contains("approver:opsgate-admin"));
    assert_eq!(
        detail.page().flashes,
        vec![(
            "success".to_owned(),
            "Ticket created and queued for approval".to_owned()
        )]
    );
}

#[tokio::test]
async fn test_manual_ticket_form_defaults_investigator_to_codex() {
    let app = TestApp::new();
    app.sign_in();
    let response = app.get("/tickets").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.text();
    assert!(body.contains("name=\"steps-0-role\""));
    assert!(body.contains("<option value=\"investigator\" selected>investigator</option>"));
    assert!(body.contains("name=\"steps-0-agent\""));
    assert!(body.contains("<option value=\"codex\" selected>codex</option>"));
    assert!(body.contains("<option value=\"claude\">claude</option>"));
}

#[tokio::test]
async fn test_manual_ticket_form_renders_role_scaffolding() {
    let app = TestApp::new();
    app.sign_in();
    let response = app.get("/tickets").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.text();
    for text in [
        "Role model",
        "OpsGate currently supports exactly three workflow roles.",
        "Inspect-only investigation",
        "Repo-first implementation",
        "Independent review gate",
        "Use suggested prompt",
    ] {
        assert!(body.contains(text), "{text}");
    }
}

#[tokio::test]
async fn test_manual_ticket_creation_defaults_agent_from_role() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Role-based defaults"),
                ("summary", "Agent values should default from step role"),
                ("steps-0-role", "implementer"),
                (
                    "steps-0-prompt_markdown",
                    "Prepare the implementation plan.",
                ),
                ("steps-1-role", "reviewer"),
                ("steps-1-prompt_markdown", "Review the implementation plan."),
            ],
        )
        .await;
    let ticket = created(&app, &response).await;
    assert_eq!(
        ticket["execution_plan"],
        json!([
            {"role": "implementer", "agent": "codex", "prompt_markdown": "Prepare the implementation plan."},
            {"role": "reviewer", "agent": "claude", "prompt_markdown": "Review the implementation plan."},
        ])
    );
}

#[tokio::test]
async fn test_manual_ticket_creation_supports_legacy_single_step_fields() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Legacy single step"),
                ("summary", "Old field names should still work"),
                ("step_role", "reviewer"),
                ("step_agent", "claude"),
                ("prompt_markdown", "Review the change set."),
            ],
        )
        .await;
    let ticket = created(&app, &response).await;
    assert_eq!(
        ticket["execution_plan"],
        json!([{"role": "reviewer", "agent": "claude", "prompt_markdown": "Review the change set."}])
    );
}

#[tokio::test]
async fn test_manual_ticket_creation_rejects_empty_execution_plan_from_ui() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "No steps"),
                ("summary", "Submitting without steps should fail"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let body = response.text();
    assert!(body.contains("execution_plan must be a non-empty array"));
    assert!(body.contains("value=\"No steps\""));
    assert!(body.contains(">Submitting without steps should fail</textarea>"));
    assert!(body.contains("No workflow steps yet"));
    // The empty-state note is shown (not `hidden`) and no step is rendered.
    let page = response.page();
    let empty = page.element("workflow-empty").unwrap();
    assert!(!empty.iter().any(|(name, _)| name == "hidden"));
    let form = page.form("/tickets").unwrap();
    assert!(form.field("steps-0-role").is_none());
    assert_eq!(
        page.flashes,
        vec![(
            "error".to_owned(),
            "execution_plan must be a non-empty array".to_owned()
        )]
    );
    response.assert_security_headers();
}

#[tokio::test]
async fn test_manual_ticket_form_uses_implementer_guidance_for_legacy_implementor_role() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Legacy implementor guidance"),
                (
                    "summary",
                    "Guidance should still match implementer semantics",
                ),
                ("steps-0-role", "implementor"),
                ("steps-0-agent", "codex"),
                ("steps-0-prompt_markdown", "Prepare the fix in source."),
            ],
        )
        .await;
    let ticket = created(&app, &response).await;
    assert_eq!(
        ticket["execution_plan"],
        json!([{"role": "implementor", "agent": "codex", "prompt_markdown": "Prepare the fix in source."}])
    );
    let body = app.get("/tickets").await.text();
    assert!(body.contains("Repo-first implementation"));
    assert!(body.contains("Do not patch production files ad hoc as the primary fix path."));
}

#[tokio::test]
async fn test_manual_ticket_creation_enforces_operator_reviewer_floor_when_enabled() {
    let app = TestApp::with_env(&[(
        "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
        "true",
    )]);
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Needs reviewer"),
                ("summary", "Policy floor should reject this"),
                ("steps-0-role", "implementer"),
                ("steps-0-agent", "codex"),
                ("steps-0-prompt_markdown", "Make a change."),
                ("steps-1-role", "investigator"),
                ("steps-1-agent", "claude"),
                ("steps-1-prompt_markdown", "Collect logs."),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let body = response.text();
    assert!(body.contains("requires at least one reviewer step"));
    assert!(body.contains("Operator policy floor"));
    // Rust-only: with the floor on, a fresh form starts with a reviewer
    // step on claude.
    let fresh = app.get("/tickets").await.page();
    let form = fresh.form("/tickets").unwrap();
    assert_eq!(form.value("steps-0-role"), Some("reviewer"));
    assert_eq!(form.value("steps-0-agent"), Some("claude"));
}

#[tokio::test]
async fn test_manual_ticket_creation_rejects_invalid_context_json() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Bad context"),
                ("summary", "This should fail"),
                ("steps-0-role", "reviewer"),
                ("steps-0-agent", "codex"),
                ("steps-0-prompt_markdown", "Inspect state."),
                ("steps-1-role", "implementer"),
                ("steps-1-agent", "claude"),
                ("steps-1-prompt_markdown", "Prepare a no-op fix."),
                ("context_json", "[1, 2, 3]"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let body = response.text();
    assert!(body.contains("context_json must decode to an object"));
    assert!(body.contains(">[1, 2, 3]</textarea>"));
    assert!(body.contains(">Inspect state.</textarea>"));
    assert!(body.contains(">Prepare a no-op fix.</textarea>"));
    let form = response.page().form("/tickets").cloned().unwrap();
    assert_eq!(form.value("steps-1-role"), Some("implementer"));
    assert_eq!(form.value("steps-1-agent"), Some("claude"));
}

#[tokio::test]
async fn test_manual_ticket_creation_rejects_unsupported_agent_from_ui() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Bad agent"),
                ("summary", "Unsupported agents should be rejected"),
                ("steps-0-role", "reviewer"),
                ("steps-0-agent", "shell"),
                ("steps-0-prompt_markdown", "Review the proposed change."),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let body = response.text();
    assert!(body.contains("agent must be one of: codex, claude"));
    assert!(body.contains("value=\"Bad agent\""));
    assert!(body.contains(">shell (unsupported)</option>"));
    assert!(body.contains(">Review the proposed change.</textarea>"));
}

#[tokio::test]
async fn test_manual_ticket_creation_requires_csrf_token() {
    let app = TestApp::new();
    app.sign_in();
    let before = app.snapshot();
    let response = app
        .send(Call::post("/tickets").form(&[
            ("title", "Missing token"),
            ("summary", "This should be rejected"),
            ("step_role", "reviewer"),
            ("step_agent", "codex"),
            ("prompt_markdown", "Do nothing."),
        ]))
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some("/tickets"));
    assert!(
        app.get("/tickets")
            .await
            .text()
            .contains("Invalid form token")
    );
    assert_eq!(app.snapshot(), before);
}

#[tokio::test]
async fn test_manual_ticket_creation_rejects_tampered_csrf_token() {
    let app = TestApp::new();
    app.sign_in();
    let before = app.snapshot();
    let response = app
        .post_form(
            "/tickets",
            "tampered-token",
            &[
                ("title", "Bad token"),
                ("summary", "This should be rejected"),
                ("step_role", "reviewer"),
                ("step_agent", "codex"),
                ("prompt_markdown", "Do nothing."),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some("/tickets"));
    assert!(
        app.get("/tickets")
            .await
            .text()
            .contains("Invalid form token")
    );
    assert_eq!(app.snapshot(), before);
}

/// `test_manual_context_rejects_excessive_nesting`: Python fakes a
/// `RecursionError` of `json.loads`; Rust's decoder stops at its own
/// recursion limit, which this nesting exceeds (400 `invalid_context_json`,
/// nothing written).
#[tokio::test]
async fn test_manual_context_rejects_excessive_nesting() {
    let app = TestApp::new();
    let token = app.sign_in();
    let before = app.snapshot();
    let context = format!("{{\"nested\":{}0{}}}", "[".repeat(2000), "]".repeat(2000));
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "Nested"),
                ("summary", "Nested context"),
                ("steps-0-role", "investigator"),
                ("steps-0-agent", "codex"),
                ("steps-0-prompt_markdown", "Inspect"),
                ("context_json", &context),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.text().contains("context_json must be valid JSON"));
    assert_eq!(app.snapshot(), before);
}

#[tokio::test]
async fn test_real_manual_context_nesting_limit() {
    for depth in [64_usize, 65, 2000] {
        let app = TestApp::new();
        let token = app.sign_in();
        let before = app.snapshot();
        let context = format!(
            "{{\"nested\":{}0{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let response = app
            .post_form(
                "/tickets",
                &token,
                &[
                    ("title", "Nested"),
                    ("summary", "Nested context"),
                    ("steps-0-role", "investigator"),
                    ("steps-0-agent", "codex"),
                    ("steps-0-prompt_markdown", "Inspect"),
                    ("context_json", &context),
                ],
            )
            .await;
        let expected = if depth == 64 {
            StatusCode::FOUND
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(response.status, expected, "{depth}");
        if depth != 64 {
            assert_eq!(app.snapshot(), before, "{depth}");
        }
    }
}

#[tokio::test]
async fn test_manual_ticket_duration_rejects_invalid_values() {
    for duration in ["1.5", "0", "31536001", "1_000"] {
        let app = TestApp::new();
        let token = app.sign_in();
        let before = app.snapshot();
        let response = app
            .post_form(
                "/tickets",
                &token,
                &[
                    ("title", "Duration"),
                    ("summary", "Invalid"),
                    ("steps-0-role", "investigator"),
                    ("steps-0-agent", "codex"),
                    ("steps-0-prompt_markdown", "Inspect"),
                    ("max_duration_seconds", duration),
                ],
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{duration}");
        assert_eq!(app.snapshot(), before, "{duration}");
        // The form keeps the value as sent.
        let form = response.page().form("/tickets").cloned().unwrap();
        assert_eq!(form.value("max_duration_seconds"), Some(duration));
    }
}

/// Python's unhandled `ValueError`s of the form (an `int()` of more than
/// 4300 digits in a step index or in `context_json`) are 500s; nothing is
/// written.
#[tokio::test]
async fn oversized_integers_are_unhandled_errors() {
    let app = TestApp::new();
    let token = app.sign_in();
    let before = app.snapshot();
    let index = format!("steps-{}-role", "9".repeat(4301));
    let context = format!("{{\"a\": {}}}", "1".repeat(4301));
    for fields in [
        vec![
            ("title", "T"),
            ("summary", "S"),
            (index.as_str(), "investigator"),
        ],
        vec![
            ("title", "T"),
            ("summary", "S"),
            ("steps-0-role", "investigator"),
            ("context_json", context.as_str()),
        ],
    ] {
        let response = app.post_form("/tickets", &token, &fields).await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(app.snapshot(), before);
    // A duration of more than 4300 digits is `invalid_ticket` (Python's
    // `ValueError` is caught there).
    let response = app
        .post_form(
            "/tickets",
            &token,
            &[
                ("title", "T"),
                ("summary", "S"),
                ("steps-0-role", "investigator"),
                ("max_duration_seconds", &"1".repeat(4301)),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(
        response
            .text()
            .contains("max_duration_seconds must be an integer")
    );
}

/// The re-rendered page lists the query's view, and a `GET` with a form
/// body fills the form with it (Werkzeug parses form bodies of any method).
#[tokio::test]
async fn rerendered_form_keeps_view_and_fields() {
    let app = TestApp::new();
    let token = app.sign_in();
    let response = app
        .post_form(
            "/tickets?view=archived",
            &token,
            &[
                ("title", "  Kept  "),
                ("summary", "Kept summary"),
                ("task_ref", " ref "),
                ("expires_at", "not a date"),
                ("max_duration_seconds", " "),
                ("steps-3-role", "reviewer"),
                ("steps-1-role", "investigator"),
                ("steps-1-agent", ""),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let page = response.page();
    assert!(
        page.text
            .contains("Archived tickets stay readable and restorable")
    );
    let form = page.form("/tickets").unwrap();
    assert_eq!(form.value("title"), Some("Kept"));
    assert_eq!(form.value("task_ref"), Some("ref"));
    assert_eq!(form.value("expires_at"), Some("not a date"));
    assert_eq!(form.value("max_duration_seconds"), Some("3600"));
    // Steps in index order, renumbered from 0, agents defaulted by role.
    assert_eq!(form.value("steps-0-role"), Some("investigator"));
    assert_eq!(form.value("steps-0-agent"), Some("codex"));
    assert_eq!(form.value("steps-1-role"), Some("reviewer"));
    assert_eq!(form.value("steps-1-agent"), Some("claude"));
    assert_eq!(form.value("csrf_token"), Some(token.as_str()));

    let get = app
        .send(
            Call::new(axum::http::Method::GET, "/tickets")
                .form(&[("title", "From body"), ("steps-0-role", "reviewer")]),
        )
        .await;
    assert_eq!(get.status, StatusCode::OK);
    let form = get.page().form("/tickets").cloned().unwrap();
    assert_eq!(form.value("title"), Some("From body"));
    assert_eq!(form.value("steps-0-agent"), Some("claude"));
}
