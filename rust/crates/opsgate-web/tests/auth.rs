//! Bearer tokens (`web::auth`, PLAN.md 4.5.1).

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, NYXMON_TOKEN, OPERATOR_TOKEN, RUNNER_TOKEN, TestApp, ticket_payload};
use serde_json::json;

const NON_ASCII_TOKEN: &str = "té-über";

#[tokio::test]
async fn test_api_bearer_endpoints_reject_non_ascii_token() {
    let app = TestApp::new();
    for (method, path, error) in [
        (Method::POST, "/api/v1/tickets", "invalid_submit_token"),
        (
            Method::GET,
            "/api/v1/tickets/missing-ticket",
            "auth_required",
        ),
        (Method::POST, "/api/v1/runner/claim", "invalid_runner_token"),
        (
            Method::POST,
            "/api/v1/runner/missing-ticket/status",
            "invalid_runner_token",
        ),
    ] {
        let response = app
            .send(
                Call::new(method.clone(), path)
                    .bearer(NON_ASCII_TOKEN)
                    .json(&json!({})),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(response.error(), error, "{method} {path}");
    }
}

/// `get_bearer_token`: exactly `Bearer `, the rest stripped; each token
/// opens only its own routes.
#[tokio::test]
async fn bearer_token_rules() {
    let app = TestApp::new();
    let create = |authorization: &str| {
        Call::post("/api/v1/tickets")
            .header("authorization", authorization)
            .json(&ticket_payload("Bearer", None))
    };
    for (authorization, status) in [
        (format!("Bearer {NYXMON_TOKEN}"), StatusCode::CREATED),
        (format!("Bearer   {NYXMON_TOKEN} \t"), StatusCode::CREATED),
        (format!("Bearer {OPERATOR_TOKEN}"), StatusCode::CREATED),
        (format!("bearer {NYXMON_TOKEN}"), StatusCode::UNAUTHORIZED),
        (format!("Bearer{NYXMON_TOKEN}"), StatusCode::UNAUTHORIZED),
        (format!("Token {NYXMON_TOKEN}"), StatusCode::UNAUTHORIZED),
        (format!("Bearer {NYXMON_TOKEN}x"), StatusCode::UNAUTHORIZED),
        (format!("Bearer {RUNNER_TOKEN}"), StatusCode::UNAUTHORIZED),
        ("Bearer ".to_owned(), StatusCode::UNAUTHORIZED),
    ] {
        let response = app.send(create(&authorization)).await;
        assert_eq!(response.status, status, "{authorization:?}");
        if status == StatusCode::UNAUTHORIZED {
            assert_eq!(response.error(), "invalid_submit_token");
        }
    }
    let submitter_claims = app
        .send(Call::post("/api/v1/runner/claim").bearer(NYXMON_TOKEN))
        .await;
    assert_eq!(submitter_claims.error(), "invalid_runner_token");
}

/// The openclaw submitter exists only with its token configured.
#[tokio::test]
async fn openclaw_without_token_is_no_submitter() {
    let app = TestApp::with_env(&[("OPSGATE_SUBMIT_TOKEN_OPENCLAW", "")]);
    let response = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(common::OPENCLAW_TOKEN)
                .json(&ticket_payload("No openclaw", None)),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}
