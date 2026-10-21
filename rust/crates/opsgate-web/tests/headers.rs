//! Security headers on every response (`web::headers`, PLAN.md 4.4 step 5).

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, NYXMON_TOKEN, TestApp, ticket_payload};

/// `test_ui_pages_cannot_be_framed` with the pages of slice S4a (the login
/// page, the forbidden page); the ticket pages of slice S5 get the headers
/// from the same layer and S5 adds them here.
#[tokio::test]
async fn test_ui_pages_cannot_be_framed() {
    let app = TestApp::new();
    let login = app.get("/login").await;
    assert_eq!(login.status, StatusCode::OK);
    login.assert_security_headers();
    let forbidden = app
        .send(Call::new(Method::GET, "/login").peer(Some("8.8.8.8:1")))
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    forbidden.assert_security_headers();
}

#[tokio::test]
async fn test_api_error_and_redirect_responses_carry_security_headers() {
    let app = TestApp::new();
    app.get("/api/v1/health").await.assert_security_headers();
    let unauthenticated = app.get("/api/v1/tickets/does-not-exist").await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    unauthenticated.assert_security_headers();
    // A redirect: the UI-CSRF check of a form without token (the `GET
    // /tickets` redirect of the Python test is slice S5's route).
    let redirect = app
        .send(Call::post("/tickets").form(&[("title", "x")]))
        .await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    redirect.assert_security_headers();
    let missing = app.get("/no-such-page").await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    missing.assert_security_headers();
    let wrong_method = app.send(Call::new(Method::PUT, "/api/v1/tickets")).await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    wrong_method.assert_security_headers();
    let created = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(NYXMON_TOKEN)
                .json(&ticket_payload("H", None)),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    created.assert_security_headers();
}

#[tokio::test]
async fn test_forbidden_network_response_carries_security_headers() {
    let app = TestApp::new();
    let response = app
        .send(Call::new(Method::GET, "/tickets").peer(Some("203.0.113.9:1")))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    response.assert_security_headers();
}
