//! The session cookie and the approver check (`web::session`, PLAN.md
//! 4.5.2, D-1), observed through `GET /api/v1/tickets/{id}` (the Python
//! tests use `GET /tickets`, slice S5's page); logout and the server-side
//! revocation (4.5.3, S4b).

mod common;

use axum::http::{Method, StatusCode};
use common::{APPROVER, Call, NEW_PASSWORD_HASH, NYXMON_TOKEN, TestApp, ticket_payload};
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_web::session::SessionData;
use opsgate_web::testing::session_cookie;

async fn ticket(app: &TestApp) -> String {
    let id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Session", None))
        .await;
    format!("/api/v1/tickets/{id}")
}

fn data(app: &TestApp, change: impl FnOnce(&mut SessionData)) -> SessionData {
    let generation = app
        .state
        .store()
        .ui_session_generation(APPROVER)
        .unwrap()
        .unwrap();
    let mut data = SessionData {
        username: Some(APPROVER.to_owned()),
        auth_at: Some(isoformat_z(&utc_now())),
        session_generation: Some(generation),
        csrf_token: Some("csrf".to_owned()),
        flashes: Vec::new(),
    };
    change(&mut data);
    data
}

/// The cookie's attributes (P1): `HttpOnly`, `SameSite=Lax`, `Path=/`,
/// `Secure` only with `OPSGATE_SESSION_COOKIE_SECURE`, no expiry; written
/// only when the session changed.
#[tokio::test]
async fn cookie_attributes_and_writes() {
    for secure in [false, true] {
        let app = TestApp::with_env(&[(
            "OPSGATE_SESSION_COOKIE_SECURE",
            if secure { "true" } else { "false" },
        )]);
        let first = app.get("/login").await;
        let cookie = first.set_cookie().expect("the render creates a CSRF token");
        assert!(cookie.starts_with("session="));
        for attribute in ["HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(cookie.contains(attribute), "{cookie}");
        }
        assert_eq!(cookie.contains("Secure"), secure, "{cookie}");
        assert!(
            !cookie.contains("Expires") && !cookie.contains("Max-Age"),
            "{cookie}"
        );
        let token = app.session().csrf_token.unwrap();
        // The session did not change: no cookie, the same token.
        let second = app.get("/login").await;
        assert_eq!(second.set_cookie(), None);
        assert_eq!(app.session().csrf_token.unwrap(), token);
        // API answers that do not touch the session set no cookie.
        assert_eq!(app.get("/api/v1/health").await.set_cookie(), None);
    }
}

/// A cookie that does not decrypt (another key, tampering, Flask's format)
/// is an empty session.
#[tokio::test]
async fn unusable_cookies_are_empty_sessions() {
    let app = TestApp::new();
    let path = ticket(&app).await;
    let other = TestApp::with_env(&[("OPSGATE_SESSION_SECRET", &"y".repeat(32))]);
    for cookie in [
        session_cookie(&other.state, &data(&app, |_| {})),
        "session=eyJ1c2VybmFtZSI6Im9wc2dhdGUtYWRtaW4ifQ.ZxYz.abc".to_owned(),
        "session=".to_owned(),
    ] {
        app.set_cookie(Some(cookie.clone()));
        let response = app.get(&path).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{cookie}");
        // An empty session that did not change is not written.
        assert_eq!(response.set_cookie(), None, "{cookie}");
    }
}

#[tokio::test]
async fn a_signed_in_session_authenticates() {
    let app = TestApp::new();
    let path = ticket(&app).await;
    app.sign_in();
    let response = app.get(&path).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.set_cookie(), None);
}

/// `get_session_user`: a session naming the approver that fails a later
/// check is cleared (the cookie deleted); one naming somebody else is left
/// alone.
#[tokio::test]
async fn failing_sessions_are_cleared() {
    let app = TestApp::new();
    let path = ticket(&app).await;
    let cases: Vec<(&str, SessionData, bool)> = vec![
        ("no auth_at", data(&app, |data| data.auth_at = None), true),
        (
            "unparsable auth_at",
            data(&app, |data| data.auth_at = Some("yesterday".to_owned())),
            true,
        ),
        (
            "naive auth_at",
            data(&app, |data| {
                data.auth_at = Some("2026-10-21T10:00:00".to_owned())
            }),
            true,
        ),
        (
            "timed out",
            data(&app, |data| {
                data.auth_at = Some(isoformat_z(&(utc_now() - chrono::TimeDelta::seconds(3601))));
            }),
            true,
        ),
        (
            "no generation",
            data(&app, |data| data.session_generation = None),
            true,
        ),
        (
            "other generation",
            data(&app, |data| {
                data.session_generation = data.session_generation.map(|generation| generation + 1);
            }),
            true,
        ),
        (
            "other user",
            data(&app, |data| data.username = Some("someone".to_owned())),
            false,
        ),
        ("no user", data(&app, |data| data.username = None), false),
    ];
    for (name, session, cleared) in cases {
        app.set_cookie(Some(session_cookie(&app.state, &session)));
        let response = app.get(&path).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{name}");
        if cleared {
            let cookie = response.set_cookie().unwrap_or_default();
            assert!(cookie.starts_with("session=;"), "{name}: {cookie}");
            assert!(cookie.contains("Max-Age=0"), "{name}: {cookie}");
            for attribute in ["HttpOnly", "SameSite=Lax", "Path=/"] {
                assert!(cookie.contains(attribute), "{name}: {cookie}");
            }
        } else {
            assert_eq!(response.set_cookie(), None, "{name}");
        }
    }
    // A revocation (logout, password change) invalidates a signed-in cookie.
    app.sign_in();
    assert_eq!(app.get(&path).await.status, StatusCode::OK);
    app.state.store().revoke_ui_sessions(APPROVER).unwrap();
    assert_eq!(app.get(&path).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.cookie(), None);
}

/// Python's `timedelta(seconds=…)` overflows beyond 999 999 999 days: every
/// check of an approver session is then a 500.
#[tokio::test]
async fn session_timeout_beyond_timedelta_is_500() {
    let app = TestApp::with_env(&[("OPSGATE_UI_SESSION_TIMEOUT_SECONDS", "86400000000000")]);
    let path = ticket(&app).await;
    app.sign_in();
    let response = app.send(Call::new(Method::GET, &path)).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    let app = TestApp::with_env(&[("OPSGATE_UI_SESSION_TIMEOUT_SECONDS", "86399999999999")]);
    let path = ticket(&app).await;
    app.sign_in();
    assert_eq!(app.get(&path).await.status, StatusCode::OK);
}

// ------------------------------------------- logout and revocation (S4b)

async fn pending_ticket(app: &TestApp, task_ref: &str) -> String {
    app.create_ticket(NYXMON_TOKEN, ticket_payload("Hardening", Some(task_ref)))
        .await
}

fn generation(app: &TestApp) -> i64 {
    app.state
        .store()
        .ui_session_generation(APPROVER)
        .unwrap()
        .unwrap()
}

/// `POST /logout` with the session's form token.
async fn logout(app: &TestApp) -> common::TestResponse {
    let token = app.csrf_token();
    app.send(Call::post("/logout").form(&[("csrf_token", &token)]))
        .await
}

#[tokio::test]
async fn test_cookie_replayed_after_logout_is_rejected() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "logout-replay").await;
    app.login("/login").await;
    let stolen_cookie = app.cookie();
    let stolen_csrf = app.csrf_token();

    let response = logout(&app).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert!(response.location().unwrap().ends_with("/login"));
    response.assert_security_headers();

    app.set_cookie(stolen_cookie.clone());
    assert!(!app.authenticated(&ticket_id).await);

    app.set_cookie(stolen_cookie);
    let api_replay = app
        .send(
            Call::post(&format!("/api/v1/tickets/{ticket_id}/approve"))
                .header("x-csrf-token", &stolen_csrf),
        )
        .await;
    assert_eq!(api_replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.ticket_state(&ticket_id).await, "pending_approval");
}

#[tokio::test]
async fn test_logout_revokes_other_sessions_and_fresh_login_works() {
    let first = TestApp::new();
    let ticket_id = pending_ticket(&first, "logout-other").await;
    let second = first.sharing(&[]);
    first.login("/login").await;
    second.login("/login").await;

    logout(&first).await;

    assert!(!second.authenticated(&ticket_id).await);
    second.login("/login").await;
    assert!(second.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_anonymous_logout_does_not_revoke_sessions() {
    let approver = TestApp::new();
    let ticket_id = pending_ticket(&approver, "logout-anon").await;
    let anonymous = approver.sharing(&[]);
    approver.login("/login").await;
    let before = generation(&approver);

    anonymous.get("/login").await;
    let response = logout(&anonymous).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some("/login"));

    assert_eq!(generation(&approver), before);
    assert!(approver.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_password_change_revokes_existing_sessions() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "password-change").await;
    app.login("/login").await;
    let old_cookie = app.cookie();

    let rotated = app.sharing(&[("OPSGATE_UI_PASSWORD_BCRYPT", NEW_PASSWORD_HASH)]);
    rotated.set_cookie(old_cookie);
    assert!(!rotated.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_restart_with_same_password_keeps_sessions() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "restart").await;
    app.login("/login").await;
    let cookie = app.cookie();

    let restarted = app.sharing(&[]);
    restarted.set_cookie(cookie);
    assert!(restarted.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_session_without_generation_is_treated_as_logged_out() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "no-generation").await;
    app.login("/login").await;
    let mut data = app.session();
    data.session_generation = None;
    app.set_cookie(Some(session_cookie(&app.state, &data)));

    assert!(!app.authenticated(&ticket_id).await);
    // The failing session was cleared.
    assert_eq!(app.cookie(), None);
}

/// Logout bumps the generation once per authenticated session, clears the
/// session (the cookie is deleted) and needs the form token; a session that
/// no longer authenticates revokes nothing.
#[tokio::test]
async fn logout_clears_the_session_and_bumps_once() {
    let app = TestApp::new();
    let start = generation(&app);
    app.login("/login").await;
    let response = logout(&app).await;
    let cookie = response.set_cookie().unwrap();
    assert!(
        cookie.starts_with("session=;") && cookie.contains("Max-Age=0"),
        "{cookie}"
    );
    assert_eq!(app.cookie(), None);
    assert_eq!(generation(&app), start + 1);

    // A stale session (the old generation) signs nobody out.
    let stale = SessionData {
        username: Some(APPROVER.to_owned()),
        auth_at: Some(isoformat_z(&utc_now())),
        session_generation: Some(start),
        csrf_token: Some("stale".to_owned()),
        flashes: Vec::new(),
    };
    app.set_cookie(Some(session_cookie(&app.state, &stale)));
    let response = logout(&app).await;
    assert_eq!(response.location(), Some("/login"));
    assert_eq!(generation(&app), start + 1);

    // Without the form token logout is the UI-CSRF redirect and nothing else.
    app.login("/login").await;
    let response = app
        .send(Call::post("/logout").form(&[("csrf_token", "wrong")]))
        .await;
    assert_eq!(response.location(), Some("/tickets"));
    assert_eq!(generation(&app), start + 1);
    assert_eq!(app.session().username.as_deref(), Some(APPROVER));
}

/// Logout after the approver's row is gone: the session no longer
/// authenticates (no stored generation), so nothing is revoked; the session
/// is cleared.
#[tokio::test]
async fn logout_without_the_approver_row() {
    let app = TestApp::new();
    app.login("/login").await;
    app.connection()
        .execute("UPDATE ui_session_state SET username = 'other'", [])
        .unwrap();
    let response = logout(&app).await;
    assert_eq!(response.location(), Some("/login"));
    assert_eq!(app.cookie(), None);
}
