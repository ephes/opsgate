//! The session cookie and the approver check (`web::session`, PLAN.md
//! 4.5.2, D-1), observed through `GET /api/v1/tickets/{id}`.

mod common;

use axum::http::{Method, StatusCode};
use common::{APPROVER, Call, NYXMON_TOKEN, TestApp, ticket_payload};
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
