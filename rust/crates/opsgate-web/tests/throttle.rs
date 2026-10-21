//! The login throttle over HTTP (`web::login::throttle`, PLAN.md 4.5.3)
//! with a fake clock (`FakeClock` of `tests/test_api.py`); the sequence
//! rules themselves are pinned by `fixtures/throttle.json`
//! (`login_fixtures.rs`).

mod common;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::{APPROVER, Call, NYXMON_TOKEN, PASSWORD, TestApp, ticket_payload};
use opsgate_web::throttle::LoginThrottle;

/// `FakeClock`: starts at 1000 s.
#[derive(Clone)]
struct FakeClock(Arc<Mutex<f64>>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(1000.0)))
    }

    fn advance(&self, seconds: f64) {
        *self.0.lock().unwrap() += seconds;
    }

    fn throttle(&self, limit: usize, window_seconds: f64) -> LoginThrottle {
        let clock = self.clone();
        LoginThrottle::new(
            limit,
            window_seconds,
            10_000,
            Arc::new(move || *clock.0.lock().unwrap()),
        )
    }
}

async fn ticket(app: &TestApp) -> String {
    app.create_ticket(NYXMON_TOKEN, ticket_payload("Throttle", None))
        .await
}

#[tokio::test]
async fn test_login_locks_after_repeated_failures() {
    let clock = FakeClock::new();
    let app = TestApp::with_throttle(clock.throttle(3, 60.0));
    let ticket_id = ticket(&app).await;

    for _ in 0..3 {
        assert_eq!(app.failed_login("wrong-password").await, StatusCode::FOUND);
    }

    let locked = app
        .post_login("/login", APPROVER, PASSWORD, "127.0.0.1:50000")
        .await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        locked
            .text()
            .contains("Too many failed login attempts. Try again later."),
        "{}",
        locked.text()
    );
    locked.assert_security_headers();
    assert!(!app.authenticated(&ticket_id).await);

    clock.advance(61.0);
    app.login("/login").await;
    assert!(app.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_unknown_username_counts_toward_throttle() {
    let app = TestApp::with_throttle(FakeClock::new().throttle(2, 60.0));
    for _ in 0..2 {
        app.post_login("/login", "nobody", "x", "127.0.0.1:50000")
            .await;
    }
    assert_eq!(
        app.failed_login(PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_successful_login_resets_failure_count() {
    let app = TestApp::with_throttle(FakeClock::new().throttle(3, 60.0));
    app.failed_login("wrong-password").await;
    app.failed_login("wrong-password").await;
    app.login("/login").await;
    let token = app.csrf_token();
    app.send(Call::post("/logout").form(&[("csrf_token", &token)]))
        .await;

    app.failed_login("wrong-password").await;
    app.failed_login("wrong-password").await;
    assert_eq!(app.login("/login").await.status, StatusCode::FOUND);
}

#[tokio::test]
async fn test_login_throttle_is_per_client_ip() {
    let app = TestApp::with_throttle(FakeClock::new().throttle(1, 60.0));
    app.failed_login("wrong-password").await;
    assert_eq!(
        app.failed_login(PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS
    );

    let response = app
        .post_login("/login", APPROVER, PASSWORD, "100.64.0.7:41000")
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(response.location(), Some("/tickets"));
}

#[test]
fn test_login_throttle_bounds_tracked_clients() {
    let clock = FakeClock::new();
    let reading = clock.clone();
    let throttle = LoginThrottle::new(2, 60.0, 3, Arc::new(move || *reading.0.lock().unwrap()));
    for index in 0..5 {
        clock.advance(1.0);
        throttle.record_failure(&format!("10.0.0.{index}"));
    }
    assert!(throttle.tracked().len() <= 3);
    // The most recent offender is still tracked.
    throttle.record_failure("10.0.0.4");
    assert!(throttle.is_locked("10.0.0.4"));
}

/// The locked answer is the login page with status 429: the flash shown on
/// it (and not kept), the form's `next` kept, nobody signed in, the attempt
/// not counted as a failure.
#[tokio::test]
async fn the_locked_answer_is_the_login_page() {
    let clock = FakeClock::new();
    let app = TestApp::with_throttle(clock.throttle(1, 60.0));
    app.failed_login("wrong-password").await;
    app.get("/login").await;
    let token = app.csrf_token();
    let locked = app
        .send(Call::post("/login?next=/tickets/q").form(&[
            ("csrf_token", &token),
            ("username", APPROVER),
            ("password", PASSWORD),
            ("next", "/tickets/abc"),
        ]))
        .await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.content_type(), "text/html; charset=utf-8");
    let body = locked.text();
    assert!(
        body.contains("name=\"next\" value=\"/tickets/abc\""),
        "{body}"
    );
    assert!(body.contains("name=\"csrf_token\""), "{body}");
    assert!(app.session().flashes.is_empty());
    assert_eq!(app.session().username, None);
    // A lockout is no new failure: the window still ends 60 s after the
    // first one.
    clock.advance(60.0);
    assert_eq!(app.login("/login").await.location(), Some("/tickets"));
}

/// The key is the socket peer: forwarded headers never count (4.4 step 1),
/// and a request without an address (the gate switched off) shares the key
/// `unknown`.
#[tokio::test]
async fn the_key_is_the_socket_peer() {
    let app = TestApp::with_throttle(FakeClock::new().throttle(1, 60.0));
    app.failed_login("wrong-password").await;
    app.get("/login").await;
    let token = app.csrf_token();
    let forwarded = app
        .send(
            Call::post("/login")
                .header("x-forwarded-for", "100.64.0.9")
                .form(&[
                    ("csrf_token", &token),
                    ("username", APPROVER),
                    ("password", PASSWORD),
                ]),
        )
        .await;
    assert_eq!(forwarded.status, StatusCode::TOO_MANY_REQUESTS);

    // The default throttle (5 failures) on an application without the gate.
    let throttle_app = TestApp::with_env(&[("OPSGATE_REQUIRE_TAILSCALE_CONTEXT", "false")]);
    let page = throttle_app
        .send(Call::new(axum::http::Method::GET, "/login").peer(None))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    for _ in 0..5 {
        let token = throttle_app.csrf_token();
        let response = throttle_app
            .send(Call::post("/login").peer(None).form(&[
                ("csrf_token", &token),
                ("username", APPROVER),
                ("password", "wrong"),
            ]))
            .await;
        assert_eq!(response.status, StatusCode::FOUND);
    }
    let token = throttle_app.csrf_token();
    let locked = throttle_app
        .send(Call::post("/login").peer(None).form(&[
            ("csrf_token", &token),
            ("username", APPROVER),
            ("password", PASSWORD),
        ]))
        .await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    // Another client is not affected.
    let other = throttle_app
        .post_login("/login", APPROVER, PASSWORD, "127.0.0.1:50000")
        .await;
    assert_eq!(other.status, StatusCode::FOUND);
}
