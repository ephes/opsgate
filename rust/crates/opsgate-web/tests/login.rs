//! Login (`web::login`, PLAN.md 4.5.3): the page (`GET`/`HEAD /login`,
//! S4a) and the template environment it renders through (6.3), `POST
//! /login` with `next`, the bcrypt check and the session it creates (S4b).

mod common;

use axum::http::{Method, StatusCode};
use common::{APPROVER, Call, NYXMON_TOKEN, PASSWORD, TestApp, ticket_payload};
use opsgate_core::time::{parse_iso_datetime, utc_now};
use opsgate_web::session::SessionData;
use opsgate_web::testing::session_cookie;
use opsgate_web::throttle::LoginThrottle;
use std::sync::Arc;

#[tokio::test]
async fn the_login_form() {
    let app = TestApp::new();
    let page = app.get("/login").await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.content_type(), "text/html; charset=utf-8");
    let body = page.text();
    for snippet in [
        "id=\"login-form\"",
        "name=\"login\"",
        "method=\"post\"",
        "action=\"/login\"",
        "autocomplete=\"on\"",
        "name=\"username\"",
        "autocomplete=\"username\"",
        "autofocus",
        "name=\"password\"",
        "id=\"current-password\"",
        "autocomplete=\"current-password\"",
    ] {
        assert!(body.contains(snippet), "{snippet}");
    }
    let token = app.session().csrf_token.unwrap();
    assert!(
        body.contains(&format!("name=\"csrf_token\" value=\"{token}\"")),
        "{body}"
    );
    assert!(!body.contains("name=\"next\""));
}

#[tokio::test]
async fn next_is_sanitised_and_escaped() {
    let app = TestApp::new();
    for (query, next) in [
        ("next=/tickets/abc", Some("/tickets/abc")),
        ("next=%20/tickets?view%3Dall%20", Some("/tickets?view=all")),
        ("next=/tickets/%22%3E%3Cx", Some("/tickets/&#34;&gt;&lt;x")),
        ("next=https://example.com/x", None),
        ("next=//evil.example/x", None),
        ("next=javascript:alert(1)", None),
        ("next=/tickets/a%0D%0Ab", None),
        ("next=/tickets/a%09b", None),
        ("next=tickets", None),
        ("next=/first&next=/second", Some("/first")),
        ("other=/x", None),
    ] {
        let body = app.get(&format!("/login?{query}")).await.text();
        match next {
            Some(next) => assert!(
                body.contains(&format!("name=\"next\" value=\"{next}\"")),
                "{query}: {body}"
            ),
            None => assert!(!body.contains("name=\"next\""), "{query}"),
        }
    }
}

/// `HEAD /login` and `GET /login` have no side effect but the CSRF token.
#[tokio::test]
async fn the_login_page_has_no_side_effects() {
    let app = TestApp::new();
    let head = app
        .send(Call::new(Method::HEAD, "/login?next=/tickets/x"))
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
    assert_eq!(head.location(), None);
    let data = app.session();
    assert_eq!(
        data,
        SessionData {
            csrf_token: data.csrf_token.clone(),
            ..SessionData::default()
        }
    );
    // A signed-in session stays signed in.
    let token = app.sign_in();
    let before = app.session();
    let page = app.get("/login").await;
    assert_eq!(page.set_cookie(), None);
    assert_eq!(app.session(), before);
    assert!(page.text().contains(&token));
}

/// Flashes are shown once (`get_flashed_messages`, with categories) and
/// leave the session.
#[tokio::test]
async fn flashes_are_shown_once() {
    let app = TestApp::new();
    let data = SessionData {
        csrf_token: Some("token".to_owned()),
        flashes: vec![
            ("error".to_owned(), "Too <many> attempts".to_owned()),
            ("success".to_owned(), "Done".to_owned()),
        ],
        ..SessionData::default()
    };
    app.set_cookie(Some(session_cookie(&app.state, &data)));
    let body = app.get("/login").await.text();
    assert!(
        body.contains("<p class=\"flash-error\">Too &lt;many&gt; attempts</p>"),
        "{body}"
    );
    assert!(
        body.contains("<p class=\"flash-success\">Done</p>"),
        "{body}"
    );
    assert!(app.session().flashes.is_empty());
    assert_eq!(app.session().csrf_token.as_deref(), Some("token"));
    let again = app.get("/login").await.text();
    assert!(!again.contains("<p class=\"flash-"));
}

/// `test_ui_ticket_detail_redirects_to_login_with_next` gives the login path
/// (`GET /tickets/<id>` is slice S5's); `test_login_redirects_to_requested_next_path`.
#[tokio::test]
async fn test_login_redirects_to_requested_next_path() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(
            NYXMON_TOKEN,
            ticket_payload("Needs approval", Some("ui-next-2")),
        )
        .await;
    let response = app
        .login(&format!("/login?next=/tickets/{ticket_id}"))
        .await;
    assert_eq!(
        response.location(),
        Some(format!("/tickets/{ticket_id}").as_str())
    );
    response.assert_security_headers();
    assert!(app.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_login_ignores_external_next_path() {
    let app = TestApp::new();
    let response = app.login("/login?next=https://example.com/steal").await;
    assert_eq!(response.location(), Some("/tickets"));
}

#[tokio::test]
async fn test_login_ignores_protocol_relative_next_path() {
    let app = TestApp::new();
    let response = app.login("/login?next=//evil.example/steal").await;
    assert_eq!(response.location(), Some("/tickets"));
}

#[tokio::test]
async fn test_login_ignores_javascript_next_path() {
    let app = TestApp::new();
    let response = app.login("/login?next=javascript:alert(1)").await;
    assert_eq!(response.location(), Some("/tickets"));
}

#[tokio::test]
async fn test_login_ignores_control_chars_in_next_path() {
    let app = TestApp::new();
    let response = app.login("/login?next=/tickets/test%0D%0Ainvalid").await;
    assert_eq!(response.location(), Some("/tickets"));
}

#[tokio::test]
async fn test_login_form_uses_autofill_friendly_fields() {
    let app = TestApp::new();
    let response = app.get("/login").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.text();
    for snippet in [
        "id=\"login-form\"",
        "name=\"login\"",
        "action=\"/login\"",
        "autocomplete=\"on\"",
        "name=\"username\"",
        "autocomplete=\"username\"",
        "autofocus",
        "autocapitalize=\"none\"",
        "autocorrect=\"off\"",
        "spellcheck=\"false\"",
        "name=\"password\"",
        "id=\"current-password\"",
        "autocomplete=\"current-password\"",
    ] {
        assert!(body.contains(snippet), "{snippet}");
    }
}

#[tokio::test]
async fn test_login_head_is_side_effect_free() {
    let app = TestApp::new();
    for path in ["/login", "/login?next=/tickets/test-ticket"] {
        let response = app.send(Call::new(Method::HEAD, path)).await;
        assert_eq!(response.status, StatusCode::OK, "{path}");
        assert_eq!(response.location(), None, "{path}");
        assert!(app.session().flashes.is_empty(), "{path}");
    }
}

/// `test_wrong_username_still_runs_the_password_check` over HTTP: the right
/// password with a wrong username signs nobody in. (That the password check
/// runs for a wrong username too is the unit test
/// `opsgate_web::password::tests::the_password_check_always_runs`; Python
/// counts `bcrypt.checkpw` calls with a monkeypatch.)
#[tokio::test]
async fn test_wrong_username_still_runs_the_password_check() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Wrong user", None))
        .await;
    let response = app
        .post_login("/login", "someone-else", PASSWORD, "127.0.0.1:50000")
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert!(response.location().unwrap().ends_with("/login"));
    assert!(!app.authenticated(&ticket_id).await);
}

#[tokio::test]
async fn test_non_ascii_username_is_rejected_without_error() {
    let app = TestApp::new();
    let response = app
        .post_login("/login", "opsgäte-admin", PASSWORD, "127.0.0.1:50000")
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert!(response.location().unwrap().ends_with("/login"));
}

/// A successful sign-in replaces the session: the approver, `auth_at` now,
/// the stored generation and a new CSRF token; earlier flashes are gone.
/// The username is stripped; the password is not.
#[tokio::test]
async fn login_replaces_the_session() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Session", None))
        .await;
    app.set_cookie(Some(session_cookie(
        &app.state,
        &SessionData {
            csrf_token: Some("pre-login".to_owned()),
            flashes: vec![("error".to_owned(), "old".to_owned())],
            ..SessionData::default()
        },
    )));
    let response = app
        .send(Call::post("/login").form(&[
            ("csrf_token", "pre-login"),
            ("username", "  opsgate-admin\u{a0}"),
            ("password", PASSWORD),
        ]))
        .await;
    assert_eq!(
        (response.status, response.location()),
        (StatusCode::FOUND, Some("/tickets"))
    );
    let data = app.session();
    assert_eq!(data.username.as_deref(), Some(APPROVER));
    let generation = app.state.store().ui_session_generation(APPROVER).unwrap();
    assert_eq!(data.session_generation, generation);
    let auth_at = parse_iso_datetime(data.auth_at.as_deref().unwrap()).unwrap();
    assert!((utc_now() - auth_at).num_seconds().abs() < 60);
    let token = data.csrf_token.unwrap();
    assert_ne!(token, "pre-login");
    assert_eq!(token.len(), 43);
    assert!(data.flashes.is_empty());
    assert!(app.authenticated(&ticket_id).await);

    // The password is compared as sent.
    let other = TestApp::new();
    let response = other
        .post_login(
            "/login",
            APPROVER,
            &format!(" {PASSWORD}"),
            "127.0.0.1:50000",
        )
        .await;
    assert_eq!(response.location(), Some("/login"));
}

/// A failed sign-in flashes and redirects to the login page, keeping a
/// sanitised `next` (`url_for("ui_login", next=…)`); the form's `next` wins
/// over the query's; the session stays anonymous.
#[tokio::test]
async fn failed_logins_keep_next() {
    // More attempts than the default throttle allows.
    let app = TestApp::with_throttle(LoginThrottle::new(100, 900.0, 10, Arc::new(|| 0.0)));
    for (path, form_next, location) in [
        ("/login", None, "/login"),
        ("/login?next=/tickets/abc", None, "/login?next=/tickets/abc"),
        (
            "/login?next=/tickets/x%20y?view%3Dall%26a%3D%2B",
            None,
            "/login?next=/tickets/x+y?view%3Dall%26a%3D%2B",
        ),
        ("/login?next=//evil", None, "/login"),
        ("/login?next=/query", Some("/form"), "/login?next=/form"),
        ("/login?next=/query", Some("//evil"), "/login?next=/query"),
        ("/login?next=/query", Some(""), "/login?next=/query"),
    ] {
        let page = app.get(path).await;
        assert_eq!(page.status, StatusCode::OK);
        let token = app.csrf_token();
        let mut fields = vec![
            ("csrf_token", token.as_str()),
            ("username", APPROVER),
            ("password", "wrong"),
        ];
        if let Some(next) = form_next {
            fields.push(("next", next));
        }
        let response = app.send(Call::post(path).form(&fields)).await;
        assert_eq!(
            (response.status, response.location()),
            (StatusCode::FOUND, Some(location)),
            "{path} {form_next:?}"
        );
        assert_eq!(
            app.session().flashes,
            vec![(
                "error".to_owned(),
                "Invalid username or password".to_owned()
            )]
        );
        assert_eq!(app.session().username, None);
        // The next page shows the flash once.
        let shown = app.get(location).await.text();
        assert!(shown.contains("Invalid username or password"), "{shown}");
        assert!(app.session().flashes.is_empty());
    }
}

/// The success redirect goes through Werkzeug's `iri_to_uri`; the form's
/// `next` wins over the query's.
#[tokio::test]
async fn success_redirects_quote_next() {
    for (path, form_next, location) in [
        ("/login?next=/tickets/a%20b", None, "/tickets/a%20b"),
        (
            "/login?next=/tickets/%C3%A9?x=%C3%BC",
            None,
            "/tickets/%C3%A9?x=%C3%BC",
        ),
        ("/login?next=/%5Cevil.example", None, "/%5Cevil.example"),
        (
            "/login?next=/tickets?view=all%23top",
            None,
            "/tickets?view=all#top",
        ),
        (
            "/login?next=/tickets/query",
            Some("/tickets/form"),
            "/tickets/form",
        ),
        (
            "/login?next=/tickets/query",
            Some("javascript:x"),
            "/tickets/query",
        ),
        ("/login", Some("/tickets/form"), "/tickets/form"),
    ] {
        let app = TestApp::new();
        app.get(path).await;
        let token = app.csrf_token();
        let mut fields = vec![
            ("csrf_token", token.as_str()),
            ("username", APPROVER),
            ("password", PASSWORD),
        ];
        if let Some(next) = form_next {
            fields.push(("next", next));
        }
        let response = app.send(Call::post(path).form(&fields)).await;
        assert_eq!(
            (response.status, response.location()),
            (StatusCode::FOUND, Some(location)),
            "{path} {form_next:?}"
        );
    }
}

/// Missing form fields are empty strings: a failure, not an error.
#[tokio::test]
async fn missing_fields_fail_the_check() {
    let app = TestApp::new();
    app.get("/login").await;
    let token = app.csrf_token();
    let response = app
        .send(Call::post("/login").form(&[("csrf_token", &token)]))
        .await;
    assert_eq!(
        (response.status, response.location()),
        (StatusCode::FOUND, Some("/login"))
    );
}

/// A configured hash that is no bcrypt hash never matches (pyca's
/// `ValueError` counts as a mismatch).
#[tokio::test]
async fn a_malformed_configured_hash_never_matches() {
    let app = TestApp::with_env(&[("OPSGATE_UI_PASSWORD_BCRYPT", "not-a-bcrypt-hash")]);
    let response = app
        .post_login("/login", APPROVER, PASSWORD, "127.0.0.1:50000")
        .await;
    assert_eq!(response.location(), Some("/login"));
    assert_eq!(app.session().username, None);
}

/// Without the stored session generation a sign-in with the right
/// credentials is the UI error `session_state_missing`: flash and redirect
/// to `/tickets`, nobody signed in, the throttle not reset.
#[tokio::test]
async fn missing_session_state_is_a_ui_error() {
    let app = TestApp::new();
    app.connection()
        .execute("DELETE FROM ui_session_state", [])
        .unwrap();
    let response = app
        .post_login(
            "/login?next=/tickets/x",
            APPROVER,
            PASSWORD,
            "127.0.0.1:50000",
        )
        .await;
    assert_eq!(
        (response.status, response.location()),
        (StatusCode::FOUND, Some("/tickets"))
    );
    let data = app.session();
    assert_eq!(data.username, None);
    assert_eq!(
        data.flashes,
        vec![(
            "error".to_owned(),
            "Approver session state is missing".to_owned()
        )]
    );
}

/// `POST /login` passes the UI-CSRF layer first: without the token it is the
/// layer's flash and redirect, never a sign-in.
#[tokio::test]
async fn login_requires_the_form_token() {
    let app = TestApp::new();
    let response = app
        .send(Call::post("/login").form(&[("username", APPROVER), ("password", PASSWORD)]))
        .await;
    assert_eq!(
        (response.status, response.location()),
        (StatusCode::FOUND, Some("/tickets"))
    );
    assert_eq!(app.session().username, None);
    assert_eq!(
        app.session().flashes,
        vec![("error".to_owned(), "Invalid form token".to_owned())]
    );
}
