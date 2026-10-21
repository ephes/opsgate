//! `GET`/`HEAD /login` (`web::login`, PLAN.md 4.5.3) and the template
//! environment it renders through (6.3).

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, TestApp};
use opsgate_web::session::SessionData;
use opsgate_web::testing::session_cookie;

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
