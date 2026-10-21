//! The UI-CSRF layer (`web::csrf`, PLAN.md 4.4 step 3, 4.5.4): every `POST`
//! outside `/api/`, before routing and authentication; failures flash
//! "Invalid form token" and redirect (4.4 error mapping).

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, NYXMON_TOKEN, TestApp, ticket_payload};

fn flashes(app: &TestApp) -> Vec<(String, String)> {
    app.session().flashes
}

fn invalid_form_token() -> Vec<(String, String)> {
    vec![("error".to_owned(), "Invalid form token".to_owned())]
}

#[tokio::test]
async fn posts_without_the_token_flash_and_redirect() {
    for (path, location) in [
        ("/tickets", "/tickets"),
        ("/login", "/tickets"),
        ("/logout", "/tickets"),
        ("/no-such-page", "/tickets"),
        ("/tickets/abc/approve", "/tickets/abc"),
        ("/tickets/a%20b/archive", "/tickets/a%20b"),
        ("/tickets/abc/steps/3/log", "/tickets/abc"),
        ("/tickets/abc/steps/x/log", "/tickets"),
    ] {
        let app = TestApp::new();
        let response = app.send(Call::post(path).form(&[("title", "x")])).await;
        assert_eq!(response.status, StatusCode::FOUND, "{path}");
        assert_eq!(response.location(), Some(location), "{path}");
        assert_eq!(flashes(&app), invalid_form_token(), "{path}");
        // The check gave the session a token first.
        assert!(app.session().csrf_token.is_some(), "{path}");
    }
}

#[tokio::test]
async fn the_session_token_passes() {
    let app = TestApp::new();
    let token = app.sign_in();
    // The routes are later slices'; the layer lets the request through to
    // the router (405 for the login page's POST before slice S4b, 404 for
    // an unknown path).
    let login = app
        .send(Call::post("/login").form(&[("csrf_token", &token), ("username", "x")]))
        .await;
    assert_eq!(login.status, StatusCode::METHOD_NOT_ALLOWED);
    let unknown = app
        .send(Call::post("/no-such-page").form(&[("csrf_token", &token)]))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert!(flashes(&app).is_empty());

    for (name, fields) in [
        ("tampered", vec![("csrf_token", format!("{token}x"))]),
        ("non-ASCII", vec![("csrf_token", "té-über".to_owned())]),
        ("empty", vec![("csrf_token", String::new())]),
        // `get` returns the first value.
        (
            "second value",
            vec![
                ("csrf_token", "wrong".to_owned()),
                ("csrf_token", token.clone()),
            ],
        ),
    ] {
        let fields: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let response = app.send(Call::post("/no-such-page").form(&fields)).await;
        assert_eq!(response.status, StatusCode::FOUND, "{name}");
        let shown = flashes(&app);
        assert_eq!(shown, invalid_form_token(), "{name}");
        app.set_cookie(Some(opsgate_web::testing::session_cookie(&app.state, &{
            let mut data = app.session();
            data.flashes.clear();
            data
        })));
    }
}

/// Only a urlencoded form carries the token: JSON bodies, multipart forms
/// (D-17) and query strings do not.
#[tokio::test]
async fn only_form_bodies_carry_the_token() {
    let app = TestApp::new();
    let token = app.sign_in();
    for call in [
        Call::post("/no-such-page").raw_json(format!("{{\"csrf_token\": \"{token}\"}}")),
        Call::post(&format!("/no-such-page?csrf_token={token}")),
        Call::post("/no-such-page")
            .header("content-type", "multipart/form-data; boundary=x")
            .body(format!(
                "--x\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{token}\r\n--x--\r\n"
            )),
    ] {
        let response = app.send(call).await;
        assert_eq!(response.status, StatusCode::FOUND);
    }
}

/// `/api/…`, other methods and the gate's refusals are not checked here.
#[tokio::test]
async fn api_paths_and_other_methods_are_exempt() {
    let app = TestApp::new();
    let created = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(NYXMON_TOKEN)
                .json(&ticket_payload("Api", None)),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.set_cookie(), None);
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let response = app.send(Call::new(method.clone(), "/no-such-page")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{method}");
    }
    let api_unknown = app.send(Call::post("/api/v1/no-such-route")).await;
    assert_eq!(api_unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(app.cookie(), None);
}

#[tokio::test]
async fn oversized_forms_are_413() {
    let app = TestApp::new();
    let response = app
        .send(
            Call::post("/no-such-page")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(vec![b'a'; opsgate_web::BODY_LIMIT + 1]),
        )
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    response.assert_security_headers();
}
