//! Both CSRF checks (`web::csrf`, PLAN.md 4.5.4). The UI-CSRF layer (4.4
//! step 3, S4a): every `POST` outside `/api/`, before routing and
//! authentication; failures flash "Invalid form token" and redirect (4.4
//! error mapping). The API-CSRF check of cookie-authenticated API actions
//! (S4b): after the approver check, before the body.

mod common;

use axum::http::{Method, StatusCode};
use common::{APPROVER, Call, NYXMON_TOKEN, RUNNER_TOKEN, TestApp, ticket_payload};
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_web::session::SessionData;
use opsgate_web::testing::session_cookie;
use serde_json::json;

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
    // The layer lets the request through to the router (a failed sign-in
    // for the login form, 404 for an unknown path).
    let login = app
        .send(Call::post("/login").form(&[("csrf_token", &token), ("username", "x")]))
        .await;
    assert_eq!(
        (login.status, login.location()),
        (StatusCode::FOUND, Some("/login"))
    );
    app.set_cookie(Some(session_cookie(&app.state, &{
        let mut data = app.session();
        data.flashes.clear();
        data
    })));
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

// ------------------------------------------------- API-CSRF (S4b, 4.5.4)

const ACTIONS: [&str; 5] = ["approve", "reject", "cancel", "archive", "unarchive"];

/// `_pending_ticket`.
async fn pending_ticket(app: &TestApp, task_ref: &str) -> String {
    app.create_ticket(NYXMON_TOKEN, ticket_payload("Hardening", Some(task_ref)))
        .await
}

/// A ticket in the state an action needs (`unarchive` needs an archived one).
async fn ticket_for(app: &TestApp, action: &str) -> String {
    let id = pending_ticket(app, &format!("csrf-{action}")).await;
    if action == "unarchive" {
        app.state
            .store()
            .archive_ticket(&id, APPROVER, None, None)
            .unwrap();
    }
    id
}

#[tokio::test]
async fn test_cookie_api_action_without_csrf_header_is_rejected() {
    for action in ACTIONS {
        let app = TestApp::new();
        let ticket_id = ticket_for(&app, action).await;
        app.login("/login").await;
        let before = app.snapshot();
        let response = app
            .send(Call::post(&format!("/api/v1/tickets/{ticket_id}/{action}")))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{action}");
        assert_eq!(response.error(), "csrf_required", "{action}");
        response.assert_security_headers();
        assert_eq!(app.snapshot(), before, "{action}");
    }
}

#[tokio::test]
async fn test_cookie_approve_with_wrong_csrf_header_is_rejected() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "csrf-wrong").await;
    app.login("/login").await;
    let response = app
        .send(
            Call::post(&format!("/api/v1/tickets/{ticket_id}/approve"))
                .header("x-csrf-token", "not-the-token")
                .header("sec-fetch-site", "same-origin"),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error(), "invalid_csrf");
    assert_eq!(app.ticket_state(&ticket_id).await, "pending_approval");
}

#[tokio::test]
async fn test_cookie_approve_with_csrf_header_succeeds() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "csrf-ok").await;
    app.login("/login").await;
    let response = app
        .send(app.csrf_header(Call::post(&format!("/api/v1/tickets/{ticket_id}/approve"))))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["state"], "approved");
    assert_eq!(response.json()["approved_by"], APPROVER);
    // The approval is audited with the approver and the caller.
    let actor: String = app
        .connection()
        .query_row(
            "SELECT actor FROM audit_events WHERE ticket_id = ? AND event_type = 'ticket_approved'",
            [&ticket_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(actor, format!("approver:{APPROVER}"));
}

#[tokio::test]
async fn test_cookie_approve_same_origin_fallback() {
    for (headers, expected) in [
        (vec![("sec-fetch-site", "same-origin")], StatusCode::OK),
        (vec![("sec-fetch-site", "same-site")], StatusCode::FORBIDDEN),
        (
            vec![("sec-fetch-site", "cross-site")],
            StatusCode::FORBIDDEN,
        ),
        (vec![("sec-fetch-site", "none")], StatusCode::FORBIDDEN),
        // Sec-Fetch-Site wins over a matching Origin when both are present.
        (
            vec![
                ("sec-fetch-site", "same-site"),
                ("origin", "http://localhost"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (vec![("origin", "http://localhost")], StatusCode::OK),
        (vec![("origin", "https://localhost")], StatusCode::FORBIDDEN),
        (
            vec![("origin", "http://other.localhost")],
            StatusCode::FORBIDDEN,
        ),
        (vec![("origin", "null")], StatusCode::FORBIDDEN),
    ] {
        let app = TestApp::new();
        let ticket_id = pending_ticket(&app, "csrf-origin").await;
        app.login("/login").await;
        // The Flask test client's host.
        let mut call =
            Call::post(&format!("/api/v1/tickets/{ticket_id}/approve")).header("host", "localhost");
        for (name, value) in &headers {
            call = call.header(name, value);
        }
        let response = app.send(call).await;
        assert_eq!(response.status, expected, "{headers:?}");
        let state = if expected == StatusCode::OK {
            "approved"
        } else {
            "pending_approval"
        };
        assert_eq!(app.ticket_state(&ticket_id).await, state, "{headers:?}");
    }
}

#[tokio::test]
async fn test_bearer_callers_are_unaffected_by_api_csrf() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "csrf-bearer").await;
    let path = format!("/api/v1/tickets/{ticket_id}");
    let runner = app
        .send(Call::new(Method::GET, &path).bearer(RUNNER_TOKEN))
        .await;
    assert_eq!(runner.status, StatusCode::OK);

    // A submit token never authorizes approval, with or without a CSRF header.
    let approve = format!("{path}/approve");
    let submitter = app.send(Call::post(&approve).bearer(NYXMON_TOKEN)).await;
    assert_eq!(submitter.status, StatusCode::UNAUTHORIZED);
    assert_eq!(submitter.error(), "auth_required");

    app.login("/login").await;
    let approved = app.send(app.csrf_header(Call::post(&approve))).await;
    assert_eq!(approved.status, StatusCode::OK);

    let claim = app
        .send(
            Call::post("/api/v1/runner/claim")
                .bearer(RUNNER_TOKEN)
                .json(&json!({"runner_host": "runner-a"})),
        )
        .await;
    assert_eq!(claim.status, StatusCode::OK);
    assert_eq!(claim.json()["ticket"]["id"], ticket_id.as_str());
}

#[tokio::test]
async fn test_unauthenticated_api_action_reports_auth_before_csrf() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "csrf-anon").await;
    for action in ACTIONS {
        let response = app
            .send(Call::post(&format!("/api/v1/tickets/{ticket_id}/{action}")))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{action}");
        assert_eq!(response.error(), "auth_required", "{action}");
    }
    // Also for a ticket that does not exist (no lookup before the checks).
    let missing = app
        .send(Call::post("/api/v1/tickets/missing/approve"))
        .await;
    assert_eq!(missing.error(), "auth_required");
}

#[tokio::test]
async fn test_api_session_actions_reject_non_ascii_csrf_header() {
    for action in ACTIONS {
        let app = TestApp::new();
        let ticket_id = ticket_for(&app, action).await;
        app.login("/login").await;
        let response = app
            .send(
                Call::post(&format!("/api/v1/tickets/{ticket_id}/{action}"))
                    .header("x-csrf-token", "té-über".as_bytes())
                    .json(&json!({"reason": "nope"})),
            )
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{action}");
        assert_eq!(response.error(), "invalid_csrf", "{action}");
    }
}

/// The header token decides when present (also against a same-origin
/// report, as the stripped header value of 4.4); an empty header falls back to the same-origin check; repeated
/// header lines are joined (", ") and never match; a session without a
/// token is checked for the same origin only.
#[tokio::test]
async fn header_token_rules() {
    let app = TestApp::new();
    app.login("/login").await;
    let token = app.csrf_token();
    for (headers, expected) in [
        (vec![("x-csrf-token", token.clone())], "ok"),
        (
            vec![
                ("x-csrf-token", token.clone()),
                ("sec-fetch-site", "cross-site".to_owned()),
            ],
            "ok",
        ),
        (
            vec![
                ("x-csrf-token", format!("{token}x")),
                ("sec-fetch-site", "same-origin".to_owned()),
            ],
            "invalid_csrf",
        ),
        // Spaces and tabs around a header value are not part of it (waitress).
        (vec![("x-csrf-token", format!(" {token}\t"))], "ok"),
        (
            vec![
                ("x-csrf-token", String::new()),
                ("sec-fetch-site", "same-origin".to_owned()),
            ],
            "ok",
        ),
        (vec![("x-csrf-token", String::new())], "csrf_required"),
        (
            vec![
                ("x-csrf-token", token.clone()),
                ("x-csrf-token", token.clone()),
            ],
            "invalid_csrf",
        ),
    ] {
        let ticket_id = pending_ticket(&app, &format!("rules-{}", app.snapshot()[0].len())).await;
        let mut call = Call::post(&format!("/api/v1/tickets/{ticket_id}/archive"));
        for (name, value) in &headers {
            call = call.header(name, value);
        }
        let response = app.send(call).await;
        let outcome = if response.status == StatusCode::OK {
            "ok".to_owned()
        } else {
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{headers:?}");
            response.error()
        };
        assert_eq!(outcome, expected, "{headers:?}");
    }

    // A signed-in session without a CSRF token: the header is ignored.
    let generation = app.state.store().ui_session_generation(APPROVER).unwrap();
    app.set_cookie(Some(session_cookie(
        &app.state,
        &SessionData {
            username: Some(APPROVER.to_owned()),
            auth_at: Some(isoformat_z(&utc_now())),
            session_generation: generation,
            ..SessionData::default()
        },
    )));
    let ticket_id = pending_ticket(&app, "no-session-token").await;
    let path = format!("/api/v1/tickets/{ticket_id}/approve");
    let refused = app
        .send(Call::post(&path).header("x-csrf-token", "anything"))
        .await;
    assert_eq!(refused.error(), "csrf_required");
    let passed = app
        .send(
            Call::post(&path)
                .header("x-csrf-token", "anything")
                .header("sec-fetch-site", "same-origin"),
        )
        .await;
    assert_eq!(passed.status, StatusCode::OK);
}

/// `expected_request_origin` is `http://` and Werkzeug's `request.host`:
/// the `Host` header without the default port, empty when it is no valid
/// host. Without a `Host` header Rust expects the empty host (D-19).
#[tokio::test]
async fn origin_uses_the_request_host() {
    for (host, origin, expected) in [
        (
            Some("opsgate.test:8711"),
            "http://opsgate.test:8711",
            StatusCode::OK,
        ),
        (
            Some("OpsGate.Test:8711"),
            "http://opsgate.test:8711",
            StatusCode::OK,
        ),
        (
            Some("opsgate.test:80"),
            "http://opsgate.test",
            StatusCode::OK,
        ),
        (
            Some("opsgate.test:80"),
            "http://opsgate.test:80",
            StatusCode::FORBIDDEN,
        ),
        (
            Some("100.64.0.1:8711"),
            "http://100.64.0.1:8711",
            StatusCode::OK,
        ),
        (Some("[::1]:8711"), "http://[::1]:8711", StatusCode::OK),
        (
            Some("opsgate.test:8711"),
            "http://opsgate.test",
            StatusCode::FORBIDDEN,
        ),
        (Some("bad host"), "http://bad host", StatusCode::FORBIDDEN),
        (Some("bad host"), "http://", StatusCode::OK),
        (None, "http://", StatusCode::OK),
        (None, "http://localhost", StatusCode::FORBIDDEN),
    ] {
        let app = TestApp::new();
        let ticket_id = pending_ticket(&app, "origin").await;
        app.login("/login").await;
        let mut call =
            Call::post(&format!("/api/v1/tickets/{ticket_id}/approve")).header("origin", origin);
        if let Some(host) = host {
            call = call.header("host", host);
        }
        let response = app.send(call).await;
        assert_eq!(response.status, expected, "{host:?} {origin}");
    }
}

/// The API-CSRF check runs before the body is read: a refused request with
/// an oversized or too deep body is still the 403.
#[tokio::test]
async fn api_csrf_comes_before_the_body() {
    let app = TestApp::new();
    let ticket_id = pending_ticket(&app, "body-order").await;
    app.login("/login").await;
    let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    for action in ["reject", "cancel"] {
        let path = format!("/api/v1/tickets/{ticket_id}/{action}");
        let response = app.send(Call::post(&path).raw_json(deep.clone())).await;
        assert_eq!(response.error(), "csrf_required", "{action}");
        let response = app
            .send(
                Call::post(&path)
                    .header("content-type", "application/json")
                    .body(vec![b' '; opsgate_web::BODY_LIMIT + 1]),
            )
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{action}");
    }
    assert_eq!(app.ticket_state(&ticket_id).await, "pending_approval");
}

/// `test_ui_ticket_actions_reject_non_ascii_form_token` (slice S5's
/// routes): a non-ASCII form token is "Invalid form token" on the detail
/// page, the action is not run and the approver stays signed in.
#[tokio::test]
async fn test_ui_ticket_actions_reject_non_ascii_form_token() {
    for action in ["approve", "reject", "cancel", "archive", "unarchive"] {
        let app = TestApp::new();
        let id = app
            .create_ticket(
                NYXMON_TOKEN,
                ticket_payload(
                    "Non-ASCII form token",
                    Some(&format!("non-ascii-ui-csrf-{action}")),
                ),
            )
            .await;
        app.sign_in();
        let before = app.snapshot();
        let response = app
            .send(
                Call::post(&format!("/tickets/{id}/{action}"))
                    .form(&[("csrf_token", "té-über"), ("reason", "nope")]),
            )
            .await;
        assert_eq!(response.status, StatusCode::FOUND, "{action}");
        assert_eq!(
            response.location(),
            Some(format!("/tickets/{id}").as_str()),
            "{action}"
        );
        let detail = app.get(&format!("/tickets/{id}")).await;
        assert_eq!(detail.status, StatusCode::OK, "{action}");
        assert!(detail.text().contains("Invalid form token"), "{action}");
        assert_eq!(app.snapshot(), before, "{action}");
    }
}
