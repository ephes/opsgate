//! The bearer routes and health over HTTP (`web::api`, slice S4a): ports
//! of `tests/test_api.py` and the JSON body rules of PLAN.md 4.6.

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, NYXMON_TOKEN, OPENCLAW_TOKEN, RUNNER_TOKEN, TestApp, ticket_payload};
use serde_json::{Value, json};

#[tokio::test]
async fn test_create_and_get_ticket_submit_token() {
    let app = TestApp::new();
    let created = app
        .send(
            Call::post("/api/v1/tickets").bearer(NYXMON_TOKEN).json(&json!({
                "title": "Investigate disk alert",
                "summary": "Disk usage crossed threshold",
                "task_ref": "alert-123",
                "execution_plan": [
                    {"role": "investigator", "agent": "codex", "prompt_markdown": "Investigate issue"}
                ],
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.content_type(), "application/json");
    let created = created.json();
    assert_eq!(created["state"], "pending_approval");
    assert_eq!(created["source"], "nyxmon");

    let fetched = app
        .send(
            Call::new(
                Method::GET,
                &format!("/api/v1/tickets/{}", created["id"].as_str().unwrap()),
            )
            .bearer(NYXMON_TOKEN),
        )
        .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.json(), created);
}

#[tokio::test]
async fn test_get_ticket_forbidden_for_other_submitter_source() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(
            NYXMON_TOKEN,
            ticket_payload("Cross source", Some("cross-source-1")),
        )
        .await;
    let response = app
        .send(
            Call::new(Method::GET, &format!("/api/v1/tickets/{ticket_id}")).bearer(OPENCLAW_TOKEN),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error(), "forbidden");
}

/// The order of `api_get_ticket`: 401, then 404, then 403; the runner token
/// and an approver session read every ticket.
#[tokio::test]
async fn get_ticket_checks_in_python_order() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Order", None))
        .await;
    let path = format!("/api/v1/tickets/{ticket_id}");

    let anonymous = app
        .send(Call::new(Method::GET, "/api/v1/tickets/missing"))
        .await;
    assert_eq!(
        (anonymous.status, anonymous.error().as_str()),
        (StatusCode::UNAUTHORIZED, "auth_required")
    );
    let missing = app
        .send(Call::new(Method::GET, "/api/v1/tickets/missing").bearer(OPENCLAW_TOKEN))
        .await;
    assert_eq!(
        (missing.status, missing.error().as_str()),
        (StatusCode::NOT_FOUND, "ticket_not_found")
    );
    for token in [RUNNER_TOKEN, NYXMON_TOKEN] {
        let response = app.send(Call::new(Method::GET, &path).bearer(token)).await;
        assert_eq!(response.status, StatusCode::OK, "{token}");
    }

    app.sign_in();
    let approver = app.send(Call::new(Method::GET, &path)).await;
    assert_eq!(approver.status, StatusCode::OK);
    assert_eq!(approver.json()["id"], ticket_id.as_str());
    // A submitter of another source is refused even with an approver session.
    let mixed = app
        .send(Call::new(Method::GET, &path).bearer(OPENCLAW_TOKEN))
        .await;
    assert_eq!(mixed.status, StatusCode::FORBIDDEN);
    // HEAD answers the GET route.
    let head = app
        .send(Call::new(Method::HEAD, &path).bearer(RUNNER_TOKEN))
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
}

/// `test_health_endpoint_reports_ok` (web half; the store half is
/// `opsgate-store/tests/create.rs`).
#[tokio::test]
async fn test_health_endpoint_reports_ok() {
    let app = TestApp::new();
    let response = app.get("/api/v1/health").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["db"], "ok");
    assert_eq!(body["service"], "opsgate");
    assert_eq!(body["ticket_counters"], json!({}));
}

#[tokio::test]
async fn test_health_reports_no_runner_heartbeat_before_first_poll() {
    let app = TestApp::new();
    let body = app.get("/api/v1/health").await.json();
    assert_eq!(body["runner_last_heartbeat"], Value::Null);
    assert_eq!(body["runner_host"], Value::Null);
}

#[tokio::test]
async fn test_runner_claim_without_token_records_no_heartbeat() {
    let app = TestApp::new();
    let claim = app
        .send(Call::post("/api/v1/runner/claim").json(&json!({"runner_host": "runner-anon"})))
        .await;
    assert_eq!(claim.status, StatusCode::UNAUTHORIZED);
    assert_eq!(claim.error(), "invalid_runner_token");
    assert_eq!(
        app.get("/api/v1/health").await.json()["runner_last_heartbeat"],
        Value::Null
    );
}

async fn claim(app: &TestApp, call: Call) -> Value {
    let response = app.send(call.bearer(RUNNER_TOKEN)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()
}

fn heartbeat_hosts(app: &TestApp) -> Vec<String> {
    let connection = app.connection();
    let mut statement = connection
        .prepare("SELECT runner_host FROM runner_heartbeats ORDER BY runner_host")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The runner host of a claim: the body's `runner_host`, else the client
/// address; falsy bodies and bodies without JSON are `{}`.
#[tokio::test]
async fn claim_derives_the_runner_host() {
    let app = TestApp::new();
    let idle = claim(
        &app,
        Call::post("/api/v1/runner/claim").json(&json!({"runner_host": " runner-a "})),
    )
    .await;
    assert_eq!(idle, json!({"ticket": null}));
    for body in ["null", "false", "0", "0.0", "\"\"", "[]", "{}", "{"] {
        claim(&app, Call::post("/api/v1/runner/claim").raw_json(body)).await;
    }
    claim(
        &app,
        Call::post("/api/v1/runner/claim").body("{\"runner_host\": \"plain\"}"),
    )
    .await;
    claim(
        &app,
        Call::post("/api/v1/runner/claim")
            .json(&json!({"runner_host": "v6"}))
            .peer(Some("[::1]:4000")),
    )
    .await;
    claim(
        &app,
        Call::post("/api/v1/runner/claim").json(&json!({"runner_host": null})),
    )
    .await;
    assert_eq!(
        heartbeat_hosts(&app),
        vec!["127.0.0.1", "None", "runner-a", "v6"]
    );

    // D-4 and D-3: a truthy non-object body, a container as runner_host.
    for body in ["[1]", "\"x\"", "1", "true", "{\"runner_host\": [\"a\"]}"] {
        let response = app
            .send(
                Call::post("/api/v1/runner/claim")
                    .bearer(RUNNER_TOKEN)
                    .raw_json(body),
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(response.error(), "invalid_json", "{body}");
    }
}

/// A claim over HTTP hands out the approved ticket, recorded with the
/// client address and user agent; the status route reports on it.
#[tokio::test]
async fn claim_and_status_over_http() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Claim", Some("claim-1")))
        .await;
    app.state
        .store()
        .approve_ticket(&ticket_id, common::APPROVER, None, None)
        .unwrap();
    let claimed = claim(
        &app,
        Call::post("/api/v1/runner/claim")
            .json(&json!({"runner_host": "runner-a"}))
            .header("user-agent", "agent/1 é"),
    )
    .await;
    assert_eq!(claimed["ticket"]["id"], ticket_id.as_str());
    assert_eq!(claimed["ticket"]["state"], "running");
    assert_eq!(claimed["ticket"]["runner_host"], "runner-a");
    let (source_ip, user_agent): (String, String) = app
        .connection()
        .query_row(
            "SELECT source_ip, user_agent FROM audit_events WHERE event_type = 'runner_claimed'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(source_ip, "127.0.0.1");
    // Header bytes are latin-1, as waitress hands them to the application.
    assert_eq!(user_agent, "agent/1 Ã©");

    let path = format!("/api/v1/runner/{ticket_id}/status");
    let status = app
        .send(
            Call::post(&path)
                .bearer(RUNNER_TOKEN)
                .json(&json!({"runner_host": "runner-a", "state": "succeeded"})),
        )
        .await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.text());
    assert_eq!(status.json()["state"], "succeeded");

    // Another host is the peer address when the body names none.
    let other = app
        .send(Call::post(&path).bearer(RUNNER_TOKEN).json(&json!({})))
        .await;
    assert_eq!(
        (other.status, other.error().as_str()),
        (StatusCode::CONFLICT, "invalid_state")
    );
    let missing = app
        .send(
            Call::post("/api/v1/runner/missing/status")
                .bearer(RUNNER_TOKEN)
                .json(&json!({})),
        )
        .await;
    assert_eq!(
        (missing.status, missing.error().as_str()),
        (StatusCode::NOT_FOUND, "ticket_not_found")
    );
    for body in ["[]", "null", "{", "1"] {
        let response = app
            .send(Call::post(&path).bearer(RUNNER_TOKEN).raw_json(body))
            .await;
        assert_eq!(
            (response.status, response.error().as_str()),
            (StatusCode::BAD_REQUEST, "invalid_json"),
            "{body}"
        );
    }
}

/// `test_json_decode_errors_are_domain_responses` for the bearer endpoints
/// (the approver's reject and cancel cases need slice S4b's routes): a body
/// nested 2000 levels deep is 400 `invalid_json` and changes nothing.
#[tokio::test]
async fn test_json_decode_errors_are_domain_responses() {
    let app = TestApp::new();
    let body = format!("{{\"context\":{}0{}}}", "[".repeat(2000), "]".repeat(2000));
    for (endpoint, token) in [
        ("/api/v1/tickets", NYXMON_TOKEN),
        ("/api/v1/runner/missing/status", RUNNER_TOKEN),
        ("/api/v1/runner/claim", RUNNER_TOKEN),
    ] {
        let before = app.snapshot();
        let response = app
            .send(Call::post(endpoint).bearer(token).raw_json(body.clone()))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{endpoint}");
        assert_eq!(response.error(), "invalid_json", "{endpoint}");
        assert_eq!(app.snapshot(), before, "{endpoint}");
    }
}

#[tokio::test]
async fn test_real_json_nesting_limit() {
    for depth in [64_usize, 65, 129, 2000] {
        let app = TestApp::new();
        let before = app.snapshot();
        let body = format!(
            "{{\"title\":\"Nesting\",\"summary\":\"Boundary\",\"execution_plan\":\
             [{{\"role\":\"investigator\",\"agent\":\"codex\",\"prompt_markdown\":\"Inspect\"}}],\
             \"context\":{{\"nested\":{}0{}}}}}",
            "[".repeat(depth - 2),
            "]".repeat(depth - 2)
        );
        let response = app
            .send(
                Call::post("/api/v1/tickets")
                    .bearer(NYXMON_TOKEN)
                    .raw_json(body),
            )
            .await;
        if depth == 64 {
            assert_eq!(response.status, StatusCode::CREATED);
        } else {
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "{depth}");
            assert_eq!(response.error(), "invalid_json", "{depth}");
            assert_eq!(app.snapshot(), before, "{depth}");
        }
    }
}

#[tokio::test]
async fn test_malformed_required_json_retains_domain_response() {
    let app = TestApp::new();
    for (endpoint, token) in [
        ("/api/v1/tickets", NYXMON_TOKEN),
        ("/api/v1/runner/missing/status", RUNNER_TOKEN),
    ] {
        let before = app.snapshot();
        let response = app
            .send(Call::post(endpoint).bearer(token).raw_json("{"))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{endpoint}");
        assert_eq!(response.error(), "invalid_json", "{endpoint}");
        assert_eq!(app.snapshot(), before, "{endpoint}");
    }
}

/// Only `application/json` and `application/*+json` bodies are JSON; a
/// UTF-8 BOM is accepted.
#[tokio::test]
async fn json_content_types() {
    let app = TestApp::new();
    let payload = ticket_payload("Types", None).to_string();
    for (content_type, status) in [
        ("text/plain", StatusCode::BAD_REQUEST),
        ("application/x-www-form-urlencoded", StatusCode::BAD_REQUEST),
        (
            "application/vnd.opsgate+json; charset=utf-8",
            StatusCode::CREATED,
        ),
        ("APPLICATION/JSON", StatusCode::CREATED),
    ] {
        let response = app
            .send(
                Call::post("/api/v1/tickets")
                    .bearer(NYXMON_TOKEN)
                    .header("content-type", content_type)
                    .body(payload.clone()),
            )
            .await;
        assert_eq!(response.status, status, "{content_type}");
    }
    let mut bom = b"\xEF\xBB\xBF".to_vec();
    bom.extend_from_slice(payload.as_bytes());
    let response = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(NYXMON_TOKEN)
                .raw_json(bom),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
}

/// The token is checked before the body is read; bodies over 8 MiB are 413
/// (D-5).
#[tokio::test]
async fn body_limit_applies_after_the_token_check() {
    let app = TestApp::new();
    let huge = vec![b' '; opsgate_web::BODY_LIMIT + 1];
    let anonymous = app
        .send(Call::post("/api/v1/tickets").raw_json(huge.clone()))
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    for (endpoint, token) in [
        ("/api/v1/tickets", NYXMON_TOKEN),
        ("/api/v1/runner/claim", RUNNER_TOKEN),
        ("/api/v1/runner/x/status", RUNNER_TOKEN),
    ] {
        let response = app
            .send(Call::post(endpoint).bearer(token).raw_json(huge.clone()))
            .await;
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE, "{endpoint}");
        response.assert_security_headers();
    }
    let mut fits = ticket_payload("Fits", None).to_string().into_bytes();
    fits.resize(opsgate_web::BODY_LIMIT, b' ');
    let response = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(NYXMON_TOKEN)
                .raw_json(fits),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
}

/// A stored row the store cannot read is a 500 without details, as
/// Python's unhandled exceptions.
#[tokio::test]
async fn unreadable_stored_rows_are_500() {
    let app = TestApp::new();
    let ticket_id = app
        .create_ticket(NYXMON_TOKEN, ticket_payload("Corrupt", None))
        .await;
    app.connection()
        .execute(
            "UPDATE tickets SET context_json = '{' WHERE id = ?1",
            [&ticket_id],
        )
        .unwrap();
    let response = app
        .send(Call::new(Method::GET, &format!("/api/v1/tickets/{ticket_id}")).bearer(NYXMON_TOKEN))
        .await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!response.text().contains("context_json"));
    response.assert_security_headers();
}

/// Routing (4.3): one segment per id, no trailing-slash variants, 405 for
/// another method, `%2F` separates segments as in Werkzeug.
#[tokio::test]
async fn routing_methods_and_unknown_paths() {
    let app = TestApp::new();
    for (method, path, status) in [
        (
            Method::GET,
            "/api/v1/tickets",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::PUT,
            "/api/v1/tickets",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            "/api/v1/runner/claim",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::DELETE,
            "/api/v1/tickets/x",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (Method::GET, "/api/v1/health/", StatusCode::NOT_FOUND),
        (Method::GET, "/api/v1/tickets/a/b", StatusCode::NOT_FOUND),
        (Method::GET, "/api/v1/tickets/a%2Fb", StatusCode::NOT_FOUND),
        (Method::GET, "/api/v2/health", StatusCode::NOT_FOUND),
        (Method::HEAD, "/api/v1/health", StatusCode::OK),
        (Method::GET, "/api%2Fv1/health", StatusCode::OK),
        (Method::GET, "//api/v1/health", StatusCode::OK),
        (
            Method::POST,
            "/api/v1/health",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let response = app.send(Call::new(method.clone(), path)).await;
        assert_eq!(response.status, status, "{method} {path}");
        response.assert_security_headers();
    }
    // A percent-encoded id reaches the store decoded.
    let response = app
        .send(Call::new(Method::GET, "/api/v1/tickets/a%20b").bearer(NYXMON_TOKEN))
        .await;
    assert_eq!(response.error(), "ticket_not_found");
}
