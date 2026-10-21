//! The network gate and the client address (`web::gate`, PLAN.md 4.4
//! steps 1 and 2).

mod common;

use axum::http::{Method, StatusCode};
use common::{Call, NYXMON_TOKEN, TestApp, ticket_payload};
use serde_json::json;

#[tokio::test]
async fn test_api_rejects_non_tailscale_source_ip() {
    let app = TestApp::new();
    let response = app
        .send(
            Call::post("/api/v1/tickets")
                .bearer(NYXMON_TOKEN)
                .json(&json!({
                    "title": "Forbidden source",
                    "summary": "CIDR enforcement",
                    "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}],
                }))
                .peer(Some("8.8.8.8:1234")),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(
        response.json(),
        json!({"error": "forbidden", "message": "Access denied"})
    );
    assert!(app.snapshot()[0].is_empty());
}

/// Every path but the health endpoint is gated, unknown ones too; UI paths
/// get the `forbidden.html` page, which (as every render) gives the session
/// a CSRF token.
#[tokio::test]
async fn the_gate_covers_every_path_but_health() {
    let app = TestApp::new();
    let outsider =
        |method: Method, path: &str| Call::new(method, path).peer(Some("203.0.113.9:1234"));
    for path in [
        "/api/v1/tickets/x",
        "/api/v1/no-such-route",
        "/api/v1/health/",
    ] {
        let response = app.send(outsider(Method::GET, path)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response.error(), "forbidden", "{path}");
    }
    for (method, path) in [
        (Method::GET, "/login"),
        (Method::GET, "/tickets"),
        (Method::GET, "/no-such-page"),
        (Method::POST, "/login"),
        (Method::HEAD, "/login"),
    ] {
        app.set_cookie(None);
        let response = app.send(outsider(method.clone(), path)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(response.content_type(), "text/html; charset=utf-8");
        if method != Method::HEAD {
            assert!(response.text().contains("<h1>Forbidden</h1>"));
        }
        assert!(app.session().csrf_token.is_some(), "{method} {path}");
    }
    // The health endpoint is exempt, for every method.
    assert_eq!(
        app.send(outsider(Method::GET, "/api/v1/health"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.send(outsider(Method::POST, "/api/v1/health"))
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        app.send(outsider(Method::GET, "/api%2Fv1/health"))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn addresses_against_networks() {
    let app = TestApp::new();
    for (peer, allowed) in [
        (Some("127.0.0.1:1"), true),
        (Some("100.64.0.1:1"), true),
        (Some("100.127.255.255:1"), true),
        (Some("100.128.0.0:1"), false),
        (Some("[::1]:1"), true),
        // IPv4-mapped addresses do not match IPv4 networks.
        (Some("[::ffff:127.0.0.1]:1"), false),
        (Some("[fd7a:115c:a1e0::1]:1"), false),
        // No connection information: an empty address is refused.
        (None, false),
    ] {
        let response = app
            .send(Call::new(Method::GET, "/api/v1/tickets/x").peer(peer))
            .await;
        let expected = if allowed {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status, expected, "{peer:?}");
    }
    assert!(opsgate_web::gate::is_allowed_network(
        "fe80::1%en0",
        &["fe80::/10".parse().unwrap()]
    ));
    assert!(!opsgate_web::gate::is_allowed_network(
        "",
        &["0.0.0.0/0".parse().unwrap()]
    ));
}

#[tokio::test]
async fn the_gate_can_be_switched_off() {
    let app = TestApp::with_env(&[("OPSGATE_REQUIRE_TAILSCALE_CONTEXT", "false")]);
    let response = app
        .send(Call::new(Method::GET, "/api/v1/tickets/x").peer(Some("8.8.8.8:1")))
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

/// `test_trusted_proxy_headers_restore_client_ip_for_access_and_audit` with
/// the production expectation (PLAN.md 4.4 step 1): waitress drops the
/// forwarded headers before the application, so even a trusting process
/// gates and audits the socket peer.
#[tokio::test]
async fn test_trusted_proxy_headers_restore_client_ip_for_access_and_audit() {
    let app = TestApp::with_env(&[("OPSGATE_TRUST_PROXY_HEADERS", "true")]);
    let proxied = |peer: &str| {
        Call::post("/api/v1/tickets")
            .bearer(NYXMON_TOKEN)
            .header("x-forwarded-for", "100.100.100.42")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "ops.example")
            .header("forwarded", "for=100.100.100.42")
            .json(&ticket_payload("Proxy path", Some("proxy-audit-1")))
            .peer(Some(peer))
    };
    let refused = app.send(proxied("203.0.113.8:1234")).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    let created = app.send(proxied("127.0.0.1:1234")).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let ticket_id = created.json()["id"].as_str().unwrap().to_owned();
    let source_ip: String = app
        .connection()
        .query_row(
            "SELECT source_ip FROM audit_events WHERE ticket_id = ?1 AND event_type = 'ticket_created'",
            [&ticket_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(source_ip, "127.0.0.1");
}
