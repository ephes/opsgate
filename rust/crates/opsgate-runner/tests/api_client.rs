//! The HTTP API client against an in-process axum server (PLAN.md 4.13.1;
//! port of `test_api_normalizes_transport_and_response_errors`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use opsgate_runner::{HttpApiClient, JsonObject, RunnerApi, RunnerApiError};
use serde_json::{Value, json};

const TOKEN: &str = "runner-token-000000000000";

/// One canned answer.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    delay: Duration,
    location: Option<&'static str>,
}

impl Reply {
    fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            content_type: "application/json",
            delay: Duration::ZERO,
            location: None,
        }
    }

    fn json(status: u16, body: Value) -> Self {
        Self::new(status, body.to_string())
    }
}

/// A request as the server saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: Method,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct Fake {
    replies: Mutex<VecDeque<Reply>>,
    seen: Mutex<Vec<Seen>>,
}

async fn handle(
    State(fake): State<Arc<Fake>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let text = |name| {
        headers
            .get(name)
            .map(|value: &header::HeaderValue| value.to_str().unwrap().to_owned())
    };
    fake.seen.lock().unwrap().push(Seen {
        method,
        path: uri.path().to_owned(),
        authorization: text(header::AUTHORIZATION),
        content_type: text(header::CONTENT_TYPE),
        body: body.to_vec(),
    });
    let reply = fake
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| Reply::json(200, json!({})));
    tokio::time::sleep(reply.delay).await;
    let mut response = (
        StatusCode::from_u16(reply.status).unwrap(),
        [(header::CONTENT_TYPE, reply.content_type)],
        reply.body,
    )
        .into_response();
    if let Some(location) = reply.location {
        response
            .headers_mut()
            .insert(header::LOCATION, location.parse().unwrap());
    }
    response
}

struct Server {
    fake: Arc<Fake>,
    client: HttpApiClient,
}

impl Server {
    async fn start(replies: Vec<Reply>) -> Self {
        let fake = Arc::new(Fake {
            replies: Mutex::new(replies.into()),
            ..Fake::default()
        });
        let app = Router::new().fallback(handle).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HttpApiClient::with_timeout(
            &format!("http://{address}"),
            TOKEN,
            Duration::from_millis(500),
        )
        .unwrap();
        Self { fake, client }
    }

    fn seen(&self) -> Vec<Seen> {
        self.fake.seen.lock().unwrap().clone()
    }
}

fn object(value: Value) -> JsonObject {
    value.as_object().unwrap().clone()
}

fn assert_error(error: &RunnerApiError, status: u16, code: &str) {
    assert_eq!(
        (error.status_code, error.error_code.as_str()),
        (status, code),
        "{error}"
    );
    assert!(!error.to_string().contains("secret"), "{error}");
}

/// `test_api_normalizes_transport_and_response_errors[url|timeout|json|unicode|shape]`.
#[tokio::test]
async fn api_normalizes_transport_and_response_errors() {
    // url: nothing listens on the port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client =
        HttpApiClient::with_timeout(&format!("http://{address}"), TOKEN, Duration::from_secs(5))
            .unwrap();
    assert_error(
        &client.get_ticket("ticket").await.unwrap_err(),
        503,
        "transport_error",
    );

    let mut slow = Reply::json(200, json!({"secret": "late"}));
    slow.delay = Duration::from_secs(3);
    let server = Server::start(vec![
        slow,
        Reply::new(200, "secret malformed body"),
        Reply::new(200, b"\xff".to_vec()),
        Reply::new(200, "[]"),
        Reply::new(200, "\u{feff}{}"),
        Reply::new(200, "NaN"),
    ])
    .await;
    let expected = [
        (503, "transport_error"),
        (502, "invalid_response"),
        (502, "invalid_response"),
        (500, "invalid_response"),
        (502, "invalid_response"),
        (502, "invalid_response"),
    ];
    for (status, code) in expected {
        let error = server.client.get_ticket("ticket").await.unwrap_err();
        assert_error(&error, status, code);
    }
}

/// Requests carry the bearer token; claim and status send JSON bodies.
#[tokio::test]
async fn requests_carry_token_and_json_bodies() {
    let ticket = json!({"id": "t1", "state": "running"});
    let server = Server::start(vec![
        Reply::json(200, ticket.clone()),
        Reply::json(200, json!({"ticket": ticket.clone()})),
        Reply::json(200, json!({"state": "running"})),
    ])
    .await;
    assert_eq!(
        server.client.get_ticket("t1").await.unwrap(),
        object(ticket.clone())
    );
    assert_eq!(
        server.client.claim_ticket("runner-a").await.unwrap(),
        Some(object(ticket))
    );
    let payload =
        object(json!({"runner_host": "runner-a", "event": "heartbeat", "tmux_sessions": []}));
    server.client.update_status("t1", &payload).await.unwrap();

    let seen = server.seen();
    let bearer = Some(format!("Bearer {TOKEN}"));
    assert_eq!(seen[0].method, Method::GET);
    assert_eq!(seen[0].path, "/api/v1/tickets/t1");
    assert_eq!(seen[0].authorization, bearer);
    assert_eq!(seen[0].content_type, None);
    assert!(seen[0].body.is_empty());
    assert_eq!(seen[1].method, Method::POST);
    assert_eq!(seen[1].path, "/api/v1/runner/claim");
    assert_eq!(seen[1].authorization, bearer);
    assert_eq!(seen[1].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[1].body).unwrap(),
        json!({"runner_host": "runner-a"})
    );
    assert_eq!(seen[2].path, "/api/v1/runner/t1/status");
    assert_eq!(seen[2].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[2].body).unwrap(),
        Value::Object(payload)
    );
}

/// `claim_ticket`: null or missing ticket → none; a non-object ticket is
/// `(500, invalid_ticket)`; an empty 2xx body is `{}`.
#[tokio::test]
async fn claim_results() {
    let server = Server::start(vec![
        Reply::json(200, json!({"ticket": null})),
        Reply::json(200, json!({})),
        Reply::new(200, ""),
        Reply::json(200, json!({"ticket": [1]})),
        Reply::json(200, json!({"ticket": "x"})),
        Reply::new(204, ""),
    ])
    .await;
    for _ in 0..3 {
        assert_eq!(server.client.claim_ticket("h").await.unwrap(), None);
    }
    for _ in 0..2 {
        let error = server.client.claim_ticket("h").await.unwrap_err();
        assert_error(&error, 500, "invalid_ticket");
    }
    assert_eq!(
        server.client.get_ticket("t").await.unwrap(),
        JsonObject::new()
    );
}

/// HTTP errors keep the status and pass on only the three known codes.
#[tokio::test]
async fn http_errors_expose_only_known_codes() {
    let mut redirect = Reply::new(302, "");
    redirect.location = Some("/api/v1/tickets/other");
    let mut html = Reply::new(404, "<html>secret</html>");
    html.content_type = "text/html";
    let cases = [
        (
            Reply::json(409, json!({"error": "state_changed"})),
            409,
            "state_changed",
        ),
        (
            Reply::json(409, json!({"error": "invalid_state"})),
            409,
            "invalid_state",
        ),
        (
            Reply::json(
                409,
                json!({"error": "runner_host_mismatch", "message": "secret"}),
            ),
            409,
            "runner_host_mismatch",
        ),
        (
            Reply::json(409, json!({"error": "ticket_not_found"})),
            409,
            "http_error",
        ),
        (
            Reply::json(500, json!({"error": "invalid_state"})),
            500,
            "invalid_state",
        ),
        (Reply::json(400, json!({"error": 1})), 400, "http_error"),
        (
            Reply::json(400, json!(["invalid_state"])),
            400,
            "http_error",
        ),
        (Reply::new(401, b"\xff".to_vec()), 401, "http_error"),
        (html, 404, "http_error"),
        (redirect, 302, "http_error"),
    ];
    let (replies, expected): (Vec<_>, Vec<_>) = cases
        .into_iter()
        .map(|(reply, status, code)| (reply, (status, code)))
        .unzip();
    let server = Server::start(replies).await;
    for (status, code) in expected {
        let error = server
            .client
            .update_status("t", &JsonObject::new())
            .await
            .unwrap_err();
        assert_error(&error, status, code);
    }
    // The redirect was not followed.
    assert_eq!(server.seen().len(), 10);
}

#[test]
fn debug_output_redacts_the_token() {
    let client =
        HttpApiClient::with_timeout("http://127.0.0.1:1", TOKEN, Duration::from_secs(1)).unwrap();
    assert!(!format!("{client:?}").contains(TOKEN));
}
