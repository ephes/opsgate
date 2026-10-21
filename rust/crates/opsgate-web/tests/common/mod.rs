//! Shared helpers of the web tests: the application of `tests/test_api.py`
//! (`_build_settings`) on a temporary database, called in-process with
//! `tower::ServiceExt::oneshot` (the Flask test client's role) from a
//! chosen peer address, with a cookie jar for the session cookie.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body_util::BodyExt;
use opsgate_core::settings::{Environment, load_api_settings};
use opsgate_store::Store;
use opsgate_web::session::SessionData;
use opsgate_web::{AppState, app, testing};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

pub const NYXMON_TOKEN: &str = "nyxmon-token-000000000000";
pub const OPENCLAW_TOKEN: &str = "openclaw-token-0000000000";
pub const OPERATOR_TOKEN: &str = "operator-token-00000000000";
pub const RUNNER_TOKEN: &str = "runner-token-000000000000";
pub const APPROVER: &str = "opsgate-admin";
/// A bcrypt hash; S4a never verifies it (`POST /login` is slice S4b's).
pub const PASSWORD_HASH: &str = "$2b$04$fixture.hash.not.verified.in.these.tests.xxxxxxxxxxxx";

/// The security headers every response carries (`EXPECTED_SECURITY_HEADERS`).
pub const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("x-frame-options", "DENY"),
    (
        "content-security-policy",
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "same-origin"),
    ("cache-control", "no-store"),
];

/// One application on its own temporary database.
pub struct TestApp {
    pub state: AppState,
    router: Router,
    pub dir: TempDir,
    /// The browser's session cookie value (`session=<value>`), if any.
    jar: Mutex<Option<String>>,
}

impl TestApp {
    /// The settings of `tests/test_api.py` (`_build_settings`).
    pub fn new() -> Self {
        Self::with_env(&[])
    }

    /// As [`TestApp::new`] with some variables replaced or added.
    pub fn with_env(extra: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("opsgate.sqlite3");
        let exec = dir.path().join("exec");
        let mut vars: Vec<(String, String)> = [
            ("OPSGATE_SERVICE_NAME", "opsgate"),
            ("OPSGATE_BIND_HOST", "127.0.0.1"),
            ("OPSGATE_DB_PATH", db.to_str().unwrap()),
            ("OPSGATE_SESSION_SECRET", &"x".repeat(32)),
            ("OPSGATE_TRUST_PROXY_HEADERS", "false"),
            ("OPSGATE_SESSION_COOKIE_SECURE", "false"),
            ("OPSGATE_UI_SESSION_TIMEOUT_SECONDS", "3600"),
            ("OPSGATE_UI_USERNAME", APPROVER),
            ("OPSGATE_UI_PASSWORD_BCRYPT", PASSWORD_HASH),
            ("OPSGATE_RUNNER_TOKEN", RUNNER_TOKEN),
            ("OPSGATE_SUBMIT_TOKEN_OPENCLAW", OPENCLAW_TOKEN),
            ("OPSGATE_SUBMIT_TOKEN_NYXMON", NYXMON_TOKEN),
            ("OPSGATE_SUBMIT_TOKEN_OPERATOR", OPERATOR_TOKEN),
            ("OPSGATE_REQUIRE_TAILSCALE_CONTEXT", "true"),
            (
                "OPSGATE_ALLOWED_CIDRS",
                "127.0.0.1/32,::1/128,100.64.0.0/10",
            ),
            ("OPSGATE_EXECUTION_DATA_DIR", exec.to_str().unwrap()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        for (key, value) in extra {
            vars.retain(|(name, _)| name != key);
            vars.push(((*key).to_owned(), (*value).to_owned()));
        }
        let mut environment = Environment::from_vars(vars);
        let settings = load_api_settings(&mut environment).expect("test settings are valid");
        let state = AppState::new(Store::open(settings).unwrap()).unwrap();
        Self {
            router: app(state.clone()),
            state,
            dir,
            jar: Mutex::new(None),
        }
    }

    pub fn db_path(&self) -> PathBuf {
        PathBuf::from(&self.state.settings().db_path)
    }

    pub fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.db_path()).unwrap()
    }

    /// Every row of the tables a failed request must not touch
    /// (`database_snapshot`).
    pub fn snapshot(&self) -> Vec<Vec<String>> {
        let connection = self.connection();
        ["tickets", "audit_events", "runner_heartbeats"]
            .iter()
            .map(|table| {
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        Ok((0..columns)
                            .map(|index| format!("{:?}", row.get_ref(index).unwrap()))
                            .collect::<Vec<_>>()
                            .join("|"))
                    })
                    .unwrap()
                    .map(Result::unwrap)
                    .collect()
            })
            .collect()
    }

    /// Replaces the browser's session cookie (`None` clears the jar).
    pub fn set_cookie(&self, cookie: Option<String>) {
        *self.jar.lock().unwrap() = cookie;
    }

    pub fn cookie(&self) -> Option<String> {
        self.jar.lock().unwrap().clone()
    }

    /// Signs the browser in through the test helper of S4a; returns the
    /// session's CSRF token.
    pub fn sign_in(&self) -> String {
        let session = testing::approver_session(&self.state).unwrap();
        self.set_cookie(Some(session.cookie));
        session.csrf_token
    }

    /// The browser's session content.
    pub fn session(&self) -> SessionData {
        let cookie = self.cookie().unwrap_or_default();
        let value = cookie.strip_prefix("session=").unwrap_or_default();
        SessionData::decrypt(value, self.state.session_key()).unwrap_or_default()
    }

    /// Sends `call` with the browser's cookie and keeps the cookie the
    /// response sets or deletes.
    pub async fn send(&self, call: Call) -> TestResponse {
        let mut builder = Request::builder().method(call.method).uri(&call.path);
        for (name, value) in &call.headers {
            builder = builder.header(name.as_str(), HeaderValue::from_bytes(value).unwrap());
        }
        if call.with_jar
            && let Some(cookie) = self.cookie()
        {
            builder = builder.header(COOKIE, cookie);
        }
        let mut request = builder.body(Body::from(call.body)).unwrap();
        if let Some(peer) = call.peer {
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let response = TestResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        };
        if call.with_jar {
            match testing::session_from_response(&self.state, &response.headers) {
                Some(Some(_)) => {
                    let header = response.set_cookie().unwrap();
                    let pair = header.split(';').next().unwrap().to_owned();
                    self.set_cookie(Some(pair));
                }
                Some(None) => self.set_cookie(None),
                None => {}
            }
        }
        response
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        self.send(Call::new(Method::GET, path)).await
    }

    /// Submits a ticket with `token`; panics unless 201.
    pub async fn create_ticket(&self, token: &str, payload: Value) -> String {
        let response = self
            .send(Call::post("/api/v1/tickets").bearer(token).json(&payload))
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
        response.json()["id"].as_str().unwrap().to_owned()
    }
}

/// A ticket body of `create_ticket` in `tests/test_api.py`.
pub fn ticket_payload(title: &str, task_ref: Option<&str>) -> Value {
    let mut payload = json!({
        "title": title,
        "summary": format!("{title} summary"),
        "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}],
    });
    if let Some(task_ref) = task_ref {
        payload["task_ref"] = json!(task_ref);
    }
    payload
}

/// One request.
pub struct Call {
    method: Method,
    path: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    peer: Option<SocketAddr>,
    with_jar: bool,
}

impl Call {
    /// A request from 127.0.0.1 with the browser's cookie.
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: Some("127.0.0.1:50000".parse().unwrap()),
            with_jar: true,
        }
    }

    pub fn post(path: &str) -> Self {
        Self::new(Method::POST, path)
    }

    pub fn header(mut self, name: &str, value: impl AsRef<[u8]>) -> Self {
        self.headers
            .push((name.to_owned(), value.as_ref().to_vec()));
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", format!("Bearer {token}"))
    }

    /// A JSON body with `Content-Type: application/json`.
    pub fn json(self, value: &Value) -> Self {
        self.raw_json(value.to_string())
    }

    /// Body text with `Content-Type: application/json`.
    pub fn raw_json(self, body: impl Into<Vec<u8>>) -> Self {
        self.header(CONTENT_TYPE.as_str(), "application/json")
            .body(body)
    }

    /// A form body (`application/x-www-form-urlencoded`).
    pub fn form(self, fields: &[(&str, &str)]) -> Self {
        let body = fields
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        self.header(CONTENT_TYPE.as_str(), "application/x-www-form-urlencoded")
            .body(body)
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The socket peer (`None`: no connection information).
    pub fn peer(mut self, peer: Option<&str>) -> Self {
        self.peer = peer.map(|address| address.parse().unwrap());
        self
    }

    /// Without the browser's cookie jar (neither sent nor updated).
    pub fn without_jar(mut self) -> Self {
        self.with_jar = false;
        self
    }
}

fn encode(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl TestResponse {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }

    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or_default().to_owned()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn location(&self) -> Option<&str> {
        self.headers
            .get(LOCATION)
            .map(|value| value.to_str().unwrap())
    }

    pub fn set_cookie(&self) -> Option<String> {
        self.headers
            .get(SET_COOKIE)
            .map(|value| value.to_str().unwrap().to_owned())
    }

    pub fn content_type(&self) -> String {
        self.headers
            .get(CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    /// `_assert_security_headers`.
    pub fn assert_security_headers(&self) {
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(
                self.headers.get(name).map(|value| value.to_str().unwrap()),
                Some(value),
                "{name} on {}",
                self.status
            );
        }
        let policy = self.headers["content-security-policy"].to_str().unwrap();
        let directives: Vec<&str> = policy.split(';').map(str::trim).collect();
        for directive in [
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
        ] {
            assert!(directives.contains(&directive), "{directive}");
        }
    }
}
