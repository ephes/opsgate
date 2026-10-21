//! The runner's client of the OpsGate API (`RunnerApiClient`, PLAN.md 4.13.1).
//!
//! Every call sends `Authorization: Bearer <runner token>`; claim and status
//! send a JSON body. Failures become a [`RunnerApiError`] with Python's status
//! and category: a 2xx body that is not UTF-8 JSON is `(502,
//! invalid_response)`, a JSON value that is not an object `(500,
//! invalid_response)`, an HTTP error `(status, code)` where `code` is the
//! body's `error` only for `invalid_state`, `state_changed` and
//! `runner_host_mismatch` (else `http_error`), and every transport failure
//! (connect, timeout, protocol, body read) `(503, transport_error)`. Error
//! texts never contain response bodies or transport diagnostics.
//!
//! Plain HTTP only (D-10). Redirects are not followed and proxy variables
//! are ignored: the API answers its runner routes directly on loopback
//! (Python's `urlopen` would follow a `GET` redirect and honour `http_proxy`;
//! neither occurs in production).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use opsgate_core::settings::RunnerSettings;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value};

/// A JSON object as the runner handles tickets, status payloads and
/// artifacts (a Python `dict`).
pub type JsonObject = Map<String, Value>;

/// `urlopen(request, timeout=15)`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The API error codes the client passes on; every other code is
/// `http_error` (`RunnerApiClient._request`).
const EXPOSED_ERROR_CODES: [&str; 3] = ["invalid_state", "state_changed", "runner_host_mismatch"];

/// A failed API call (`RunnerApiError`): an HTTP-like status and a category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerApiError {
    /// The HTTP status, or 500/502/503 for the client's own categories.
    pub status_code: u16,
    /// `invalid_state`, `state_changed`, `runner_host_mismatch`,
    /// `http_error`, `invalid_response`, `invalid_ticket` or
    /// `transport_error` (fakes may use others).
    pub error_code: String,
    message: &'static str,
}

impl RunnerApiError {
    /// An error with a fixed message (never derived from a response).
    pub fn new(message: &'static str, status_code: u16, error_code: impl Into<String>) -> Self {
        Self {
            status_code,
            error_code: error_code.into(),
            message,
        }
    }

    fn transport() -> Self {
        Self::new("Runner API transport failure", 503, "transport_error")
    }

    fn invalid_response(status_code: u16) -> Self {
        Self::new("Invalid JSON response", status_code, "invalid_response")
    }

    /// The fixed description of the error.
    pub fn message(&self) -> &str {
        self.message
    }
}

impl std::fmt::Display for RunnerApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (status={} category={})",
            self.message, self.status_code, self.error_code
        )
    }
}

impl std::error::Error for RunnerApiError {}

/// The API calls of the runner. [`HttpApiClient`] talks to the real API;
/// tests use fakes.
pub trait RunnerApi: Send + Sync {
    /// `POST /api/v1/runner/claim` with `{"runner_host": …}`: the claimed
    /// ticket, or `None` when the queue is empty. A `ticket` that is neither
    /// null nor an object is `(500, invalid_ticket)`.
    fn claim_ticket(
        &self,
        runner_host: &str,
    ) -> impl Future<Output = Result<Option<JsonObject>, RunnerApiError>> + Send;

    /// `GET /api/v1/tickets/<id>`.
    fn get_ticket(
        &self,
        ticket_id: &str,
    ) -> impl Future<Output = Result<JsonObject, RunnerApiError>> + Send;

    /// `POST /api/v1/runner/<id>/status` with `payload`.
    fn update_status(
        &self,
        ticket_id: &str,
        payload: &JsonObject,
    ) -> impl Future<Output = Result<JsonObject, RunnerApiError>> + Send;
}

impl<T: RunnerApi> RunnerApi for Arc<T> {
    fn claim_ticket(
        &self,
        runner_host: &str,
    ) -> impl Future<Output = Result<Option<JsonObject>, RunnerApiError>> + Send {
        (**self).claim_ticket(runner_host)
    }

    fn get_ticket(
        &self,
        ticket_id: &str,
    ) -> impl Future<Output = Result<JsonObject, RunnerApiError>> + Send {
        (**self).get_ticket(ticket_id)
    }

    fn update_status(
        &self,
        ticket_id: &str,
        payload: &JsonObject,
    ) -> impl Future<Output = Result<JsonObject, RunnerApiError>> + Send {
        (**self).update_status(ticket_id, payload)
    }
}

/// The HTTP client (`RunnerApiClient`).
#[derive(Clone)]
pub struct HttpApiClient {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for HttpApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpApiClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl HttpApiClient {
    /// A client for `OPSGATE_RUNNER_API_BASE_URL` with the runner token and
    /// the 15 s timeout.
    pub fn new(settings: &RunnerSettings) -> reqwest::Result<Self> {
        Self::with_timeout(
            &settings.runner_api_base_url,
            &settings.runner_token,
            REQUEST_TIMEOUT,
        )
    }

    /// A client with an explicit base URL (without trailing slash), token
    /// and per-request timeout.
    pub fn with_timeout(base_url: &str, token: &str, timeout: Duration) -> reqwest::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            base_url: base_url.to_owned(),
            token: token.to_owned(),
            client,
        })
    }

    /// `RunnerApiClient._request`.
    async fn request(
        &self,
        method: Method,
        path: &str,
        payload: Option<&JsonObject>,
    ) -> Result<JsonObject, RunnerApiError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token));
        if let Some(payload) = payload {
            // `json.dumps(payload, sort_keys=True)`; the text is P2.
            let body = serde_json::to_vec(payload).map_err(|_| RunnerApiError::transport())?;
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| RunnerApiError::transport())?;
        let status = response.status();
        let body = response.bytes().await;
        if !status.is_success() {
            let code = body
                .ok()
                .and_then(|body| exposed_error_code(&body))
                .unwrap_or("http_error");
            return Err(RunnerApiError::new(
                "Runner API HTTP error",
                status.as_u16(),
                code,
            ));
        }
        let body = body.map_err(|_| RunnerApiError::transport())?;
        decode_object(&body)
    }
}

/// The 2xx body: UTF-8 (`bytes.decode("utf-8")`, a BOM is not skipped),
/// empty → `{}`, `json.loads`, an object.
fn decode_object(body: &[u8]) -> Result<JsonObject, RunnerApiError> {
    let text = std::str::from_utf8(body).map_err(|_| RunnerApiError::invalid_response(502))?;
    let text = if text.is_empty() { "{}" } else { text };
    match opsgate_core::json::parse(text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(RunnerApiError::invalid_response(500)),
        Err(_) => Err(RunnerApiError::invalid_response(502)),
    }
}

/// The `error` of an HTTP error body, if it is one the client passes on.
fn exposed_error_code(body: &[u8]) -> Option<&'static str> {
    let text = std::str::from_utf8(body).ok()?;
    let Ok(Value::Object(object)) = opsgate_core::json::parse(text) else {
        return None;
    };
    let code = object.get("error")?.as_str()?;
    EXPOSED_ERROR_CODES
        .iter()
        .copied()
        .find(|known| *known == code)
}

impl RunnerApi for HttpApiClient {
    async fn claim_ticket(&self, runner_host: &str) -> Result<Option<JsonObject>, RunnerApiError> {
        let mut payload = JsonObject::new();
        payload.insert("runner_host".to_owned(), Value::from(runner_host));
        let body = self
            .request(Method::POST, "/api/v1/runner/claim", Some(&payload))
            .await?;
        match body.get("ticket") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Object(ticket)) => Ok(Some(ticket.clone())),
            Some(_) => Err(RunnerApiError::new(
                "runner claim returned invalid ticket payload",
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "invalid_ticket",
            )),
        }
    }

    async fn get_ticket(&self, ticket_id: &str) -> Result<JsonObject, RunnerApiError> {
        self.request(Method::GET, &format!("/api/v1/tickets/{ticket_id}"), None)
            .await
    }

    async fn update_status(
        &self,
        ticket_id: &str,
        payload: &JsonObject,
    ) -> Result<JsonObject, RunnerApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/runner/{ticket_id}/status"),
            Some(payload),
        )
        .await
    }
}
