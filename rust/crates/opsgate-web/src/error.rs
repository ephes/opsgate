//! Error mapping (`handle_service_error`, `api_error`, PLAN.md 4.4).
//!
//! Handlers and layers return [`AppError`]. Its response carries the error
//! in the response extensions; the [`map_errors`] layer, which knows the
//! request path and the session, turns it into the answer Python gives:
//!
//! - a `ServiceError` on `/api/…`: `{"error": code, "message": text}` with
//!   its status;
//! - a `ServiceError` elsewhere: the message flashed as `error` and a 302 to
//!   the ticket's detail page when the path is a ticket action or step log
//!   path (`TICKET_ACTION_PATH_PATTERN`, `TICKET_LOG_PATH_PATTERN`), else to
//!   `/tickets`;
//! - anything else (SQLite errors, unreadable stored rows, a template that
//!   fails): 500 without details (Python's unhandled exceptions), one log
//!   line naming the error (D-12);
//! - an oversized body: 413 (D-5).

use std::sync::{Arc, LazyLock};

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use opsgate_core::error::ServiceError;
use opsgate_core::json::canonical_json;
use opsgate_store::StoreError;
use regex::Regex;
use serde_json::{Value, json};

use crate::path::RequestPath;
use crate::session::SessionHandle;
use crate::urls;

/// Why a request failed.
#[derive(Debug)]
pub enum AppError {
    /// A rejected operation (`ServiceError`).
    Service(ServiceError),
    /// An unhandled error: 500. The text names the error for the log line,
    /// never a secret or a request value.
    Internal(String),
    /// A request body larger than [`crate::BODY_LIMIT`] (D-5): 413.
    PayloadTooLarge,
    /// The request body could not be read (the client went away): 400.
    BodyUnreadable,
}

impl AppError {
    /// `ServiceError(message, status, code)`.
    pub fn service(message: impl Into<String>, status: u16, code: &'static str) -> Self {
        Self::Service(ServiceError::new(message, status, code))
    }
}

impl From<ServiceError> for AppError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<StoreError> for AppError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Service(error) => Self::Service(error),
            other => Self::Internal(format!("store: {other}")),
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Service(error) => write!(f, "{} ({}): {}", error.code, error.status, error),
            Self::Internal(text) => f.write_str(text),
            Self::PayloadTooLarge => f.write_str("request body too large"),
            Self::BodyUnreadable => f.write_str("request body unreadable"),
        }
    }
}

impl std::error::Error for AppError {}

/// The error a response stands for, until [`map_errors`] renders it.
#[derive(Debug, Clone)]
struct PendingError(Arc<AppError>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
        response
            .extensions_mut()
            .insert(PendingError(Arc::new(self)));
        response
    }
}

/// The layer: renders the [`AppError`] of an inner response for the
/// request's path and session.
pub async fn map_errors(request: Request, next: Next) -> Response {
    let path = RequestPath::of(&request);
    let session = SessionHandle::of(&request);
    let mut response = next.run(request).await;
    match response.extensions_mut().remove::<PendingError>() {
        Some(PendingError(error)) => error_response(&path, &session, &error),
        None => response,
    }
}

/// The response for `error` on a request for `path`.
pub fn error_response(path: &str, session: &SessionHandle, error: &AppError) -> Response {
    match error {
        AppError::Service(error) if path.starts_with("/api/") => api_error(error),
        AppError::Service(error) => {
            session.flash(&error.message, "error");
            let target = ticket_detail_redirect_path(path)
                .unwrap_or_else(|| urls::url_for("ui_tickets", &[]).unwrap_or_default());
            redirect(&target)
        }
        AppError::Internal(text) => {
            tracing::error!("request failed: {text}");
            internal_server_error()
        }
        AppError::PayloadTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            html_body("413 Request Entity Too Large", "Request Entity Too Large"),
        )
            .into_response(),
        AppError::BodyUnreadable => (
            StatusCode::BAD_REQUEST,
            html_body("400 Bad Request", "Bad Request"),
        )
            .into_response(),
    }
}

/// `api_error(error)`: `{"error": code, "message": text}` with the status.
pub fn api_error(error: &ServiceError) -> Response {
    json_response(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        &json!({"error": error.code, "message": error.message}),
    )
}

/// `jsonify(value), status`: compact, sorted keys, ASCII (the serializer of
/// 4.8; formatting is P2), `application/json`. A value Rust cannot write
/// (a non-finite float, D-2) is a 500.
pub fn json_response(status: StatusCode, value: &Value) -> Response {
    match canonical_json(value) {
        Ok(mut text) => {
            text.push('\n');
            (
                status,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                text,
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!("request failed: response JSON: {error}");
            internal_server_error()
        }
    }
}

/// `redirect(location)` to a local target: 302 with the `Location` header,
/// which Werkzeug passes through `iri_to_uri` ([`urls::local_iri_to_uri`];
/// targets built by `url_for` are unchanged by it).
pub fn redirect(location: &str) -> Response {
    redirect_with_status(&urls::local_iri_to_uri(location), StatusCode::FOUND)
}

/// A redirect with `status` (302, or 308 for Werkzeug's routing redirects).
pub fn redirect_with_status(location: &str, status: StatusCode) -> Response {
    match HeaderValue::try_from(location) {
        Ok(value) => {
            let body = html_body(
                "Redirecting...",
                "You should be redirected automatically to the target URL.",
            );
            let mut response = (status, body).into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => {
            tracing::error!("request failed: redirect target is no header value");
            internal_server_error()
        }
    }
}

/// A 500 without details.
pub fn internal_server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        html_body("500 Internal Server Error", "Internal Server Error"),
    )
        .into_response()
}

fn html_body(title: &str, heading: &str) -> axum::response::Html<String> {
    axum::response::Html(format!(
        "<!doctype html>\n<html lang=en>\n<title>{title}</title>\n<h1>{heading}</h1>\n"
    ))
}

static TICKET_ACTION_PATH: LazyLock<Regex> = LazyLock::new(|| {
    // Python's `$` also matches before a final newline.
    Regex::new(r"\A/tickets/([^/]+)/(?:approve|reject|cancel|archive|unarchive)\n?\z")
        .unwrap_or_else(|error| panic!("pattern: {error}"))
});

static TICKET_LOG_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A/tickets/([^/]+)/steps/\d+/log\n?\z")
        .unwrap_or_else(|error| panic!("pattern: {error}"))
});

/// `ticket_detail_redirect_path_for_request`: the detail page of the ticket
/// a ticket action or step log path names.
pub fn ticket_detail_redirect_path(path: &str) -> Option<String> {
    [&*TICKET_ACTION_PATH, &*TICKET_LOG_PATH]
        .into_iter()
        .find_map(|pattern| pattern.captures(path))
        .and_then(|captures| captures.get(1))
        .map(|ticket_id| urls::ticket_detail(ticket_id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_paths_follow_the_python_patterns() {
        for (path, expected) in [
            ("/tickets/abc/approve", Some("/tickets/abc")),
            ("/tickets/abc/unarchive", Some("/tickets/abc")),
            ("/tickets/abc/approve\n", Some("/tickets/abc")),
            ("/tickets/abc/approve\n\n", None),
            ("/tickets/a b/cancel", Some("/tickets/a%20b")),
            ("/tickets/abc/steps/12/log", Some("/tickets/abc")),
            ("/tickets/abc/steps/١/log", Some("/tickets/abc")),
            ("/tickets/abc/steps/x/log", None),
            ("/tickets/abc/approve/x", None),
            ("/tickets/abc", None),
            ("/tickets", None),
            ("/x/tickets/abc/approve", None),
        ] {
            assert_eq!(
                ticket_detail_redirect_path(path).as_deref(),
                expected,
                "{path:?}"
            );
        }
    }
}
