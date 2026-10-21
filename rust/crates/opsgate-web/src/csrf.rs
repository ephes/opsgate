//! The UI-CSRF check (`enforce_ui_csrf`, PLAN.md 4.4 step 3, 4.5.4).
//!
//! Every `POST` whose path does not start with `/api/` (also unknown paths
//! and routes added by later slices) must carry the session's CSRF token in
//! the form field `csrf_token`. The session gets a token first if it has
//! none (`ensure_csrf_token`); the comparison is constant time over UTF-8
//! bytes. A mismatch is `ServiceError("Invalid form token", 400,
//! "invalid_csrf")`, which the error mapping turns into a flash and a
//! redirect. The check runs before authentication and before routing; the
//! parsed form travels on in the request extensions, so handlers do not
//! read the body twice.

use axum::body::Body;
use axum::extract::Request;
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::body::read_body;
use crate::client::constant_time_eq;
use crate::error::AppError;
use crate::form::FormData;
use crate::path::RequestPath;
use crate::session::SessionHandle;

/// The layer.
pub async fn enforce_ui_csrf(request: Request, next: Next) -> Response {
    if request.method() != Method::POST || RequestPath::of(&request).starts_with("/api/") {
        return next.run(request).await;
    }
    let session = SessionHandle::of(&request);
    let session_token = match session.ensure_csrf_token() {
        Ok(token) => token,
        Err(error) => return error.into_response(),
    };
    let (parts, body) = request.into_parts();
    let bytes = match read_body(body).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let form = FormData::from_body(&parts.headers, &bytes);
    let form_token = form.get("csrf_token").unwrap_or_default();
    if !constant_time_eq(session_token.as_bytes(), form_token.as_bytes()) {
        return AppError::service("Invalid form token", 400, "invalid_csrf").into_response();
    }
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(form);
    next.run(request).await
}
