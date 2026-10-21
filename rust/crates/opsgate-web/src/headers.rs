//! Security headers on every response (`add_security_headers`,
//! `SECURITY_HEADERS`, PLAN.md 4.4 step 5): redirects, errors, the gate's
//! 403, unknown routes, wrong methods and oversized bodies included.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// `SECURITY_HEADERS` of `app.py`, in its order.
pub const SECURITY_HEADERS: [(HeaderName, &str); 5] = [
    (X_FRAME_OPTIONS, "DENY"),
    (
        CONTENT_SECURITY_POLICY,
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
    ),
    (X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (REFERRER_POLICY, "same-origin"),
    (CACHE_CONTROL, "no-store"),
];

/// The layer: sets (replaces) each header on the response.
pub async fn add_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}
