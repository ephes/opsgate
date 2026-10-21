//! The two CSRF checks of PLAN.md 4.5.4: the UI-CSRF layer
//! ([`enforce_ui_csrf`]) and the API-CSRF check of cookie-authenticated API
//! calls ([`enforce_api_session_csrf`]).
//!
//! UI-CSRF (`enforce_ui_csrf`, 4.4 step 3):
//! Every `POST` whose path does not start with `/api/` (also unknown paths
//! and routes added by later slices) must carry the session's CSRF token in
//! the form field `csrf_token`. The session gets a token first if it has
//! none (`ensure_csrf_token`); the comparison is constant time over UTF-8
//! bytes. A mismatch is `ServiceError("Invalid form token", 400,
//! "invalid_csrf")`, which the error mapping turns into a flash and a
//! redirect. The check runs before authentication and before routing; the
//! parsed form travels on in the request extensions, so handlers do not
//! read the body twice.
//!
//! API-CSRF (`enforce_api_session_csrf`, after the approver check of
//! `require_approver_session`): a non-`GET`/`HEAD`/`OPTIONS` request passes
//! when the session has a token and `X-CSRF-Token` equals it (constant time
//! over UTF-8 bytes; a non-empty header that differs is 403 `invalid_csrf`);
//! without the header, when the browser reports a same-origin request:
//! `Sec-Fetch-Site` (stripped, lowercased) is `same-origin`, or, without that
//! header, `Origin` (stripped, lowercased) is `http://<host>` of the request;
//! else 403 `csrf_required`.

use std::sync::LazyLock;

use axum::body::Body;
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use opsgate_core::pytext::{py_lower, strip};
use opsgate_core::settings::ApiSettings;
use regex::Regex;

use crate::body::read_body;
use crate::client::{self, constant_time_eq, header};
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

/// `CSRF_HEADER_NAME`.
pub const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// `enforce_api_session_csrf` for a request whose session authenticated.
pub fn enforce_api_session_csrf(
    parts: &Parts,
    session: &SessionHandle,
    settings: &ApiSettings,
) -> Result<(), AppError> {
    if matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    let session_token = session.data().csrf_token.unwrap_or_default();
    let header_token = header(&parts.headers, CSRF_HEADER_NAME).unwrap_or_default();
    if !session_token.is_empty() && !header_token.is_empty() {
        if constant_time_eq(session_token.as_bytes(), header_token.as_bytes()) {
            return Ok(());
        }
        return Err(AppError::service("Invalid CSRF token", 403, "invalid_csrf"));
    }
    if is_same_origin_request(&parts.headers, &expected_request_origin(parts, settings)) {
        return Ok(());
    }
    Err(AppError::service(
        format!(
            "Cookie-authenticated API calls require the {CSRF_HEADER_NAME} header or a same-origin request"
        ),
        403,
        "csrf_required",
    ))
}

/// `is_same_origin_request`: `Sec-Fetch-Site` decides when present, else
/// `Origin`; neither header → not same-origin.
pub fn is_same_origin_request(headers: &HeaderMap, expected_origin: &str) -> bool {
    if let Some(fetch_site) = header(headers, "sec-fetch-site") {
        return py_lower(strip(&fetch_site)) == "same-origin";
    }
    if let Some(origin) = header(headers, "origin") {
        return py_lower(strip(&origin)) == expected_origin;
    }
    false
}

/// `expected_request_origin`: `f"{request.scheme}://{request.host}".lower()`
/// with the connection's scheme (`http`, 4.4 step 1).
pub fn expected_request_origin(parts: &Parts, settings: &ApiSettings) -> String {
    let view = client::view(parts, settings);
    let host = request_host(&view.scheme, view.host.as_deref());
    py_lower(&format!("{}://{host}", view.scheme))
}

/// Werkzeug's `host_is_trusted` pattern without a trusted list: a domain or
/// IPv4 address, or a bracketed IPv6 address, and an optional port.
static HOST_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)\A(?:[a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::([1-9][0-9]{0,4}))?\z")
        .unwrap_or_else(|error| panic!("pattern: {error}"))
});

/// `request.host` (Werkzeug's `get_host`) for the `Host` header in its WSGI
/// form: the default port of the scheme removed, and empty when the value
/// is no valid `host[:port]`. Without a `Host` header Werkzeug falls back to
/// waitress's `SERVER_NAME` and port (`waitress.invalid:<port>`); Rust uses
/// the empty host there (D-19: a browser always sends `Host`).
pub fn request_host(scheme: &str, host_header: Option<&str>) -> String {
    let Some(host) = host_header else {
        return String::new();
    };
    let host = match scheme {
        "http" | "ws" => host.strip_suffix(":80").unwrap_or(host),
        "https" | "wss" => host.strip_suffix(":443").unwrap_or(host),
        _ => host,
    };
    let valid = HOST_PATTERN.captures(host).is_some_and(|captures| {
        captures.get(1).is_none_or(|port| {
            port.as_str()
                .parse::<u32>()
                .is_ok_and(|port| port <= 65_535)
        })
    });
    if valid {
        host.to_owned()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn request_host_follows_get_host() {
        for (header, expected) in [
            (Some("localhost"), "localhost"),
            (Some("localhost:80"), "localhost"),
            (Some("localhost:8711"), "localhost:8711"),
            (Some("LOCALHOST:8711"), "LOCALHOST:8711"),
            (Some("100.64.0.1:8711"), "100.64.0.1:8711"),
            (Some("[::1]:8711"), "[::1]:8711"),
            (Some("[::1]:80"), "[::1]"),
            (Some("localhost:65535"), "localhost:65535"),
            (Some("localhost:65536"), ""),
            (Some("localhost:0"), ""),
            (Some("localhost:08711"), ""),
            (Some("localhost:"), ""),
            (Some("a, b"), ""),
            (Some("exa mple"), ""),
            (Some("bücher.example"), ""),
            (Some(""), ""),
            (Some("localhost:80:80"), "localhost:80"),
            (None, ""),
        ] {
            assert_eq!(request_host("http", header), expected, "{header:?}");
        }
        assert_eq!(request_host("https", Some("host:443")), "host");
        assert_eq!(request_host("https", Some("host:80")), "host:80");
    }

    #[test]
    fn same_origin_headers() {
        let headers = |pairs: &[(&'static str, &[u8])]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.append(*name, HeaderValue::from_bytes(value).unwrap());
            }
            map
        };
        let expected = "http://localhost";
        for (pairs, same) in [
            (vec![("sec-fetch-site", &b"same-origin"[..])], true),
            (vec![("sec-fetch-site", b" Same-Origin \xa0")], true),
            (vec![("sec-fetch-site", b"same-site")], false),
            (vec![("sec-fetch-site", b"")], false),
            (
                vec![
                    ("sec-fetch-site", b"same-site"),
                    ("origin", b"http://localhost"),
                ],
                false,
            ),
            (vec![("origin", b"http://localhost")], true),
            (vec![("origin", b" HTTP://LOCALHOST ")], true),
            (vec![("origin", b"https://localhost")], false),
            (vec![("origin", b"null")], false),
            (vec![("origin", b"")], false),
            (vec![], false),
        ] {
            assert_eq!(
                is_same_origin_request(&headers(&pairs), expected),
                same,
                "{pairs:?}"
            );
        }
    }
}
