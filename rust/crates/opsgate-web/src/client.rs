//! What a request says about its caller (PLAN.md 4.4 step 1, 4.5.1): the
//! client address, headers as the WSGI application sees them, bearer tokens.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use opsgate_core::proxy_fix::{ClientView, client_view, wsgi_header_value};
use opsgate_core::pytext::strip;
use opsgate_core::settings::{ApiSettings, SubmitterPolicy};
use subtle::ConstantTimeEq;

/// The client view of the request (`request.remote_addr`, `request.scheme`,
/// `request.host`). Forwarded headers never change it (4.4 step 1): the
/// address is the socket peer's (empty without connection information, as
/// `request.remote_addr or ""`), the scheme the connection's (`http`), the
/// host the `Host` header in its WSGI form.
pub fn view(parts: &Parts, settings: &ApiSettings) -> ClientView {
    let socket = ClientView {
        remote_addr: parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(address)| address.ip().to_string())
            .unwrap_or_default(),
        scheme: "http".to_owned(),
        host: header(&parts.headers, "host"),
    };
    client_view(socket, settings.trust_proxy_headers)
}

/// `request.headers.get(name)`: every line of the header joined with `", "`,
/// bytes decoded as latin-1 (waitress), or `None` without one.
pub fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    wsgi_header_value(headers.get_all(name).iter().map(|value| value.as_bytes()))
}

/// `request.headers.get("User-Agent")`.
pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    header(headers, "user-agent")
}

/// `get_bearer_token`: the `Authorization` header must start with exactly
/// `Bearer `; the rest, stripped, is the token; empty is no token.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = header(headers, "authorization")?;
    let token = strip(value.strip_prefix("Bearer ")?);
    (!token.is_empty()).then(|| token.to_owned())
}

/// Constant-time comparison of two byte strings (`hmac.compare_digest` over
/// UTF-8 bytes; different lengths never match).
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

/// `authenticate_submitter`: the first configured submitter (order of 4.2)
/// whose token equals the stripped token, compared as bytes, so a non-ASCII
/// token never raises (`test_api_bearer_endpoints_reject_non_ascii_token`).
pub fn authenticate_submitter<'a>(
    settings: &'a ApiSettings,
    token: Option<&str>,
) -> Option<&'a SubmitterPolicy> {
    let presented = strip(token?);
    if presented.is_empty() {
        return None;
    }
    settings
        .submitter_policies
        .iter()
        .find(|submitter| constant_time_eq(submitter.token.as_bytes(), presented.as_bytes()))
}

/// `is_runner_token`.
pub fn is_runner_token(settings: &ApiSettings, token: Option<&str>) -> bool {
    match token {
        Some(token) if !token.is_empty() => {
            constant_time_eq(strip(token).as_bytes(), settings.runner_token.as_bytes())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(lines: &[(&'static str, &[u8])]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in lines {
            map.append(*name, HeaderValue::from_bytes(value).unwrap());
        }
        map
    }

    #[test]
    fn bearer_token_follows_get_bearer_token() {
        for (value, expected) in [
            (&b"Bearer abc"[..], Some("abc")),
            (b"Bearer   abc  ", Some("abc")),
            (b"Bearer ", None),
            (b"Bearer \xc2\xa0", Some("\u{c2}")),
            (b"bearer abc", None),
            (b"Bearerabc", None),
            (b"Basic abc", None),
            (b"Bearer Bearer abc", Some("Bearer abc")),
        ] {
            assert_eq!(
                bearer_token(&headers(&[("authorization", value)])).as_deref(),
                expected,
                "{value:?}"
            );
        }
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn non_ascii_header_bytes_are_latin1() {
        let map = headers(&[("user-agent", "té".as_bytes())]);
        assert_eq!(user_agent(&map).as_deref(), Some("tÃ©"));
        let map = headers(&[("user-agent", b"a"), ("user-agent", b" b ")]);
        assert_eq!(user_agent(&map).as_deref(), Some("a, b"));
    }
}
