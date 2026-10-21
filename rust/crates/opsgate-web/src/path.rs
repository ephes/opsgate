//! `request.path` (PLAN.md 4.3, 4.4): the percent-decoded request path the
//! Python application routes on and that its gates look at.
//!
//! Waitress hands the application `PATH_INFO` percent-decoded (bytes as
//! latin-1), Werkzeug turns it back into bytes and decodes them as UTF-8
//! with replacement characters (`_wsgi_decoding_dance`) and both its
//! `request.path` and its router collapse leading slashes
//! (`"/" + path.lstrip("/")`). So `/api%2Fv1/health` is the health endpoint,
//! `%2F` separates path segments and `//login` is the login page. The layer
//! here computes that path once, stores it in the request extensions for the
//! gates and the error mapping, and hands the router the same path
//! re-encoded, so axum matches exactly the segments Werkzeug matches and its
//! `Path` extractor yields the decoded segment.

use axum::extract::Request;
use axum::http::Uri;
use axum::http::uri::PathAndQuery;
use axum::middleware::Next;
use axum::response::Response;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// Characters a path keeps unencoded when it is handed to the router:
/// urllib's always-safe characters plus Werkzeug's path-segment set
/// (`quote(value, safe="!$&'()*+,/:;=@")`, the set `url_for` uses too).
pub(crate) const PATH_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');

/// The decoded request path of a request (`request.path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath(pub String);

impl RequestPath {
    /// The decoded path of `request`: the one [`decode_path`] stored, or
    /// computed from the URI when the layer did not run (unit tests of
    /// single layers).
    pub fn of(request: &Request) -> String {
        request
            .extensions()
            .get::<RequestPath>()
            .map_or_else(|| decode(request.uri().path()), |path| path.0.clone())
    }
}

/// Werkzeug's `request.path` for the raw request path `raw`.
pub fn decode(raw: &str) -> String {
    let bytes: Vec<u8> = percent_decode_str(raw).collect();
    let text = String::from_utf8_lossy(&bytes);
    format!("/{}", text.trim_start_matches('/'))
}

/// The layer: stores [`RequestPath`] and gives the router the decoded path,
/// re-encoded with [`PATH_SAFE`] (the query string is kept as sent).
pub async fn decode_path(mut request: Request, next: Next) -> Response {
    let decoded = decode(request.uri().path());
    let encoded = utf8_percent_encode(&decoded, PATH_SAFE).to_string();
    if encoded != request.uri().path()
        && let Some(uri) = with_path(request.uri(), &encoded)
    {
        *request.uri_mut() = uri;
    }
    request.extensions_mut().insert(RequestPath(decoded));
    next.run(request).await
}

fn with_path(uri: &Uri, path: &str) -> Option<Uri> {
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::try_from(path_and_query).ok()?);
    Uri::from_parts(parts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_werkzeug() {
        assert_eq!(decode("/api/v1/health"), "/api/v1/health");
        assert_eq!(decode("/api%2Fv1/health"), "/api/v1/health");
        assert_eq!(decode("//login"), "/login");
        assert_eq!(decode("///"), "/");
        assert_eq!(decode(""), "/");
        assert_eq!(decode("/tickets/a%20b"), "/tickets/a b");
        // Invalid UTF-8 becomes replacement characters, an invalid escape
        // stays as it is.
        assert_eq!(decode("/x%FF%zz"), "/x\u{fffd}%zz");
        assert_eq!(decode("/caf%C3%A9"), "/café");
    }

    #[test]
    fn re_encoding_keeps_segments() {
        for (raw, expected) in [
            ("/api%2Fv1/health", "/api/v1/health"),
            ("/tickets/a%20b", "/tickets/a%20b"),
            ("/tickets/a%3Fb", "/tickets/a%3Fb"),
            ("/tickets/a%25b", "/tickets/a%25b"),
            ("/tickets/caf%C3%A9", "/tickets/caf%C3%A9"),
            ("/tickets/x!$&'()*+,:;=@", "/tickets/x!$&'()*+,:;=@"),
        ] {
            assert_eq!(
                utf8_percent_encode(&decode(raw), PATH_SAFE).to_string(),
                expected,
                "{raw}"
            );
        }
    }
}
