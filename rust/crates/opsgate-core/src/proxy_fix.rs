//! The client address, scheme and host the application works with
//! (`rust/PLAN.md` 4.4 step 1). Pinned by `rust/fixtures/proxy_fix.json`.
//!
//! `create_app` wraps the Flask application in Werkzeug's
//! `ProxyFix(x_for=1, x_proto=1, x_host=1)` when `OPSGATE_TRUST_PROXY_HEADERS`
//! is set, but production serves it with `waitress.serve(app, ...)` and the
//! default adjustments (`__main__.py`). Waitress then wraps the application in
//! its own proxy-header middleware with `trusted_proxy=None` and
//! `clear_untrusted_proxy_headers=True`, which deletes `X-Forwarded-For`,
//! `-Host`, `-Proto`, `-Port`, `-By` and `Forwarded` from the request before
//! `ProxyFix` runs. The application therefore always sees the socket peer
//! address, the connection's scheme and the `Host` header, with or without
//! the setting; the Flask test client used by
//! `tests/test_api.py::test_trusted_proxy_headers_restore_client_ip_for_access_and_audit`
//! bypasses waitress and is not what runs. The Rust port keeps the production
//! behaviour: forwarded headers never change the client address (so they can
//! never open the network gate, 4.4 step 2), the scheme or the host.

/// What the application sees as the request's origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    /// `REMOTE_ADDR` (`request.remote_addr`): the socket peer address.
    pub remote_addr: String,
    /// `wsgi.url_scheme` (`request.scheme`): the connection's scheme.
    pub scheme: String,
    /// `HTTP_HOST`, the `Host` header in its WSGI form
    /// ([`wsgi_header_value`]), if any.
    pub host: Option<String>,
}

/// The view the application works with for a request whose socket view is
/// `socket`. `trust_proxy_headers` (`OPSGATE_TRUST_PROXY_HEADERS`) has no
/// effect behind waitress (module docs), so the socket view is returned for
/// both values; the parameter keeps the setting visible at the call site.
pub fn client_view(socket: ClientView, trust_proxy_headers: bool) -> ClientView {
    let _ = trust_proxy_headers;
    socket
}

/// One header in the form waitress hands to the application: the values of
/// every line with that name, each stripped of spaces and tabs, joined with
/// `", "`, bytes decoded as latin-1. `None` without any line.
pub fn wsgi_header_value<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Option<String> {
    let mut joined: Option<String> = None;
    for value in values {
        let text = match joined.as_mut() {
            Some(text) => {
                text.push_str(", ");
                text
            }
            None => joined.insert(String::new()),
        };
        text.extend(trim_space_tab(value).iter().map(|byte| char::from(*byte)));
    }
    joined
}

fn trim_space_tab(value: &[u8]) -> &[u8] {
    let is_ows = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let start = value
        .iter()
        .position(|byte| !is_ows(byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_ows(byte))
        .map_or(start, |index| index + 1);
    &value[start..end]
}
