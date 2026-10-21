//! The client address, scheme and host behind a trusted proxy
//! (`OPSGATE_TRUST_PROXY_HEADERS`, `rust/PLAN.md` 4.4 step 1): Werkzeug's
//! `ProxyFix(x_for=1, x_proto=1, x_host=1)` as Python runs it behind
//! waitress. Pinned by `rust/fixtures/proxy_fix.json`.
//!
//! Header values reach Werkzeug the way waitress builds the WSGI environ:
//! repeated header lines joined with `", "`, each value stripped of spaces
//! and tabs, bytes decoded as latin-1 ([`wsgi_header_value`]). Werkzeug then
//! splits the value as an RFC 9110 list (`werkzeug.http.parse_list_header`:
//! commas inside quoted strings do not split, items are stripped of spaces
//! and tabs, empty items are dropped, an unclosed quoted string makes the
//! whole header empty, a fully quoted item is unquoted) and takes the last
//! item. A header without items leaves the original value in place.

/// What the application sees as the request's origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    /// `REMOTE_ADDR` (`request.remote_addr`).
    pub remote_addr: String,
    /// `wsgi.url_scheme` (`request.scheme`), not normalised.
    pub scheme: String,
    /// `HTTP_HOST` (the `Host` header), if any.
    pub host: Option<String>,
}

/// The forwarded headers of one request, each already in its WSGI form
/// ([`wsgi_header_value`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardedHeaders<'a> {
    pub x_forwarded_for: Option<&'a str>,
    pub x_forwarded_proto: Option<&'a str>,
    pub x_forwarded_host: Option<&'a str>,
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

/// Apply `ProxyFix(x_for=1, x_proto=1, x_host=1)` to the socket's view of
/// the request.
pub fn apply(original: ClientView, headers: ForwardedHeaders<'_>) -> ClientView {
    let mut view = original;
    if let Some(remote_addr) = last_value(headers.x_forwarded_for) {
        view.remote_addr = remote_addr;
    }
    if let Some(scheme) = last_value(headers.x_forwarded_proto) {
        view.scheme = scheme;
    }
    if let Some(host) = last_value(headers.x_forwarded_host) {
        view.host = Some(host);
    }
    view
}

/// `ProxyFix._get_real_value(1, value)`, `None` also for an empty result
/// (Werkzeug only replaces the environ value when it is truthy).
fn last_value(value: Option<&str>) -> Option<String> {
    let value = value.filter(|value| !value.is_empty())?;
    parse_list_header(value)
        .pop()
        .filter(|item| !item.is_empty())
}

/// `werkzeug.http.parse_list_header` (Werkzeug 3.1).
pub fn parse_list_header(value: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut item = String::new();
    let mut escape = false;
    let mut quote = false;
    for c in value.chars() {
        if escape {
            escape = false;
            item.push(c);
            continue;
        }
        if quote {
            if c == '\\' {
                escape = true;
            } else if c == '"' {
                quote = false;
            }
            item.push(c);
            continue;
        }
        if c == ',' {
            items.push(std::mem::take(&mut item));
            continue;
        }
        if c == '"' {
            quote = true;
        }
        item.push(c);
    }
    if quote {
        // An unclosed quoted string invalidates the whole header.
        return Vec::new();
    }
    items.push(item);
    items
        .iter()
        .map(|item| item.trim_matches([' ', '\t']))
        .filter(|item| !item.is_empty())
        .map(unquote_header_value)
        .collect()
}

/// `werkzeug.http.unquote_header_value`: a value wrapped in double quotes
/// loses them, and a backslash before any character but a newline is
/// removed.
fn unquote_header_value(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        // `re.sub(r"\\(.)", r"\g<1>", inner)`: `.` does not match `\n`.
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.clone().next() {
                    Some(escaped) if escaped != '\n' => {
                        out.push(escaped);
                        chars.next();
                    }
                    _ => out.push(c),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        value.to_owned()
    }
}
