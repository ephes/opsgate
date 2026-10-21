//! Form bodies and query strings as Werkzeug reads them (`request.form`,
//! `request.args`): `parse_qsl(text, keep_blank_values=True,
//! errors="werkzeug.url_quote")` into a multi-dict whose `get` returns the
//! first value.
//!
//! Pairs are separated by `&` only; empty pairs are skipped; a pair without
//! `=` has an empty value; `+` is a space; percent escapes are decoded as
//! UTF-8, and bytes that are no valid UTF-8 stay percent-encoded (`%FF`,
//! uppercase), as Werkzeug's error handler re-quotes them. A form body is
//! read only for `Content-Type: application/x-www-form-urlencoded`
//! (parameters ignored); a body that is not UTF-8 is an empty form, as
//! Werkzeug's silent parser makes it. `multipart/form-data` bodies are not
//! parsed (D-17): no OpsGate form uses them.

use axum::http::HeaderMap;
use percent_encoding::percent_decode_str;

use crate::client::header;

/// An ordered multi-dict of form fields or query arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormData(Vec<(String, String)>);

impl FormData {
    /// `parse_qsl(text, keep_blank_values=True, errors="werkzeug.url_quote")`.
    pub fn parse(text: &str) -> Self {
        Self(
            text.split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (unquote_plus(name), unquote_plus(value))
                })
                .collect(),
        )
    }

    /// `request.form` of a request with these headers and body bytes.
    pub fn from_body(headers: &HeaderMap, body: &[u8]) -> Self {
        if mimetype(headers).as_deref() != Some("application/x-www-form-urlencoded") {
            return Self::default();
        }
        std::str::from_utf8(body).map_or_else(|_| Self::default(), Self::parse)
    }

    /// `request.args` of a request with this query string.
    pub fn from_query(query: Option<&str>) -> Self {
        query.map_or_else(Self::default, Self::parse)
    }

    /// `get(key)`: the first value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// `key in form`.
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// `keys()`: each key once, in the order of its first occurrence.
    pub fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = Vec::new();
        for (name, _) in &self.0 {
            if !keys.contains(&name.as_str()) {
                keys.push(name);
            }
        }
        keys
    }

    /// Whether the form has no field (`not request.form`).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// All pairs in order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.0
    }
}

/// The request's mimetype: the `Content-Type` value before any `;`,
/// stripped and lowercased (Werkzeug's `request.mimetype`); `None` without
/// the header.
pub fn mimetype(headers: &HeaderMap) -> Option<String> {
    let value = header(headers, "content-type")?;
    let essence = value.split(';').next().unwrap_or_default();
    Some(essence.trim().to_ascii_lowercase())
}

/// `unquote_plus(text, errors="werkzeug.url_quote")`.
fn unquote_plus(text: &str) -> String {
    let text = text.replace('+', " ");
    if !text.contains('%') {
        return text;
    }
    let bytes: Vec<u8> = percent_decode_str(&text).collect();
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn pairs(text: &str) -> Vec<(String, String)> {
        FormData::parse(text).0
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    #[test]
    fn parse_qsl_rules() {
        assert_eq!(pairs(""), vec![]);
        assert_eq!(pairs("a=1&&b"), vec![pair("a", "1"), pair("b", "")]);
        assert_eq!(pairs("a=1=2;c=3"), vec![pair("a", "1=2;c=3")]);
        assert_eq!(pairs("a+b=c+d%20e"), vec![pair("a b", "c d e")]);
        assert_eq!(pairs("x=%C3%A9%FF%zz%"), vec![pair("x", "é%FF%zz%")]);
        assert_eq!(pairs("x=%E2%82"), vec![pair("x", "%E2%82")]);
        assert_eq!(pairs("x=é%2B"), vec![pair("x", "é+")]);
        assert_eq!(pairs("=v"), vec![pair("", "v")]);
    }

    #[test]
    fn get_returns_the_first_value_and_keys_are_unique() {
        let form = FormData::parse("a=1&b=2&a=3");
        assert_eq!(form.get("a"), Some("1"));
        assert_eq!(form.get("c"), None);
        assert!(form.contains("b"));
        assert_eq!(form.keys(), vec!["a", "b"]);
    }

    #[test]
    fn form_bodies_need_the_form_content_type() {
        let mut headers = HeaderMap::new();
        assert!(FormData::from_body(&headers, b"a=1").is_empty());
        headers.insert(
            "content-type",
            HeaderValue::from_static(" Application/X-WWW-Form-URLEncoded ; charset=latin-1"),
        );
        assert_eq!(FormData::from_body(&headers, b"a=1").get("a"), Some("1"));
        // Not UTF-8: Werkzeug's silent parser gives an empty form.
        assert!(FormData::from_body(&headers, b"a=\xff").is_empty());
        headers.insert(
            "content-type",
            HeaderValue::from_static("multipart/form-data; boundary=x"),
        );
        assert!(FormData::from_body(&headers, b"a=1").is_empty());
    }
}
