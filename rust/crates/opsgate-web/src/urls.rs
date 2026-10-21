//! `url_for` (PLAN.md 6.3): the endpoint names of `app.py` and the paths
//! of 4.3, built as Werkzeug builds them. Path variables are quoted with
//! `quote(value, safe="!$&'()*+,/:;=@")`, `<int:…>` variables are written as
//! integers, and keyword arguments that are no path variable become the
//! query string (`urlencode(items, safe="!$'()*,/:;?@")`, `None` values
//! dropped, in the order given).

use opsgate_core::settings::py_int_decimal;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::path::PATH_SAFE;

/// `quote_plus(value, safe="!$'()*,/:;?@")` without the space, which is
/// written as `+` afterwards.
const QUERY_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'?')
    .remove(b'@')
    .remove(b' ');

/// One segment of an endpoint's rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Static(&'static str),
    /// `<name>`: one path segment (`UnicodeConverter`).
    Text(&'static str),
    /// `<int:name>`.
    Int(&'static str),
}

use Part::{Int, Static, Text};

/// The endpoints of `app.py` (view function names) and their rules (4.3).
const ENDPOINTS: &[(&str, &[Part])] = &[
    ("api_health", &[Static("/api/v1/health")]),
    ("api_create_ticket", &[Static("/api/v1/tickets")]),
    (
        "api_get_ticket",
        &[Static("/api/v1/tickets/"), Text("ticket_id")],
    ),
    (
        "api_approve_ticket",
        &[
            Static("/api/v1/tickets/"),
            Text("ticket_id"),
            Static("/approve"),
        ],
    ),
    (
        "api_reject_ticket",
        &[
            Static("/api/v1/tickets/"),
            Text("ticket_id"),
            Static("/reject"),
        ],
    ),
    (
        "api_cancel_ticket",
        &[
            Static("/api/v1/tickets/"),
            Text("ticket_id"),
            Static("/cancel"),
        ],
    ),
    (
        "api_archive_ticket",
        &[
            Static("/api/v1/tickets/"),
            Text("ticket_id"),
            Static("/archive"),
        ],
    ),
    (
        "api_unarchive_ticket",
        &[
            Static("/api/v1/tickets/"),
            Text("ticket_id"),
            Static("/unarchive"),
        ],
    ),
    ("api_runner_claim", &[Static("/api/v1/runner/claim")]),
    (
        "api_runner_status",
        &[
            Static("/api/v1/runner/"),
            Text("ticket_id"),
            Static("/status"),
        ],
    ),
    ("ui_root", &[Static("/")]),
    ("ui_login", &[Static("/login")]),
    ("ui_logout", &[Static("/logout")]),
    ("ui_tickets", &[Static("/tickets")]),
    (
        "ui_ticket_detail",
        &[Static("/tickets/"), Text("ticket_id")],
    ),
    (
        "ui_ticket_step_log",
        &[
            Static("/tickets/"),
            Text("ticket_id"),
            Static("/steps/"),
            Int("step_number"),
            Static("/log"),
        ],
    ),
    (
        "ui_ticket_approve",
        &[Static("/tickets/"), Text("ticket_id"), Static("/approve")],
    ),
    (
        "ui_ticket_reject",
        &[Static("/tickets/"), Text("ticket_id"), Static("/reject")],
    ),
    (
        "ui_ticket_cancel",
        &[Static("/tickets/"), Text("ticket_id"), Static("/cancel")],
    ),
    (
        "ui_ticket_archive",
        &[Static("/tickets/"), Text("ticket_id"), Static("/archive")],
    ),
    (
        "ui_ticket_unarchive",
        &[Static("/tickets/"), Text("ticket_id"), Static("/unarchive")],
    ),
];

/// A value given to `url_for`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlArg {
    /// `str(value)` of the argument.
    Text(String),
    /// An integer argument.
    Int(i64),
    /// `None`: dropped from the query string, an error for a path variable.
    None,
}

impl From<&str> for UrlArg {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for UrlArg {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<i64> for UrlArg {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

/// Why `url_for` cannot build a URL (Werkzeug's `BuildError` or a
/// converter's `ValueError`): an unknown endpoint, a missing path variable or
/// an `<int:…>` value that is no integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError(pub String);

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BuildError {}

/// `url_for(endpoint, **args)`.
pub fn url_for(endpoint: &str, args: &[(&str, UrlArg)]) -> Result<String, BuildError> {
    let rule = ENDPOINTS
        .iter()
        .find(|(name, _)| *name == endpoint)
        .map(|(_, rule)| *rule)
        .ok_or_else(|| BuildError(format!("unknown endpoint {endpoint:?}")))?;
    let mut url = String::new();
    let mut used = Vec::new();
    for part in rule {
        match *part {
            Static(text) => url.push_str(text),
            Text(name) | Int(name) => {
                let value = args
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value)
                    .filter(|value| **value != UrlArg::None)
                    .ok_or_else(|| BuildError(format!("{endpoint}: missing {name:?}")))?;
                used.push(name);
                let text = match (part, value) {
                    (Int(_), UrlArg::Int(number)) => number.to_string(),
                    // `str(int(value))`, of any size.
                    (Int(_), UrlArg::Text(text)) => py_int_decimal(text)
                        .ok_or_else(|| BuildError(format!("{endpoint}: {name:?} is no integer")))?,
                    (_, UrlArg::Int(number)) => number.to_string(),
                    (_, UrlArg::Text(text)) => text.clone(),
                    (_, UrlArg::None) => unreachable!("filtered above"),
                };
                url.push_str(&quote_path(&text));
            }
        }
    }
    let query: Vec<String> = args
        .iter()
        .filter(|(key, _)| !used.contains(key))
        .filter_map(|(key, value)| {
            let text = match value {
                UrlArg::Text(text) => text.clone(),
                UrlArg::Int(number) => number.to_string(),
                UrlArg::None => return None,
            };
            Some(format!("{}={}", quote_query(key), quote_query(&text)))
        })
        .collect();
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }
    Ok(url)
}

/// `url_for("ui_ticket_detail", ticket_id=…)`.
pub fn ticket_detail(ticket_id: &str) -> String {
    format!("/tickets/{}", quote_path(ticket_id))
}

/// A path variable as Werkzeug quotes it.
pub fn quote_path(value: &str) -> String {
    utf8_percent_encode(value, PATH_SAFE).to_string()
}

/// `iri_to_uri`'s safe set of the path (`%!$&'()*+,/:;=@`).
const IRI_PATH_SAFE: &AsciiSet = &PATH_SAFE.remove(b'%');
/// `iri_to_uri`'s safe set of the query (the path's plus `?`).
const IRI_QUERY_SAFE: &AsciiSet = &IRI_PATH_SAFE.remove(b'?');
/// `iri_to_uri`'s safe set of the fragment (the query's plus `#`).
const IRI_FRAGMENT_SAFE: &AsciiSet = &IRI_QUERY_SAFE.remove(b'#');

/// Werkzeug's `iri_to_uri` for a local target (a path with an optional
/// query and fragment, no scheme and no network location), which every
/// `Location` header goes through: characters outside each part's safe set
/// are percent-encoded as UTF-8, existing escapes are kept, and an empty
/// query or fragment is dropped with its separator (`urlunsplit`).
pub fn local_iri_to_uri(location: &str) -> String {
    let (rest, fragment) = location.split_once('#').unwrap_or((location, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut uri = utf8_percent_encode(path, IRI_PATH_SAFE).to_string();
    if !query.is_empty() {
        uri.push('?');
        uri.extend(utf8_percent_encode(query, IRI_QUERY_SAFE));
    }
    if !fragment.is_empty() {
        uri.push('#');
        uri.extend(utf8_percent_encode(fragment, IRI_FRAGMENT_SAFE));
    }
    uri
}

fn quote_query(value: &str) -> String {
    utf8_percent_encode(value, QUERY_SAFE)
        .to_string()
        .replace(' ', "+")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_rules_of_app_py() {
        assert_eq!(url_for("ui_login", &[]).unwrap(), "/login");
        assert_eq!(url_for("ui_tickets", &[]).unwrap(), "/tickets");
        assert_eq!(
            url_for("ui_tickets", &[("view", "archived".into())]).unwrap(),
            "/tickets?view=archived"
        );
        assert_eq!(
            url_for("ui_ticket_detail", &[("ticket_id", "a b/c?é".into())]).unwrap(),
            "/tickets/a%20b/c%3F%C3%A9"
        );
        assert_eq!(
            url_for(
                "ui_ticket_step_log",
                &[("ticket_id", "t".into()), ("step_number", 3.into())]
            )
            .unwrap(),
            "/tickets/t/steps/3/log"
        );
        assert_eq!(
            url_for(
                "ui_ticket_archive",
                &[("ticket_id", "t".into()), ("x", UrlArg::None)]
            )
            .unwrap(),
            "/tickets/t/archive"
        );
        assert_eq!(
            url_for("ui_login", &[("next", "/tickets/x y?view=all&a=+".into())]).unwrap(),
            "/login?next=/tickets/x+y?view%3Dall%26a%3D%2B"
        );
        assert_eq!(
            url_for("api_runner_status", &[("ticket_id", "t".into())]).unwrap(),
            "/api/v1/runner/t/status"
        );
    }

    #[test]
    fn local_iri_to_uri_follows_werkzeug() {
        for (location, expected) in [
            ("/tickets", "/tickets"),
            ("/tickets/a b", "/tickets/a%20b"),
            ("/tickets/é?x=ü#ä", "/tickets/%C3%A9?x=%C3%BC#%C3%A4"),
            ("/tickets/%2F?a=%20", "/tickets/%2F?a=%20"),
            ("/t\\\"<>^`{|}[]", "/t%5C%22%3C%3E%5E%60%7B%7C%7D%5B%5D"),
            ("/a?b?c=d&e=f+g", "/a?b?c=d&e=f+g"),
            ("/a#b#c?d", "/a#b#c?d"),
            ("/a?#b", "/a#b"),
            ("/a?", "/a"),
            ("/a#", "/a"),
            ("/!$&'()*+,/:;=@~._-", "/!$&'()*+,/:;=@~._-"),
            ("/a\u{1}\u{7f}", "/a%01%7F"),
            (
                "/login?next=/tickets/x+y?view%3Dall",
                "/login?next=/tickets/x+y?view%3Dall",
            ),
        ] {
            assert_eq!(local_iri_to_uri(location), expected, "{location:?}");
        }
    }

    #[test]
    fn local_iri_to_uri_matches_werkzeug_examples() {
        // Expected values: `werkzeug.urls.iri_to_uri` (Werkzeug 3.1).
        for (location, expected) in [
            ("/tickets", "/tickets"),
            ("/tickets?", "/tickets"),
            ("/tickets#", "/tickets"),
            ("/tickets?view=all x#f g", "/tickets?view=all%20x#f%20g"),
            ("/tickets/é?q=ü", "/tickets/%C3%A9?q=%C3%BC"),
            ("/tickets?a=%zz&b=%41", "/tickets?a=%zz&b=%41"),
            (
                "/tickets\u{1}|<>\"{}^`",
                "/tickets%01%7C%3C%3E%22%7B%7D%5E%60",
            ),
            ("/tickets?x=[]|", "/tickets?x=%5B%5D%7C"),
            ("/tickets/a#b#c?d", "/tickets/a#b#c?d"),
            ("/tickets?a?b#c", "/tickets?a?b#c"),
            (
                "/login?next=/tickets/x+y?view%3Dall%26a%3D%2B",
                "/login?next=/tickets/x+y?view%3Dall%26a%3D%2B",
            ),
        ] {
            assert_eq!(local_iri_to_uri(location), expected, "{location:?}");
        }
    }

    #[test]
    fn int_variables_take_python_integers() {
        let big = "1".repeat(60);
        assert_eq!(
            url_for(
                "ui_ticket_step_log",
                &[
                    ("ticket_id", "t".into()),
                    ("step_number", big.clone().into())
                ]
            )
            .unwrap(),
            format!("/tickets/t/steps/{big}/log")
        );
        assert_eq!(
            url_for(
                "ui_ticket_step_log",
                &[("ticket_id", "t".into()), ("step_number", " 0_7 ".into())]
            )
            .unwrap(),
            "/tickets/t/steps/7/log"
        );
    }

    #[test]
    fn build_errors() {
        assert!(url_for("nope", &[]).is_err());
        assert!(url_for("ui_ticket_detail", &[]).is_err());
        assert!(url_for("ui_ticket_detail", &[("ticket_id", UrlArg::None)]).is_err());
        assert!(
            url_for(
                "ui_ticket_step_log",
                &[("ticket_id", "t".into()), ("step_number", "x".into())]
            )
            .is_err()
        );
    }
}
