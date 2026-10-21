//! `rust/fixtures/proxy_fix.json` (PLAN.md 4.4 step 1): the client address,
//! scheme and host the Python application sees in production (waitress with
//! default adjustments around the Flask app with or without Werkzeug's
//! `ProxyFix`) for the same header lines.

use opsgate_core::proxy_fix::{ClientView, client_view, wsgi_header_value};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("../../../fixtures/proxy_fix.json");

/// A fixture string stands for latin-1 bytes, one character per byte.
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 character"))
        .collect()
}

/// The WSGI value of header `name` (names compare case-insensitively).
fn header(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    wsgi_header_value(
        headers
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice()),
    )
}

#[test]
fn cases_match_python_behind_waitress() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("proxy_fix.json parses");
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let headers: Vec<(String, Vec<u8>)> = case["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    latin1_bytes(pair[1].as_str().unwrap()),
                )
            })
            .collect();
        for (key, trust) in [("untrusted", false), ("trusted", true)] {
            let socket = ClientView {
                remote_addr: case["remote_addr"].as_str().unwrap().to_owned(),
                scheme: case["scheme"].as_str().unwrap().to_owned(),
                host: header(&headers, "Host"),
            };
            let view = client_view(socket, trust);
            let actual =
                json!({"remote_addr": view.remote_addr, "scheme": view.scheme, "host": view.host});
            if actual != case["result"][key] {
                failures.push(format!(
                    "{name} ({key}): {actual} != {}",
                    case["result"][key]
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn forwarded_headers_reach_the_fixture_cases() {
    // The corpus does send forwarded headers that Werkzeug's ProxyFix alone
    // would apply, so the identical results above are waitress's doing.
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let single = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "single proxy")
        .unwrap();
    assert_eq!(
        single["headers"][1],
        json!(["X-Forwarded-For", "100.64.0.9"])
    );
    assert_eq!(single["result"]["trusted"]["remote_addr"], "100.64.0.1");
}

#[test]
fn wsgi_header_value_joins_and_strips() {
    assert_eq!(wsgi_header_value(Vec::<&[u8]>::new()), None);
    assert_eq!(
        wsgi_header_value([&b" a \t"[..], b"", b"\tb"]),
        Some("a, , b".to_owned())
    );
    assert_eq!(wsgi_header_value([&b"\xe9"[..]]), Some("\u{e9}".to_owned()));
}
