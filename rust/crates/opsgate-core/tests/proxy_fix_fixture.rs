//! `rust/fixtures/proxy_fix.json` (PLAN.md 4.4 step 1): the client address,
//! scheme and host Werkzeug's `ProxyFix(x_for=1, x_proto=1, x_host=1)`
//! produces behind waitress for the same header lines.

use opsgate_core::proxy_fix::{ClientView, ForwardedHeaders, apply, wsgi_header_value};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("../../../fixtures/proxy_fix.json");

/// A fixture string stands for latin-1 bytes, one character per byte.
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 character"))
        .collect()
}

/// The WSGI value of header `name` (case-insensitive, as HTTP header names
/// are; hyper keeps `X_Forwarded_For` a different name, as waitress drops it).
fn header(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    let values: Vec<&[u8]> = headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
        .collect();
    if values.is_empty() {
        None
    } else {
        wsgi_header_value(values)
    }
}

#[test]
fn cases_match_werkzeug() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("proxy_fix.json parses");
    let cases = fixture["cases"].as_array().unwrap();
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
        let forwarded_for = header(&headers, "X-Forwarded-For");
        let forwarded_proto = header(&headers, "X-Forwarded-Proto");
        let forwarded_host = header(&headers, "X-Forwarded-Host");
        let original = ClientView {
            remote_addr: case["remote_addr"].as_str().unwrap().to_owned(),
            scheme: case["scheme"].as_str().unwrap().to_owned(),
            host: header(&headers, "Host"),
        };
        let view = apply(
            original,
            ForwardedHeaders {
                x_forwarded_for: forwarded_for.as_deref(),
                x_forwarded_proto: forwarded_proto.as_deref(),
                x_forwarded_host: forwarded_host.as_deref(),
            },
        );
        let actual =
            json!({"remote_addr": view.remote_addr, "scheme": view.scheme, "host": view.host});
        if actual != case["result"] {
            failures.push(format!("{name}: {actual} != {}", case["result"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
