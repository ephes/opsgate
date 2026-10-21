//! Request bodies (PLAN.md 4.6, D-4, D-5).
//!
//! A body is read only when a handler needs it, after the checks Python
//! makes before touching it (a bearer route answers 401 before it reads the
//! body), and never beyond [`crate::BODY_LIMIT`] (413).
//!
//! JSON (`parse_request_json`, Flask's `get_json(silent=True)` plus
//! `check_json_depth`): only a `Content-Type` of `application/json` or
//! `application/*+json` (parameters ignored) has JSON; an undecodable body is
//! no JSON; nesting deeper than 64 levels is 400 `invalid_json`, also when
//! `serde_json` gives up at its 128-level recursion limit (Python decodes up
//! to its own recursion limit and then fails the depth check or raises
//! `RecursionError`, both `invalid_json`).

use axum::body::{Body, Bytes};
use axum::http::HeaderMap;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use opsgate_core::json::{check_depth, parse_bytes};
use opsgate_core::pytext::{py_str, strip};
use opsgate_core::validate::py_truthy;
use serde_json::{Map, Value};

use crate::BODY_LIMIT;
use crate::error::AppError;
use crate::form::mimetype;

/// The whole body, at most [`BODY_LIMIT`] bytes.
pub async fn read_body(body: Body) -> Result<Bytes, AppError> {
    match Limited::new(body, BODY_LIMIT).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            Err(AppError::PayloadTooLarge)
        }
        Err(_) => Err(AppError::BodyUnreadable),
    }
}

/// Whether the request declares a JSON body (`request.is_json`).
pub fn is_json(headers: &HeaderMap) -> bool {
    let Some(mimetype) = mimetype(headers) else {
        return false;
    };
    mimetype == "application/json"
        || (mimetype.starts_with("application/") && mimetype.ends_with("+json"))
}

fn invalid_json(message: &str) -> AppError {
    AppError::service(message, 400, "invalid_json")
}

/// `parse_request_json()`: the decoded body, `None` when the request has no
/// JSON, or 400 `invalid_json` when it nests too deep.
pub fn parse_request_json(headers: &HeaderMap, body: &[u8]) -> Result<Option<Value>, AppError> {
    if !is_json(headers) {
        return Ok(None);
    }
    match parse_bytes(body) {
        Ok(value) => {
            check_depth(&value).map_err(|_| invalid_json("JSON nesting is too deep"))?;
            Ok(Some(value))
        }
        Err(error) if error.exceeds_recursion_limit() => {
            Err(invalid_json("JSON nesting is too deep"))
        }
        Err(_) => Ok(None),
    }
}

/// A JSON object or 400 `invalid_json` "JSON object required" (ticket
/// creation, runner status).
pub fn require_object(value: Option<Value>) -> Result<Map<String, Value>, AppError> {
    match value {
        Some(Value::Object(map)) => Ok(map),
        _ => Err(invalid_json("JSON object required")),
    }
}

/// `parse_request_json() or {}` (reject, cancel, claim): no JSON and a falsy
/// value are `{}`; a truthy value that is no object is 400 `invalid_json`
/// (D-4; Python: 500).
pub fn object_or_empty(value: Option<Value>) -> Result<Map<String, Value>, AppError> {
    match value {
        Some(Value::Object(map)) => Ok(map),
        Some(value) if py_truthy(&value) => Err(invalid_json("JSON object required")),
        _ => Ok(Map::new()),
    }
}

/// `str(payload.get(key, "")).strip()` of a text field the web layer reads
/// (`reason`, `runner_host`): an array or object, or a number that overflows
/// to infinity, is 400 `invalid_json` (D-2, D-3).
pub fn text_field(payload: &Map<String, Value>, key: &str) -> Result<String, AppError> {
    match payload.get(key) {
        None => Ok(String::new()),
        Some(value) => py_str(value)
            .map(|text| strip(&text).to_owned())
            .map_err(|_| invalid_json(&format!("{key} must be text, not a JSON array or object"))),
    }
}

/// The runner host of a claim or status request: the body's `runner_host`
/// (stripped), else the client address, else `runner`.
pub fn runner_host(payload: &Map<String, Value>, client_ip: &str) -> Result<String, AppError> {
    let host = text_field(payload, "runner_host")?;
    Ok(if !host.is_empty() {
        host
    } else if !client_ip.is_empty() {
        client_ip.to_owned()
    } else {
        "runner".to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serde_json::json;

    fn headers(content_type: &'static str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert("content-type", HeaderValue::from_static(content_type));
        map
    }

    fn code(result: Result<Option<Value>, AppError>) -> &'static str {
        match result {
            Err(AppError::Service(error)) => error.code,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn content_types() {
        for (content_type, json) in [
            ("application/json", true),
            ("Application/JSON; charset=utf-8", true),
            ("application/vnd.opsgate+json", true),
            ("application/+json", true),
            ("text/json", false),
            ("application/json-patch", false),
            ("text/plain", false),
        ] {
            assert_eq!(is_json(&headers(content_type)), json, "{content_type}");
        }
        assert!(!is_json(&HeaderMap::new()));
    }

    #[test]
    fn decoding() {
        let json = headers("application/json");
        assert_eq!(
            parse_request_json(&json, b"{\"a\": 1}").unwrap(),
            Some(json!({"a": 1}))
        );
        assert_eq!(
            parse_request_json(&json, b"\xef\xbb\xbf[]").unwrap(),
            Some(json!([]))
        );
        assert_eq!(parse_request_json(&json, b"{").unwrap(), None);
        assert_eq!(parse_request_json(&json, b"").unwrap(), None);
        assert_eq!(parse_request_json(&json, b"\xff").unwrap(), None);
        assert_eq!(
            parse_request_json(&headers("text/plain"), b"{}").unwrap(),
            None
        );
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(
            parse_request_json(&json, nested(64).as_bytes())
                .unwrap()
                .is_some()
        );
        assert_eq!(
            code(parse_request_json(&json, nested(65).as_bytes())),
            "invalid_json"
        );
        assert_eq!(
            code(parse_request_json(&json, nested(129).as_bytes())),
            "invalid_json"
        );
        assert_eq!(
            code(parse_request_json(&json, nested(2000).as_bytes())),
            "invalid_json"
        );
        // Malformed text within serde_json's limit is no JSON, as in Python.
        assert_eq!(
            parse_request_json(&json, "[".repeat(100).as_bytes()).unwrap(),
            None
        );
    }

    #[test]
    fn objects_and_falsy_values() {
        assert!(require_object(None).is_err());
        assert!(require_object(Some(json!([]))).is_err());
        assert_eq!(require_object(Some(json!({}))).unwrap(), Map::new());
        for falsy in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert_eq!(
                object_or_empty(Some(falsy.clone())).unwrap(),
                Map::new(),
                "{falsy}"
            );
        }
        for truthy in [json!([1]), json!("x"), json!(1), json!(true)] {
            assert!(object_or_empty(Some(truthy.clone())).is_err(), "{truthy}");
        }
        assert_eq!(object_or_empty(None).unwrap(), Map::new());
    }

    #[test]
    fn runner_host_derivation() {
        let host = |payload: Value, ip: &str| {
            runner_host(payload.as_object().unwrap(), ip).map_err(|error| error.to_string())
        };
        assert_eq!(
            host(json!({"runner_host": " r1 "}), "1.2.3.4").unwrap(),
            "r1"
        );
        assert_eq!(
            host(json!({"runner_host": "  "}), "1.2.3.4").unwrap(),
            "1.2.3.4"
        );
        assert_eq!(host(json!({}), "").unwrap(), "runner");
        assert_eq!(host(json!({"runner_host": null}), "").unwrap(), "None");
        assert_eq!(host(json!({"runner_host": false}), "").unwrap(), "False");
        assert_eq!(host(json!({"runner_host": 0}), "").unwrap(), "0");
        assert_eq!(host(json!({"runner_host": 1.5}), "").unwrap(), "1.5");
        assert!(host(json!({"runner_host": ["x"]}), "").is_err());
        assert!(host(json!({"runner_host": {}}), "").is_err());
    }
}
