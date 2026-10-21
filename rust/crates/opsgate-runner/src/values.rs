//! Python conversions the runner applies to values of API tickets and
//! artifacts: `str()`, truthiness and `int()`.

use opsgate_core::pytext;
use serde_json::Value;

use crate::api::JsonObject;

/// `str(value)`. Scalars as Python (PLAN.md 4.6). Arrays, objects and
/// overflowing floats never occur where the runner reads text (the API
/// validates plans and writes the other fields itself); Python would use
/// their `repr`, this uses their JSON text. The runner only compares such
/// text with fixed names or passes it on, so both behave the same.
pub(crate) fn py_text(value: &Value) -> String {
    match pytext::py_str(value) {
        Ok(text) => text.into_owned(),
        Err(_) => value.to_string(),
    }
}

/// `str(object.get(key, default))`.
pub(crate) fn text_or(object: &JsonObject, key: &str, default: &str) -> String {
    object.get(key).map_or_else(|| default.to_owned(), py_text)
}

/// `bool(value)` of a decoded JSON value.
pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => match opsgate_core::json::py_number(number) {
            opsgate_core::json::PyNumber::Int(digits) => digits != "0",
            opsgate_core::json::PyNumber::Float(float) => float != 0.0,
        },
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `int(value)`: integers, finite floats (truncated), booleans and integer
/// strings (Python's `int()` grammar for ASCII digits). `None` for what
/// Python rejects (`TypeError`/`ValueError`/`OverflowError`) and for
/// integers outside `i64`.
pub(crate) fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => match opsgate_core::json::py_number(number) {
            opsgate_core::json::PyNumber::Int(digits) => digits.parse().ok(),
            opsgate_core::json::PyNumber::Float(float) => {
                let truncated = float.trunc();
                // `i64::MAX as f64` rounds up to 2^63, so the bound is exclusive.
                (truncated.is_finite()
                    && truncated >= -(2_f64.powi(63))
                    && truncated < 2_f64.powi(63))
                .then_some(truncated as i64)
            }
        },
        Value::String(text) => parse_py_int(text),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// `int(text)` for a string (surrounding Python whitespace allowed).
pub(crate) fn parse_py_int(text: &str) -> Option<i64> {
    let stripped = pytext::strip(text);
    if stripped.is_empty() {
        return None;
    }
    opsgate_core::settings::parse_int(Some(stripped), 0, "value").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn conversions_follow_python() {
        assert_eq!(py_text(&json!("running")), "running");
        assert_eq!(py_text(&json!(null)), "None");
        assert_eq!(py_text(&json!(2)), "2");
        assert!(!truthy(&json!(0)));
        assert!(!truthy(&json!(0.0)));
        assert!(!truthy(&json!("")));
        assert!(truthy(&json!("0")));
        assert!(truthy(&json!([0])));
        assert_eq!(py_int(&json!(120)), Some(120));
        assert_eq!(py_int(&json!(1.9)), Some(1));
        assert_eq!(py_int(&json!(-1.9)), Some(-1));
        assert_eq!(py_int(&json!(true)), Some(1));
        assert_eq!(py_int(&json!(" 1_0 ")), Some(10));
        assert_eq!(py_int(&json!("1.5")), None);
        assert_eq!(py_int(&json!("  ")), None);
        assert_eq!(py_int(&json!(null)), None);
        assert_eq!(py_int(&json!([1])), None);
        let huge = opsgate_core::json::parse("1e300").unwrap();
        assert_eq!(py_int(&huge), None);
    }
}
