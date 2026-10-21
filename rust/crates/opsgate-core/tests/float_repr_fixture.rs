//! `fixtures/float_repr.json` (PLAN.md 4.8): CPython's `repr(float)` for
//! more than 10 000 doubles and the `float()` reading of JSON number tokens.

use opsgate_core::json::{PyNumber, canonical_json, parse, py_float_repr, py_number};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/float_repr.json"))
        .expect("fixture is JSON")
}

#[test]
fn repr_of_every_fixture_double_matches_cpython() {
    let document = fixture();
    let bits = document["bits"].as_object().expect("bits");
    assert!(
        bits.len() >= 10_000,
        "PLAN.md 4.8 asks for at least 10 000 values"
    );
    for (hex, expected) in bits {
        let value = f64::from_bits(u64::from_str_radix(hex, 16).expect("hex bits"));
        let expected = expected.as_str().expect("repr");
        assert_eq!(py_float_repr(value), expected, "bits {hex}");
        // The same through the formatter, for a float built in Rust.
        assert_eq!(
            canonical_json(&Value::from(value)).unwrap(),
            expected,
            "bits {hex}"
        );
    }
}

#[test]
fn number_tokens_read_like_cpython_float() {
    let document = fixture();
    let tokens = document["tokens"].as_object().expect("tokens");
    for (token, expected) in tokens {
        let value = parse(token).unwrap_or_else(|error| panic!("{token}: {error}"));
        let Value::Number(number) = &value else {
            panic!("{token} is not a number")
        };
        let PyNumber::Float(float) = py_number(number) else {
            panic!("{token} is not a float")
        };
        match expected.as_str() {
            Some(expected) => {
                assert_eq!(py_float_repr(float), expected, "{token}");
                assert_eq!(canonical_json(&value).unwrap(), expected, "{token}");
            }
            None => {
                assert!(float.is_infinite(), "{token} should overflow");
                assert!(canonical_json(&value).is_err(), "{token} is D-2");
            }
        }
    }
}
