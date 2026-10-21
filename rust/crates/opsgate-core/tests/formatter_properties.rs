//! Property tests of the JSON formatter (PLAN.md 7.1): for arbitrary values,
//! the canonical and stored texts are ASCII, parse back to the same value
//! (numbers compared as Python reads them), and are fixed points.

use opsgate_core::json::{PyNumber, canonical_json, parse, py_number, stored_json};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

fn number() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>().prop_filter_map("finite", |value| Number::from_f64(value).map(Value::Number)),
        "-?[1-9][0-9]{0,60}".prop_map(|digits| parse(&digits).unwrap()),
        ("-?(0|[1-9][0-9]{0,19})", "[0-9]{1,20}", -330_i32..330).prop_filter_map(
            "finite (an overflowing token is D-2)",
            |(int, frac, exp)| {
                let value = parse(&format!("{int}.{frac}e{exp}")).unwrap();
                let Value::Number(number) = &value else {
                    return None;
                };
                matches!(py_number(number), PyNumber::Float(float) if float.is_finite())
                    .then_some(value)
            }
        ),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<String>().prop_map(Value::String),
        number(),
    ];
    leaf.prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((any::<String>(), inner), 0..6)
                .prop_map(|entries| Value::Object(entries.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// Structural equality with numbers compared as Python values (a token and
/// its re-rendering differ in spelling, not in value).
fn same(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => match (py_number(a), py_number(b)) {
            (PyNumber::Int(a), PyNumber::Int(b)) => a == b,
            (PyNumber::Float(a), PyNumber::Float(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        },
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| same(a, b)))
        }
        _ => left == right,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn texts_are_ascii_round_trips_and_fixed_points(value in value()) {
        for text in [canonical_json(&value), stored_json(&value)] {
            let text = text.expect("finite values serialize");
            prop_assert!(text.is_ascii());
            let reparsed = parse(&text).expect("output parses");
            prop_assert!(same(&value, &reparsed), "{} vs {}", value, reparsed);
        }
        let canonical = canonical_json(&value).unwrap();
        prop_assert_eq!(canonical_json(&parse(&canonical).unwrap()).unwrap(), canonical.clone());
        prop_assert_eq!(serde_json::from_str::<Value>(&canonical).is_ok(), true);
    }
}
