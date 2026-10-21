//! `fixtures/pystr.json` (PLAN.md 4.6): `str()` of JSON scalars (stored
//! values, so exact), `str.strip()`, `str.lower()` and the character sets
//! behind them.

use opsgate_core::json::parse;
use opsgate_core::pytext::{is_space, py_lower, py_str, strip};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/pystr.json")).expect("fixture is JSON")
}

fn code_points(document: &Value, name: &str) -> Vec<u32> {
    document[name]
        .as_array()
        .expect(name)
        .iter()
        .map(|item| item.as_u64().expect("code point") as u32)
        .collect()
}

#[test]
fn str_of_json_scalars_matches_cpython() {
    let document = fixture();
    for case in document["str"].as_array().expect("str") {
        let input = case["input"].as_str().expect("input");
        let parsed = parse(input);
        match case.get("divergence").and_then(Value::as_str) {
            Some(divergence) => {
                assert!(divergence == "D-2" || divergence == "D-3", "{divergence}");
                let text = parsed.as_ref().ok().map(py_str);
                assert!(
                    !matches!(text, Some(Ok(_))),
                    "{divergence} input accepted: {input:?}"
                );
            }
            None => {
                let value = parsed.unwrap_or_else(|error| panic!("{input:?}: {error}"));
                assert_eq!(
                    py_str(&value).unwrap(),
                    case["python"].as_str().expect("python"),
                    "{input:?}"
                );
            }
        }
    }
}

#[test]
fn strip_and_lower_match_cpython() {
    let document = fixture();
    for case in document["strip"].as_array().expect("strip") {
        let input = case["input"].as_str().expect("input");
        assert_eq!(
            strip(input),
            case["python"].as_str().expect("python"),
            "{input:?}"
        );
    }
    for case in document["lower"].as_array().expect("lower") {
        let input = case["input"].as_str().expect("input");
        assert_eq!(
            py_lower(input),
            case["python"].as_str().expect("python"),
            "{input:?}"
        );
    }
}

#[test]
fn whitespace_set_is_pythons() {
    let whitespace = code_points(&fixture(), "whitespace");
    for character in (0..=0x10_FFFF).filter_map(char::from_u32) {
        assert_eq!(
            is_space(character),
            whitespace.contains(&(character as u32)),
            "U+{:04X}",
            character as u32
        );
    }
}

#[test]
fn only_pythons_characters_lower_to_ascii() {
    let to_ascii = code_points(&fixture(), "lower_to_ascii");
    for character in (0x80..=0x10_FFFF).filter_map(char::from_u32) {
        let lowered = py_lower(character.encode_utf8(&mut [0; 4]));
        assert_eq!(
            lowered.is_ascii(),
            to_ascii.contains(&(character as u32)),
            "U+{:04X}",
            character as u32
        );
    }
}
