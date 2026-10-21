//! `fixtures/checksum.json` and `fixtures/storage_json.json` (PLAN.md 4.8,
//! acceptance S2a): the canonical text and the payload checksum match CPython
//! byte for byte, the stored-column text matches semantically (and, with the
//! same formatter, byte for byte), D-2 inputs are rejected.

use opsgate_core::json::{canonical_json, parse, payload_checksum, stored_json};
use serde_json::Value;

fn cases(fixture: &str) -> Vec<Value> {
    let document: Value = serde_json::from_str(fixture).expect("fixture is JSON");
    document["cases"].as_array().expect("cases").clone()
}

fn field<'a>(case: &'a Value, name: &str) -> &'a str {
    case[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} missing in {case}"))
}

#[test]
fn checksum_fixture_matches_cpython_byte_for_byte() {
    let cases = cases(include_str!("../../../fixtures/checksum.json"));
    assert!(
        cases.len() >= 500,
        "PLAN.md 4.8 asks for at least 500 payloads"
    );
    let (mut matched, mut rejected) = (0, 0);
    for case in &cases {
        let input = field(case, "input");
        let parsed = parse(input);
        if case.get("error").is_some() {
            assert!(parsed.is_err(), "Python cannot decode {input:?}, Rust did");
            rejected += 1;
            continue;
        }
        if case.get("divergence").is_some() {
            assert_eq!(case["divergence"], "D-2");
            let canonical = parsed.as_ref().ok().map(canonical_json);
            assert!(
                !matches!(canonical, Some(Ok(_))),
                "D-2 input accepted: {input:?}"
            );
            rejected += 1;
            continue;
        }
        let value = parsed.unwrap_or_else(|error| panic!("{input:?}: {error}"));
        let canonical = canonical_json(&value).unwrap_or_else(|error| panic!("{input:?}: {error}"));
        assert_eq!(
            canonical,
            field(case, "canonical"),
            "canonical text of {input:?}"
        );
        assert_eq!(
            payload_checksum(&value).unwrap(),
            field(case, "checksum"),
            "checksum of {input:?}"
        );
        // The canonical text is a fixed point.
        assert_eq!(
            canonical_json(&parse(&canonical).unwrap()).unwrap(),
            canonical
        );
        matched += 1;
    }
    assert!(matched >= 500, "only {matched} payloads matched");
    assert!(rejected > 0);
}

#[test]
fn storage_fixture_matches_cpython() {
    let cases = cases(include_str!("../../../fixtures/storage_json.json"));
    assert!(cases.len() >= 100);
    for case in &cases {
        let input = field(case, "input");
        let parsed = parse(input);
        if case.get("divergence").is_some() {
            assert_eq!(case["divergence"], "D-2");
            let stored = parsed.as_ref().ok().map(stored_json);
            assert!(
                !matches!(stored, Some(Ok(_))),
                "D-2 input accepted: {input:?}"
            );
            continue;
        }
        let value = parsed.unwrap_or_else(|error| panic!("{input:?}: {error}"));
        let stored = stored_json(&value).unwrap();
        let python = field(case, "stored");
        // The contract (P2): Python and Rust read the same value back.
        let python_value = parse(python).unwrap();
        assert_eq!(
            canonical_json(&parse(&stored).unwrap()),
            canonical_json(&python_value),
            "{input:?}"
        );
        // The formatter is shared with the checksum, so the bytes agree too.
        assert_eq!(stored, python, "stored text of {input:?}");
    }
}
