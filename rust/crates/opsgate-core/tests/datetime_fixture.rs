//! `fixtures/datetime.json` (PLAN.md 4.9, acceptance S2a): every input Rust
//! accepts gives CPython 3.14's instant; every input Rust rejects is rejected
//! by Python too or marked D-7; `isoformat_z` matches.

use chrono::{TimeDelta, TimeZone, Utc};
use opsgate_core::time::{isoformat_z, parse_iso_datetime};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/datetime.json")).expect("fixture is JSON")
}

#[test]
fn parse_matches_cpython_or_is_d7() {
    let document = fixture();
    let cases = document["parse"].as_array().expect("parse");
    assert!(cases.len() >= 500);
    let mut divergent = 0;
    for case in cases {
        let input = case["input"].as_str().expect("input");
        let rust = parse_iso_datetime(input).map(|value| isoformat_z(&value));
        match (case["python"].as_str(), case.get("divergence")) {
            (None, _) => assert!(
                rust.is_err(),
                "Python rejects {input:?}, Rust gave {rust:?}"
            ),
            (Some(_), Some(divergence)) => {
                assert_eq!(divergence, "D-7");
                assert!(rust.is_err(), "D-7 input accepted: {input:?}");
                divergent += 1;
            }
            (Some(python), None) => assert_eq!(rust.as_deref(), Ok(python), "{input:?}"),
        }
    }
    assert!(divergent > 0);
}

#[test]
fn isoformat_z_matches_cpython() {
    let document = fixture();
    for case in document["format"].as_array().expect("format") {
        let parts: Vec<u32> = case["utc"]
            .as_array()
            .expect("utc")
            .iter()
            .map(|n| n.as_u64().unwrap() as u32)
            .collect();
        let [year, month, day, hour, minute, second, micros] = parts[..] else {
            panic!("seven components")
        };
        let value = Utc
            .with_ymd_and_hms(year as i32, month, day, hour, minute, second)
            .unwrap()
            + TimeDelta::microseconds(i64::from(micros));
        assert_eq!(
            isoformat_z(&value),
            case["python"].as_str().expect("python"),
            "{parts:?}"
        );
    }
}
