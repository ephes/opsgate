//! `rust/fixtures/bcrypt.json` and `rust/fixtures/throttle.json` (PLAN.md
//! 4.5.3, 7.2): the password check of `ui_login` (pyca bcrypt 4.3's
//! `checkpw`, `ValueError` as a mismatch) and `LoginThrottle` with a fake
//! clock, both against Python's results.

use std::sync::{Arc, Mutex};

use opsgate_web::password::checkpw;
use opsgate_web::throttle::LoginThrottle;
use serde_json::Value;

const BCRYPT: &str = include_str!("../../../fixtures/bcrypt.json");
const THROTTLE: &str = include_str!("../../../fixtures/throttle.json");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn bcrypt_checks_match_pyca() {
    let fixture: Value = serde_json::from_str(BCRYPT).unwrap();
    assert!(
        fixture["library"]
            .as_str()
            .unwrap()
            .starts_with("pyca bcrypt 4.3."),
        "{}",
        fixture["library"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 50, "{}", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        let password = hex(case["password_hex"].as_str().unwrap());
        let hash = case["hash"].as_str().unwrap();
        let expected = case["matches"].as_bool().unwrap();
        if checkpw(&password, hash.as_bytes()) != expected {
            failures.push(case["name"].as_str().unwrap().to_owned());
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
    // The corpus covers what PLAN.md 4.5.3 names.
    for name in [
        "$2a$ right password",
        "$2b$ right password",
        "$2y$ right password",
        "73 bytes: truncated to 72",
        "embedded NUL, matching",
        "embedded NUL, other bytes after the NUL",
        "cost 3",
        "salt with non-zero trailing bits",
    ] {
        assert!(
            cases.iter().any(|case| case["name"] == name),
            "missing case {name}"
        );
    }
}

/// The fake clock of a scenario.
#[derive(Clone, Default)]
struct FakeClock(Arc<Mutex<f64>>);

impl FakeClock {
    fn set(&self, now: f64) {
        *self.0.lock().unwrap() = now;
    }
}

fn expected_failures(value: &Value) -> Vec<(String, Vec<f64>)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let key = entry[0].as_str().unwrap().to_owned();
            let stamps = entry[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|stamp| stamp.as_f64().unwrap())
                .collect();
            (key, stamps)
        })
        .collect()
}

#[test]
fn throttle_sequences_match_python() {
    let fixture: Value = serde_json::from_str(THROTTLE).unwrap();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 40, "{}", scenarios.len());
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let clock = FakeClock::default();
        let reading = clock.clone();
        let throttle = LoginThrottle::new(
            usize::try_from(scenario["limit"].as_u64().unwrap()).unwrap(),
            scenario["window_seconds"].as_f64().unwrap(),
            usize::try_from(scenario["max_tracked_clients"].as_u64().unwrap()).unwrap(),
            Arc::new(move || *reading.0.lock().unwrap()),
        );
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            clock.set(step["now"].as_f64().unwrap());
            let key = step["key"].as_str().unwrap();
            let result = match step["op"].as_str().unwrap() {
                "fail" => {
                    throttle.record_failure(key);
                    Value::Null
                }
                "locked" => Value::Bool(throttle.is_locked(key)),
                "reset" => {
                    throttle.reset(key);
                    Value::Null
                }
                other => panic!("{name}: unknown op {other}"),
            };
            assert_eq!(result, step["result"], "{name} step {index}");
            assert_eq!(
                throttle.tracked(),
                expected_failures(&step["failures"]),
                "{name} step {index}"
            );
        }
    }
}
