//! `fixtures/validation.json` (PLAN.md 4.7.1 steps 1–10, acceptance S2c):
//! every request body yields the normalised ticket Python produces (the same
//! canonical checksum text, byte for byte, and the same `payload_checksum`)
//! or the same error code and status; D-2/D-3 cases yield the decided Rust
//! result. The body is decoded as the API decodes it: text Rust cannot
//! decode (D-2) is `invalid_json`.

use opsgate_core::error::ServiceError;
use opsgate_core::json::{canonical_json, parse};
use opsgate_core::validate::{NewTicketContext, NormalizedTicket, normalize_new_ticket};
use serde_json::Value;

fn cases() -> Vec<Value> {
    let document: Value =
        serde_json::from_str(include_str!("../../../fixtures/validation.json")).expect("JSON");
    document["cases"].as_array().expect("cases").clone()
}

fn text<'a>(case: &'a Value, name: &str) -> &'a str {
    case[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} missing in {case}"))
}

/// The body as `POST /api/v1/tickets` would hand it to validation.
fn validate(case: &Value) -> Result<NormalizedTicket, ServiceError> {
    let body = match parse(text(case, "input")) {
        Ok(Value::Object(body)) => body,
        Ok(other) => panic!("fixture input is not an object: {other}"),
        Err(error) => return Err(ServiceError::new(error.to_string(), 400, "invalid_json")),
    };
    let context = NewTicketContext {
        source: text(case, "source"),
        require_reviewer_step_floor: case["floor"].as_bool().expect("floor"),
        max_duration_seconds_default: case["default_duration"].as_i64().expect("default"),
    };
    normalize_new_ticket(&body, &context)
}

#[test]
fn validation_fixture_matches_python() {
    let cases = cases();
    assert!(
        cases.len() >= 150,
        "PLAN.md acceptance S2c asks for at least 150 payloads"
    );
    let (mut tickets, mut errors, mut divergent) = (0, 0, 0);
    for case in &cases {
        let name = text(case, "name");
        let expected = match case.get("divergence") {
            Some(divergence) => {
                assert!(
                    divergence == "D-2" || divergence == "D-3",
                    "{name}: {divergence}"
                );
                divergent += 1;
                &case["rust"]
            }
            None => &case["python"],
        };
        let outcome = validate(case);
        if let Some(error) = expected.get("error") {
            let actual = outcome
                .map(|ticket| ticket.payload_checksum)
                .expect_err(&format!("{name}: expected {error}"));
            assert_eq!(actual.code, text(error, "code"), "{name}: {actual:?}");
            assert_eq!(
                u64::from(actual.status),
                error["status"].as_u64().expect("status"),
                "{name}"
            );
            // Messages are P2; compared where both stop at the same check.
            if let Some(message) = error
                .get("message")
                .filter(|_| case.get("message_divergence").is_none())
            {
                assert_eq!(actual.message, message.as_str().unwrap(), "{name}");
            }
            errors += 1;
            continue;
        }
        let ticket = outcome.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let canonical = canonical_json(&ticket.payload().to_value()).expect("finite");
        assert_eq!(canonical, text(expected, "canonical"), "{name}");
        assert_eq!(
            ticket.payload_checksum,
            text(expected, "payload_checksum"),
            "{name}"
        );
        tickets += 1;
    }
    assert!(tickets >= 100, "only {tickets} accepted payloads");
    assert!(errors >= 150, "only {errors} rejected payloads");
    assert!(divergent > 0);
}

#[test]
fn every_step_and_code_is_covered() {
    let cases = cases();
    for code in [
        "source_mismatch",
        "invalid_ticket",
        "invalid_execution_plan",
        "invalid_policy_requirements",
        "policy_floor_violation",
        "missing_reviewer_step",
        "invalid_expires_at",
    ] {
        assert!(
            cases
                .iter()
                .any(|case| case["python"]["error"]["code"] == code),
            "no case for {code}"
        );
    }
    for divergence in ["D-2", "D-3"] {
        assert!(
            cases.iter().any(|case| case["divergence"] == divergence),
            "no case for {divergence}"
        );
    }
}
