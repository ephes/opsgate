//! Ports of the `tests/test_api.py` cases of ticket validation (TESTMAP,
//! slice S2c), at the level of `normalize_new_ticket`: what the API answers
//! (code, status, message) and what it would store. The HTTP parts of those
//! tests (status of the response, nothing stored, nothing claimable) are
//! covered by the API parity harness and the web slices.

use opsgate_core::error::ServiceError;
use opsgate_core::json::parse;
use opsgate_core::validate::{
    NewTicketContext, NormalizedTicket, PlanStep, normalize_new_ticket, parse_execution_plan,
};
use serde_json::{Value, json};

const NYXMON: NewTicketContext<'static> = NewTicketContext {
    source: "nyxmon",
    require_reviewer_step_floor: false,
    max_duration_seconds_default: 3600,
};

const OPERATOR: NewTicketContext<'static> = NewTicketContext {
    source: "operator",
    require_reviewer_step_floor: false,
    max_duration_seconds_default: 3600,
};

/// The body as the API decodes it; undecodable text is `invalid_json`.
fn create(body: &str, context: &NewTicketContext<'_>) -> Result<NormalizedTicket, ServiceError> {
    match parse(body) {
        Ok(Value::Object(body)) => normalize_new_ticket(&body, context),
        Ok(other) => panic!("not an object: {other}"),
        Err(error) => Err(ServiceError::new(error.to_string(), 400, "invalid_json")),
    }
}

fn create_value(
    body: Value,
    context: &NewTicketContext<'_>,
) -> Result<NormalizedTicket, ServiceError> {
    create(&body.to_string(), context)
}

fn inspect_plan() -> Value {
    json!([{"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}])
}

fn step(role: &str, agent: &str, prompt: &str) -> PlanStep {
    PlanStep {
        role: role.to_owned(),
        agent: agent.to_owned(),
        prompt_markdown: prompt.to_owned(),
    }
}

#[test]
fn test_api_ticket_creation_rejects_unsupported_agent() {
    let error = create_value(
        json!({
            "title": "Bad API agent",
            "summary": "Unsupported agents should be rejected",
            "execution_plan": [
                {"role": "investigator", "agent": "shell", "prompt_markdown": "Inspect the service"}
            ],
        }),
        &NYXMON,
    )
    .unwrap_err();
    assert_eq!(
        error,
        ServiceError::new(
            "agent must be one of: codex, claude",
            400,
            "invalid_execution_plan"
        )
    );
}

#[test]
fn test_api_ticket_creation_normalizes_agent_case() {
    let ticket = create_value(
        json!({
            "title": "Mixed case agent",
            "summary": "Agent values should normalize to lowercase",
            "execution_plan": [
                {"role": "reviewer", "agent": "CLAUDE", "prompt_markdown": "Review the change"}
            ],
        }),
        &NYXMON,
    )
    .unwrap();
    assert_eq!(
        ticket.execution_plan,
        [step("reviewer", "claude", "Review the change")]
    );
}

#[test]
fn test_operator_submitter_may_explicitly_require_reviewer_step() {
    let ticket = create_value(
        json!({
            "title": "Operator task",
            "summary": "Operator may opt into reviewer requirement",
            "execution_plan": [{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
            "policy_requirements": {"require_reviewer_step": true},
        }),
        &OPERATOR,
    )
    .unwrap();
    assert_eq!(
        ticket.policy_requirements,
        json!({"require_reviewer_step": true})
    );
}

#[test]
fn test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor() {
    let ticket = create_value(
        json!({
            "title": "Operator task with omitted policy",
            "summary": "Should default to no reviewer floor",
            "execution_plan": [{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}],
        }),
        &OPERATOR,
    )
    .unwrap();
    assert_eq!(
        ticket.policy_requirements,
        json!({"require_reviewer_step": false})
    );
}

#[test]
fn test_api_rejects_non_text_plan_fields() {
    for field in ["role", "agent", "prompt_markdown"] {
        for value in [
            json!(null),
            json!(true),
            json!(42),
            json!([]),
            json!({}),
            json!(""),
            json!("   "),
        ] {
            let mut plan = inspect_plan();
            plan[0][field] = value.clone();
            let error = create_value(
                json!({"title": "Invalid plan", "summary": "Validate text", "execution_plan": plan}),
                &NYXMON,
            )
            .unwrap_err();
            assert_eq!(error.code, "invalid_execution_plan", "{field}={value}");
            assert_eq!(error.status, 400);
            // The same check guards stored plans at approval and claim.
            assert_eq!(
                parse_execution_plan(&plan).unwrap_err().code,
                "invalid_execution_plan"
            );
        }
    }
}

/// The `invalid_expires_at` half; the time half is
/// `src/time.rs::tests::utc_overflow_is_out_of_range` (S2a).
#[test]
fn test_api_rejects_utc_expiry_overflow() {
    for expiry in ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"] {
        let error = create_value(
            json!({"title": "Expiry", "summary": "Bounds", "expires_at": expiry,
                   "execution_plan": inspect_plan()}),
            &NYXMON,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ServiceError::new(
                "Datetime is outside supported UTC bounds",
                400,
                "invalid_expires_at"
            ),
            "{expiry}"
        );
    }
}

#[test]
fn test_api_accepts_trimmed_plan_and_optional_expiry() {
    for (expiry, stored) in [
        (None, None),
        (
            Some("2099-01-01T01:00:00+01:00"),
            Some("2099-01-01T00:00:00Z"),
        ),
    ] {
        let mut body = json!({
            "title": "Valid", "summary": "Normalization",
            "execution_plan": [{"role": " investigator ", "agent": " CODEX ", "prompt_markdown": " Inspect "}],
        });
        if let Some(expiry) = expiry {
            body["expires_at"] = json!(expiry);
        }
        let ticket = create_value(body, &NYXMON).unwrap();
        assert_eq!(
            ticket.execution_plan,
            [step("investigator", "codex", "Inspect")]
        );
        assert_eq!(ticket.expires_at.as_deref(), stored);
    }
}

#[test]
fn test_ticket_duration_rejects_invalid_values() {
    let googol = format!("1{}", "0".repeat(100));
    for duration in [
        "true", "false", "1.5", "900.0", &googol, "0", "-1", "\"900\"", "31536001",
    ] {
        let body = format!(
            r#"{{"title": "Duration", "summary": "Invalid duration", "max_duration_seconds": {duration},
               "execution_plan": [{{"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}}]}}"#
        );
        let error = create(&body, &NYXMON).unwrap_err();
        assert_eq!(error.code, "invalid_ticket", "{duration}");
        assert_eq!(error.status, 400);
    }
    // D-2: `float("inf")` reaches Python as an `Infinity` literal, which
    // Rust cannot decode (Python: `invalid_ticket`).
    let body = r#"{"title": "Duration", "summary": "Invalid duration", "max_duration_seconds": Infinity,
                   "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}]}"#;
    assert_eq!(create(body, &NYXMON).unwrap_err().code, "invalid_json");
}

#[test]
fn test_ticket_duration_accepts_boundaries() {
    for (duration, stored) in [
        (json!(1), 1),
        (json!(31_536_000), 31_536_000),
        (json!(null), 3600),
    ] {
        let ticket = create_value(
            json!({"title": "Duration", "summary": "Valid duration", "max_duration_seconds": duration,
                   "execution_plan": inspect_plan()}),
            &NYXMON,
        )
        .unwrap();
        assert_eq!(ticket.max_duration_seconds, stored);
    }
}

#[test]
fn test_ticket_duration_rejects_json_exponent_overflow() {
    let error = create(
        concat!(
            r#"{"title":"Overflow","summary":"Duration","max_duration_seconds":1e309,"#,
            r#""execution_plan":[{"role":"investigator","agent":"codex","prompt_markdown":"Inspect"}]}"#
        ),
        &NYXMON,
    )
    .unwrap_err();
    assert_eq!(error.code, "invalid_ticket");
}

/// P3 D-2: Python answers `invalid_ticket` ("<field> must be valid UTF-8
/// text"); Rust cannot decode a body with a lone surrogate escape and
/// answers `invalid_json` before validation.
#[test]
fn test_ticket_text_rejects_unpaired_surrogates() {
    for field in ["title", "summary", "task_ref"] {
        for surrogate in [r"\ud800", r"\udfff"] {
            let mut body = json!({"title": "Title", "summary": "Summary", "task_ref": "task",
                                  "execution_plan": inspect_plan()});
            body[field] = json!("private text @");
            let text = body.to_string().replace('@', &surrogate.repeat(1000));
            let error = create(&text, &NYXMON).unwrap_err();
            assert_eq!(error.code, "invalid_json", "{field}");
            assert_eq!(error.status, 400);
        }
    }
}

/// P3 D-2: Python rejects lone surrogates in the creation metadata
/// (`source`, `created_by`, `source_ip`, `user_agent`) with
/// `invalid_ticket`. Rust strings cannot hold one: a body field with a lone
/// surrogate escape is undecodable (`invalid_json`), the configured source
/// and username come from settings that must be UTF-8 (D-8), and the web
/// layer reads header bytes as latin-1 text as WSGI does (S4a), so step 11's
/// check has nothing to reject. What remains testable here is the body path.
#[test]
fn test_ticket_creation_metadata_rejects_unpaired_surrogates() {
    let body = format!(
        r#"{{"source": "bad\ud800", "title": "Title", "summary": "Summary", "execution_plan": {}}}"#,
        inspect_plan()
    );
    assert_eq!(create(&body, &NYXMON).unwrap_err().code, "invalid_json");
}

#[test]
fn normalised_ticket_and_checksum_payload() {
    let ticket = create(
        r#"{"source": " nyxmon ", "task_ref": "  nyxmon-check-42 ", "title": " T ", "summary": "S\n",
            "execution_plan": [{"role": "reviewer", "agent": "Claude", "prompt_markdown": "Review", "x": 1}],
            "policy_requirements": {"require_reviewer_step": true, "extra": 1},
            "context": {"value": 0.95, "threshold": 3.0},
            "expires_at": "2099-01-01T01:00:00.5+01:00", "max_duration_seconds": 1800}"#,
        &NYXMON,
    )
    .unwrap();
    assert_eq!(ticket.source, "nyxmon");
    assert_eq!(ticket.task_ref.as_deref(), Some("nyxmon-check-42"));
    assert_eq!((ticket.title.as_str(), ticket.summary.as_str()), ("T", "S"));
    assert_eq!(
        ticket.execution_plan,
        [step("reviewer", "claude", "Review")]
    );
    assert_eq!(
        ticket.policy_requirements,
        json!({"require_reviewer_step": true})
    );
    assert_eq!(
        ticket.expires_at.as_deref(),
        Some("2099-01-01T00:00:00.500000Z")
    );
    assert_eq!(ticket.max_duration_seconds, 1800);
    assert_eq!(
        opsgate_core::json::canonical_json(&ticket.payload().to_value()).unwrap(),
        concat!(
            r#"{"context":{"threshold":3.0,"value":0.95},"#,
            r#""execution_plan":[{"agent":"claude","prompt_markdown":"Review","role":"reviewer"}],"#,
            r#""expires_at":"2099-01-01T00:00:00.500000Z","max_duration_seconds":1800,"#,
            r#""policy_requirements":{"require_reviewer_step":true},"source":"nyxmon","#,
            r#""summary":"S","task_ref":"nyxmon-check-42","title":"T"}"#
        )
    );
    assert_eq!(
        ticket.payload_checksum,
        ticket.payload().checksum().unwrap()
    );
}

#[test]
fn text_field_divergences() {
    // D-3: Python stores the repr of an array or object.
    for field in ["title", "summary", "task_ref"] {
        let mut body = json!({"title": "T", "summary": "S", "execution_plan": inspect_plan()});
        body[field] = json!(["x"]);
        assert_eq!(
            create_value(body, &NYXMON).unwrap_err().code,
            "invalid_ticket",
            "{field}"
        );
    }
    // D-2: Python stores `inf`.
    let body = r#"{"title": 1e400, "summary": "S", "execution_plan": []}"#;
    assert_eq!(create(body, &NYXMON).unwrap_err().code, "invalid_ticket");
    // Python rejects these too: `source_mismatch`, `invalid_expires_at`.
    let body = r#"{"source": ["nyxmon"], "title": "T", "summary": "S"}"#;
    assert_eq!(create(body, &NYXMON).unwrap_err().code, "source_mismatch");
    let body = r#"{"title": "T", "summary": "S", "execution_plan": [{"role": "a", "agent": "codex",
                   "prompt_markdown": "p"}], "expires_at": {"at": 1}}"#;
    assert_eq!(
        create(body, &NYXMON).unwrap_err().code,
        "invalid_expires_at"
    );
    // D-2: an overflowing float in the context cannot be hashed.
    let body = r#"{"title": "T", "summary": "S", "execution_plan": [{"role": "a", "agent": "codex",
                   "prompt_markdown": "p"}], "context": {"metric": 1e400}}"#;
    let error = create(body, &NYXMON).unwrap_err();
    assert_eq!((error.status, error.code), (400, "invalid_json"));
}
