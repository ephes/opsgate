//! Validation and normalisation of a new ticket (PLAN.md 4.7.1 steps 1–10)
//! and the plan/policy checks that approval and claim repeat on stored
//! tickets (4.7.2, 4.7.3).
//!
//! Ported Python (`service.py`): `normalize_agent`, `parse_execution_plan`,
//! `parse_policy_requirements`, `merge_policy_requirements`,
//! `enforce_policy_against_plan`, `OpsGateService._normalize_new_ticket`,
//! `_ticket_payload_from_fields` and `require_reviewer_step_floor_for_source`.
//! Pinned by `fixtures/validation.json`.
//!
//! Divergences (PLAN.md section 5): `str()` of a JSON array or object in
//! `title`, `summary` or `task_ref` is `invalid_ticket` (D-3; Python stores
//! the `repr`), and so is `str()` of a number that overflows to infinity
//! there (D-2; Python stores `inf`); a payload whose checksum would contain a
//! non-finite float is `invalid_json` (D-2; Python stores `Infinity`). Lone
//! surrogates cannot reach this module: they make the request body
//! undecodable (`invalid_json`, D-2), so step 4 (`validate_storage_text`)
//! has nothing left to check.

use std::borrow::Cow;

use serde_json::{Map, Value, json};

use crate::error::ServiceError;
use crate::json::{PyNumber, payload_checksum, py_number};
use crate::pytext::{PyStrError, py_lower, py_str, strip};
use crate::settings::{MAX_DURATION_SECONDS, SubmitterPolicy};
use crate::time::{isoformat_z, parse_iso_datetime};

/// `SUPPORTED_AGENTS`, in the order the error message lists them.
pub const SUPPORTED_AGENTS: [&str; 2] = ["codex", "claude"];

/// One normalised step of an execution plan: role and prompt stripped, agent
/// stripped, lowercased and supported. Extra keys of the input are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub role: String,
    pub agent: String,
    pub prompt_markdown: String,
}

impl PlanStep {
    /// The step as stored and hashed: `{"role", "agent", "prompt_markdown"}`.
    pub fn to_value(&self) -> Value {
        json!({
            "role": self.role,
            "agent": self.agent,
            "prompt_markdown": self.prompt_markdown,
        })
    }
}

/// A normalised plan as a JSON array (`execution_plan_json`, the checksum).
pub fn plan_value(steps: &[PlanStep]) -> Value {
    Value::Array(steps.iter().map(PlanStep::to_value).collect())
}

fn invalid_plan(message: impl Into<String>) -> ServiceError {
    ServiceError::new(message, 400, "invalid_execution_plan")
}

/// `normalize_agent`: `str(agent).strip().lower()` must be a supported agent.
pub fn normalize_agent(raw: &str) -> Result<String, ServiceError> {
    let normalized = py_lower(strip(raw));
    if SUPPORTED_AGENTS.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(invalid_plan(format!(
            "agent must be one of: {}",
            SUPPORTED_AGENTS.join(", ")
        )))
    }
}

/// `parse_execution_plan`: a non-empty array of objects, each with non-blank
/// string `role`, `agent` and `prompt_markdown`; the first failing step
/// decides the message. Pass [`Value::Null`] for an absent plan.
pub fn parse_execution_plan(raw: &Value) -> Result<Vec<PlanStep>, ServiceError> {
    let steps = match raw {
        Value::Array(steps) if !steps.is_empty() => steps,
        _ => return Err(invalid_plan("execution_plan must be a non-empty array")),
    };
    steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let Value::Object(step) = step else {
                return Err(invalid_plan(format!(
                    "execution_plan[{index}] must be an object"
                )));
            };
            let text = |key: &str| match step.get(key) {
                Some(Value::String(text)) if !strip(text).is_empty() => Some(text.as_str()),
                _ => None,
            };
            let (Some(role), Some(agent), Some(prompt_markdown)) =
                (text("role"), text("agent"), text("prompt_markdown"))
            else {
                return Err(invalid_plan(format!(
                    "execution_plan[{index}] requires role, agent, and prompt_markdown"
                )));
            };
            Ok(PlanStep {
                role: strip(role).to_owned(),
                agent: normalize_agent(agent)?,
                prompt_markdown: strip(prompt_markdown).to_owned(),
            })
        })
        .collect()
}

fn invalid_policy(message: &str) -> ServiceError {
    ServiceError::new(message, 400, "invalid_policy_requirements")
}

/// `parse_policy_requirements`: `null` or `""` → `{}` (`None`); any other
/// non-object is rejected; of an object only a boolean
/// `require_reviewer_step` is kept (`Some(value)`; absent → `None`). Pass
/// [`Value::Null`] for an absent field.
pub fn parse_policy_requirements(raw: &Value) -> Result<Option<bool>, ServiceError> {
    match raw {
        Value::Null => Ok(None),
        Value::String(text) if text.is_empty() => Ok(None),
        Value::Object(policy) => match policy.get("require_reviewer_step") {
            None => Ok(None),
            Some(Value::Bool(require)) => Ok(Some(*require)),
            Some(_) => Err(invalid_policy(
                "policy_requirements.require_reviewer_step must be true/false",
            )),
        },
        _ => Err(invalid_policy("policy_requirements must be an object")),
    }
}

/// `merge_policy_requirements`: the submitter's floor cannot be weakened by
/// an explicit `false`; the effective requirement is `floor or ticket`.
pub fn merge_policy_requirements(floor: bool, ticket: Option<bool>) -> Result<bool, ServiceError> {
    if floor && ticket == Some(false) {
        return Err(ServiceError::new(
            "Ticket policy cannot weaken submit token policy floor",
            400,
            "policy_floor_violation",
        ));
    }
    Ok(floor || ticket == Some(true))
}

/// The effective policy as stored and hashed: `{"require_reviewer_step": b}`.
pub fn policy_value(require_reviewer_step: bool) -> Value {
    json!({ "require_reviewer_step": require_reviewer_step })
}

/// `enforce_policy_against_plan`: a required reviewer needs a step whose
/// role, stripped and lowercased, is `reviewer`.
pub fn enforce_policy_against_plan(
    require_reviewer_step: bool,
    plan: &[PlanStep],
) -> Result<(), ServiceError> {
    if require_reviewer_step
        && !plan
            .iter()
            .any(|step| py_lower(strip(&step.role)) == "reviewer")
    {
        return Err(ServiceError::new(
            "policy_requirements.require_reviewer_step=true requires at least one reviewer step",
            400,
            "missing_reviewer_step",
        ));
    }
    Ok(())
}

/// `policy_requirements.get("require_reviewer_step", False)` of a stored
/// policy object, with Python's truthiness: approval enforces the stored
/// policy without parsing it first (4.7.2).
pub fn stored_policy_requires_reviewer(policy: &Map<String, Value>) -> bool {
    policy.get("require_reviewer_step").is_some_and(py_truthy)
}

/// Python's `bool()` of a value decoded by `json.loads`.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => match py_number(number) {
            PyNumber::Int(digits) => digits != "0",
            // NaN is truthy in Python, as `!= 0.0` gives.
            PyNumber::Float(value) => value != 0.0,
        },
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `require_reviewer_step_floor_for_source`: the floor of the submitter whose
/// source matches (stripped, lowercased), else `false`. Manual tickets use it
/// with `"operator"`.
pub fn require_reviewer_step_floor_for_source(policies: &[SubmitterPolicy], source: &str) -> bool {
    let wanted = py_lower(strip(source));
    policies
        .iter()
        .find(|policy| py_lower(strip(&policy.source)) == wanted)
        .is_some_and(|policy| policy.require_reviewer_step_floor)
}

/// `_ticket_payload_from_fields`: the fields the payload checksum covers
/// (4.8). Approval and claim build it from the stored columns; creation from
/// the normalised ticket.
#[derive(Debug, Clone, Copy)]
pub struct TicketPayload<'a> {
    pub source: &'a str,
    pub task_ref: Option<&'a str>,
    pub title: &'a str,
    pub summary: &'a str,
    pub execution_plan: &'a [PlanStep],
    pub policy_requirements: &'a Value,
    pub context: &'a Value,
    pub expires_at: Option<&'a str>,
    pub max_duration_seconds: i64,
}

impl TicketPayload<'_> {
    /// The payload as the JSON object `compute_payload_checksum` hashes.
    pub fn to_value(&self) -> Value {
        json!({
            "source": self.source,
            "task_ref": self.task_ref,
            "title": self.title,
            "summary": self.summary,
            "execution_plan": plan_value(self.execution_plan),
            "policy_requirements": self.policy_requirements,
            "context": self.context,
            "expires_at": self.expires_at,
            "max_duration_seconds": self.max_duration_seconds,
        })
    }

    /// `compute_payload_checksum(payload)` (byte-exact, 4.8). A non-finite
    /// float in the context or policy is `invalid_json` (D-2).
    pub fn checksum(&self) -> Result<String, ServiceError> {
        payload_checksum(&self.to_value()).map_err(|error| {
            ServiceError::new(
                format!("Ticket payload cannot be stored: {error}"),
                400,
                "invalid_json",
            )
        })
    }
}

/// Who creates the ticket and the settings normalisation needs.
#[derive(Debug, Clone, Copy)]
pub struct NewTicketContext<'a> {
    /// The authenticated source (`submitter.source`, or `"operator"` for the
    /// manual form).
    pub source: &'a str,
    /// The submitter's reviewer floor ([`require_reviewer_step_floor_for_source`]
    /// for the manual form).
    pub require_reviewer_step_floor: bool,
    /// `OPSGATE_MAX_DURATION_SECONDS_DEFAULT`.
    pub max_duration_seconds_default: i64,
}

/// The result of `_normalize_new_ticket`: the values `_insert_ticket` writes
/// and the checksum over them.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedTicket {
    pub source: String,
    pub task_ref: Option<String>,
    pub title: String,
    pub summary: String,
    pub execution_plan: Vec<PlanStep>,
    /// The effective policy, `{"require_reviewer_step": <bool>}`.
    pub policy_requirements: Value,
    /// Always a JSON object.
    pub context: Value,
    /// `isoformat_z` of the parsed expiry.
    pub expires_at: Option<String>,
    pub max_duration_seconds: i64,
    pub payload_checksum: String,
}

impl NormalizedTicket {
    /// The checksum payload of this ticket.
    pub fn payload(&self) -> TicketPayload<'_> {
        TicketPayload {
            source: &self.source,
            task_ref: self.task_ref.as_deref(),
            title: &self.title,
            summary: &self.summary,
            execution_plan: &self.execution_plan,
            policy_requirements: &self.policy_requirements,
            context: &self.context,
            expires_at: self.expires_at.as_deref(),
            max_duration_seconds: self.max_duration_seconds,
        }
    }
}

fn invalid_ticket(message: impl Into<String>) -> ServiceError {
    ServiceError::new(message, 400, "invalid_ticket")
}

/// `str(value)` of a ticket text field; arrays and objects (D-3) and
/// overflowing numbers (D-2) are `invalid_ticket`.
fn ticket_text<'a>(value: &'a Value, field: &str) -> Result<Cow<'a, str>, ServiceError> {
    py_str(value).map_err(|error| {
        invalid_ticket(match error {
            PyStrError::Container => format!("{field} must be text, not a JSON array or object"),
            PyStrError::NonFiniteFloat => format!("{field} is a number out of range"),
        })
    })
}

/// `isoformat_z(parse_iso_datetime(str(expires_at)))` (4.9). `str()` of an
/// array, an object or an overflowing number never parses in Python either,
/// so they are `invalid_expires_at` too.
fn normalize_expires_at(raw: &Value) -> Result<Option<String>, ServiceError> {
    if raw.is_null() {
        return Ok(None);
    }
    let invalid = |message: String| ServiceError::new(message, 400, "invalid_expires_at");
    let text = py_str(raw).map_err(|_| invalid("Invalid isoformat string".to_owned()))?;
    parse_iso_datetime(&text)
        .map(|moment| Some(isoformat_z(&moment)))
        .map_err(|error| invalid(error.to_string()))
}

/// `max_duration_seconds`: `null` or absent → the configured default; else a
/// JSON integer (`type(x) is int`: not a bool, not a float such as `900.0`
/// or `1e309`) from 1 to [`MAX_DURATION_SECONDS`].
pub fn normalize_max_duration_seconds(raw: &Value, default: i64) -> Result<i64, ServiceError> {
    let value = match raw {
        Value::Null => Some(default),
        Value::Number(number) => match py_number(number) {
            // Out of `i64` is out of the bounds as well.
            PyNumber::Int(digits) => digits.parse::<i64>().ok(),
            PyNumber::Float(_) => None,
        },
        _ => None,
    };
    value
        .filter(|seconds| (1..=MAX_DURATION_SECONDS).contains(seconds))
        .ok_or_else(|| {
            invalid_ticket(format!(
                "max_duration_seconds must be an integer from 1 to {MAX_DURATION_SECONDS}"
            ))
        })
}

/// `OpsGateService._normalize_new_ticket` (4.7.1 steps 1–10): validate a
/// decoded JSON object in Python's order, the first failing check deciding
/// the error, and return the normalised ticket with its payload checksum.
pub fn normalize_new_ticket(
    payload: &Map<String, Value>,
    context: &NewTicketContext<'_>,
) -> Result<NormalizedTicket, ServiceError> {
    let field = |name: &str| payload.get(name).unwrap_or(&Value::Null);

    // 1. `str(payload.get("source", source)).strip()` must be the
    // authenticated source. `str()` of an array, an object or an overflowing
    // number can never equal one of the fixed source names (4.2), so Python
    // answers `source_mismatch` for them as well.
    let source_mismatch = || {
        ServiceError::new(
            "Ticket source must match the authenticated creation path",
            403,
            "source_mismatch",
        )
    };
    let source = match payload.get("source") {
        None => strip(context.source).to_owned(),
        Some(value) => strip(&py_str(value).map_err(|_| source_mismatch())?).to_owned(),
    };
    if source != context.source {
        return Err(source_mismatch());
    }

    // 2. Title and summary (absent → "", `null` → "None").
    let required_text = |name: &str| match payload.get(name) {
        None => Ok(String::new()),
        Some(value) => ticket_text(value, name).map(|text| strip(&text).to_owned()),
    };
    let title = required_text("title")?;
    let summary = required_text("summary")?;
    if title.is_empty() || summary.is_empty() {
        return Err(invalid_ticket("title and summary are required"));
    }

    // 3. `task_ref`: `null`/absent stays none, blank becomes none.
    let task_ref = match field("task_ref") {
        Value::Null => None,
        value => Some(strip(&ticket_text(value, "task_ref")?).to_owned()).filter(|t| !t.is_empty()),
    };

    // 4. `validate_storage_text`: Rust strings are UTF-8; lone surrogates
    // were rejected when the body was decoded (D-2).

    // 5. Execution plan.
    let execution_plan = parse_execution_plan(field("execution_plan"))?;

    // 6. Policy: parse, merge with the submitter's floor, enforce.
    let ticket_policy = parse_policy_requirements(field("policy_requirements"))?;
    let require_reviewer_step =
        merge_policy_requirements(context.require_reviewer_step_floor, ticket_policy)?;
    enforce_policy_against_plan(require_reviewer_step, &execution_plan)?;

    // 7. Context: absent or `null` → `{}`.
    let ticket_context = match field("context") {
        Value::Null => Value::Object(Map::new()),
        value @ Value::Object(_) => value.clone(),
        _ => return Err(invalid_ticket("context must be an object")),
    };

    // 8. Expiry.
    let expires_at = normalize_expires_at(field("expires_at"))?;

    // 9. Duration.
    let max_duration_seconds = normalize_max_duration_seconds(
        field("max_duration_seconds"),
        context.max_duration_seconds_default,
    )?;

    // 10. Checksum of the normalised payload.
    let mut ticket = NormalizedTicket {
        source,
        task_ref,
        title,
        summary,
        execution_plan,
        policy_requirements: policy_value(require_reviewer_step),
        context: ticket_context,
        expires_at,
        max_duration_seconds,
        payload_checksum: String::new(),
    };
    ticket.payload_checksum = ticket.payload().checksum()?;
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn truthiness_is_pythons() {
        for (text, truthy) in [
            ("null", false),
            ("false", false),
            ("true", true),
            ("0", false),
            ("-0", false),
            ("0.0", false),
            ("-0.0", false),
            ("1e-400", false),
            ("2", true),
            ("0.5", true),
            ("1e400", true),
            ("\"\"", false),
            ("\"0\"", true),
            ("[]", false),
            ("[0]", true),
            ("{}", false),
            ("{\"a\": 0}", true),
        ] {
            assert_eq!(py_truthy(&parse(text).unwrap()), truthy, "{text}");
        }
    }

    #[test]
    fn stored_policy_truthiness() {
        let policy = |text: &str| match parse(text).unwrap() {
            Value::Object(map) => map,
            other => panic!("{other}"),
        };
        assert!(!stored_policy_requires_reviewer(&policy("{}")));
        assert!(!stored_policy_requires_reviewer(&policy(
            r#"{"require_reviewer_step": 0}"#
        )));
        assert!(stored_policy_requires_reviewer(&policy(
            r#"{"require_reviewer_step": "no"}"#
        )));
        assert!(stored_policy_requires_reviewer(&policy(
            r#"{"require_reviewer_step": true}"#
        )));
    }

    #[test]
    fn floor_lookup_strips_and_lowercases() {
        let policies = vec![
            SubmitterPolicy {
                source: "nyxmon".to_owned(),
                token: "n".repeat(20),
                require_reviewer_step_floor: false,
            },
            SubmitterPolicy {
                source: "operator".to_owned(),
                token: "o".repeat(20),
                require_reviewer_step_floor: true,
            },
        ];
        assert!(require_reviewer_step_floor_for_source(
            &policies, "operator"
        ));
        assert!(require_reviewer_step_floor_for_source(
            &policies,
            " OPERATOR\t"
        ));
        assert!(!require_reviewer_step_floor_for_source(&policies, "nyxmon"));
        assert!(!require_reviewer_step_floor_for_source(
            &policies, "openclaw"
        ));
        assert!(!require_reviewer_step_floor_for_source(&[], "operator"));
    }

    #[test]
    fn merge_rules() {
        assert_eq!(merge_policy_requirements(false, None), Ok(false));
        assert_eq!(merge_policy_requirements(false, Some(false)), Ok(false));
        assert_eq!(merge_policy_requirements(false, Some(true)), Ok(true));
        assert_eq!(merge_policy_requirements(true, None), Ok(true));
        assert_eq!(merge_policy_requirements(true, Some(true)), Ok(true));
        assert_eq!(
            merge_policy_requirements(true, Some(false))
                .unwrap_err()
                .code,
            "policy_floor_violation"
        );
    }
}
