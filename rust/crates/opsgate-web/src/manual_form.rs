//! The manual ticket form of the ticket list page (PLAN.md 4.11): role
//! defaults and prompt scaffolding (`DEFAULT_AGENT_BY_ROLE`,
//! `ROLE_PROMPT_SCAFFOLDING`), the step editor's fields
//! (`parse_manual_ticket_steps`), the ticket payload the form submits
//! (`build_manual_ticket_payload`) and the values it shows again
//! (`build_manual_ticket_form_data`).
//!
//! Field names (P1): the multi-step editor posts
//! `steps-<n>-role|agent|prompt_markdown`; the legacy single-step form
//! `step_role`, `step_agent`, `prompt_markdown`; then `title`, `summary`,
//! `task_ref`, `max_duration_seconds`, `expires_at`, `context_json`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use opsgate_core::json::{ParseError, check_depth, parse};
use opsgate_core::pytext::{py_lower, strip};
use opsgate_core::settings::py_int_decimal;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::error::AppError;
use crate::form::FormData;

/// `DEFAULT_AGENT_BY_ROLE`; any other role defaults to `codex`.
pub const DEFAULT_AGENT_BY_ROLE: [(&str, &str); 4] = [
    ("implementer", "codex"),
    ("implementor", "codex"),
    ("reviewer", "claude"),
    ("investigator", "codex"),
];

/// `ROLE_PROMPT_SCAFFOLDING` (`implementor` is `implementer`'s).
pub static ROLE_PROMPT_SCAFFOLDING: LazyLock<Map<String, Value>> = LazyLock::new(|| {
    let investigator = json!({
        "title": "Inspect-only investigation",
        "summary": "Use this role to inspect state, collect evidence, identify the owning repo/workspace, and explain next steps.",
        "dos": [
            "Read code, config, logs, tickets, and deployment state.",
            "Explain findings and likely root cause in concrete terms.",
            "Point to the source repo/workspace that should own the fix.",
        ],
        "donts": [
            "Do not edit source files or commit changes.",
            "Do not deploy, restart services, or patch files on live hosts.",
            "Do not perform ad hoc remediation while acting as investigator.",
        ],
        "placeholder": "Inspect current state only. Gather evidence, identify the owning repo/workspace, and propose next steps without making changes.",
        "suggested_prompt": "Inspect the current state only. Do not edit source files, commit changes, deploy code, restart services, or patch files on the live host.\n\nGather the relevant logs, config, code, and deployment context. Identify the owning repo or workspace, explain the likely root cause, and end with concrete recommended next steps.",
    });
    let implementer = json!({
        "title": "Repo-first implementation",
        "summary": "Use this role to make the intended change in the source of truth, validate it, and prepare it for deploy.",
        "dos": [
            "Change the correct repo or workspace, not the live host directly.",
            "Run the relevant validation commands before calling the work ready.",
            "Commit, deploy, and verify only after the reviewer loop is complete.",
        ],
        "donts": [
            "Do not patch production files ad hoc as the primary fix path.",
            "Do not skip validation or omit deploy verification.",
            "Do not treat the reviewer step as optional when policy requires it.",
        ],
        "placeholder": "Implement the change in the correct repo/workspace, run validation, and prepare a clear deploy and verification path.",
        "suggested_prompt": "Make the intended change in the correct repo or workspace, not by patching files directly on the live host.\n\nDescribe the files you changed, run the relevant validation commands, summarize the results, and prepare the change for reviewer feedback. Once the reviewer loop is complete, commit, deploy through the normal workflow, and verify the live result.",
    });
    let reviewer = json!({
        "title": "Independent review gate",
        "summary": "Use this role to inspect the proposed change, validation evidence, and rollout plan before implementation is considered ready.",
        "dos": [
            "Review diffs, prompts, logs, validation output, and deploy steps.",
            "Call out risks, missing tests, or unclear assumptions.",
            "State clearly whether the implementer loop is ready to proceed.",
        ],
        "donts": [
            "Do not make independent implementation changes in the reviewer step.",
            "Do not commit or deploy while acting as reviewer.",
            "Do not approve vague prompts that lack validation or rollout detail.",
        ],
        "placeholder": "Review the proposed change, validation evidence, and deploy plan. Call out risks and state whether it is ready.",
        "suggested_prompt": "Review the proposed change, validation evidence, and deployment plan.\n\nDo not make additional implementation changes, commit code, or deploy while acting as reviewer. Call out concrete risks, missing validation, or unclear assumptions, and state whether the implementer loop is ready to proceed.",
    });
    let mut scaffolding = Map::new();
    scaffolding.insert("investigator".to_owned(), investigator);
    scaffolding.insert("implementer".to_owned(), implementer.clone());
    scaffolding.insert("reviewer".to_owned(), reviewer);
    scaffolding.insert("implementor".to_owned(), implementer);
    scaffolding
});

/// `DEFAULT_AGENT_BY_ROLE` as a JSON object (the template's
/// `role_agent_defaults`).
pub fn role_agent_defaults() -> Value {
    Value::Object(
        DEFAULT_AGENT_BY_ROLE
            .iter()
            .map(|(role, agent)| ((*role).to_owned(), Value::from(*agent)))
            .collect(),
    )
}

/// `default_agent_for_role`: by the stripped, lowercased role; `codex`
/// otherwise.
pub fn default_agent_for_role(role: &str) -> &'static str {
    let role = py_lower(strip(role));
    DEFAULT_AGENT_BY_ROLE
        .iter()
        .find(|(name, _)| *name == role)
        .map_or("codex", |(_, agent)| agent)
}

/// `prompt_scaffolding_for_role`: by the stripped, lowercased role; the
/// investigator's otherwise.
pub fn prompt_scaffolding_for_role(role: &str) -> &'static Value {
    let role = py_lower(strip(role));
    ROLE_PROMPT_SCAFFOLDING
        .get(&role)
        .or_else(|| ROLE_PROMPT_SCAFFOLDING.get("investigator"))
        .unwrap_or(&Value::Null)
}

/// One step of the form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualStep {
    pub role: String,
    pub agent: String,
    pub prompt_markdown: String,
}

impl ManualStep {
    fn to_value(&self) -> Value {
        json!({
            "role": self.role,
            "agent": self.agent,
            "prompt_markdown": self.prompt_markdown,
        })
    }
}

/// `default_manual_step`: a reviewer when the operator's reviewer floor is
/// on, else an investigator, with the role's agent and no prompt.
pub fn default_manual_step(operator_requires_reviewer: bool) -> ManualStep {
    let role = if operator_requires_reviewer {
        "reviewer"
    } else {
        "investigator"
    };
    ManualStep {
        role: role.to_owned(),
        agent: default_agent_for_role(role).to_owned(),
        prompt_markdown: String::new(),
    }
}

/// `MANUAL_STEP_FIELD_PATTERN` with `re.match`: Python's `\d` is any
/// Unicode decimal digit, its `$` also matches before a final newline.
static MANUAL_STEP_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Asteps-(\d+)-(role|agent|prompt_markdown)\n?\z")
        .unwrap_or_else(|error| panic!("pattern: {error}"))
});

/// `parse_manual_ticket_steps`: the steps of the multi-step editor (keys
/// `steps-<n>-<field>`, ordered by `int(n)`, the last key naming a field of
/// a step winning, each value the stripped first value of its key, an
/// empty agent defaulting from the role); else the legacy single step if
/// any of its fields is present; else none.
///
/// An index `int()` cannot convert (more than 4300 digits) is Python's
/// unhandled `ValueError`: 500.
pub fn parse_manual_ticket_steps(
    form: &FormData,
    operator_requires_reviewer: bool,
) -> Result<Vec<ManualStep>, AppError> {
    // Keyed by the index's (length, digits): the numeric order of
    // non-negative decimals without leading zeros.
    let mut indexed: BTreeMap<(usize, String), BTreeMap<&str, String>> = BTreeMap::new();
    for key in form.keys() {
        let Some(captures) = MANUAL_STEP_FIELD.captures(key) else {
            continue;
        };
        let (Some(index), Some(field)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let index = py_int_decimal(index.as_str()).ok_or_else(|| {
            AppError::Internal("int() of a manual step index failed (ValueError)".to_owned())
        })?;
        let value = strip(form.get(key).unwrap_or_default()).to_owned();
        indexed
            .entry((index.len(), index))
            .or_default()
            .insert(field.as_str(), value);
    }
    if !indexed.is_empty() {
        return Ok(indexed
            .into_values()
            .map(|fields| {
                let field = |name: &str| fields.get(name).cloned().unwrap_or_default();
                let role = field("role");
                let agent = Some(field("agent"))
                    .filter(|agent| !agent.is_empty())
                    .unwrap_or_else(|| default_agent_for_role(&role).to_owned());
                ManualStep {
                    agent,
                    prompt_markdown: field("prompt_markdown"),
                    role,
                }
            })
            .collect());
    }
    if ["step_role", "step_agent", "prompt_markdown"]
        .iter()
        .any(|key| form.contains(key))
    {
        let default_step = default_manual_step(operator_requires_reviewer);
        let role_field = strip(form.get("step_role").unwrap_or(&default_step.role));
        let role = if role_field.is_empty() {
            default_step.role.clone()
        } else {
            role_field.to_owned()
        };
        let agent = strip(form.get("step_agent").unwrap_or_default());
        let agent = if agent.is_empty() {
            default_agent_for_role(role_field).to_owned()
        } else {
            agent.to_owned()
        };
        return Ok(vec![ManualStep {
            role,
            agent,
            prompt_markdown: strip(form.get("prompt_markdown").unwrap_or_default()).to_owned(),
        }]);
    }
    Ok(Vec::new())
}

/// `request.form.get(key, "").strip()`.
fn field(form: &FormData, key: &str) -> String {
    strip(form.get(key).unwrap_or_default()).to_owned()
}

/// `build_manual_ticket_form_data`: the values the form shows (again after
/// a failed submission); an empty form (a fresh page) gets the default
/// step.
pub fn form_data(form: &FormData, operator_requires_reviewer: bool) -> Result<Value, AppError> {
    let mut steps = parse_manual_ticket_steps(form, operator_requires_reviewer)?;
    if steps.is_empty() && form.is_empty() {
        steps.push(default_manual_step(operator_requires_reviewer));
    }
    let max_duration = strip(form.get("max_duration_seconds").unwrap_or("3600"));
    Ok(json!({
        "title": field(form, "title"),
        "summary": field(form, "summary"),
        "task_ref": field(form, "task_ref"),
        "max_duration_seconds": if max_duration.is_empty() { "3600" } else { max_duration },
        "expires_at": field(form, "expires_at"),
        "context_json": field(form, "context_json"),
        "steps": steps.iter().map(ManualStep::to_value).collect::<Vec<_>>(),
    }))
}

fn invalid_context_json(message: String) -> AppError {
    AppError::service(message, 400, "invalid_context_json")
}

/// `build_manual_ticket_payload`: the JSON object the form submits to
/// `create_manual_ticket`. `max_duration_seconds` must be ASCII digits
/// (`[0-9]+`, an integer of at most 4300 digits) else 400 `invalid_ticket`;
/// `context_json` must decode (400 `invalid_context_json`; D-2 for the
/// inputs only Python decodes), nest at most 64 levels and be an object. An
/// integer token of more than 4300 digits in `context_json` is Python's
/// unhandled `ValueError`: 500.
pub fn payload(
    form: &FormData,
    operator_requires_reviewer: bool,
) -> Result<Map<String, Value>, AppError> {
    let mut payload = Map::new();
    payload.insert("title".to_owned(), Value::from(field(form, "title")));
    payload.insert("summary".to_owned(), Value::from(field(form, "summary")));
    let steps = parse_manual_ticket_steps(form, operator_requires_reviewer)?;
    payload.insert(
        "execution_plan".to_owned(),
        Value::Array(steps.iter().map(ManualStep::to_value).collect()),
    );
    for key in ["task_ref", "expires_at"] {
        let value = field(form, key);
        if !value.is_empty() {
            payload.insert(key.to_owned(), Value::from(value));
        }
    }
    let max_duration = field(form, "max_duration_seconds");
    if !max_duration.is_empty() {
        let seconds = Some(&max_duration)
            .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|text| py_int_decimal(text))
            .and_then(|decimal| serde_json::from_str::<Value>(&decimal).ok())
            .ok_or_else(|| {
                AppError::service(
                    "max_duration_seconds must be an integer",
                    400,
                    "invalid_ticket",
                )
            })?;
        payload.insert("max_duration_seconds".to_owned(), seconds);
    }
    let context_raw = field(form, "context_json");
    if !context_raw.is_empty() {
        let context = match parse(&context_raw) {
            Ok(context) => context,
            Err(ParseError::IntegerTooLong) => {
                return Err(AppError::Internal(
                    "context_json: integer token beyond 4300 digits (ValueError)".to_owned(),
                ));
            }
            Err(error) if error.exceeds_recursion_limit() => {
                return Err(invalid_context_json(
                    "context_json must be valid JSON: nesting is too deep".to_owned(),
                ));
            }
            Err(error) => {
                return Err(invalid_context_json(format!(
                    "context_json must be valid JSON: {error}"
                )));
            }
        };
        check_depth(&context).map_err(|too_deep| invalid_context_json(too_deep.to_string()))?;
        let Value::Object(_) = context else {
            return Err(invalid_context_json(
                "context_json must decode to an object".to_owned(),
            ));
        };
        payload.insert("context".to_owned(), context);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> FormData {
        FormData::parse(
            &pairs
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            key,
                            percent_encoding::NON_ALPHANUMERIC
                        ),
                        percent_encoding::utf8_percent_encode(
                            value,
                            percent_encoding::NON_ALPHANUMERIC
                        )
                    )
                })
                .collect::<Vec<_>>()
                .join("&"),
        )
    }

    fn step(role: &str, agent: &str, prompt: &str) -> ManualStep {
        ManualStep {
            role: role.to_owned(),
            agent: agent.to_owned(),
            prompt_markdown: prompt.to_owned(),
        }
    }

    fn code(error: AppError) -> &'static str {
        match error {
            AppError::Service(error) => error.code,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn role_defaults() {
        assert_eq!(default_agent_for_role(" Reviewer "), "claude");
        assert_eq!(default_agent_for_role("implementor"), "codex");
        assert_eq!(default_agent_for_role("unknown"), "codex");
        assert_eq!(default_agent_for_role(""), "codex");
        assert_eq!(
            prompt_scaffolding_for_role("IMPLEMENTOR")["title"],
            "Repo-first implementation"
        );
        assert_eq!(
            prompt_scaffolding_for_role("other")["title"],
            "Inspect-only investigation"
        );
        assert_eq!(default_manual_step(true), step("reviewer", "claude", ""));
        assert_eq!(
            default_manual_step(false),
            step("investigator", "codex", "")
        );
    }

    #[test]
    fn multi_step_fields() {
        let steps = parse_manual_ticket_steps(
            &form(&[
                ("steps-10-role", "reviewer"),
                ("steps-2-role", " implementer "),
                ("steps-2-prompt_markdown", " Fix "),
                ("steps-02-agent", "claude"),
                ("steps-\u{661}0-prompt_markdown", "Review"),
                ("steps-2-role", "ignored second value"),
                ("steps-3-role\n", "investigator"),
                ("steps-4-role\n\n", "ignored"),
                ("steps--1-role", "ignored"),
                ("xsteps-5-role", "ignored"),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(
            steps,
            vec![
                step("implementer", "claude", "Fix"),
                step("investigator", "codex", ""),
                step("reviewer", "claude", "Review"),
            ]
        );
        let huge = format!("steps-{}-role", "9".repeat(4301));
        assert!(matches!(
            parse_manual_ticket_steps(&form(&[(&huge, "x")]), false),
            Err(AppError::Internal(_))
        ));
    }

    #[test]
    fn legacy_fields() {
        let parse = |pairs: &[(&str, &str)], floor| parse_manual_ticket_steps(&form(pairs), floor);
        assert_eq!(
            parse(
                &[("step_role", "reviewer"), ("prompt_markdown", " p ")],
                false
            )
            .unwrap(),
            vec![step("reviewer", "claude", "p")]
        );
        assert_eq!(
            parse(&[("prompt_markdown", "p")], true).unwrap(),
            vec![step("reviewer", "claude", "p")]
        );
        // A blank role takes the default role, but the agent defaults from
        // the blank role (Python's quirk).
        assert_eq!(
            parse(&[("step_role", " "), ("step_agent", "")], true).unwrap(),
            vec![step("reviewer", "codex", "")]
        );
        assert_eq!(parse(&[("title", "x")], false).unwrap(), vec![]);
    }

    #[test]
    fn form_data_defaults() {
        let fresh = form_data(&FormData::default(), true).unwrap();
        assert_eq!(fresh["max_duration_seconds"], "3600");
        assert_eq!(
            fresh["steps"],
            json!([{"role": "reviewer", "agent": "claude", "prompt_markdown": ""}])
        );
        let posted = form_data(
            &form(&[
                ("csrf_token", "t"),
                ("max_duration_seconds", " "),
                ("title", " T "),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(posted["steps"], json!([]));
        assert_eq!(posted["max_duration_seconds"], "3600");
        assert_eq!(posted["title"], "T");
    }

    #[test]
    fn payload_rules() {
        let base = [
            ("title", " T "),
            ("summary", "S"),
            ("steps-0-role", "investigator"),
        ];
        let with = |extra: &[(&str, &str)]| {
            let mut pairs = base.to_vec();
            pairs.extend_from_slice(extra);
            payload(&form(&pairs), false)
        };
        let plain = with(&[("task_ref", " "), ("expires_at", "")]).unwrap();
        assert_eq!(
            Value::Object(plain),
            json!({
                "title": "T", "summary": "S",
                "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": ""}],
            })
        );
        let full = with(&[
            ("task_ref", "ref"),
            ("expires_at", "2030-01-01T00:00:00Z"),
            ("max_duration_seconds", " 0900 "),
            ("context_json", "{\"a\": 1.5, \"a\": 2}"),
        ])
        .unwrap();
        assert_eq!(full["max_duration_seconds"], json!(900));
        assert_eq!(full["context"], json!({"a": 2}));
        assert_eq!(full["task_ref"], "ref");
        let big = with(&[("max_duration_seconds", &"9".repeat(4300))]).unwrap();
        assert_eq!(big["max_duration_seconds"].to_string(), "9".repeat(4300));
        for duration in ["1.5", "-1", "1_000", "+1", "\u{661}", &"9".repeat(4301)] {
            assert_eq!(
                code(with(&[("max_duration_seconds", duration)]).unwrap_err()),
                "invalid_ticket",
                "{duration}"
            );
        }
        for context in [
            "[1, 2, 3]",
            "{",
            "NaN",
            "{\"a\": NaN}",
            "\u{feff}{}",
            &format!("{}{}", "[".repeat(65), "]".repeat(65)),
            &format!("{{\"nested\":{}0{}}}", "[".repeat(2000), "]".repeat(2000)),
        ] {
            assert_eq!(
                code(with(&[("context_json", context)]).unwrap_err()),
                "invalid_context_json",
                "{context}"
            );
        }
        let at_limit = format!("{{\"nested\":{}0{}}}", "[".repeat(63), "]".repeat(63));
        assert!(with(&[("context_json", &at_limit)]).is_ok());
        assert!(matches!(
            with(&[("context_json", &format!("{{\"a\": {}}}", "1".repeat(4301)))]),
            Err(AppError::Internal(_))
        ));
    }
}
