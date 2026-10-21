//! The runner's status update (PLAN.md 4.7.4): heartbeats, step events and
//! the final state of a running ticket, with the result and the tmux
//! session list. The checks run in Python's order; every rejected update
//! writes nothing.
//!
//! Ported Python: `service.py:RUNNER_EVENT_TYPES`,
//! `OpsGateService.update_runner_status`.

use std::borrow::Cow;

use opsgate_core::error::ServiceError;
use opsgate_core::json::stored_json;
use opsgate_core::pytext::{py_lower, py_str, strip};
use opsgate_core::time::{isoformat_z, utc_now};
use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;
use serde_json::{Map, Value};

use crate::Ticket;
use crate::audit::{self, AuditEvent};
use crate::claim::update_runner_heartbeat;
use crate::connection::write_transaction;
use crate::create::Actor;
use crate::error::StoreError;
use crate::ticket::is_terminal_state;
use crate::transitions::{ReadHook, read_ticket, require_row_changed, reread};

/// `RUNNER_EVENT_TYPES`.
pub const RUNNER_EVENT_TYPES: [&str; 8] = [
    "heartbeat",
    "step_started",
    "step_finished",
    "step_failed",
    "timeout",
    "failed",
    "ticket_succeeded",
    "invalid_plan",
];

/// The states a runner may request.
const RUNNER_STATES: [&str; 4] = ["running", "succeeded", "failed", "canceled"];

/// The results a runner may report.
const RUNNER_RESULTS: [&str; 4] = ["success", "failure", "timeout", "canceled"];

fn bad_request(message: &str, code: &'static str) -> StoreError {
    ServiceError::new(message, 400, code).into()
}

fn conflict(message: &str, code: &'static str) -> StoreError {
    ServiceError::new(message, 409, code).into()
}

/// `str(value).strip().lower()` of a runner field; a JSON array or object
/// (D-3) or an overflowing number (D-2) is answered with the field's error,
/// which Python's `str()` of them fails as well.
fn lowered(value: &Value, message: &str, code: &'static str) -> Result<String, StoreError> {
    let text = py_str(value).map_err(|_| bad_request(message, code))?;
    Ok(py_lower(strip(&text)))
}

/// The results compatible with a state (`compatible_results`).
fn compatible(state: &str, result: &str) -> bool {
    match state {
        "succeeded" => result == "success",
        "failed" => matches!(result, "failure" | "timeout"),
        "canceled" => result == "canceled",
        _ => false,
    }
}

/// `update_runner_status` (4.7.4). `runner_host` is the one the web layer
/// derived (body `runner_host` stripped, else the client address, else
/// `"runner"`).
pub(crate) fn update_runner_status(
    connection: &mut Connection,
    ticket_id: &str,
    runner_host: &str,
    payload: &Map<String, Value>,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    // Before the transaction, as in Python. Only a missing `event` defaults;
    // an empty or blank text becomes `heartbeat` after stripping.
    let event = match payload.get("event") {
        None => "heartbeat".to_owned(),
        Some(value) => lowered(value, "Invalid runner event", "invalid_runner_event")?,
    };
    let event = if event.is_empty() {
        "heartbeat".to_owned()
    } else {
        event
    };
    if !RUNNER_EVENT_TYPES.contains(&event.as_str()) {
        return Err(bad_request("Invalid runner event", "invalid_runner_event"));
    }
    // `payload.get(key)`: an explicit `null` counts as absent (`is not None`).
    let present = |key: &str| payload.get(key).filter(|value| !value.is_null());
    let state_raw = present("state");
    let result_raw = present("result");
    // `str(payload.get("result_detail", "")).strip()`: `null` is "None".
    // An array, an object (D-3) or an overflowing number (D-2) is refused.
    let result_detail: Cow<'_, str> = match payload.get("result_detail") {
        None => Cow::Borrowed(""),
        Some(value) => match py_str(value) {
            Ok(text) => Cow::Owned(strip(&text).to_owned()),
            Err(_) => {
                return Err(bad_request(
                    "result_detail must be text, not a JSON array or object",
                    "invalid_json",
                ));
            }
        },
    };
    let tmux_sessions_raw = present("tmux_sessions");

    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    let previous_state = row.state.as_str();
    if is_terminal_state(previous_state) {
        return Err(conflict("Ticket is in terminal state", "invalid_state"));
    }
    if !matches!(previous_state, "approved" | "running") {
        return Err(conflict(
            "Ticket cannot receive runner status in current state",
            "invalid_state",
        ));
    }
    if state_raw.is_none() && previous_state != "running" {
        return Err(conflict(
            "Heartbeat requires running state",
            "invalid_state",
        ));
    }
    if previous_state == "running" {
        let assigned = strip(row.runner_host.as_deref().unwrap_or_default());
        if !assigned.is_empty() && assigned != runner_host {
            return Err(conflict(
                "Runner host does not own this running ticket",
                "runner_host_mismatch",
            ));
        }
    }

    let now = isoformat_z(&utc_now());
    let mut fields: Vec<(&str, SqlValue)> = vec![
        ("runner_host", SqlValue::Text(runner_host.to_owned())),
        ("last_heartbeat_at", SqlValue::Text(now.clone())),
    ];
    let mut next_state = previous_state.to_owned();
    let mut result_value: Option<String> = None;

    if let Some(raw) = state_raw {
        let requested = lowered(raw, "Invalid runner state", "invalid_runner_state")?;
        if !RUNNER_STATES.contains(&requested.as_str()) {
            return Err(bad_request("Invalid runner state", "invalid_runner_state"));
        }
        let terminal = is_terminal_state(&requested);
        if terminal && previous_state != "running" {
            return Err(conflict(
                "Terminal runner update requires running state",
                "invalid_state",
            ));
        }
        if previous_state == "running" && terminal {
            fields.push(("finished_at", SqlValue::Text(now.clone())));
        }
        fields.push(("state", SqlValue::Text(requested.clone())));
        result_value = match requested.as_str() {
            "succeeded" => Some("success".to_owned()),
            "failed" => Some("failure".to_owned()),
            "canceled" => Some("canceled".to_owned()),
            _ => None,
        };
        next_state = requested;
    }

    if let Some(raw) = result_raw {
        let requested = lowered(raw, "Invalid runner result", "invalid_runner_result")?;
        if !RUNNER_RESULTS.contains(&requested.as_str()) {
            return Err(bad_request(
                "Invalid runner result",
                "invalid_runner_result",
            ));
        }
        if !compatible(&next_state, &requested) {
            return Err(bad_request(
                "Runner result is incompatible with state",
                "invalid_runner_result",
            ));
        }
        result_value = Some(requested);
    }

    if let Some(result) = result_value {
        fields.push(("result", SqlValue::Text(result)));
    }
    if !result_detail.is_empty() {
        fields.push(("result_detail", SqlValue::Text(result_detail.to_string())));
    }
    if let Some(raw) = tmux_sessions_raw {
        if !raw.is_array() {
            return Err(bad_request(
                "tmux_sessions must be an array",
                "invalid_tmux_sessions",
            ));
        }
        // A body with a non-finite float never decodes (D-2), so this holds.
        let text = stored_json(raw)
            .map_err(|_| bad_request("tmux_sessions cannot be stored", "invalid_json"))?;
        fields.push(("tmux_sessions_json", SqlValue::Text(text)));
    }

    let assignments: Vec<String> = fields
        .iter()
        .map(|(column, _)| format!("{column} = ?"))
        .collect();
    let mut values: Vec<SqlValue> = fields.into_iter().map(|(_, value)| value).collect();
    values.push(SqlValue::Text(ticket_id.to_owned()));
    values.push(SqlValue::Text(previous_state.to_owned()));
    let changed = transaction.execute(
        &format!(
            "UPDATE tickets SET {} WHERE id = ? AND state = ?",
            assignments.join(", ")
        ),
        rusqlite::params_from_iter(values),
    )?;
    require_row_changed(changed)?;
    update_runner_heartbeat(&transaction, runner_host)?;

    let mut metadata = Map::new();
    metadata.insert("event".into(), Value::String(event.clone()));
    metadata.insert(
        "result_detail".into(),
        Value::String(result_detail.into_owned()),
    );
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: &format!("runner_{event}"),
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some(previous_state),
            new_state: Some(&next_state),
            metadata: &metadata,
        },
    )?;
    transaction.commit()?;
    reread(
        connection,
        ticket_id,
        "Ticket not found after runner update",
    )
}
