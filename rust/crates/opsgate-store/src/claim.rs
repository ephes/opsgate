//! The runner's claim (PLAN.md 4.7.3): in one `BEGIN IMMEDIATE`
//! transaction, take the oldest approved, not archived ticket; expire it
//! lazily, fail it when its stored JSON no longer validates
//! (`invalid_stored_plan`) or its recomputed payload checksum differs from
//! the one approved (`prompt_tampered`), and try the next; otherwise mark it
//! `running` for the runner host. Every poll records the runner's heartbeat.
//!
//! Ported Python (`service.py:OpsGateService`): `claim_ticket`,
//! `_update_runner_heartbeat`, `parse_stored_json` as claim applies it.

use std::path::Path;

use opsgate_core::error::ServiceError;
use opsgate_core::json::parse_stored;
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_core::validate::{
    TicketPayload, enforce_policy_against_plan, parse_execution_plan, parse_policy_requirements,
    stored_policy_requires_reviewer,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::Ticket;
use crate::audit::{self, AuditEvent};
use crate::connection::write_transaction;
use crate::create::{Actor, maybe_expire_ticket};
use crate::error::StoreError;
use crate::ticket::TicketRow;
use crate::transitions::reread;

/// `_update_runner_heartbeat`: upsert the runner's heartbeat row inside the
/// caller's transaction.
pub(crate) fn update_runner_heartbeat(
    connection: &Connection,
    runner_host: &str,
) -> Result<(), StoreError> {
    let now = isoformat_z(&utc_now());
    connection.execute(
        "INSERT INTO runner_heartbeats (runner_host, last_heartbeat_at, updated_at) \
         VALUES (?, ?, ?) \
         ON CONFLICT(runner_host) \
         DO UPDATE SET last_heartbeat_at=excluded.last_heartbeat_at, updated_at=excluded.updated_at",
        (runner_host, &now, &now),
    )?;
    Ok(())
}

/// Why a claimed ticket cannot run.
enum Rejected {
    /// The stored JSON fails validation (`ServiceError` in Python's `try`):
    /// the ticket fails with `invalid_stored_plan` and this error code.
    InvalidStoredPlan(&'static str),
    /// Python's unhandled exceptions inside the claim (an unparsable stored
    /// duration): the whole claim fails (500) and rolls back.
    Unhandled(StoreError),
}

impl From<ServiceError> for Rejected {
    fn from(error: ServiceError) -> Self {
        Self::InvalidStoredPlan(error.code)
    }
}

/// `parse_stored_json` of one column: undecodable (incl. the D-2 texts) or
/// nested deeper than 64 levels → `invalid_stored_json`.
fn stored(text: &str) -> Result<Value, Rejected> {
    parse_stored(text).map_err(|_| Rejected::InvalidStoredPlan("invalid_stored_json"))
}

/// The validation block of `claim_ticket`, in Python's order, and the
/// checksum it recomputes. The stored policy is validated
/// (`parse_policy_requirements`) without dropping keys, so the checksum
/// covers it as approved.
fn current_checksum(row: &TicketRow) -> Result<String, Rejected> {
    let plan = parse_execution_plan(&stored(&row.execution_plan_json)?)?;
    let policy = stored(&row.policy_requirements_json)?;
    let Value::Object(policy_map) = &policy else {
        return Err(Rejected::InvalidStoredPlan("invalid_policy_requirements"));
    };
    parse_policy_requirements(&policy)?;
    enforce_policy_against_plan(stored_policy_requires_reviewer(policy_map), &plan)?;
    let context = stored(&row.context_json)?;
    if !context.is_object() {
        return Err(Rejected::InvalidStoredPlan("invalid_ticket"));
    }
    if !stored(&row.tmux_sessions_json)?.is_array() {
        return Err(Rejected::InvalidStoredPlan("invalid_tmux_sessions"));
    }
    let max_duration_seconds = row.max_duration_int().map_err(Rejected::Unhandled)?;
    // A float that overflows to infinity (D-2): Python hashes `Infinity`;
    // Rust cannot, and fails the ticket instead of blocking the queue.
    Ok(TicketPayload {
        source: &row.source,
        task_ref: row.task_ref.as_deref(),
        title: &row.title,
        summary: &row.summary,
        execution_plan: &plan,
        policy_requirements: &policy,
        context: &context,
        expires_at: row.expires_at.as_deref(),
        max_duration_seconds,
    }
    .checksum()?)
}

/// Marks an approved ticket `failed` (compare-and-set on `approved`) with
/// the audit event `ticket_failed`; whether it changed.
fn fail_ticket(
    connection: &Connection,
    row: &TicketRow,
    detail: &str,
    metadata: &Map<String, Value>,
    actor: &Actor<'_>,
) -> Result<bool, StoreError> {
    let changed = connection.execute(
        "UPDATE tickets \
         SET state = 'failed', \
             finished_at = ?, \
             result = 'failure', \
             result_detail = ? \
         WHERE id = ? AND state = 'approved'",
        (isoformat_z(&utc_now()), detail, &row.id),
    )?;
    if changed == 0 {
        return Ok(false);
    }
    audit::record(
        connection,
        &AuditEvent {
            ticket_id: &row.id,
            event_type: "ticket_failed",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some("approved"),
            new_state: Some("failed"),
            metadata,
        },
    )?;
    Ok(true)
}

/// `claim_ticket` (4.7.3): the claimed ticket, or `None` when nothing is
/// claimable. The disable file stops claims before the database is touched
/// (no heartbeat either).
pub(crate) fn claim(
    connection: &mut Connection,
    disable_file_path: &Path,
    actor: &Actor<'_>,
    runner_host: &str,
) -> Result<Option<Ticket>, StoreError> {
    // `Path.exists()`: follows symlinks; a broken link or an error is no file.
    if disable_file_path.exists() {
        return Ok(None);
    }
    let transaction = write_transaction(connection)?;
    loop {
        let row = transaction
            .query_row(
                "SELECT * FROM tickets \
                 WHERE state = 'approved' \
                   AND archived_at IS NULL \
                 ORDER BY approved_at ASC, created_at ASC \
                 LIMIT 1",
                [],
                |row| Ok(TicketRow::from_row(row)),
            )
            .optional()?
            .transpose()?;
        let Some(row) = row else {
            // An idle poll still counts as a heartbeat, so health can tell an
            // idle runner from a dead one.
            update_runner_heartbeat(&transaction, runner_host)?;
            transaction.commit()?;
            return Ok(None);
        };

        if maybe_expire_ticket(&transaction, &row, actor)? {
            continue;
        }

        let current = match current_checksum(&row) {
            Ok(checksum) => checksum,
            Err(Rejected::Unhandled(error)) => return Err(error),
            Err(Rejected::InvalidStoredPlan(code)) => {
                let mut metadata = Map::new();
                metadata.insert("reason".into(), Value::from("invalid_stored_plan"));
                metadata.insert("error".into(), Value::from(code));
                fail_ticket(&transaction, &row, "invalid_stored_plan", &metadata, actor)?;
                continue;
            }
        };

        let approved = row.approved_payload_checksum.as_deref().unwrap_or_default();
        if approved.is_empty() || approved != current {
            let mut metadata = Map::new();
            metadata.insert("reason".into(), Value::from("prompt_tampered"));
            fail_ticket(&transaction, &row, "prompt_tampered", &metadata, actor)?;
            continue;
        }

        let started_at = isoformat_z(&utc_now());
        let changed = transaction.execute(
            "UPDATE tickets \
             SET state = 'running', \
                 runner_host = ?, \
                 started_at = COALESCE(started_at, ?), \
                 last_heartbeat_at = ? \
             WHERE id = ? AND state = 'approved'",
            (runner_host, &started_at, &started_at, &row.id),
        )?;
        if changed == 0 {
            continue;
        }
        let mut metadata = Map::new();
        metadata.insert("runner_host".into(), Value::from(runner_host));
        audit::record(
            &transaction,
            &AuditEvent {
                ticket_id: &row.id,
                event_type: "runner_claimed",
                actor: actor.actor,
                source_ip: actor.source_ip,
                user_agent: actor.user_agent,
                previous_state: Some("approved"),
                new_state: Some("running"),
                metadata: &metadata,
            },
        )?;
        update_runner_heartbeat(&transaction, runner_host)?;
        transaction.commit()?;
        return reread(connection, &row.id, "Ticket disappeared after claim").map(Some);
    }
}
