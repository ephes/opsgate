//! Ticket creation (PLAN.md 4.7.1): validation (`opsgate_core::validate`,
//! steps 1–10), then in one `BEGIN IMMEDIATE` transaction the lazy expiry of
//! the open tickets with the same `(source, task_ref)`, the insert (the
//! dedupe index turns a second open ticket into 409
//! `duplicate_open_ticket`) and the audit event (step 12).
//!
//! Ported Python (`service.py`): `create_ticket`, `create_manual_ticket`,
//! `_insert_ticket`, `_expire_open_tickets_for_task_ref`,
//! `_maybe_expire_ticket`.

use opsgate_core::error::ServiceError;
use opsgate_core::json::stored_json;
use opsgate_core::pytext::strip;
use opsgate_core::settings::SubmitterPolicy;
use opsgate_core::time::{isoformat_z, parse_iso_datetime, utc_now};
use opsgate_core::validate::{NewTicketContext, NormalizedTicket, plan_value};
use rusqlite::{Connection, ErrorCode};
use serde_json::{Map, Value};

use crate::audit::{self, AuditEvent};
use crate::connection::write_transaction;
use crate::error::{StoreError, Unreadable};
use crate::ticket::{TicketRow, is_open_state, select_ticket, select_tickets};

/// Who performs an operation, for the audit trail: `submit:<source>` or
/// `approver:<user>`, the client address and the `User-Agent` header.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub actor: &'a str,
    pub source_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// The submitter a bearer token authenticated (`SubmitterContext`).
pub(crate) fn submitter_context(
    submitter: &SubmitterPolicy,
    max_duration_seconds_default: i64,
) -> NewTicketContext<'_> {
    NewTicketContext {
        source: &submitter.source,
        require_reviewer_step_floor: submitter.require_reviewer_step_floor,
        max_duration_seconds_default,
    }
}

/// `_maybe_expire_ticket`: whether the ticket is (now) expired. A ticket
/// whose non-blank `expires_at` lies at or before now and whose state is
/// open becomes `expired` (compare-and-set on the state read, so a ticket
/// another writer changed in between is left alone) with an audit event
/// `ticket_expired`. A stored `expires_at` that does not parse is an error,
/// as Python's `ValueError` is (500, the transaction rolls back).
pub fn maybe_expire_ticket(
    connection: &Connection,
    row: &TicketRow,
    actor: &Actor<'_>,
) -> Result<bool, StoreError> {
    let Some(raw) = row.expires_at.as_deref().filter(|raw| !raw.is_empty()) else {
        return Ok(false);
    };
    // `optional_iso_datetime`: blank after stripping counts as no expiry.
    if strip(raw).is_empty() {
        return Ok(false);
    }
    let expires_at = parse_iso_datetime(raw).map_err(|error| Unreadable {
        table: "tickets",
        key: Some(row.id.clone()),
        column: "expires_at".to_owned(),
        reason: error.to_string(),
    })?;
    if expires_at > utc_now() {
        return Ok(false);
    }
    if row.state == "expired" {
        return Ok(true);
    }
    if !is_open_state(&row.state) {
        return Ok(false);
    }
    let changed = connection.execute(
        "UPDATE tickets \
         SET state = 'expired', \
             finished_at = ?, \
             result = 'failure', \
             result_detail = 'expired_before_execution' \
         WHERE id = ? AND state = ?",
        (isoformat_z(&utc_now()), &row.id, &row.state),
    )?;
    if changed != 1 {
        // Read before another writer changed it: leave the newer state alone
        // and let the caller's own guarded write decide.
        return Ok(false);
    }
    let mut metadata = Map::new();
    metadata.insert("expires_at".into(), Value::String(raw.to_owned()));
    audit::record(
        connection,
        &AuditEvent {
            ticket_id: &row.id,
            event_type: "ticket_expired",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some(&row.state),
            new_state: Some("expired"),
            metadata: &metadata,
        },
    )?;
    Ok(true)
}

/// `_expire_open_tickets_for_task_ref`: lazily expire the pending and
/// approved, not archived tickets of this `(source, task_ref)`, oldest
/// first, so an expired ticket does not block its replacement.
fn expire_open_tickets_for_task_ref(
    connection: &Connection,
    source: &str,
    task_ref: Option<&str>,
    actor: &Actor<'_>,
) -> Result<(), StoreError> {
    let Some(task_ref) = task_ref else {
        return Ok(());
    };
    let rows = select_tickets(
        connection,
        "SELECT * FROM tickets \
         WHERE source = ? \
           AND task_ref = ? \
           AND archived_at IS NULL \
           AND state IN ('pending_approval', 'approved') \
         ORDER BY created_at ASC",
        (source, task_ref),
    )?;
    for row in &rows {
        maybe_expire_ticket(connection, row, actor)?;
    }
    Ok(())
}

/// A stored JSON column of a new ticket (`json.dumps(x, sort_keys=True)`).
/// Validation already refused non-finite floats (D-2), so this cannot fail
/// for a [`NormalizedTicket`].
fn column_text(value: &Value, column: &str) -> Result<String, StoreError> {
    stored_json(value).map_err(|error| {
        ServiceError::new(
            format!("{column} cannot be stored: {error}"),
            400,
            "invalid_json",
        )
        .into()
    })
}

/// `_insert_ticket`: expire stale open tickets of the same task, insert the
/// new ticket as `pending_approval`, record `ticket_created`, commit, and
/// return the stored ticket serialised. Any constraint violation of the
/// insert (the dedupe index) is 409 `duplicate_open_ticket` and nothing is
/// written.
pub(crate) fn insert_ticket(
    connection: &mut Connection,
    ticket: &NormalizedTicket,
    created_by: &str,
    actor: &Actor<'_>,
) -> Result<Map<String, Value>, StoreError> {
    let ticket_id = uuid::Uuid::new_v4().to_string();
    let created_at = isoformat_z(&utc_now());
    // Step 11 (`validate_storage_text` of the creator, address and user
    // agent): Rust strings are always UTF-8.
    let execution_plan_json = column_text(&plan_value(&ticket.execution_plan), "execution_plan")?;
    let policy_requirements_json = column_text(&ticket.policy_requirements, "policy_requirements")?;
    let context_json = column_text(&ticket.context, "context")?;

    let transaction = write_transaction(connection)?;
    expire_open_tickets_for_task_ref(
        &transaction,
        &ticket.source,
        ticket.task_ref.as_deref(),
        actor,
    )?;
    let inserted = transaction.execute(
        "INSERT INTO tickets (\
         id, source, task_ref, title, summary, \
         execution_plan_json, policy_requirements_json, context_json, \
         payload_checksum, approved_payload_checksum, \
         state, created_by, created_at, \
         expires_at, max_duration_seconds\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending_approval', ?, ?, ?, ?)",
        (
            &ticket_id,
            &ticket.source,
            &ticket.task_ref,
            &ticket.title,
            &ticket.summary,
            &execution_plan_json,
            &policy_requirements_json,
            &context_json,
            &ticket.payload_checksum,
            created_by,
            &created_at,
            &ticket.expires_at,
            ticket.max_duration_seconds,
        ),
    );
    match inserted {
        Ok(_) => {}
        // Python catches `sqlite3.IntegrityError`, every constraint failure.
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == ErrorCode::ConstraintViolation =>
        {
            return Err(ServiceError::new(
                "Duplicate open ticket for source/task_ref",
                409,
                "duplicate_open_ticket",
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    }
    let mut metadata = Map::new();
    metadata.insert(
        "task_ref".into(),
        ticket.task_ref.clone().map_or(Value::Null, Value::String),
    );
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id: &ticket_id,
            event_type: "ticket_created",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: None,
            new_state: Some("pending_approval"),
            metadata: &metadata,
        },
    )?;
    transaction.commit()?;

    let row = select_ticket(connection, &ticket_id)?
        .ok_or_else(|| ServiceError::new("Ticket creation failed", 500, "db_error"))?;
    row.serialize()
}
