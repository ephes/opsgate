//! The approver's transitions (PLAN.md 4.7.2): approve, reject, cancel,
//! archive and unarchive. Each runs in one `BEGIN IMMEDIATE` transaction:
//! read the ticket, check its state, write with a compare-and-set on the
//! state it read (no row changed → 409 `state_changed`, nothing written),
//! record the audit event, commit, and return the ticket read again.
//!
//! Ported Python (`service.py:OpsGateService`): `approve_ticket`,
//! `reject_ticket`, `cancel_ticket`, `archive_ticket`, `unarchive_ticket`,
//! `_require_row_changed`, `_ticket_payload_from_fields` (as approval uses
//! it).

use std::sync::Arc;

use opsgate_core::error::ServiceError;
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_core::validate::{
    TicketPayload, enforce_policy_against_plan, parse_execution_plan,
    stored_policy_requires_reviewer,
};
use rusqlite::{Connection, ErrorCode};
use serde_json::{Map, Value};

use crate::Ticket;
use crate::audit::{self, AuditEvent};
use crate::connection::write_transaction;
use crate::create::{Actor, maybe_expire_ticket};
use crate::error::StoreError;
use crate::ticket::{
    TicketRow, is_archivable_state, is_open_state, select_ticket, ticket_not_found,
};

/// A test seam for the race tests (PLAN.md 7.1, `tests/test_ticket_transition_races.py`
/// patches `_select_ticket` the same way): every transition and the runner
/// status update call it inside their transaction right after they read the
/// ticket, with the row read, and continue with the row it returns. The race
/// tests pause there (a second writer runs meanwhile) or hand back a stale
/// row. Production stores have none.
pub type ReadHook = Arc<dyn Fn(Option<TicketRow>) -> Option<TicketRow> + Send + Sync>;

/// `_select_ticket` of a transition, through the read hook: the row, or 404
/// `ticket_not_found`.
pub(crate) fn read_ticket(
    connection: &Connection,
    ticket_id: &str,
    hook: Option<&ReadHook>,
) -> Result<TicketRow, StoreError> {
    let row = select_ticket(connection, ticket_id)?;
    let row = match hook {
        Some(hook) => hook(row),
        None => row,
    };
    row.ok_or_else(|| ticket_not_found().into())
}

/// `_require_row_changed`: a compare-and-set `UPDATE` that matched no row
/// means the state read is no longer current.
pub(crate) fn require_row_changed(changed: usize) -> Result<(), StoreError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(ServiceError::new(
            "Ticket changed concurrently; reload and retry",
            409,
            "state_changed",
        )
        .into())
    }
}

/// The ticket read again after the commit (`_select_ticket` +
/// `_serialize_ticket`); gone → 500 `db_error` with `message`.
pub(crate) fn reread(
    connection: &Connection,
    ticket_id: &str,
    message: &str,
) -> Result<Ticket, StoreError> {
    select_ticket(connection, ticket_id)?
        .ok_or_else(|| StoreError::from(ServiceError::new(message, 500, "db_error")))?
        .serialize()
}

fn conflict(message: &str, code: &'static str) -> StoreError {
    ServiceError::new(message, 409, code).into()
}

/// The payload checksum approval computes from the stored columns
/// (`approve_ticket`, 4.7.2, 4.8): the plan decoded and re-validated
/// (`parse_execution_plan`, 400), the stored policy enforced with Python's
/// truthiness (400 `missing_reviewer_step`), the context, `expires_at` and
/// `int(max_duration_seconds)` as stored. Python decodes the columns with
/// plain `json.loads` and fails with an unhandled exception for undecodable
/// JSON, a policy that is not an object (`AttributeError` of `.get`) and a
/// duration `int()` rejects: these are unreadable values here (500). A
/// non-finite float (D-2) is `invalid_json`.
///
/// `check-db --dump` recomputes the same checksum for every ticket (11.2).
pub fn approval_checksum(row: &TicketRow) -> Result<String, StoreError> {
    let plan = row.json_column("execution_plan_json", &row.execution_plan_json)?;
    let plan = parse_execution_plan(&plan)?;
    let policy = row.json_column("policy_requirements_json", &row.policy_requirements_json)?;
    let Value::Object(policy_map) = &policy else {
        return Err(row.unreadable(
            "policy_requirements_json",
            "not a JSON object (Python: AttributeError)",
        ));
    };
    enforce_policy_against_plan(stored_policy_requires_reviewer(policy_map), &plan)?;
    let context = row.json_column("context_json", &row.context_json)?;
    let max_duration_seconds = row.max_duration_int()?;
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

fn single(key: &str, value: Value) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(key.to_owned(), value);
    map
}

fn optional_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.to_owned()))
}

/// `approve_ticket` (4.7.2).
pub(crate) fn approve(
    connection: &mut Connection,
    ticket_id: &str,
    approver: &str,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    if row.is_archived() {
        return Err(conflict(
            "Archived ticket must be restored before approval",
            "archived_ticket",
        ));
    }
    if row.state != "pending_approval" {
        return Err(conflict("Ticket is not pending approval", "invalid_state"));
    }
    if maybe_expire_ticket(&transaction, &row, actor)? {
        // The expiry is kept; the approval is refused.
        transaction.commit()?;
        return Err(conflict(
            "Ticket expired and cannot be approved",
            "ticket_expired",
        ));
    }
    let approved_checksum = approval_checksum(&row)?;
    let approved_at = isoformat_z(&utc_now());
    let changed = transaction.execute(
        "UPDATE tickets \
         SET state = 'approved', \
             approved_by = ?, \
             approved_at = ?, \
             approved_payload_checksum = ? \
         WHERE id = ? AND state = 'pending_approval' AND archived_at IS NULL",
        (approver, &approved_at, &approved_checksum, ticket_id),
    )?;
    require_row_changed(changed)?;
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: "ticket_approved",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some("pending_approval"),
            new_state: Some("approved"),
            metadata: &single(
                "approved_payload_checksum",
                Value::String(approved_checksum.clone()),
            ),
        },
    )?;
    transaction.commit()?;
    reread(connection, ticket_id, "Ticket not found after approval")
}

/// `reject_ticket` (4.7.2): an empty reason stores `rejected_by_approver`;
/// the audit metadata keeps the reason as given.
pub(crate) fn reject(
    connection: &mut Connection,
    ticket_id: &str,
    reason: &str,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    if row.is_archived() {
        return Err(conflict(
            "Archived ticket must be restored before rejection",
            "archived_ticket",
        ));
    }
    if row.state != "pending_approval" {
        return Err(conflict(
            "Ticket cannot be rejected in current state",
            "invalid_state",
        ));
    }
    let detail = if reason.is_empty() {
        "rejected_by_approver"
    } else {
        reason
    };
    let changed = transaction.execute(
        "UPDATE tickets \
         SET state = 'rejected', \
             finished_at = ?, \
             result = 'failure', \
             result_detail = ? \
         WHERE id = ? AND state = 'pending_approval' AND archived_at IS NULL",
        (isoformat_z(&utc_now()), detail, ticket_id),
    )?;
    require_row_changed(changed)?;
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: "ticket_rejected",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some("pending_approval"),
            new_state: Some("rejected"),
            metadata: &single("reason", Value::String(reason.to_owned())),
        },
    )?;
    transaction.commit()?;
    reread(connection, ticket_id, "Ticket not found after rejection")
}

/// `cancel_ticket` (4.7.2): from any open state; an empty reason stores
/// `canceled_by_approver`.
pub(crate) fn cancel(
    connection: &mut Connection,
    ticket_id: &str,
    reason: &str,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    if row.is_archived() {
        return Err(conflict(
            "Archived ticket must be restored before cancel",
            "archived_ticket",
        ));
    }
    if !is_open_state(&row.state) {
        return Err(conflict(
            "Ticket cannot be canceled in current state",
            "invalid_state",
        ));
    }
    let detail = if reason.is_empty() {
        "canceled_by_approver"
    } else {
        reason
    };
    let changed = transaction.execute(
        "UPDATE tickets \
         SET state = 'canceled', \
             finished_at = ?, \
             result = 'canceled', \
             result_detail = ? \
         WHERE id = ? AND state = ? AND archived_at IS NULL",
        (isoformat_z(&utc_now()), detail, ticket_id, &row.state),
    )?;
    require_row_changed(changed)?;
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: "ticket_canceled",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some(&row.state),
            new_state: Some("canceled"),
            metadata: &single("reason", Value::String(reason.to_owned())),
        },
    )?;
    transaction.commit()?;
    reread(connection, ticket_id, "Ticket not found after cancel")
}

/// `archive_ticket` (4.7.2): pending or terminal tickets only; the state
/// check comes before the archived check.
pub(crate) fn archive(
    connection: &mut Connection,
    ticket_id: &str,
    approver: &str,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    if !is_archivable_state(&row.state) {
        return Err(conflict(
            "Only pending-approval or terminal tickets can be archived",
            "invalid_state",
        ));
    }
    if row.is_archived() {
        return Err(conflict("Ticket is already archived", "already_archived"));
    }
    let archived_at = isoformat_z(&utc_now());
    let changed = transaction.execute(
        "UPDATE tickets \
         SET archived_at = ?, \
             archived_by = ? \
         WHERE id = ? AND state = ? AND archived_at IS NULL",
        (&archived_at, approver, ticket_id, &row.state),
    )?;
    require_row_changed(changed)?;
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: "ticket_archived",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some(&row.state),
            new_state: Some(&row.state),
            metadata: &single("archived_at", Value::String(archived_at.clone())),
        },
    )?;
    transaction.commit()?;
    reread(connection, ticket_id, "Ticket not found after archive")
}

/// `unarchive_ticket` (4.7.2): the compare-and-set also matches the archive
/// stamp read; restoring an open ticket whose `(source, task_ref)` has
/// another open ticket violates the dedupe index → 409
/// `duplicate_open_ticket`.
pub(crate) fn unarchive(
    connection: &mut Connection,
    ticket_id: &str,
    actor: &Actor<'_>,
    hook: Option<&ReadHook>,
) -> Result<Ticket, StoreError> {
    let transaction = write_transaction(connection)?;
    let row = read_ticket(&transaction, ticket_id, hook)?;
    if !row.is_archived() {
        return Err(conflict("Ticket is not archived", "not_archived"));
    }
    // `str(row["archived_at"])`: a non-empty text here.
    let previous_archived_at = row.archived_at.clone().unwrap_or_default();
    let previous_archived_by = row.archived_by.clone();
    let updated = transaction.execute(
        "UPDATE tickets \
         SET archived_at = NULL, \
             archived_by = NULL \
         WHERE id = ? AND state = ? AND archived_at = ? AND archived_by IS ?",
        (
            ticket_id,
            &row.state,
            &previous_archived_at,
            &previous_archived_by,
        ),
    );
    let changed = match updated {
        Ok(changed) => changed,
        // Python catches `sqlite3.IntegrityError`, every constraint failure.
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == ErrorCode::ConstraintViolation =>
        {
            return Err(conflict(
                "Cannot restore archived ticket while another open ticket exists for this source/task_ref",
                "duplicate_open_ticket",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    require_row_changed(changed)?;
    let mut metadata = Map::new();
    metadata.insert(
        "previous_archived_at".into(),
        Value::String(previous_archived_at),
    );
    metadata.insert(
        "previous_archived_by".into(),
        optional_text(previous_archived_by.as_deref()),
    );
    audit::record(
        &transaction,
        &AuditEvent {
            ticket_id,
            event_type: "ticket_unarchived",
            actor: actor.actor,
            source_ip: actor.source_ip,
            user_agent: actor.user_agent,
            previous_state: Some(&row.state),
            new_state: Some(&row.state),
            metadata: &metadata,
        },
    )?;
    transaction.commit()?;
    reread(connection, ticket_id, "Ticket not found after unarchive")
}
