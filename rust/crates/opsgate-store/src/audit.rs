//! Audit events (PLAN.md 4.7): one row per transition with the replaced and
//! the new state; the metadata content is P1, its text format P2.
//!
//! Ported Python: `service.py:OpsGateService._record_audit_event`.

use opsgate_core::json::stored_json;
use opsgate_core::time::{isoformat_z, utc_now};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::error::{StoreError, Unreadable};

/// One audit event; the timestamp is taken when it is written.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent<'a> {
    pub ticket_id: &'a str,
    pub event_type: &'a str,
    pub actor: &'a str,
    pub source_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub previous_state: Option<&'a str>,
    pub new_state: Option<&'a str>,
    /// Stored as `json.dumps(metadata or {}, sort_keys=True)`.
    pub metadata: &'a Map<String, Value>,
}

/// `_record_audit_event`: insert the event inside the caller's transaction.
pub fn record(connection: &Connection, event: &AuditEvent<'_>) -> Result<(), StoreError> {
    let metadata = stored_json(&Value::Object(event.metadata.clone())).map_err(|error| {
        // A non-finite float in metadata copied from a stored value (D-2).
        Unreadable {
            table: "audit_events",
            key: Some(event.ticket_id.to_owned()),
            column: "metadata_json".to_owned(),
            reason: error.to_string(),
        }
    })?;
    connection.execute(
        "INSERT INTO audit_events (\
         ticket_id, event_type, actor, timestamp, \
         source_ip, user_agent, previous_state, new_state, metadata_json\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.ticket_id,
            event.event_type,
            event.actor,
            isoformat_z(&utc_now()),
            event.source_ip,
            event.user_agent,
            event.previous_state,
            event.new_state,
            metadata,
        ),
    )?;
    Ok(())
}
