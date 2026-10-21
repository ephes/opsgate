//! `GET /api/v1/health` data (PLAN.md 4.6): ticket counts per state and the
//! newest runner heartbeat.
//!
//! Ported Python: `service.py:OpsGateService.health`.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::error::StoreError;
use crate::ticket::text_column;

/// `health()`: `{"status": "ok", "service", "db": "ok",
/// "runner_last_heartbeat", "runner_host", "ticket_counters"}`. A database
/// that cannot be read is an error (500), never `"db"` other than `"ok"`.
pub(crate) fn health(
    connection: &Connection,
    service_name: &str,
) -> Result<Map<String, Value>, StoreError> {
    let mut counters = Map::new();
    let mut statement =
        connection.prepare("SELECT state, COUNT(*) AS count FROM tickets GROUP BY state")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let state = text_column(row, "tickets", None, "state")?.unwrap_or_default();
        let count: i64 = row.get("count")?;
        counters.insert(state, Value::from(count));
    }

    let runner = connection
        .query_row(
            "SELECT runner_host, last_heartbeat_at FROM runner_heartbeats ORDER BY last_heartbeat_at DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    text_column(row, "runner_heartbeats", None, "runner_host"),
                    text_column(row, "runner_heartbeats", None, "last_heartbeat_at"),
                ))
            },
        )
        .optional()?;
    let (runner_host, runner_last_heartbeat) = match runner {
        Some((host, heartbeat)) => (host?, heartbeat?),
        None => (None, None),
    };
    let optional = |value: Option<String>| value.map_or(Value::Null, Value::String);

    let mut health = Map::new();
    health.insert("status".into(), Value::from("ok"));
    health.insert("service".into(), Value::from(service_name));
    health.insert("db".into(), Value::from("ok"));
    health.insert(
        "runner_last_heartbeat".into(),
        optional(runner_last_heartbeat),
    );
    health.insert("runner_host".into(), optional(runner_host));
    health.insert("ticket_counters".into(), Value::Object(counters));
    Ok(health)
}
