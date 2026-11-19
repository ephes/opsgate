//! `GET /api/v1/health` data (PLAN.md 4.6): ticket counts per state and the
//! newest runner heartbeat.
//!
//! Ported Python: `service.py:OpsGateService.health`.

use chrono::{DateTime, TimeDelta, Utc};
use opsgate_core::time::{parse_iso_datetime, utc_now};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::error::StoreError;
use crate::ticket::text_column;

/// `health()`: `{"status": "ok", "service", "db": "ok",
/// "runner_last_heartbeat", "runner_host", "runner_readiness", "ticket_counters"}`. A database
/// that cannot be read is an error (500), never `"db"` other than `"ok"`.
pub(crate) fn health(
    connection: &Connection,
    service_name: &str,
) -> Result<Map<String, Value>, StoreError> {
    let snapshot = connection.unchecked_transaction()?;
    let counters = {
        let mut counters = Map::new();
        let mut statement =
            snapshot.prepare("SELECT state, COUNT(*) AS count FROM tickets GROUP BY state")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let state = text_column(row, "tickets", None, "state")?.unwrap_or_default();
            let count: i64 = row.get("count")?;
            counters.insert(state, Value::from(count));
        }
        counters
    };

    let runner = snapshot
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
    snapshot.commit()?;
    let readiness = runner_readiness(runner_last_heartbeat.as_deref(), utc_now());
    let optional = |value: Option<String>| value.map_or(Value::Null, Value::String);

    let mut health = Map::new();
    health.insert("runner_readiness".into(), readiness);
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

/// Readiness is independent of control-plane liveness. Five seconds of
/// future clock skew is tolerated; timestamps beyond that cannot prove readiness.
fn runner_readiness(heartbeat: Option<&str>, now: DateTime<Utc>) -> Value {
    let status = match heartbeat {
        None => "unavailable",
        Some(stamp) => match parse_iso_datetime(stamp) {
            Err(_) => "clock_invalid",
            Ok(stamp) => {
                let age = now.signed_duration_since(stamp);
                if age < TimeDelta::seconds(-5) {
                    "clock_invalid"
                } else if age > TimeDelta::seconds(120) {
                    "stale"
                } else {
                    "fresh"
                }
            }
        },
    };
    serde_json::json!({"status": status, "freshness_threshold_seconds": 120})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_counts_and_latest_heartbeat_share_a_wal_snapshot() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("health.sqlite3");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        crate::schema::apply(&writer).unwrap();
        writer
            .execute_batch(
                "INSERT INTO tickets (id, source, title, summary, execution_plan_json,
                    policy_requirements_json, context_json, payload_checksum, state,
                    created_by, created_at, max_duration_seconds)
                 VALUES ('synthetic', 'test', 't', 's', '[]', '{}', '{}',
                    'hash', 'approved', 'test', 'now', 1);
                 INSERT INTO runner_heartbeats VALUES
                    ('earlier-runner', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
            )
            .unwrap();

        let reader = Connection::open(&path).unwrap();
        let mut writer = Some(writer);
        // SQLite prepares the heartbeat query after consuming the counters.
        reader
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "runner_heartbeats",
                        ..
                    }
                ) && let Some(writer) = writer.take()
                {
                    writer
                        .execute_batch(
                            "BEGIN IMMEDIATE;
                             UPDATE tickets SET state = 'running' WHERE id = 'synthetic';
                             INSERT INTO runner_heartbeats VALUES
                                ('new-runner', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z');
                             COMMIT;",
                        )
                        .unwrap();
                }
                Authorization::Allow
            }))
            .unwrap();

        let health_before = health(&reader, "test-service").unwrap();
        assert_eq!(
            health_before["ticket_counters"],
            serde_json::json!({"approved": 1})
        );
        assert_eq!(health_before["runner_host"], "earlier-runner");
        assert_eq!(
            health_before["runner_last_heartbeat"],
            "2026-01-01T00:00:00Z"
        );

        let health_after = health(&reader, "test-service").unwrap();
        assert_eq!(
            health_after["ticket_counters"],
            serde_json::json!({"running": 1})
        );
        assert_eq!(health_after["runner_host"], "new-runner");
        assert_eq!(
            health_after["runner_last_heartbeat"],
            "2026-01-01T00:00:01Z"
        );
    }

    #[test]
    fn readiness_boundaries_use_a_fixed_clock() {
        let now = parse_iso_datetime("2026-01-01T00:00:00Z").unwrap();
        for (age, status) in [
            (0, "fresh"),
            (120, "fresh"),
            (121, "stale"),
            (-5, "fresh"),
            (-6, "clock_invalid"),
        ] {
            let stamp = opsgate_core::time::isoformat_z(&(now - TimeDelta::seconds(age)));
            assert_eq!(runner_readiness(Some(&stamp), now)["status"], status);
        }
    }
}
