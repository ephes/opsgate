//! `fixtures/store.json` (PLAN.md 4.5.2, 4.6, 4.7): every scenario the
//! Python service ran is replayed against `opsgate_store::Store` on a fresh
//! database, and every step result and the final content of all four tables
//! must equal Python's: creation, reads and the session generation (S3a),
//! the transitions, claim and runner status updates (S3b). Values the
//! service generates are masked the way the generator masks them, after
//! their format was checked (4.9).

mod common;

use std::collections::HashSet;
use std::path::Path;

use opsgate_core::json::{canonical_json, parse, stored_json};
use opsgate_store::{ArchivedFilter, Store, StoreError};
use regex::Regex;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};

const FIXTURE: &str = include_str!("../../../fixtures/store.json");

/// `_STORE_GENERATED_COLUMNS` of the generator.
const GENERATED_COLUMNS: [&str; 6] = [
    "created_at",
    "approved_at",
    "started_at",
    "last_heartbeat_at",
    "finished_at",
    "archived_at",
];

/// `_STORE_GENERATED_METADATA`.
const GENERATED_METADATA: [&str; 2] = ["archived_at", "previous_archived_at"];

struct Masks {
    ids: Vec<String>,
    timestamp: Regex,
    mask: String,
    /// `_store_fixed_values`: texts a step wrote, never masked.
    fixed: HashSet<String>,
}

/// `_store_fixed_values`: the text values of the `update` and `insert`
/// steps.
fn fixed_values(steps: &[Value]) -> HashSet<String> {
    let mut fixed = HashSet::new();
    for step in steps {
        for key in ["set", "row"] {
            if let Some(Value::Object(values)) = step.get(key) {
                fixed.extend(
                    values
                        .values()
                        .filter_map(|v| v.as_str().map(str::to_owned)),
                );
            }
        }
    }
    fixed
}

impl Masks {
    fn ticket_id(&self, value: &Value) -> Value {
        match value
            .as_str()
            .and_then(|id| self.ids.iter().position(|known| known == id))
        {
            Some(index) => Value::String(format!("ticket-{}", index + 1)),
            None => value.clone(),
        }
    }

    fn timestamp(&self, value: &Value) -> Value {
        match value {
            Value::Null => Value::Null,
            Value::String(text) if self.timestamp.is_match(text) => {
                Value::String(self.mask.clone())
            }
            other => panic!("unexpected generated timestamp {other}"),
        }
    }

    /// A value the service may have generated: kept when a step wrote it.
    fn generated(&self, value: &Value) -> Value {
        match value {
            Value::Null => Value::Null,
            Value::String(text) if self.fixed.contains(text) => value.clone(),
            other => self.timestamp(other),
        }
    }

    fn ticket(&self, ticket: &Map<String, Value>) -> Value {
        let mut masked = ticket.clone();
        for column in GENERATED_COLUMNS {
            masked.insert(column.into(), self.generated(&ticket[column]));
        }
        masked.insert("id".into(), self.ticket_id(&ticket["id"]));
        Value::Object(masked)
    }

    /// The archive stamps in audit metadata (re-serialised as Python's
    /// `json.dumps(sort_keys=True)` when one is masked).
    fn metadata(&self, text: &Value) -> Value {
        let Value::Object(mut metadata) = parse(text.as_str().unwrap()).unwrap() else {
            panic!("metadata is an object");
        };
        if !GENERATED_METADATA
            .iter()
            .any(|key| metadata.contains_key(*key))
        {
            return text.clone();
        }
        for key in GENERATED_METADATA {
            if let Some(value) = metadata.get(key) {
                let masked = self.generated(value);
                metadata.insert(key.into(), masked);
            }
        }
        Value::String(stored_json(&Value::Object(metadata)).unwrap())
    }

    fn health(&self, mut health: Map<String, Value>) -> Value {
        let masked = self.generated(&health["runner_last_heartbeat"]);
        health.insert("runner_last_heartbeat".into(), masked);
        Value::Object(health)
    }
}

/// A SQLite value as Python's `sqlite3` returns it, as JSON.
fn sql_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::from(value),
        ValueRef::Real(value) => Value::from(value),
        ValueRef::Text(text) => Value::String(String::from_utf8(text.to_vec()).unwrap()),
        ValueRef::Blob(_) => panic!("no BLOBs in these scenarios"),
    }
}

fn rows(connection: &Connection, sql: &str) -> Vec<Map<String, Value>> {
    let mut statement = connection.prepare(sql).unwrap();
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut rows = statement.query([]).unwrap();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let mut map = Map::new();
        for (index, name) in names.iter().enumerate() {
            map.insert(name.clone(), sql_json(row.get_ref(index).unwrap()));
        }
        out.push(map);
    }
    out
}

fn tables(db_path: &Path, masks: &Masks) -> Value {
    let connection =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tickets: Vec<Value> = rows(&connection, "SELECT * FROM tickets ORDER BY rowid")
        .iter()
        .map(|row| masks.ticket(row))
        .collect();
    let audit: Vec<Value> = rows(&connection, "SELECT * FROM audit_events ORDER BY id")
        .into_iter()
        .map(|mut row| {
            row.insert("ticket_id".into(), masks.ticket_id(&row["ticket_id"]));
            row.insert("timestamp".into(), masks.timestamp(&row["timestamp"]));
            row.insert(
                "metadata_json".into(),
                masks.metadata(&row["metadata_json"]),
            );
            Value::Object(row)
        })
        .collect();
    let sessions: Vec<Value> = rows(
        &connection,
        "SELECT * FROM ui_session_state ORDER BY username",
    )
    .into_iter()
    .map(|mut row| {
        row.insert("updated_at".into(), masks.timestamp(&row["updated_at"]));
        Value::Object(row)
    })
    .collect();
    let heartbeats: Vec<Value> = rows(
        &connection,
        "SELECT * FROM runner_heartbeats ORDER BY runner_host",
    )
    .into_iter()
    .map(|mut row| {
        for column in ["last_heartbeat_at", "updated_at"] {
            let masked = masks.generated(&row[column]);
            row.insert(column.into(), masked);
        }
        Value::Object(row)
    })
    .collect();
    serde_json::json!({
        "tickets": tickets,
        "audit_events": audit,
        "ui_session_state": sessions,
        "runner_heartbeats": heartbeats,
    })
}

/// Bind a JSON scalar of the fixture as Python's `sqlite3` binds it.
fn sql_param(value: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as Sql;
    match value {
        Value::Null => Sql::Null,
        Value::Bool(value) => Sql::Integer(i64::from(*value)),
        Value::Number(number) => match number.as_i64() {
            Some(value) => Sql::Integer(value),
            None => Sql::Real(number.as_f64().unwrap()),
        },
        Value::String(text) => Sql::Text(text.clone()),
        other => panic!("not a scalar: {other}"),
    }
}

fn outcome(result: Result<Value, StoreError>) -> Value {
    match result {
        Ok(value) => serde_json::json!({ "ok": value }),
        Err(StoreError::Service(error)) => serde_json::json!({
            "error": {"code": error.code, "status": error.status, "message": error.message}
        }),
        // Python names the exception type; any non-domain error is a 500.
        Err(_) => serde_json::json!({ "unhandled": null }),
    }
}

/// The ticket a step names: the n-th created one (`ticket`) or a literal
/// `id`.
fn target(step: &Map<String, Value>, masks: &Masks) -> String {
    match step.get("ticket") {
        Some(index) => masks.ids[index.as_u64().unwrap() as usize - 1].clone(),
        None => step["id"].as_str().unwrap().to_owned(),
    }
}

fn run_step(store: &mut Store, step: &Map<String, Value>, masks: &mut Masks) -> Value {
    let text = |key: &str| step[key].as_str().unwrap().to_owned();
    let optional = |key: &str| step[key].as_str().map(str::to_owned);
    let op = text("op");
    let result: Result<Value, StoreError> = match op.as_str() {
        "create" | "create_manual" => {
            let Value::Object(payload) = parse(&text("body")).unwrap() else {
                panic!("body is an object");
            };
            let source_ip = optional("source_ip");
            let user_agent = optional("user_agent");
            let created = if op == "create" {
                let submitter = common::submitter(store, &text("source"));
                store.create_ticket(
                    &payload,
                    &submitter,
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                )
            } else {
                store.create_manual_ticket(
                    &payload,
                    &text("creator"),
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                )
            };
            created.map(|ticket| {
                masks.ids.push(ticket["id"].as_str().unwrap().to_owned());
                masks.ticket(&ticket)
            })
        }
        "update" | "insert" => {
            let connection = Connection::open(store.db_path()).unwrap();
            if op == "update" {
                let set = step["set"].as_object().unwrap();
                let assignments: Vec<String> =
                    set.keys().map(|column| format!("{column} = ?")).collect();
                let mut params: Vec<rusqlite::types::Value> = set.values().map(sql_param).collect();
                let index = step["ticket"].as_u64().unwrap() as usize - 1;
                params.push(rusqlite::types::Value::Text(masks.ids[index].clone()));
                connection
                    .execute(
                        &format!("UPDATE tickets SET {} WHERE id = ?", assignments.join(", ")),
                        rusqlite::params_from_iter(params),
                    )
                    .unwrap();
            } else {
                let row = step["row"].as_object().unwrap();
                let columns: Vec<&str> = row.keys().map(String::as_str).collect();
                let marks = vec!["?"; columns.len()].join(", ");
                connection
                    .execute(
                        &format!(
                            "INSERT INTO {} ({}) VALUES ({marks})",
                            text("table"),
                            columns.join(", ")
                        ),
                        rusqlite::params_from_iter(row.values().map(sql_param)),
                    )
                    .unwrap();
            }
            Ok(Value::Null)
        }
        "get" => {
            let id = target(step, masks);
            store.get_ticket(&id).map(|ticket| masks.ticket(&ticket))
        }
        "list" => {
            let archived = match text("archived").as_str() {
                "exclude" => ArchivedFilter::Exclude,
                "only" => ArchivedFilter::Only,
                "include" => ArchivedFilter::Include,
                other => panic!("filter {other}"),
            };
            store
                .list_tickets(step["limit"].as_i64().unwrap(), archived)
                .map(|tickets| Value::Array(tickets.iter().map(|t| masks.ticket(t)).collect()))
        }
        "health" => store.health().map(|health| masks.health(health)),
        "approve" | "reject" | "cancel" | "archive" | "unarchive" => {
            let id = target(step, masks);
            let approver = text("approver");
            let source_ip = optional("source_ip");
            let user_agent = optional("user_agent");
            let (ip, agent) = (source_ip.as_deref(), user_agent.as_deref());
            match op.as_str() {
                "approve" => store.approve_ticket(&id, &approver, ip, agent),
                "reject" => store.reject_ticket(&id, &approver, &text("reason"), ip, agent),
                "cancel" => store.cancel_ticket(&id, &approver, &text("reason"), ip, agent),
                "archive" => store.archive_ticket(&id, &approver, ip, agent),
                _ => store.unarchive_ticket(&id, &approver, ip, agent),
            }
            .map(|ticket| masks.ticket(&ticket))
        }
        "claim" => {
            let source_ip = optional("source_ip");
            let user_agent = optional("user_agent");
            store
                .claim_ticket(
                    &text("runner_host"),
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                )
                .map(|claimed| claimed.map_or(Value::Null, |ticket| masks.ticket(&ticket)))
        }
        "status" => {
            let id = target(step, masks);
            let Value::Object(payload) = parse(&text("body")).unwrap() else {
                panic!("body is an object");
            };
            let source_ip = optional("source_ip");
            let user_agent = optional("user_agent");
            store
                .update_runner_status(
                    &id,
                    &text("runner_host"),
                    &payload,
                    source_ip.as_deref(),
                    user_agent.as_deref(),
                )
                .map(|ticket| masks.ticket(&ticket))
        }
        "disable" => {
            let disable_file = Path::new(&store.settings().disable_file_path).to_owned();
            if step["present"].as_bool().unwrap() {
                std::fs::create_dir_all(disable_file.parent().unwrap()).unwrap();
                std::fs::write(&disable_file, "").unwrap();
            } else {
                std::fs::remove_file(&disable_file).unwrap();
            }
            Ok(Value::Null)
        }
        "generation" => store
            .ui_session_generation(&text("username"))
            .map(|generation| generation.map_or(Value::Null, Value::from)),
        "revoke" => store.revoke_ui_sessions(&text("username")).map(Value::from),
        "restart" => {
            let settings = common::settings(store.db_path(), step["settings"].as_object().unwrap());
            Store::open(settings).map(|reopened| {
                *store = reopened;
                Value::Null
            })
        }
        other => panic!("unknown op {other}"),
    };
    outcome(result)
}

/// Python's expectation with the unhandled exception's type name dropped.
fn expected_outcome(result: &Value) -> Value {
    if result.get("unhandled").is_some() {
        serde_json::json!({ "unhandled": null })
    } else {
        result.clone()
    }
}

/// JSON values compare by their canonical text: number tokens such as
/// `1E5` and `100000.0` are the same Python float (4.8).
fn canonical(value: &Value) -> String {
    canonical_json(value).unwrap()
}

#[test]
fn store_scenarios_match_python() {
    let fixture = parse(FIXTURE).unwrap();
    let timestamp = Regex::new(fixture["timestamp_pattern"].as_str().unwrap()).unwrap();
    let mask = fixture["timestamp_mask"].as_str().unwrap().to_owned();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 10);
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        // Store::open creates the missing parent directory, as Python does.
        let db_path = directory.path().join("run").join("opsgate.sqlite3");
        let mut store = Store::open(common::settings(
            &db_path,
            scenario["settings"].as_object().unwrap(),
        ))
        .unwrap();
        let mut masks = Masks {
            ids: Vec::new(),
            timestamp: timestamp.clone(),
            mask: mask.clone(),
            fixed: fixed_values(scenario["steps"].as_array().unwrap()),
        };
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let step = step.as_object().unwrap();
            let actual = run_step(&mut store, step, &mut masks);
            let expected = expected_outcome(&step["result"]);
            assert_eq!(
                canonical(&actual),
                canonical(&expected),
                "{name} step {index} ({})",
                step["op"]
            );
        }
        assert_eq!(
            canonical(&tables(&db_path, &masks)),
            canonical(&scenario["tables"]),
            "{name}: tables"
        );
    }
}
