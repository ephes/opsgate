//! Shared helpers of the store tests: API settings for a temporary database
//! (the values of `rust/fixtures/generate.py:_store_settings`).

#![allow(dead_code)]

use std::path::Path;

use opsgate_core::settings::{ApiSettings, Environment, SubmitterPolicy, load_api_settings};
use opsgate_store::{Store, StoreError};
use serde_json::{Map, Value};

pub const HASH_ONE: &str = "$2b$12$fixture.hash.one.not.verified.by.these.scenarios.xx";

/// Settings options as `store.json` gives them: `ui_username`,
/// `ui_password_bcrypt`, `operator_floor`.
pub fn settings(db_path: &Path, options: &Map<String, Value>) -> ApiSettings {
    let text = |key: &str, default: &str| {
        options
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let operator_floor = options
        .get("operator_floor")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // `_settings`: the execution data directory (and so the disable file,
    // `<dir>/.disabled`) next to the database.
    let execution_data_dir = db_path.parent().unwrap().join("remediation");
    let mut environment = Environment::from_vars([
        ("OPSGATE_DB_PATH", db_path.to_str().unwrap().to_owned()),
        (
            "OPSGATE_EXECUTION_DATA_DIR",
            execution_data_dir.to_str().unwrap().to_owned(),
        ),
        ("OPSGATE_UI_USERNAME", text("ui_username", "opsgate-admin")),
        (
            "OPSGATE_UI_PASSWORD_BCRYPT",
            text("ui_password_bcrypt", HASH_ONE),
        ),
        ("OPSGATE_SESSION_SECRET", "x".repeat(32)),
        (
            "OPSGATE_RUNNER_TOKEN",
            "runner-token-000000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_OPENCLAW",
            "openclaw-token-0000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_NYXMON",
            "nyxmon-token-000000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_OPERATOR",
            "operator-token-00000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
            operator_floor.to_string(),
        ),
    ]);
    load_api_settings(&mut environment).expect("test settings are valid")
}

/// A store on `<dir>/opsgate.sqlite3` with the default options.
pub fn store(dir: &Path) -> Store {
    Store::open(settings(&dir.join("opsgate.sqlite3"), &Map::new())).expect("store opens")
}

/// The submitter policy of `source`.
pub fn submitter(store: &Store, source: &str) -> SubmitterPolicy {
    store
        .settings()
        .submitter_policies
        .iter()
        .find(|policy| policy.source == source)
        .cloned()
        .expect("configured submitter")
}

/// A JSON object from a `serde_json::json!` literal.
pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// The approver of the store tests (`ui_username` of the settings).
pub const APPROVER: &str = "opsgate-admin";

/// The `POST /api/v1/tickets` body of the Python tests' `create_ticket`
/// helper: one investigator step unless `plan` is given.
pub fn ticket_payload(
    title: &str,
    task_ref: Option<&str>,
    plan: Option<Value>,
) -> Map<String, Value> {
    let mut payload = object(serde_json::json!({
        "title": title,
        "summary": format!("{title} summary"),
        "execution_plan": plan.unwrap_or_else(|| serde_json::json!([
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}
        ])),
    }));
    if let Some(task_ref) = task_ref {
        payload.insert("task_ref".into(), task_ref.into());
    }
    payload
}

/// A reviewer step plan with `require_reviewer_step: true` (the Python tests'
/// usual runner fixture).
pub fn reviewer_payload(title: &str, task_ref: Option<&str>) -> Map<String, Value> {
    let mut payload = ticket_payload(
        title,
        task_ref,
        Some(serde_json::json!([
            {"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}
        ])),
    );
    payload.insert(
        "policy_requirements".into(),
        serde_json::json!({"require_reviewer_step": true}),
    );
    payload
}

/// Creates a ticket as `source` and returns its id.
pub fn create(store: &Store, source: &str, payload: &Map<String, Value>) -> String {
    store
        .create_ticket(
            payload,
            &submitter(store, source),
            Some("127.0.0.1"),
            Some("test"),
        )
        .expect("ticket created")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Approves as [`APPROVER`].
pub fn approve(store: &Store, ticket_id: &str) -> Result<Map<String, Value>, StoreError> {
    store.approve_ticket(ticket_id, APPROVER, None, None)
}

/// Claims as `runner_host`.
pub fn claim(store: &Store, runner_host: &str) -> Option<Map<String, Value>> {
    store
        .claim_ticket(runner_host, None, None)
        .expect("claim succeeds")
}

/// A runner status update from a `json!` object.
pub fn status(
    store: &Store,
    ticket_id: &str,
    runner_host: &str,
    payload: Value,
) -> Result<Map<String, Value>, StoreError> {
    store.update_runner_status(ticket_id, runner_host, &object(payload), None, None)
}

/// `(status, code)` of a domain error; panics on success or a 500.
pub fn error<T: std::fmt::Debug>(result: Result<T, StoreError>) -> (u16, &'static str) {
    let error = result.expect_err("a domain error");
    let service = error
        .service()
        .unwrap_or_else(|| panic!("not a domain error: {error}"));
    (service.status, service.code)
}

/// Runs SQL on the database directly, as the Python tests prepare states.
pub fn execute(store: &Store, sql: &str, params: impl rusqlite::Params) {
    rusqlite::Connection::open(store.db_path())
        .unwrap()
        .execute(sql, params)
        .unwrap();
}

/// `(event_type, previous_state, new_state, metadata)` of a ticket's audit
/// events in order.
pub fn audit(
    store: &Store,
    ticket_id: &str,
) -> Vec<(String, Option<String>, Option<String>, Value)> {
    let connection = rusqlite::Connection::open(store.db_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT event_type, previous_state, new_state, metadata_json \
             FROM audit_events WHERE ticket_id = ? ORDER BY id",
        )
        .unwrap();
    statement
        .query_map([ticket_id], |row| {
            let metadata: String = row.get(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                serde_json::from_str(&metadata).unwrap(),
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The event types of a ticket's audit trail.
pub fn audit_event_types(store: &Store, ticket_id: &str) -> Vec<String> {
    audit(store, ticket_id)
        .into_iter()
        .map(|(event, ..)| event)
        .collect()
}

/// Every row of every table, for "nothing was written" checks.
pub fn snapshot(store: &Store) -> Vec<Vec<String>> {
    let connection = rusqlite::Connection::open(store.db_path()).unwrap();
    [
        "tickets",
        "audit_events",
        "runner_heartbeats",
        "ui_session_state",
    ]
    .iter()
    .map(|table| {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                Ok((0..columns)
                    .map(|index| format!("{:?}", row.get_ref(index).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    })
    .collect()
}
