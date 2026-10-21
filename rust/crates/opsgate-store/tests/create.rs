//! Ticket creation, reading and health at the store level (PLAN.md 4.6,
//! 4.7.1). The tests named like a Python test of `tests/test_api.py` port its
//! store half (`rust/TESTMAP.md`); the HTTP half lands with the web slices.

mod common;

use std::time::Duration;

use common::{object, submitter};
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_store::{ArchivedFilter, Store, StoreError};
use rusqlite::Connection;
use serde_json::{Map, Value, json};

fn payload(task_ref: Option<&str>) -> Map<String, Value> {
    let mut payload = object(json!({
        "title": "Investigate alert",
        "summary": "Same task ref",
        "execution_plan": [
            {"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}
        ],
    }));
    if let Some(task_ref) = task_ref {
        payload.insert("task_ref".into(), task_ref.into());
    }
    payload
}

fn create(
    store: &Store,
    source: &str,
    payload: &Map<String, Value>,
) -> Result<Map<String, Value>, StoreError> {
    store.create_ticket(
        payload,
        &submitter(store, source),
        Some("127.0.0.1"),
        Some("test"),
    )
}

fn error_code(result: Result<Map<String, Value>, StoreError>) -> &'static str {
    result.unwrap_err().service().expect("a domain error").code
}

fn audit_event_types(store: &Store, ticket_id: &str) -> Vec<String> {
    let connection = Connection::open(store.db_path()).unwrap();
    let mut statement = connection
        .prepare("SELECT event_type FROM audit_events WHERE ticket_id = ? ORDER BY id")
        .unwrap();
    statement
        .query_map([ticket_id], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn count(store: &Store, table: &str) -> i64 {
    Connection::open(store.db_path())
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn test_dedupe_enforced_for_open_task_ref() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let first = create(&store, "openclaw", &payload(Some("same-ref"))).unwrap();
    assert_eq!(first["state"], "pending_approval");

    let second = create(&store, "openclaw", &payload(Some("same-ref"))).unwrap_err();
    let error = second.service().unwrap();
    assert_eq!((error.status, error.code), (409, "duplicate_open_ticket"));
    // Nothing of the failed attempt is written.
    assert_eq!(count(&store, "tickets"), 1);
    assert_eq!(count(&store, "audit_events"), 1);
}

#[test]
fn test_dedupe_expires_stale_pending_ticket_before_replacement_submit() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let past = isoformat_z(&(utc_now() - Duration::from_secs(3600)));
    let future = isoformat_z(&(utc_now() + Duration::from_secs(3600)));
    let mut original_payload = payload(Some("same-ref-expired-pending"));
    original_payload.insert("expires_at".into(), past.clone().into());
    let original = create(&store, "nyxmon", &original_payload).unwrap();
    let original_id = original["id"].as_str().unwrap();

    let mut replacement_payload = original_payload.clone();
    replacement_payload.insert("title".into(), "Investigate alert recurrence".into());
    replacement_payload.insert("expires_at".into(), future.into());
    let replacement = create(&store, "nyxmon", &replacement_payload).unwrap();
    assert_ne!(replacement["id"], original["id"]);
    assert_eq!(replacement["state"], "pending_approval");

    let read_back = store.get_ticket(original_id).unwrap();
    assert_eq!(read_back["state"], "expired");
    assert_eq!(read_back["result"], "failure");
    assert_eq!(read_back["result_detail"], "expired_before_execution");
    assert!(read_back["finished_at"].is_string());
    assert_eq!(
        audit_event_types(&store, original_id).last().unwrap(),
        "ticket_expired"
    );
    let metadata: String = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT metadata_json FROM audit_events WHERE event_type = 'ticket_expired'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(metadata, format!("{{\"expires_at\": \"{past}\"}}"));
}

#[test]
fn test_dedupe_not_applied_when_task_ref_missing() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let first = create(&store, "openclaw", &payload(None)).unwrap();
    let second = create(&store, "openclaw", &payload(None)).unwrap();
    assert_ne!(first["id"], second["id"]);
    assert_eq!(first["task_ref"], Value::Null);
}

#[test]
fn created_ticket_has_python_shape_and_audit() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let ticket = create(&store, "nyxmon", &payload(Some("ref"))).unwrap();
    let keys: Vec<&str> = ticket.keys().map(String::as_str).collect();
    let mut expected = vec![
        "id",
        "source",
        "task_ref",
        "title",
        "summary",
        "execution_plan",
        "policy_requirements",
        "context",
        "payload_checksum",
        "approved_payload_checksum",
        "state",
        "created_by",
        "created_at",
        "approved_by",
        "approved_at",
        "expires_at",
        "max_duration_seconds",
        "tmux_sessions",
        "runner_host",
        "last_heartbeat_at",
        "started_at",
        "finished_at",
        "result",
        "result_detail",
        "archived_at",
        "archived_by",
        "is_archived",
        "is_terminal",
        "is_archivable",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    assert_eq!(ticket["created_by"], "submit:nyxmon");
    assert_eq!(ticket["max_duration_seconds"], 3600);
    assert_eq!(ticket["tmux_sessions"], json!([]));
    assert_eq!(
        ticket["policy_requirements"],
        json!({"require_reviewer_step": false})
    );
    assert_eq!(
        (
            &ticket["is_archived"],
            &ticket["is_terminal"],
            &ticket["is_archivable"]
        ),
        (&json!(false), &json!(false), &json!(true))
    );
    let id = ticket["id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.get_version_num() == 4));
    assert_eq!(audit_event_types(&store, id), ["ticket_created"]);
    let (actor, ip, agent, previous, new, metadata): (String, String, String, Option<String>, String, String) =
        Connection::open(store.db_path())
            .unwrap()
            .query_row(
                "SELECT actor, source_ip, user_agent, previous_state, new_state, metadata_json FROM audit_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .unwrap();
    assert_eq!(
        (
            actor.as_str(),
            ip.as_str(),
            agent.as_str(),
            previous,
            new.as_str(),
            metadata.as_str()
        ),
        (
            "submit:nyxmon",
            "127.0.0.1",
            "test",
            None,
            "pending_approval",
            "{\"task_ref\": \"ref\"}"
        )
    );
}

#[test]
fn manual_ticket_uses_operator_source_and_approver_actor() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let ticket = store
        .create_manual_ticket(&payload(Some("m")), "opsgate-admin", None, None)
        .unwrap();
    assert_eq!(ticket["source"], "operator");
    assert_eq!(ticket["created_by"], "approver:opsgate-admin");
    // A body naming another source is a mismatch for the manual path too.
    let mut other = payload(None);
    other.insert("source".into(), "nyxmon".into());
    assert_eq!(
        error_code(store.create_manual_ticket(&other, "opsgate-admin", None, None)),
        "source_mismatch"
    );
}

#[test]
fn unparsable_stored_expiry_fails_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let first = create(&store, "nyxmon", &payload(Some("ref"))).unwrap();
    Connection::open(store.db_path())
        .unwrap()
        .execute(
            "UPDATE tickets SET expires_at = 'garbage' WHERE id = ?",
            [first["id"].as_str().unwrap()],
        )
        .unwrap();
    let error = create(&store, "nyxmon", &payload(Some("ref"))).unwrap_err();
    assert!(matches!(error, StoreError::Unreadable(_)), "{error}");
    assert_eq!(count(&store, "tickets"), 1);
    assert_eq!(count(&store, "audit_events"), 1);
}

#[test]
fn get_and_list() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    assert_eq!(error_code(store.get_ticket("missing")), "ticket_not_found");
    let first = create(&store, "nyxmon", &payload(Some("a"))).unwrap();
    let second = create(&store, "nyxmon", &payload(Some("b"))).unwrap();
    assert_eq!(
        store.get_ticket(first["id"].as_str().unwrap()).unwrap(),
        first
    );
    let listed = store.list_tickets(100, ArchivedFilter::default()).unwrap();
    assert_eq!(listed, [second.clone(), first.clone()]);
    assert_eq!(
        store.list_tickets(1, ArchivedFilter::Include).unwrap(),
        [second]
    );
    assert!(
        store
            .list_tickets(100, ArchivedFilter::Only)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unreadable_stored_json_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let ticket = create(&store, "nyxmon", &payload(None)).unwrap();
    let id = ticket["id"].as_str().unwrap();
    for (column, text) in [
        ("context_json", "{not json"),
        // D-2: Python reads the literal, Rust cannot.
        ("context_json", "{\"x\": NaN}"),
        ("tmux_sessions_json", ""),
    ] {
        let connection = Connection::open(store.db_path()).unwrap();
        connection
            .execute(
                &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
                [text, id],
            )
            .unwrap();
        let error = store.get_ticket(id).unwrap_err();
        assert!(
            matches!(error, StoreError::Unreadable(ref u) if u.column == column),
            "{error}"
        );
        assert!(store.list_tickets(10, ArchivedFilter::Include).is_err());
        connection
            .execute(
                &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
                [if column == "context_json" { "{}" } else { "[]" }, id],
            )
            .unwrap();
    }
    assert!(store.get_ticket(id).is_ok());
}

#[test]
fn test_health_endpoint_reports_ok() {
    // Store half of the Python test: counters and the newest heartbeat.
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    create(&store, "nyxmon", &payload(None)).unwrap();
    Connection::open(store.db_path())
        .unwrap()
        .execute_batch(
            "INSERT INTO runner_heartbeats VALUES ('old', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'); \
             INSERT INTO runner_heartbeats VALUES ('new', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z');",
        )
        .unwrap();
    assert_eq!(
        Value::Object(store.health().unwrap()),
        json!({
            "status": "ok",
            "service": "opsgate",
            "db": "ok",
            "runner_last_heartbeat": "2026-10-01T00:00:00Z",
            "runner_host": "new",
            "ticket_counters": {"pending_approval": 1},
        })
    );
}

#[test]
fn test_health_reports_no_runner_heartbeat_before_first_poll() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let health = store.health().unwrap();
    assert_eq!(health["runner_last_heartbeat"], Value::Null);
    assert_eq!(health["runner_host"], Value::Null);
    assert_eq!(health["ticket_counters"], json!({}));
}

#[test]
fn session_generation_sync_and_revoke() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("opsgate.sqlite3");
    let store = Store::open(common::settings(&path, &Map::new())).unwrap();
    assert_eq!(
        store.ui_session_generation("opsgate-admin").unwrap(),
        Some(1)
    );
    assert_eq!(store.ui_session_generation("nobody").unwrap(), None);
    assert_eq!(store.revoke_ui_sessions("opsgate-admin").unwrap(), 2);
    let error = store.revoke_ui_sessions("nobody").unwrap_err();
    let error = error.service().unwrap();
    assert_eq!((error.status, error.code), (400, "unknown_approver"));
    // Same password hash: a restart keeps the generation.
    let store = Store::open(common::settings(&path, &Map::new())).unwrap();
    assert_eq!(
        store.ui_session_generation("opsgate-admin").unwrap(),
        Some(2)
    );
    // A new hash revokes every session.
    let mut options = Map::new();
    options.insert("ui_password_bcrypt".into(), "$2b$12$another".into());
    let store = Store::open(common::settings(&path, &options)).unwrap();
    assert_eq!(
        store.ui_session_generation("opsgate-admin").unwrap(),
        Some(3)
    );
    let fingerprint: String = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT password_fingerprint FROM ui_session_state",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        fingerprint,
        opsgate_store::password_fingerprint("$2b$12$another")
    );
    assert_eq!(
        opsgate_store::password_fingerprint("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
