//! Real audit INSERT rejection must roll back the entire public operation.

mod common;

use common::{APPROVER, approve, audit, claim, create, execute, snapshot, status, ticket_payload};
use opsgate_store::{Store, StoreError};
use rusqlite::Connection;
use serde_json::json;

fn reject_audit(store: &Store, event: &str) {
    // Event names come only from the fixed cases below. ABORT rejects this
    // statement, leaving the caller responsible for rolling back its mutation.
    Connection::open(store.db_path())
        .unwrap()
        .execute_batch(&format!(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events
             WHEN NEW.event_type = '{event}'
             BEGIN SELECT RAISE(ABORT, 'injected audit rejection'); END;"
        ))
        .unwrap();
}

fn injected<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    match result.expect_err("audit rejection must fail the operation") {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(_, Some(message))) => {
            assert_eq!(message, "injected audit rejection");
        }
        other => panic!("did not reach the rejecting audit trigger: {other}"),
    }
}

fn allow_audit(store: &Store) {
    execute(store, "DROP TRIGGER reject_audit", []);
}

#[test]
fn create_audit_failure_rolls_back_new_ticket() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let payload = ticket_payload("Synthetic create", Some("create-audit"), None);
    let submitter = common::submitter(&store, "nyxmon");
    let before = snapshot(&store);
    reject_audit(&store, "ticket_created");
    injected(store.create_ticket(&payload, &submitter, None, None));
    assert_eq!(snapshot(&store), before);
    allow_audit(&store);
    let id = create(&store, "nyxmon", &payload);
    assert_eq!(audit(&store, &id).len(), 1);
}

#[test]
fn create_audit_failure_rolls_back_expiry_and_replacement() {
    for event in ["ticket_expired", "ticket_created"] {
        let directory = tempfile::tempdir().unwrap();
        let store = common::store(directory.path());
        let payload = ticket_payload("Synthetic recurrence", Some("replacement-audit"), None);
        let predecessor = create(&store, "nyxmon", &payload);
        execute(
            &store,
            "UPDATE tickets SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            [&predecessor],
        );
        let before = snapshot(&store);
        reject_audit(&store, event);
        injected(store.create_ticket(&payload, &common::submitter(&store, "nyxmon"), None, None));
        assert_eq!(snapshot(&store), before, "{event}");
        allow_audit(&store);
        let replacement = create(&store, "nyxmon", &payload);
        assert_ne!(predecessor, replacement);
        assert_eq!(store.get_ticket(&predecessor).unwrap()["state"], "expired");
        assert_eq!(audit(&store, &predecessor).len(), 2);
        assert_eq!(audit(&store, &replacement).len(), 1);
    }
}

#[test]
fn transition_audit_failure_rolls_back_all_ticket_fields() {
    for event in ["ticket_approved", "ticket_canceled", "ticket_archived"] {
        let directory = tempfile::tempdir().unwrap();
        let store = common::store(directory.path());
        let id = create(
            &store,
            "nyxmon",
            &ticket_payload("Synthetic transition", None, None),
        );
        let operation = || match event {
            "ticket_approved" => approve(&store, &id),
            "ticket_canceled" => store.cancel_ticket(&id, APPROVER, "synthetic", None, None),
            "ticket_archived" => store.archive_ticket(&id, APPROVER, None, None),
            _ => unreachable!(),
        };
        let before = snapshot(&store);
        reject_audit(&store, event);
        injected(operation());
        assert_eq!(snapshot(&store), before, "{event}");
        allow_audit(&store);
        operation().unwrap();
        let events = audit(&store, &id);
        assert_eq!(events.len(), 2);
        assert_eq!(events.last().unwrap().0, event);
    }
}

#[test]
fn runner_completion_audit_failure_rolls_back_ticket_and_heartbeat() {
    for (state, result) in [
        ("succeeded", "success"),
        ("failed", "failure"),
        ("failed", "timeout"),
        ("canceled", "canceled"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = common::store(directory.path());
        let id = create(
            &store,
            "nyxmon",
            &ticket_payload("Synthetic completion", None, None),
        );
        approve(&store, &id).unwrap();
        claim(&store, "runner-a").unwrap();
        let operation = || {
            status(
                &store,
                &id,
                "runner-a",
                json!({
                    "event": "step_finished", "state": state, "result": result,
                    "result_detail": "synthetic completion", "tmux_sessions": [{"status": "done"}]
                }),
            )
        };
        let before = snapshot(&store);
        reject_audit(&store, "runner_step_finished");
        injected(operation());
        assert_eq!(snapshot(&store), before, "{state}/{result}");
        allow_audit(&store);
        let ticket = operation().unwrap();
        assert_eq!(ticket["state"], state);
        assert_eq!(ticket["result"], result);
        assert!(ticket["finished_at"].is_string());
        let events = audit(&store, &id);
        assert_eq!(events.len(), 4);
        assert_eq!(events.last().unwrap().0, "runner_step_finished");
    }
}
