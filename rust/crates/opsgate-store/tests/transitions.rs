//! The approver's transitions at the store level (PLAN.md 4.7.2): approve,
//! reject, cancel, archive, unarchive. Tests named like a Python test of
//! `tests/test_api.py` port its store half (`rust/TESTMAP.md`); the HTTP
//! half (auth, CSRF, status codes on the wire) lands with the web slices.

mod common;

use std::time::Duration;

use common::{
    APPROVER, approve, audit, audit_event_types, claim, create, error, execute, reviewer_payload,
    snapshot, status, ticket_payload,
};
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_core::validate::{TicketPayload, parse_execution_plan, policy_value};
use opsgate_store::{Store, StoreError};
use serde_json::{Value, json};

const NYXMON: &str = "nyxmon";

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    (directory, store)
}

fn archive(store: &Store, id: &str) -> Result<serde_json::Map<String, Value>, StoreError> {
    store.archive_ticket(id, APPROVER, Some("127.0.0.1"), Some("test"))
}

fn unarchive(store: &Store, id: &str) -> Result<serde_json::Map<String, Value>, StoreError> {
    store.unarchive_ticket(id, APPROVER, Some("127.0.0.1"), Some("test"))
}

fn reject(
    store: &Store,
    id: &str,
    reason: &str,
) -> Result<serde_json::Map<String, Value>, StoreError> {
    store.reject_ticket(id, APPROVER, reason, None, None)
}

fn cancel(
    store: &Store,
    id: &str,
    reason: &str,
) -> Result<serde_json::Map<String, Value>, StoreError> {
    store.cancel_ticket(id, APPROVER, reason, None, None)
}

/// `set_ticket_terminal_state` of the Python tests.
fn set_terminal(store: &Store, id: &str, state: &str, result: &str) {
    execute(
        store,
        "UPDATE tickets SET state = ?, finished_at = ?, result = ?, result_detail = ? WHERE id = ?",
        (
            state,
            isoformat_z(&utc_now()),
            result,
            format!("{state}_for_test"),
            id,
        ),
    );
}

#[test]
fn test_api_archive_and_unarchive_preserve_ticket_access_and_audit() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Archive via API", Some("archive-api-1"), None),
    );
    assert_eq!(reject(&store, &id, "done").unwrap()["state"], "rejected");

    let archived = archive(&store, &id).unwrap();
    assert_eq!(archived["state"], "rejected");
    assert_eq!(archived["is_archived"], true);
    assert_eq!(archived["archived_by"], APPROVER);
    assert!(archived["archived_at"].is_string());
    // Archived tickets stay readable.
    assert_eq!(store.get_ticket(&id).unwrap()["is_archived"], true);

    let restored = unarchive(&store, &id).unwrap();
    assert_eq!(restored["state"], "rejected");
    assert_eq!(restored["is_archived"], false);
    assert_eq!(restored["archived_at"], Value::Null);
    assert_eq!(restored["archived_by"], Value::Null);

    let events = audit(&store, &id);
    let [.., archived_event, unarchived_event] = events.as_slice() else {
        panic!("{events:?}");
    };
    assert_eq!(
        archived_event,
        &(
            "ticket_archived".to_owned(),
            Some("rejected".to_owned()),
            Some("rejected".to_owned()),
            json!({"archived_at": archived["archived_at"]}),
        )
    );
    assert_eq!(
        unarchived_event,
        &(
            "ticket_unarchived".to_owned(),
            Some("rejected".to_owned()),
            Some("rejected".to_owned()),
            json!({
                "previous_archived_at": archived["archived_at"],
                "previous_archived_by": APPROVER,
            }),
        )
    );
}

#[test]
fn test_archive_rejects_non_archivable_active_states() {
    for state in ["approved", "running"] {
        let (_directory, store) = store();
        let id = create(
            &store,
            NYXMON,
            &ticket_payload(
                "Archive blocked",
                Some(&format!("archive-api-{state}")),
                None,
            ),
        );
        approve(&store, &id).unwrap();
        if state == "running" {
            assert_eq!(claim(&store, "runner-a").unwrap()["id"], id.as_str());
            status(
                &store,
                &id,
                "runner-a",
                json!({"runner_host": "runner-a", "event": "heartbeat", "state": "running"}),
            )
            .unwrap();
        }
        let result = archive(&store, &id);
        let message = result
            .as_ref()
            .unwrap_err()
            .service()
            .unwrap()
            .message
            .clone();
        assert_eq!(error(result), (409, "invalid_state"), "{state}");
        assert_eq!(
            message,
            "Only pending-approval or terminal tickets can be archived"
        );
    }
}

#[test]
fn test_archive_allowed_for_all_terminal_states() {
    for (state, result) in [
        ("succeeded", "success"),
        ("failed", "failure"),
        ("rejected", "failure"),
        ("canceled", "canceled"),
        ("expired", "failure"),
    ] {
        let (_directory, store) = store();
        let id = create(
            &store,
            NYXMON,
            &ticket_payload(
                &format!("Archive {state}"),
                Some(&format!("archive-terminal-{state}")),
                None,
            ),
        );
        set_terminal(&store, &id, state, result);
        let archived = archive(&store, &id).unwrap();
        assert_eq!(archived["state"], state);
        assert_eq!(archived["result"], result);
        assert_eq!(archived["is_terminal"], true);
        assert_eq!(archived["is_archived"], true);
        assert_eq!(archived["is_archivable"], false);
    }
}

#[test]
fn test_archive_allowed_for_pending_approval_state() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Archive pending", Some("archive-pending-approval-1"), None),
    );
    let archived = archive(&store, &id).unwrap();
    assert_eq!(archived["state"], "pending_approval");
    assert_eq!(archived["is_terminal"], false);
    assert_eq!(archived["is_archived"], true);
}

#[test]
fn test_archive_rejects_double_archive() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Archive twice", Some("archive-api-3"), None),
    );
    reject(&store, &id, "done").unwrap();
    archive(&store, &id).unwrap();
    let before = snapshot(&store);
    assert_eq!(error(archive(&store, &id)), (409, "already_archived"));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn test_unarchive_rejects_non_archived_ticket() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Restore", Some("archive-api-4"), None),
    );
    reject(&store, &id, "done").unwrap();
    assert_eq!(error(unarchive(&store, &id)), (409, "not_archived"));
}

#[test]
fn test_unarchive_rejects_when_replacement_open_ticket_exists() {
    let (_directory, store) = store();
    let payload = ticket_payload("Original", Some("archive-api-restore-conflict"), None);
    let original = create(&store, NYXMON, &payload);
    archive(&store, &original).unwrap();
    create(&store, NYXMON, &payload);
    let before = snapshot(&store);
    assert_eq!(
        error(unarchive(&store, &original)),
        (409, "duplicate_open_ticket")
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn test_dedupe_ignores_archived_pending_ticket() {
    let (_directory, store) = store();
    let payload = ticket_payload("Investigate alert", Some("same-ref-archived"), None);
    let first = create(&store, "openclaw", &payload);
    assert_eq!(archive(&store, &first).unwrap()["is_archived"], true);
    create(&store, "openclaw", &payload);
}

#[test]
fn test_archived_pending_ticket_blocks_lifecycle_actions() {
    for (action, message) in [
        (
            "approve",
            "Archived ticket must be restored before approval",
        ),
        (
            "reject",
            "Archived ticket must be restored before rejection",
        ),
        ("cancel", "Archived ticket must be restored before cancel"),
    ] {
        let (_directory, store) = store();
        let id = create(
            &store,
            "openclaw",
            &ticket_payload(
                "Archived pending",
                Some(&format!("archive-ui-pending-{action}")),
                None,
            ),
        );
        archive(&store, &id).unwrap();
        let result = match action {
            "approve" => approve(&store, &id),
            "reject" => reject(&store, &id, "nope"),
            _ => cancel(&store, &id, "nope"),
        };
        assert_eq!(
            result.as_ref().unwrap_err().service().unwrap().message,
            message
        );
        assert_eq!(error(result), (409, "archived_ticket"), "{action}");
    }
}

#[test]
fn test_approval_revalidates_stored_agent_allowlist() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Stored bad agent", Some("approve-bad-agent-1"), None),
    );
    execute(
        &store,
        "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
        (
            r#"[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]"#,
            &id,
        ),
    );
    let result = approve(&store, &id);
    assert_eq!(
        result.as_ref().unwrap_err().service().unwrap().message,
        "agent must be one of: codex, claude"
    );
    assert_eq!(error(result), (400, "invalid_execution_plan"));
    assert_eq!(store.get_ticket(&id).unwrap()["state"], "pending_approval");
}

#[test]
fn test_approval_revalidates_stored_reviewer_requirement() {
    let (_directory, store) = store();
    let id = create(
        &store,
        "operator",
        &reviewer_payload(
            "Stored missing reviewer",
            Some("approve-missing-reviewer-1"),
        ),
    );
    execute(
        &store,
        "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
        (
            r#"[{"role":"investigator","agent":"codex","prompt_markdown":"Inspect state"}]"#,
            &id,
        ),
    );
    assert_eq!(error(approve(&store, &id)), (400, "missing_reviewer_step"));
}

/// Approval enforces the stored policy with Python's truthiness, without
/// parsing it first; a policy that is not an object, undecodable columns and
/// durations `int()` rejects are Python's unhandled exceptions (500).
#[test]
fn approval_reads_stored_values_as_python_does() {
    let reviewerless = r#"[{"role":"investigator","agent":"codex","prompt_markdown":"x"}]"#;
    for (column, value, expected) in [
        (
            "policy_requirements_json",
            r#"{"require_reviewer_step": "no"}"#,
            Some((400, "missing_reviewer_step")),
        ),
        (
            "policy_requirements_json",
            r#"{"require_reviewer_step": 0}"#,
            None,
        ),
        ("policy_requirements_json", r#"{"other": true}"#, None),
        ("policy_requirements_json", "[]", Some((500, ""))),
        ("policy_requirements_json", "null", Some((500, ""))),
        ("policy_requirements_json", "{broken", Some((500, ""))),
        ("execution_plan_json", "{broken", Some((500, ""))),
        (
            "execution_plan_json",
            "[]",
            Some((400, "invalid_execution_plan")),
        ),
        ("context_json", "[1, 2]", None),
        ("context_json", "{broken", Some((500, ""))),
        // D-2: Python stores and hashes `NaN`; Rust cannot read it.
        ("context_json", r#"{"x": NaN}"#, Some((500, ""))),
        // D-2: Python hashes `Infinity`; Rust refuses to write it.
        (
            "context_json",
            r#"{"x": 1e999}"#,
            Some((400, "invalid_json")),
        ),
    ] {
        let (_directory, store) = store();
        let id = create(&store, NYXMON, &ticket_payload("Stored", None, None));
        execute(
            &store,
            "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
            (reviewerless, &id),
        );
        execute(
            &store,
            &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
            (value, &id),
        );
        let before = snapshot(&store);
        let result = approve(&store, &id);
        match expected {
            None => assert_eq!(result.unwrap()["state"], "approved", "{column} {value}"),
            Some((500, _)) => {
                let error = result.unwrap_err();
                assert!(error.service().is_none(), "{column} {value}: {error}");
                assert_eq!(snapshot(&store), before, "{column} {value}");
            }
            Some(expected) => {
                assert_eq!(error(result), expected, "{column} {value}");
                assert_eq!(snapshot(&store), before, "{column} {value}");
            }
        }
    }
}

#[test]
fn approval_checksum_uses_int_of_the_stored_duration() {
    for (stored, effective) in [
        (rusqlite::types::Value::Integer(900), Some(900)),
        (rusqlite::types::Value::Real(900.9), Some(900)),
        (rusqlite::types::Value::Real(-0.5), Some(0)),
        (
            rusqlite::types::Value::Text(" 1_200\n".to_owned()),
            Some(1200),
        ),
        (rusqlite::types::Value::Text("n/a".to_owned()), None),
        // INTEGER affinity stores well-formed numeric text as a number.
        (rusqlite::types::Value::Text("1.5".to_owned()), Some(1)),
        (rusqlite::types::Value::Text("1e3".to_owned()), Some(1000)),
        // REAL 1e20: Python's int() is outside i64 (D-2).
        (
            rusqlite::types::Value::Text("99999999999999999999".to_owned()),
            None,
        ),
        (rusqlite::types::Value::Text("12 hours".to_owned()), None),
        // The column is NOT NULL: no NULL case.
    ] {
        let (_directory, store) = store();
        let mut payload = ticket_payload("Duration", None, None);
        payload.insert("max_duration_seconds".into(), json!(900));
        let id = create(&store, NYXMON, &payload);
        execute(
            &store,
            "UPDATE tickets SET max_duration_seconds = ? WHERE id = ?",
            (&stored, &id),
        );
        let result = approve(&store, &id);
        match effective {
            Some(seconds) => {
                let approved = result.unwrap();
                // The ticket keeps the stored value; the checksum hashes
                // `int()` of it.
                let plan = parse_execution_plan(&payload["execution_plan"]).unwrap();
                let expected = TicketPayload {
                    source: NYXMON,
                    task_ref: None,
                    title: "Duration",
                    summary: "Duration summary",
                    execution_plan: &plan,
                    policy_requirements: &policy_value(false),
                    context: &json!({}),
                    expires_at: None,
                    max_duration_seconds: seconds,
                }
                .checksum()
                .unwrap();
                assert_eq!(
                    approved["approved_payload_checksum"], expected,
                    "{stored:?}"
                );
            }
            None => assert!(result.unwrap_err().service().is_none(), "{stored:?}"),
        }
    }
}

#[test]
fn test_lazy_expiry_blocks_approval() {
    let (_directory, store) = store();
    let mut payload = reviewer_payload("Old ticket", Some("old-1"));
    payload.insert(
        "expires_at".into(),
        isoformat_z(&(utc_now() - Duration::from_secs(3600))).into(),
    );
    let id = create(&store, NYXMON, &payload);
    assert_eq!(error(approve(&store, &id)), (409, "ticket_expired"));
    // The expiry is committed although the approval fails.
    let ticket = store.get_ticket(&id).unwrap();
    assert_eq!(ticket["state"], "expired");
    assert_eq!(ticket["result_detail"], "expired_before_execution");
    let events = audit(&store, &id);
    let (event, previous, new, _) = events.last().unwrap();
    assert_eq!(
        (event.as_str(), previous.as_deref(), new.as_deref()),
        ("ticket_expired", Some("pending_approval"), Some("expired"))
    );
    // A stored expiry that does not parse is Python's ValueError: a 500,
    // nothing written.
    let other = create(&store, NYXMON, &ticket_payload("Garbage", None, None));
    execute(
        &store,
        "UPDATE tickets SET expires_at = 'not a date' WHERE id = ?",
        [&other],
    );
    let before = snapshot(&store);
    assert!(approve(&store, &other).unwrap_err().service().is_none());
    assert_eq!(snapshot(&store), before);
}

#[test]
fn test_dedupe_expires_stale_approved_ticket_before_replacement_submit() {
    let (_directory, store) = store();
    let future = isoformat_z(&(utc_now() + Duration::from_secs(3600)));
    let past = isoformat_z(&(utc_now() - Duration::from_secs(3600)));
    let mut payload = reviewer_payload("Investigate alert", Some("same-ref-expired-approved"));
    payload.insert("expires_at".into(), future.clone().into());
    let original = create(&store, NYXMON, &payload);
    assert_eq!(approve(&store, &original).unwrap()["state"], "approved");
    execute(
        &store,
        "UPDATE tickets SET expires_at = ? WHERE id = ?",
        (&past, &original),
    );
    payload.insert("title".into(), "Investigate alert recurrence".into());
    let replacement = create(&store, NYXMON, &payload);
    assert_ne!(replacement, original);
    assert_eq!(
        store.get_ticket(&replacement).unwrap()["state"],
        "pending_approval"
    );
    assert_eq!(store.get_ticket(&original).unwrap()["state"], "expired");
    assert_eq!(
        audit_event_types(&store, &original).last().unwrap(),
        "ticket_expired"
    );
}

#[test]
fn test_approve_and_reject_flow() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &reviewer_payload("Approve me", Some("approve-1")),
    );
    let approved = store
        .approve_ticket(&id, APPROVER, Some("100.64.0.7"), Some("browser"))
        .unwrap();
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["approved_by"], APPROVER);
    assert!(approved["approved_at"].is_string());
    let checksum = approved["approved_payload_checksum"].as_str().unwrap();
    assert_eq!(checksum.len(), 64);
    // Nothing was changed since creation: the approved checksum is the
    // creation checksum.
    assert_eq!(
        approved["approved_payload_checksum"],
        approved["payload_checksum"]
    );
    let events = audit(&store, &id);
    assert_eq!(
        events.last().unwrap(),
        &(
            "ticket_approved".to_owned(),
            Some("pending_approval".to_owned()),
            Some("approved".to_owned()),
            json!({"approved_payload_checksum": checksum}),
        )
    );
    let connection = rusqlite::Connection::open(store.db_path()).unwrap();
    let (actor, ip, agent): (String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT actor, source_ip, user_agent FROM audit_events \
             WHERE event_type = 'ticket_approved'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (actor.as_str(), ip.as_deref(), agent.as_deref()),
        (
            "approver:opsgate-admin",
            Some("100.64.0.7"),
            Some("browser")
        )
    );
    // A second approval finds the ticket approved.
    assert_eq!(error(approve(&store, &id)), (409, "invalid_state"));
    assert_eq!(error(reject(&store, &id, "")), (409, "invalid_state"));

    let second = create(
        &store,
        NYXMON,
        &ticket_payload("Reject me", Some("reject-1"), None),
    );
    let rejected = reject(&store, &second, "not-needed").unwrap();
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(rejected["result"], "failure");
    assert_eq!(rejected["result_detail"], "not-needed");
    assert!(rejected["finished_at"].is_string());
    assert_eq!(
        audit(&store, &second).last().unwrap().3,
        json!({"reason": "not-needed"})
    );
    // An empty reason stores the default and audits the empty reason.
    let third = create(&store, NYXMON, &ticket_payload("Reject", None, None));
    assert_eq!(
        reject(&store, &third, "").unwrap()["result_detail"],
        "rejected_by_approver"
    );
    assert_eq!(
        audit(&store, &third).last().unwrap().3,
        json!({"reason": ""})
    );
}

#[test]
fn test_cancel_flow() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &ticket_payload("Cancel me", Some("cancel-1"), None),
    );
    let canceled = cancel(&store, &id, "operator canceled").unwrap();
    assert_eq!(canceled["state"], "canceled");
    assert_eq!(canceled["result"], "canceled");
    assert_eq!(canceled["result_detail"], "operator canceled");
    assert_eq!(error(cancel(&store, &id, "")), (409, "invalid_state"));

    // From approved and running; the audit names the replaced state.
    for running in [false, true] {
        let id = create(&store, NYXMON, &ticket_payload("Cancel later", None, None));
        approve(&store, &id).unwrap();
        if running {
            claim(&store, "runner-a").unwrap();
        }
        let canceled = cancel(&store, &id, "").unwrap();
        assert_eq!(canceled["result_detail"], "canceled_by_approver");
        let previous = if running { "running" } else { "approved" };
        assert_eq!(
            audit(&store, &id).last().unwrap(),
            &(
                "ticket_canceled".to_owned(),
                Some(previous.to_owned()),
                Some("canceled".to_owned()),
                json!({"reason": ""}),
            )
        );
    }
}

#[test]
fn unknown_tickets_are_not_found() {
    let (_directory, store) = store();
    let id = "00000000-0000-4000-8000-000000000000";
    assert_eq!(error(approve(&store, id)), (404, "ticket_not_found"));
    assert_eq!(error(reject(&store, id, "")), (404, "ticket_not_found"));
    assert_eq!(error(cancel(&store, id, "")), (404, "ticket_not_found"));
    assert_eq!(error(archive(&store, id)), (404, "ticket_not_found"));
    assert_eq!(error(unarchive(&store, id)), (404, "ticket_not_found"));
    assert_eq!(
        error(status(&store, id, "runner-a", json!({}))),
        (404, "ticket_not_found")
    );
}

/// An empty `archived_at` (rows written by older code) is not archived for
/// the checks, but the compare-and-set's `archived_at IS NULL` misses it, as
/// in Python: `state_changed`.
#[test]
fn empty_archived_at_fails_the_compare_and_set() {
    let (_directory, store) = store();
    let id = create(&store, NYXMON, &ticket_payload("Legacy", None, None));
    execute(
        &store,
        "UPDATE tickets SET archived_at = '' WHERE id = ?",
        [&id],
    );
    assert_eq!(error(approve(&store, &id)), (409, "state_changed"));
    assert_eq!(error(archive(&store, &id)), (409, "state_changed"));
    assert_eq!(error(unarchive(&store, &id)), (409, "not_archived"));
}
