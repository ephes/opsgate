//! The runner's claim at the store level (PLAN.md 4.7.3): order, lazy
//! expiry, stored-JSON validation (`invalid_stored_plan`), the tamper check
//! (`prompt_tampered`), the heartbeat and the disable file. Tests named like
//! a Python test of `tests/test_api.py` port its store half
//! (`rust/TESTMAP.md`).

mod common;

use std::time::Duration;

use common::{
    approve, audit, audit_event_types, claim, create, execute, reviewer_payload, snapshot,
    ticket_payload,
};
use opsgate_core::time::{isoformat_z, utc_now};
use opsgate_store::Store;
use rusqlite::Connection;
use serde_json::{Value, json};

const NYXMON: &str = "nyxmon";

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    (directory, store)
}

fn heartbeats(store: &Store) -> Vec<(String, String, String)> {
    let connection = Connection::open(store.db_path()).unwrap();
    let mut statement = connection
        .prepare("SELECT runner_host, last_heartbeat_at, updated_at FROM runner_heartbeats ORDER BY runner_host")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn column_value(store: &Store, id: &str, column: &str) -> Value {
    let connection = Connection::open(store.db_path()).unwrap();
    connection
        .query_row(
            &format!("SELECT {column} FROM tickets WHERE id = ?"),
            [id],
            |row| {
                Ok(match row.get_ref(0)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Text(text) => {
                        Value::String(String::from_utf8(text.to_vec()).unwrap())
                    }
                    other => panic!("{other:?}"),
                })
            },
        )
        .unwrap()
}

#[test]
fn test_runner_claim_happy_path() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &reviewer_payload("Runner claim", Some("claim-1")),
    );
    approve(&store, &id).unwrap();
    let claimed = store
        .claim_ticket("runner-a", Some("127.0.0.1"), Some("runner/1"))
        .unwrap()
        .unwrap();
    assert_eq!(claimed["id"], id.as_str());
    assert_eq!(claimed["state"], "running");
    assert_eq!(claimed["runner_host"], "runner-a");
    assert!(claimed["started_at"].is_string());
    assert_eq!(claimed["started_at"], claimed["last_heartbeat_at"]);
    assert_eq!(
        audit(&store, &id).last().unwrap(),
        &(
            "runner_claimed".to_owned(),
            Some("approved".to_owned()),
            Some("running".to_owned()),
            json!({"runner_host": "runner-a"}),
        )
    );
    let connection = Connection::open(store.db_path()).unwrap();
    let (actor, ip, agent): (String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT actor, source_ip, user_agent FROM audit_events WHERE event_type = 'runner_claimed'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (actor.as_str(), ip.as_deref(), agent.as_deref()),
        ("runner:runner-a", Some("127.0.0.1"), Some("runner/1"))
    );
    let beats = heartbeats(&store);
    assert_eq!(beats.len(), 1);
    assert_eq!(beats[0].0, "runner-a");
    // Nothing left to claim.
    assert!(claim(&store, "runner-a").is_none());
}

/// A ticket claimed again after it went back to `approved` keeps its first
/// `started_at` (`COALESCE`).
#[test]
fn claim_keeps_an_earlier_started_at() {
    let (_directory, store) = store();
    let id = create(&store, NYXMON, &ticket_payload("Again", None, None));
    approve(&store, &id).unwrap();
    execute(
        &store,
        "UPDATE tickets SET started_at = '2026-01-01T00:00:00Z' WHERE id = ?",
        [&id],
    );
    let claimed = claim(&store, "runner-a").unwrap();
    assert_eq!(claimed["started_at"], "2026-01-01T00:00:00Z");
    assert_ne!(claimed["last_heartbeat_at"], claimed["started_at"]);
}

#[test]
fn claim_takes_the_oldest_approval_first() {
    let (_directory, store) = store();
    let first = create(&store, NYXMON, &ticket_payload("First created", None, None));
    let second = create(
        &store,
        NYXMON,
        &ticket_payload("Second created", None, None),
    );
    approve(&store, &second).unwrap();
    approve(&store, &first).unwrap();
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], second.as_str());
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], first.as_str());
    // Equal approval stamps: creation order decides.
    let third = create(&store, NYXMON, &ticket_payload("Third", None, None));
    let fourth = create(&store, NYXMON, &ticket_payload("Fourth", None, None));
    approve(&store, &fourth).unwrap();
    approve(&store, &third).unwrap();
    execute(
        &store,
        "UPDATE tickets SET approved_at = '2026-01-01T00:00:00Z' WHERE state = 'approved'",
        [],
    );
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], third.as_str());
}

#[test]
fn test_runner_claim_detects_checksum_tamper() {
    let (_directory, store) = store();
    let id = create(
        &store,
        NYXMON,
        &reviewer_payload("Runner tamper", Some("claim-tamper-1")),
    );
    approve(&store, &id).unwrap();
    execute(
        &store,
        "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
        (
            r#"[{"role":"reviewer","agent":"codex","prompt_markdown":"tampered"}]"#,
            &id,
        ),
    );
    assert!(claim(&store, "runner-a").is_none());
    let ticket = store.get_ticket(&id).unwrap();
    assert_eq!(ticket["state"], "failed");
    assert_eq!(ticket["result"], "failure");
    assert_eq!(ticket["result_detail"], "prompt_tampered");
    assert!(ticket["finished_at"].is_string());
    assert_eq!(ticket["runner_host"], Value::Null);
    assert_eq!(
        audit(&store, &id).last().unwrap(),
        &(
            "ticket_failed".to_owned(),
            Some("approved".to_owned()),
            Some("failed".to_owned()),
            json!({"reason": "prompt_tampered"}),
        )
    );
}

/// Any change of a hashed column is tampering; a missing or empty approval
/// checksum is too.
#[test]
fn every_hashed_field_and_the_approval_checksum_are_checked() {
    for (column, value) in [
        ("source", "openclaw"),
        ("task_ref", "other"),
        ("title", "Other"),
        ("summary", "Other"),
        (
            "policy_requirements_json",
            r#"{"require_reviewer_step": false, "x": 1}"#,
        ),
        ("context_json", r#"{"a": 1}"#),
        ("expires_at", "2999-01-01T00:00:00Z"),
        ("approved_payload_checksum", ""),
    ] {
        let (_directory, store) = store();
        let id = create(&store, NYXMON, &ticket_payload("Hashed", Some("t"), None));
        approve(&store, &id).unwrap();
        execute(
            &store,
            &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
            (value, &id),
        );
        assert!(claim(&store, "runner-a").is_none(), "{column}");
        assert_eq!(
            store.get_ticket(&id).unwrap()["result_detail"],
            "prompt_tampered",
            "{column}"
        );
    }
    let (_directory, store) = store();
    let id = create(&store, NYXMON, &ticket_payload("Hashed", None, None));
    approve(&store, &id).unwrap();
    execute(
        &store,
        "UPDATE tickets SET approved_payload_checksum = NULL, max_duration_seconds = 60 WHERE id = ?",
        [&id],
    );
    assert!(claim(&store, "runner-a").is_none());
    assert_eq!(
        store.get_ticket(&id).unwrap()["result_detail"],
        "prompt_tampered"
    );
}

#[test]
fn test_runner_claim_fails_invalid_stored_agent_and_moves_on() {
    let (_directory, store) = store();
    let bad = create(
        &store,
        NYXMON,
        &ticket_payload("Invalid agent", Some("claim-bad-agent-1"), None),
    );
    let good = create(
        &store,
        NYXMON,
        &ticket_payload("Valid", Some("claim-bad-agent-2"), None),
    );
    approve(&store, &bad).unwrap();
    approve(&store, &good).unwrap();
    execute(
        &store,
        "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
        (
            r#"[{"role":"investigator","agent":"shell","prompt_markdown":"Inspect state"}]"#,
            &bad,
        ),
    );
    let claimed = claim(&store, "runner-a").unwrap();
    assert_eq!(claimed["id"], good.as_str());
    assert_eq!(claimed["state"], "running");
    let bad_ticket = store.get_ticket(&bad).unwrap();
    assert_eq!(bad_ticket["state"], "failed");
    assert_eq!(bad_ticket["result"], "failure");
    assert_eq!(bad_ticket["result_detail"], "invalid_stored_plan");
    assert_eq!(
        audit(&store, &bad).last().unwrap().3,
        json!({"reason": "invalid_stored_plan", "error": "invalid_execution_plan"})
    );
}

#[test]
fn test_runner_claim_isolates_corrupt_stored_json() {
    let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    let cases = [
        (
            "execution_plan_json",
            "{broken".to_owned(),
            "invalid_stored_json",
        ),
        (
            "execution_plan_json",
            "[42]".to_owned(),
            "invalid_execution_plan",
        ),
        (
            "policy_requirements_json",
            "{broken".to_owned(),
            "invalid_stored_json",
        ),
        (
            "policy_requirements_json",
            "[]".to_owned(),
            "invalid_policy_requirements",
        ),
        (
            "policy_requirements_json",
            "null".to_owned(),
            "invalid_policy_requirements",
        ),
        (
            "policy_requirements_json",
            r#"{"require_reviewer_step": "false"}"#.to_owned(),
            "invalid_policy_requirements",
        ),
        ("context_json", "{broken".to_owned(), "invalid_stored_json"),
        ("context_json", "[]".to_owned(), "invalid_ticket"),
        ("context_json", "null".to_owned(), "invalid_ticket"),
        // context-recursion-exhaustion
        (
            "context_json",
            format!("{{\"nested\":{}}}", nested(100_000)),
            "invalid_stored_json",
        ),
        (
            "tmux_sessions_json",
            "{broken".to_owned(),
            "invalid_stored_json",
        ),
        (
            "tmux_sessions_json",
            "null".to_owned(),
            "invalid_tmux_sessions",
        ),
        // context-depth-limit, tmux-depth-limit
        (
            "context_json",
            format!("{{\"nested\":{}}}", nested(64)),
            "invalid_stored_json",
        ),
        ("tmux_sessions_json", nested(65), "invalid_stored_json"),
        // D-2: Python decodes `NaN` and would claim; Rust cannot read it.
        (
            "context_json",
            r#"{"x": NaN}"#.to_owned(),
            "invalid_stored_json",
        ),
        // D-2: Python hashes `Infinity`; Rust cannot, and fails the ticket.
        ("context_json", r#"{"x": 1e999}"#.to_owned(), "invalid_json"),
    ];
    for (column, stored_json, error_code) in &cases {
        for with_successor in [true, false] {
            let (_directory, store) = store();
            let bad = create(
                &store,
                NYXMON,
                &ticket_payload("Corrupt", Some("corrupt-oldest"), None),
            );
            let good = with_successor.then(|| {
                create(
                    &store,
                    NYXMON,
                    &ticket_payload("Valid", Some("valid-successor"), None),
                )
            });
            approve(&store, &bad).unwrap();
            if let Some(good) = &good {
                approve(&store, good).unwrap();
            }
            execute(
                &store,
                &format!("UPDATE tickets SET {column} = ?, approved_at = ? WHERE id = ?"),
                (stored_json, "2020-01-01T00:00:00Z", &bad),
            );
            let claimed = claim(&store, "runner-a");
            match &good {
                Some(good) => {
                    let claimed = claimed.expect("the successor is claimed");
                    assert_eq!(claimed["id"], good.as_str(), "{column} {error_code}");
                    assert_eq!(claimed["state"], "running");
                }
                None => assert!(claimed.is_none(), "{column} {error_code}"),
            }
            assert_eq!(column_of(&store, &bad, "state"), "failed");
            assert_eq!(column_of(&store, &bad, "result"), "failure");
            assert_eq!(
                column_of(&store, &bad, "result_detail"),
                "invalid_stored_plan"
            );
            assert!(column_value(&store, &bad, "finished_at").is_string());
            assert_eq!(column_value(&store, &bad, "runner_host"), Value::Null);
            assert_eq!(column_value(&store, &bad, "started_at"), Value::Null);
            let events: Vec<_> = audit(&store, &bad)
                .into_iter()
                .filter(|(event, ..)| event == "ticket_failed" || event == "runner_claimed")
                .collect();
            assert_eq!(
                events,
                vec![(
                    "ticket_failed".to_owned(),
                    Some("approved".to_owned()),
                    Some("failed".to_owned()),
                    json!({"reason": "invalid_stored_plan", "error": error_code}),
                )],
                "{column} {error_code}"
            );
            let actor: String = Connection::open(store.db_path())
                .unwrap()
                .query_row(
                    "SELECT actor FROM audit_events WHERE event_type = 'ticket_failed'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(actor, "runner:runner-a");
            // A later idle poll neither fails nor audits the row again.
            assert!(claim(&store, "runner-a").is_none());
            assert_eq!(
                audit_event_types(&store, &bad)
                    .iter()
                    .filter(|event| *event == "ticket_failed")
                    .count(),
                1
            );
        }
    }
}

fn column_of(store: &Store, id: &str, name: &str) -> String {
    column_value(store, id, name).as_str().unwrap().to_owned()
}

#[test]
fn test_runner_claim_accepts_stored_json_at_depth_limit() {
    let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    for (column, stored_json, field) in [
        (
            "context_json",
            format!("{{\"nested\":{}}}", nested(63)),
            "context",
        ),
        ("tmux_sessions_json", nested(64), "tmux_sessions"),
    ] {
        let (_directory, store) = store();
        let id = create(
            &store,
            NYXMON,
            &ticket_payload("Depth boundary", None, None),
        );
        execute(
            &store,
            &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
            (&stored_json, &id),
        );
        approve(&store, &id).unwrap();
        let claimed = claim(&store, "runner-a").unwrap();
        assert_eq!(claimed["id"], id.as_str());
        assert_eq!(claimed["state"], "running");
        assert_eq!(
            claimed[field],
            serde_json::from_str::<Value>(&stored_json).unwrap()
        );
        assert!(!audit_event_types(&store, &id).contains(&"ticket_failed".to_owned()));
    }
}

#[test]
fn test_claim_rejects_non_text_stored_plan() {
    for field in ["role", "agent", "prompt_markdown"] {
        let (_directory, store) = store();
        let id = create(&store, NYXMON, &ticket_payload("Stored", None, None));
        approve(&store, &id).unwrap();
        let mut step =
            json!({"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"});
        step[field] = Value::Null;
        execute(
            &store,
            "UPDATE tickets SET execution_plan_json = ? WHERE id = ?",
            (json!([step]).to_string(), &id),
        );
        assert!(claim(&store, "test").is_none(), "{field}");
        let ticket = store.get_ticket(&id).unwrap();
        assert_eq!(ticket["state"], "failed");
        assert_eq!(ticket["result_detail"], "invalid_stored_plan");
    }
}

#[test]
fn test_runner_does_not_claim_archived_approved_ticket() {
    let (_directory, store) = store();
    let id = create(
        &store,
        "openclaw",
        &ticket_payload("Archived approved", Some("archive-runner-1"), None),
    );
    approve(&store, &id).unwrap();
    execute(
        &store,
        "UPDATE tickets SET archived_at = ?, archived_by = ? WHERE id = ?",
        ("2026-03-11T10:00:00Z", "opsgate-admin", &id),
    );
    assert!(claim(&store, "runner-a").is_none());
    assert_eq!(store.get_ticket(&id).unwrap()["state"], "approved");
}

#[test]
fn test_idle_runner_claim_poll_records_heartbeat() {
    let (_directory, store) = store();
    create(
        &store,
        NYXMON,
        &reviewer_payload("Still pending", Some("idle-heartbeat-1")),
    );
    assert!(claim(&store, "runner-idle").is_none());
    let first = store.health().unwrap();
    assert_eq!(first["runner_host"], "runner-idle");
    assert!(first["runner_last_heartbeat"].is_string());
    assert_eq!(first["ticket_counters"], json!({"pending_approval": 1}));

    assert!(claim(&store, "runner-idle").is_none());
    let second = store.health().unwrap();
    assert!(
        second["runner_last_heartbeat"].as_str().unwrap()
            >= first["runner_last_heartbeat"].as_str().unwrap()
            // Whole-second stamps sort after fractional ones (4.9); compare
            // the parsed instants instead when one is whole-second.
            || opsgate_core::time::parse_iso_datetime(second["runner_last_heartbeat"].as_str().unwrap())
                .unwrap()
                >= opsgate_core::time::parse_iso_datetime(first["runner_last_heartbeat"].as_str().unwrap())
                    .unwrap()
    );
    let beats = heartbeats(&store);
    assert_eq!(beats.len(), 1);
    assert_eq!(beats[0].0, "runner-idle");
    assert_eq!(beats[0].1, beats[0].2);
    let runner_events: i64 = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE actor = 'runner:runner-idle'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(runner_events, 0);
}

#[test]
fn disable_file_stops_claims_without_a_heartbeat() {
    let (directory, store) = store();
    let id = create(&store, NYXMON, &ticket_payload("Paused", None, None));
    approve(&store, &id).unwrap();
    let disable = directory.path().join("remediation").join(".disabled");
    assert_eq!(
        store.settings().disable_file_path,
        disable.to_str().unwrap()
    );
    std::fs::create_dir_all(disable.parent().unwrap()).unwrap();
    std::fs::write(&disable, "").unwrap();
    let before = snapshot(&store);
    assert!(claim(&store, "runner-a").is_none());
    assert_eq!(snapshot(&store), before);
    // A symlink is followed; a dangling one is no disable file.
    std::fs::remove_file(&disable).unwrap();
    std::os::unix::fs::symlink(directory.path().join("missing"), &disable).unwrap();
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], id.as_str());
}

#[test]
fn disable_file_is_checked_before_the_database_is_opened() {
    let (directory, store) = store();
    // The database cannot be opened: a directory stands at its path.
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", store.db_path().display());
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path).unwrap();
        }
    }
    std::fs::create_dir(store.db_path()).unwrap();
    assert!(store.claim_ticket("runner-a", None, None).is_err());
    let disable = directory.path().join("remediation").join(".disabled");
    std::fs::create_dir_all(disable.parent().unwrap()).unwrap();
    std::fs::write(&disable, "").unwrap();
    // Python returns None without opening the database.
    assert!(
        store
            .claim_ticket("runner-a", None, None)
            .unwrap()
            .is_none()
    );
    assert!(store.db_path().is_dir());
}

#[test]
fn claim_expires_stale_approved_tickets_and_moves_on() {
    let (_directory, store) = store();
    let stale = create(&store, NYXMON, &ticket_payload("Stale", None, None));
    let fresh = create(&store, NYXMON, &ticket_payload("Fresh", None, None));
    approve(&store, &stale).unwrap();
    approve(&store, &fresh).unwrap();
    execute(
        &store,
        "UPDATE tickets SET expires_at = ?, approved_payload_checksum = 'x' WHERE id = ?",
        (isoformat_z(&(utc_now() - Duration::from_secs(60))), &stale),
    );
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], fresh.as_str());
    let expired = store.get_ticket(&stale).unwrap();
    assert_eq!(expired["state"], "expired");
    assert_eq!(expired["result_detail"], "expired_before_execution");
    let events = audit(&store, &stale);
    let (event, _, _, _) = events.last().unwrap();
    assert_eq!(event, "ticket_expired");
    let actor: String = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT actor FROM audit_events WHERE event_type = 'ticket_expired'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(actor, "runner:runner-a");
}

/// Python's unhandled exceptions inside the claim (an unparsable stored
/// expiry or duration) fail the whole claim and roll it back, including
/// tickets failed earlier in the same round and the heartbeat.
#[test]
fn unhandled_errors_roll_the_claim_back() {
    for (column, value) in [
        ("expires_at", "not a date"),
        ("max_duration_seconds", "n/a"),
    ] {
        let (_directory, store) = store();
        let tampered = create(&store, NYXMON, &ticket_payload("Tampered", None, None));
        let broken = create(&store, NYXMON, &ticket_payload("Broken", None, None));
        approve(&store, &tampered).unwrap();
        approve(&store, &broken).unwrap();
        execute(
            &store,
            "UPDATE tickets SET title = 'changed' WHERE id = ?",
            [&tampered],
        );
        execute(
            &store,
            &format!("UPDATE tickets SET {column} = ? WHERE id = ?"),
            (value, &broken),
        );
        let before = snapshot(&store);
        let error = store.claim_ticket("runner-a", None, None).unwrap_err();
        assert!(error.service().is_none(), "{column}: {error}");
        assert_eq!(snapshot(&store), before, "{column}");
    }
}

#[test]
fn test_ticket_unicode_text_persists_and_passes_checksum_validation() {
    let (_directory, store) = store();
    let text = "Grüße aus Köln 🛠️";
    let plan = json!([{"role": "investigator", "agent": "codex", "prompt_markdown": text}]);
    let mut payload = ticket_payload(text, Some(text), Some(plan.clone()));
    payload.insert("summary".into(), text.into());
    let id = create(&store, NYXMON, &payload);
    let ticket = store.get_ticket(&id).unwrap();
    for field in ["title", "summary", "task_ref"] {
        assert_eq!(ticket[field], text);
    }
    assert_eq!(ticket["execution_plan"], plan);
    let approved = approve(&store, &id).unwrap();
    assert_eq!(
        approved["approved_payload_checksum"],
        ticket["payload_checksum"]
    );
    let claimed = claim(&store, "test").unwrap();
    assert_eq!(claimed["id"], id.as_str());
    assert_eq!(claimed["state"], "running");
}

/// Production contexts carry floats (PLAN.md section 1): the checksum
/// recomputed at approval and claim is the creation checksum.
#[test]
fn float_contexts_pass_the_tamper_check() {
    let (_directory, store) = store();
    let mut payload = ticket_payload("Floats", Some("disk-full/macmini"), None);
    payload.insert(
        "context".into(),
        serde_json::from_str(
            r#"{"result": {"value": 0.95, "threshold": 3.0, "free_gb": 14.0,
                "big": 1e16, "small": 1e-05, "neg_zero": -0.0, "exp": 1E5,
                "int": 12345678901234567890, "text": "Grüße \"q\" \\"}}"#,
        )
        .unwrap(),
    );
    let id = create(&store, NYXMON, &payload);
    let created = store.get_ticket(&id).unwrap();
    let approved = approve(&store, &id).unwrap();
    assert_eq!(
        approved["approved_payload_checksum"],
        created["payload_checksum"]
    );
    assert_eq!(claim(&store, "runner-a").unwrap()["id"], id.as_str());
}
