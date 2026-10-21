//! The runner's status update at the store level (PLAN.md 4.7.4): check
//! order, state/result rules, the explicit `null`/`false`/`0` values,
//! `tmux_sessions`, heartbeat and audit. Tests named like a Python test of
//! `tests/test_api.py` port its store half (`rust/TESTMAP.md`).

mod common;

use common::{
    approve, audit, claim, create, error, execute, reviewer_payload, snapshot, status,
    ticket_payload,
};
use opsgate_store::Store;
use rusqlite::Connection;
use serde_json::{Value, json};

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    (directory, store)
}

/// A ticket claimed by `runner-a`.
fn running(store: &Store, task_ref: &str) -> String {
    let id = create(
        store,
        "nyxmon",
        &reviewer_payload("Runner status", Some(task_ref)),
    );
    approve(store, &id).unwrap();
    assert_eq!(claim(store, "runner-a").unwrap()["id"], id.as_str());
    id
}

#[test]
fn test_runner_status_rejects_terminal_state_regression() {
    let (_directory, store) = store();
    let id = create(
        &store,
        "nyxmon",
        &reviewer_payload("Runner status", Some("status-1")),
    );
    approve(&store, &id).unwrap();
    assert_eq!(
        error(status(
            &store,
            &id,
            "runner-a",
            json!({"runner_host": "runner-a"})
        )),
        (409, "invalid_state")
    );
    assert_eq!(claim(&store, "runner-a").unwrap()["state"], "running");
    let succeeded = status(&store, &id, "runner-a", json!({"state": "succeeded"})).unwrap();
    assert_eq!(succeeded["state"], "succeeded");
    assert_eq!(succeeded["result"], "success");
    assert!(succeeded["finished_at"].is_string());
    assert_eq!(
        error(status(&store, &id, "runner-a", json!({"state": "running"}))),
        (409, "invalid_state")
    );
    assert_eq!(
        error(status(&store, &id, "runner-a", json!({}))),
        (409, "invalid_state")
    );
}

#[test]
fn test_runner_status_accepts_timeout_result_and_tmux_sessions() {
    let (_directory, store) = store();
    let id = running(&store, "status-timeout-1");
    let tmux_sessions = json!([{
        "step_index": 0,
        "role": "reviewer",
        "agent": "codex",
        "session_name": "job-1",
        "status": "timeout",
        "attach_command": "sudo -u ops env TMUX_TMPDIR=/Users/ops/remediation/tmux tmux -L remediation attach -t job-1",
    }]);
    let failed = status(
        &store,
        &id,
        "runner-a",
        json!({
            "runner_host": "runner-a",
            "event": "timeout",
            "state": "failed",
            "result": "timeout",
            "result_detail": "max_duration_seconds_exceeded",
            "tmux_sessions": tmux_sessions,
        }),
    )
    .unwrap();
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["result"], "timeout");
    assert_eq!(failed["result_detail"], "max_duration_seconds_exceeded");
    assert_eq!(failed["tmux_sessions"], tmux_sessions);
    // Stored as `json.dumps(sort_keys=True)`.
    let stored: String = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT tmux_sessions_json FROM tickets WHERE id = ?",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        stored.starts_with(r#"[{"agent": "codex", "attach_command": "sudo"#),
        "{stored}"
    );
    assert_eq!(
        audit(&store, &id).last().unwrap(),
        &(
            "runner_timeout".to_owned(),
            Some("running".to_owned()),
            Some("failed".to_owned()),
            json!({"event": "timeout", "result_detail": "max_duration_seconds_exceeded"}),
        )
    );
}

#[test]
fn test_runner_status_rejects_invalid_tmux_sessions_payload() {
    let (_directory, store) = store();
    let id = running(&store, "status-invalid-tmux-1");
    let before = snapshot(&store);
    for value in [json!({"bad": "value"}), json!("x"), json!(0), json!(false)] {
        assert_eq!(
            error(status(
                &store,
                &id,
                "runner-a",
                json!({"runner_host": "runner-a", "tmux_sessions": value})
            )),
            (400, "invalid_tmux_sessions"),
            "{value}"
        );
    }
    assert_eq!(snapshot(&store), before);
}

#[test]
fn test_runner_status_rejects_runner_host_mismatch() {
    let (_directory, store) = store();
    let id = running(&store, "status-host-mismatch-1");
    assert_eq!(
        error(status(
            &store,
            &id,
            "runner-b",
            json!({"event": "heartbeat"})
        )),
        (409, "runner_host_mismatch")
    );
    // The assigned host is compared stripped; no assigned host accepts any.
    execute(
        &store,
        "UPDATE tickets SET runner_host = ' runner-b ' WHERE id = ?",
        [&id],
    );
    status(&store, &id, "runner-b", json!({})).unwrap();
    execute(
        &store,
        "UPDATE tickets SET runner_host = NULL WHERE id = ?",
        [&id],
    );
    assert_eq!(
        status(&store, &id, "runner-c", json!({})).unwrap()["runner_host"],
        "runner-c"
    );
}

#[test]
fn test_runner_status_rejects_invalid_event_type() {
    let (_directory, store) = store();
    let id = running(&store, "status-invalid-event-1");
    let before = snapshot(&store);
    for event in [
        json!("ticket_approved"),
        json!(null),
        json!(false),
        json!(0),
        json!(["heartbeat"]),
        json!({"event": "heartbeat"}),
    ] {
        assert_eq!(
            error(status(&store, &id, "runner-a", json!({"event": event}))),
            (400, "invalid_runner_event"),
            "{event}"
        );
    }
    // Checked before the ticket is read.
    assert_eq!(
        error(status(
            &store,
            "missing",
            "runner-a",
            json!({"event": "nope"})
        )),
        (400, "invalid_runner_event")
    );
    assert_eq!(snapshot(&store), before);
    // Case and whitespace are normalised; blank is `heartbeat`.
    for (event, expected) in [
        (" Step_Started ", "step_started"),
        ("  ", "heartbeat"),
        ("", "heartbeat"),
    ] {
        status(&store, &id, "runner-a", json!({"event": event})).unwrap();
        assert_eq!(
            audit(&store, &id).last().unwrap().0,
            format!("runner_{expected}")
        );
    }
}

#[test]
fn test_runner_status_accepts_step_failed_event() {
    let (_directory, store) = store();
    let id = running(&store, "status-step-failed-1");
    let failed = status(
        &store,
        &id,
        "runner-a",
        json!({
            "runner_host": "runner-a",
            "event": "step_failed",
            "state": "failed",
            "result": "failure",
            "result_detail": "step_1_exit_code_7",
        }),
    )
    .unwrap();
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["result"], "failure");
    assert_eq!(failed["result_detail"], "step_1_exit_code_7");
}

#[test]
fn test_runner_state_result_matrix() {
    let states = [
        None,
        Some("running"),
        Some("succeeded"),
        Some("failed"),
        Some("canceled"),
    ];
    let results = [
        None,
        Some("success"),
        Some("failure"),
        Some("timeout"),
        Some("canceled"),
    ];
    for state in states {
        for result in results {
            let (_directory, store) = store();
            let id = create(&store, "nyxmon", &ticket_payload("Matrix", None, None));
            approve(&store, &id).unwrap();
            claim(&store, "runner-a").unwrap();
            let before = snapshot(&store);
            let mut payload = json!({"runner_host": "runner-a"});
            if let Some(state) = state {
                payload["state"] = state.into();
            }
            if let Some(result) = result {
                payload["result"] = result.into();
            }
            let next = state.unwrap_or("running");
            let compatible = |result: &str| match next {
                "succeeded" => result == "success",
                "failed" => matches!(result, "failure" | "timeout"),
                "canceled" => result == "canceled",
                _ => false,
            };
            let valid = result.is_none_or(compatible);
            let outcome = status(&store, &id, "runner-a", payload);
            if valid {
                let ticket = outcome.unwrap();
                assert_eq!(ticket["state"], next, "{state:?} {result:?}");
                let default = match next {
                    "succeeded" => Some("success"),
                    "failed" => Some("failure"),
                    "canceled" => Some("canceled"),
                    _ => None,
                };
                assert_eq!(
                    ticket["result"],
                    result.or(default).map_or(Value::Null, Value::from),
                    "{state:?} {result:?}"
                );
            } else {
                assert_eq!(
                    error(outcome),
                    (400, "invalid_runner_result"),
                    "{state:?} {result:?}"
                );
                assert_eq!(snapshot(&store), before, "{state:?} {result:?}");
            }
        }
    }
}

/// The parity harness's explicit `null`/`false`/`0` cases (4.7.4) at the
/// store level.
#[test]
fn explicit_null_false_and_zero_values() {
    let (_directory, store) = store();
    let id = running(&store, "explicit-values");
    // `state: null` and `result: null` count as absent; `tmux_sessions:
    // null` leaves the column alone; `result_detail: null` stores "None".
    let ticket = status(
        &store,
        &id,
        "runner-a",
        json!({"state": null, "result": null, "tmux_sessions": null, "result_detail": null}),
    )
    .unwrap();
    assert_eq!(ticket["state"], "running");
    assert_eq!(ticket["result"], Value::Null);
    assert_eq!(ticket["tmux_sessions"], json!([]));
    assert_eq!(ticket["result_detail"], "None");
    assert_eq!(
        audit(&store, &id).last().unwrap().3,
        json!({"event": "heartbeat", "result_detail": "None"})
    );
    // `false` and `0` are values: "False"/"0" are no states or results.
    for (key, value, code) in [
        ("state", json!(false), "invalid_runner_state"),
        ("state", json!(0), "invalid_runner_state"),
        ("state", json!(["running"]), "invalid_runner_state"),
        ("result", json!(false), "invalid_runner_result"),
        ("result", json!(0), "invalid_runner_result"),
        ("result", json!({"r": 1}), "invalid_runner_result"),
        ("tmux_sessions", json!(false), "invalid_tmux_sessions"),
        ("tmux_sessions", json!(0), "invalid_tmux_sessions"),
        // D-3: Python stores the repr of a container.
        ("result_detail", json!(["x"]), "invalid_json"),
        ("result_detail", json!({"x": 1}), "invalid_json"),
    ] {
        let before = snapshot(&store);
        assert_eq!(
            error(status(&store, &id, "runner-a", json!({ key: value }))),
            (400, code),
            "{key} {value}"
        );
        assert_eq!(snapshot(&store), before, "{key} {value}");
    }
    for (value, stored) in [
        (json!(false), "False"),
        (json!(0), "0"),
        (json!(1.5), "1.5"),
        (json!("  "), "1.5"),
    ] {
        let ticket = status(&store, &id, "runner-a", json!({"result_detail": value})).unwrap();
        // A blank detail is not written: the previous value stays.
        assert_eq!(ticket["result_detail"], stored, "{value}");
    }
    let ticket = status(&store, &id, "runner-a", json!({"tmux_sessions": []})).unwrap();
    assert_eq!(ticket["tmux_sessions"], json!([]));
}

#[test]
fn approved_ticket_may_be_set_running_but_not_terminal() {
    let (_directory, store) = store();
    let id = create(&store, "nyxmon", &ticket_payload("Approved", None, None));
    approve(&store, &id).unwrap();
    assert_eq!(
        error(status(
            &store,
            &id,
            "runner-a",
            json!({"state": "succeeded"})
        )),
        (409, "invalid_state")
    );
    assert_eq!(
        error(status(&store, &id, "runner-a", json!({"state": "bogus"}))),
        (400, "invalid_runner_state")
    );
    let ticket = status(&store, &id, "runner-x", json!({"state": " RUNNING "})).unwrap();
    assert_eq!(ticket["state"], "running");
    assert_eq!(ticket["runner_host"], "runner-x");
    assert_eq!(ticket["finished_at"], Value::Null);
    // No `started_at`: only the claim sets it.
    assert_eq!(ticket["started_at"], Value::Null);
    let events = audit(&store, &id);
    assert_eq!(
        events.last().unwrap(),
        &(
            "runner_heartbeat".to_owned(),
            Some("approved".to_owned()),
            Some("running".to_owned()),
            json!({"event": "heartbeat", "result_detail": ""}),
        )
    );
    // Pending tickets receive no status at all.
    let pending = create(&store, "nyxmon", &ticket_payload("Pending", None, None));
    assert_eq!(
        error(status(
            &store,
            &pending,
            "runner-a",
            json!({"state": "running"})
        )),
        (409, "invalid_state")
    );
}

#[test]
fn status_records_the_heartbeat_and_writes_host_and_stamp() {
    let (_directory, store) = store();
    let id = running(&store, "heartbeat");
    let before = store.get_ticket(&id).unwrap();
    let ticket = store
        .update_runner_status(
            &id,
            "runner-a",
            &common::object(json!({"event": "step_started", "result_detail": "step_1_started"})),
            Some("127.0.0.1"),
            Some("runner/1"),
        )
        .unwrap();
    assert_eq!(ticket["state"], "running");
    assert_eq!(ticket["result_detail"], "step_1_started");
    assert_ne!(ticket["last_heartbeat_at"], before["last_heartbeat_at"]);
    let (host, beat): (String, String) = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT runner_host, last_heartbeat_at FROM runner_heartbeats",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(host, "runner-a");
    // `_update_runner_heartbeat` takes its own timestamp, as in Python.
    assert!(beat.ends_with('Z'), "{beat}");
    let (actor, ip, agent): (String, Option<String>, Option<String>) = Connection::open(store.db_path())
        .unwrap()
        .query_row(
            "SELECT actor, source_ip, user_agent FROM audit_events WHERE event_type = 'runner_step_started'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (actor.as_str(), ip.as_deref(), agent.as_deref()),
        ("runner:runner-a", Some("127.0.0.1"), Some("runner/1"))
    );
}
