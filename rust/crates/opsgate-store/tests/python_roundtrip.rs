//! Python ↔ Rust on one database (PLAN.md 12, S3a/S3b acceptance; 4.8,
//! 4.10): tickets created by one implementation, approved by the other and
//! claimed by the first, in both directions, with production-shaped float
//! contexts; status updates, archive and cancel across implementations; both
//! read every ticket identically; the Python service's `init_db` on the Rust
//! database and Rust's on the result change nothing (the approver keeps
//! generation 1); and the data-parity records of `check-db --dump` and
//! `rust/parity/shadow/serialize_python.py` compare without a difference
//! (11.2 step 1).
//!
//! Python runs as `python3 -I tests/python_peer.py` (`$OPSGATE_PYTHON`
//! overrides the interpreter; 3.11 or newer, standard library only). Without
//! one the test is skipped, unless `OPSGATE_REQUIRE_PYTHON=1` (set in CI),
//! which turns the skip into a failure.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{APPROVER, object};
use opsgate_core::json::canonical_json;
use opsgate_store::Store;
use serde_json::{Value, json};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn repository() -> PathBuf {
    Path::new(MANIFEST_DIR).join("../../..")
}

/// The interpreter, or `None` (skip) when there is none of 3.11 or newer.
fn python() -> Option<String> {
    let interpreter = std::env::var("OPSGATE_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let usable = Command::new(&interpreter)
        .args([
            "-I",
            "-c",
            "import sys; sys.exit(sys.version_info < (3, 11))",
        ])
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if usable {
        return Some(interpreter);
    }
    assert!(
        std::env::var("OPSGATE_REQUIRE_PYTHON").as_deref() != Ok("1"),
        "OPSGATE_REQUIRE_PYTHON=1 but {interpreter} (3.11 or newer) is not available"
    );
    eprintln!("skipped: {interpreter} 3.11 or newer is not available");
    None
}

struct Peer {
    interpreter: String,
    db: PathBuf,
}

impl Peer {
    /// Runs the operations with the Python service; one outcome each.
    fn run(&self, ops: Value) -> Vec<Value> {
        let request = json!({
            "src": repository().join("src"),
            "db": self.db,
            "ops": ops,
        });
        let mut child = Command::new(&self.interpreter)
            .arg("-I")
            .arg(Path::new(MANIFEST_DIR).join("tests/python_peer.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "python peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// One operation that must succeed; its value.
    fn ok(&self, op: Value) -> Value {
        let outcome = self.run(json!([op])).remove(0);
        match outcome.get("ok") {
            Some(value) => value.clone(),
            None => panic!("python: {op} failed: {outcome}"),
        }
    }
}

fn canonical(value: &Value) -> String {
    canonical_json(value).unwrap()
}

fn float_context() -> Value {
    serde_json::from_str(
        r#"{"producer": "nyxmon", "check": {"check_id": 42, "name": "OpsGate Health (JSON Metrics)"},
            "result": {"status": "error", "data": {"value": 0.95, "threshold": 3.0, "latency": 14.0,
            "big": 1e16, "small": 1e-05, "neg_zero": -0.0, "int": 12345678901234567890, "ok": false}},
            "text": "Grüße ☃ 😀 \"q\" \\ \n"}"#,
    )
    .unwrap()
}

fn payload(title: &str, task_ref: &str) -> Value {
    json!({
        "title": title,
        "summary": "Cross-implementation round trip",
        "task_ref": task_ref,
        "context": float_context(),
        "expires_at": "2999-01-01T10:00:00+02:00",
        "execution_plan": [
            {"role": " Implementer ", "agent": "CODEX", "prompt_markdown": "  Fix it\n"},
            {"role": "Reviewer", "agent": "claude", "prompt_markdown": "Review the change"},
        ],
        "policy_requirements": {"require_reviewer_step": true},
        "max_duration_seconds": 900,
    })
}

fn id_of(ticket: &Value) -> String {
    ticket["id"].as_str().unwrap().to_owned()
}

#[test]
fn python_and_rust_share_one_database() {
    let Some(interpreter) = python() else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("opsgate.sqlite3");
    let store = Store::open(common::settings(&db, &serde_json::Map::new())).unwrap();
    let peer = Peer {
        interpreter,
        db: db.clone(),
    };
    let submitter = common::submitter(&store, "nyxmon");

    // Python creates, Rust approves, Python claims.
    let first = peer.ok(
        json!({"op": "create", "source": "nyxmon", "payload": payload("Python first", "rt-1")}),
    );
    let first_id = id_of(&first);
    let approved = store
        .approve_ticket(&first_id, APPROVER, None, None)
        .unwrap();
    assert_eq!(
        approved["approved_payload_checksum"],
        first["payload_checksum"]
    );
    let claimed = peer.ok(json!({"op": "claim", "runner_host": "runner-py"}));
    assert_eq!(claimed["id"], first["id"]);
    assert_eq!(claimed["state"], "running");

    // Rust creates, Python approves, Rust claims.
    let second = store
        .create_ticket(
            &object(payload("Rust first", "rt-2")),
            &submitter,
            Some("127.0.0.1"),
            Some("rust"),
        )
        .unwrap();
    let second_id = second["id"].as_str().unwrap().to_owned();
    let approved = peer.ok(json!({"op": "approve", "id": second_id}));
    assert_eq!(
        approved["approved_payload_checksum"],
        second["payload_checksum"]
    );
    let claimed = store
        .claim_ticket("runner-rs", None, None)
        .unwrap()
        .unwrap();
    assert_eq!(claimed["id"], second["id"]);

    // Python creates and approves, Rust claims; Rust creates and approves,
    // Python claims.
    let third = peer
        .ok(json!({"op": "create", "source": "nyxmon", "payload": payload("Python both", "rt-3")}));
    peer.ok(json!({"op": "approve", "id": id_of(&third)}));
    assert_eq!(
        store
            .claim_ticket("runner-rs", None, None)
            .unwrap()
            .unwrap()["id"],
        third["id"]
    );
    let fourth = store
        .create_ticket(
            &object(payload("Rust both", "rt-4")),
            &submitter,
            None,
            None,
        )
        .unwrap();
    let fourth_id = fourth["id"].as_str().unwrap().to_owned();
    store
        .approve_ticket(&fourth_id, APPROVER, None, None)
        .unwrap();
    assert_eq!(
        peer.ok(json!({"op": "claim", "runner_host": "runner-py"}))["id"],
        fourth["id"]
    );

    // Status updates across implementations: the assigned host is kept.
    let mismatch = peer.run(json!([
        {"op": "status", "id": second_id, "runner_host": "runner-py", "payload": {}},
    ]));
    assert_eq!(
        mismatch[0],
        json!({"error": {"code": "runner_host_mismatch", "status": 409}})
    );
    let tmux_sessions = json!([{"step_index": 0, "status": "succeeded", "ratio": 0.5}]);
    let done = peer.ok(json!({"op": "status", "id": second_id, "runner_host": "runner-rs",
        "payload": {"event": "ticket_succeeded", "state": "succeeded", "result_detail": "completed_2_steps",
                    "tmux_sessions": tmux_sessions}}));
    assert_eq!(done["state"], "succeeded");
    let failed = store
        .update_runner_status(
            &first_id,
            "runner-py",
            &object(json!({"event": "timeout", "state": "failed", "result": "timeout"})),
            None,
            None,
        )
        .unwrap();
    assert_eq!(failed["result"], "timeout");

    // Archive in one, restore in the other, cancel in the first.
    let fifth =
        peer.ok(json!({"op": "create", "source": "nyxmon", "payload": payload("Shelved", "rt-5")}));
    let fifth_id = id_of(&fifth);
    store
        .archive_ticket(&fifth_id, APPROVER, None, None)
        .unwrap();
    assert_eq!(
        peer.ok(json!({"op": "unarchive", "id": fifth_id}))["is_archived"],
        false
    );
    store
        .cancel_ticket(&fifth_id, APPROVER, "", None, None)
        .unwrap();
    // A tampered ticket fails in either claim.
    let sixth = store
        .create_ticket(&object(payload("Tampered", "rt-6")), &submitter, None, None)
        .unwrap();
    let sixth_id = sixth["id"].as_str().unwrap().to_owned();
    peer.ok(json!({"op": "approve", "id": sixth_id}));
    common::execute(
        &store,
        "UPDATE tickets SET context_json = '{\"result\": {\"data\": {\"value\": 0.951}}}' WHERE id = ?",
        [&sixth_id],
    );
    assert_eq!(
        peer.ok(json!({"op": "claim", "runner_host": "runner-py"})),
        Value::Null
    );
    assert_eq!(
        store.get_ticket(&sixth_id).unwrap()["result_detail"],
        "prompt_tampered"
    );

    // Both read every ticket alike.
    let ids = [
        &first_id,
        &second_id,
        &id_of(&third),
        &fourth_id,
        &fifth_id,
        &sixth_id,
    ];
    for id in ids {
        let python = peer.ok(json!({"op": "get", "id": id}));
        let rust = Value::Object(store.get_ticket(id).unwrap());
        assert_eq!(canonical(&python), canonical(&rust), "{id}");
    }
    // Neither start revoked the approver's sessions.
    assert_eq!(peer.ok(json!({"op": "generation"})), json!(1));
    let reopened = Store::open(store.settings().clone()).unwrap();
    assert_eq!(reopened.ui_session_generation(APPROVER).unwrap(), Some(1));

    // The data-parity records agree (11.2 step 1).
    let rust_dump = directory.path().join("rust.jsonl");
    let python_dump = directory.path().join("python.jsonl");
    let summary = opsgate_store::dump::dump_to_file(&db, &rust_dump).unwrap();
    assert_eq!(summary.tickets, 6);
    // Four approved tickets match; the tampered one does not.
    assert_eq!((summary.approved, summary.matching), (5, 4));
    let shadow = repository().join("rust/parity/shadow");
    // The deployed venv imports `opsgate` by itself; here `src` goes on the
    // path (`-I` ignores PYTHONPATH).
    let status = Command::new(&peer.interpreter)
        .args([
            "-I",
            "-c",
            "import runpy, sys; sys.path.insert(0, sys.argv[1]); sys.argv = sys.argv[2:]; \
             runpy.run_path(sys.argv[0], run_name='__main__')",
        ])
        .arg(repository().join("src"))
        .arg(shadow.join("serialize_python.py"))
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["--out".as_ref(), python_dump.as_os_str()])
        .status()
        .unwrap();
    assert!(status.success());
    let compared = Command::new(&peer.interpreter)
        .arg("-I")
        .arg(shadow.join("compare_dump.py"))
        .arg(&python_dump)
        .arg(&rust_dump)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&compared.stdout);
    assert!(compared.status.success(), "{report}");
    assert!(report.contains("differences: 0"), "{report}");
    assert!(
        report.contains("approval checksums (python): 5 stored, 4 matching"),
        "{report}"
    );
    assert!(
        report.contains("approval checksums (rust): 5 stored, 4 matching"),
        "{report}"
    );
}
