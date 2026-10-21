//! `check-db --dump` records (PLAN.md 11.2 step 1, `opsgate_store::dump`):
//! the serialisation and the recomputed approval checksum per ticket, the
//! error kinds where either fails, the file created new with mode 0600, and
//! the database never written. The comparison with Python's records runs in
//! `python_roundtrip.rs`.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{approve, create, execute, ticket_payload};
use opsgate_store::dump::{DumpSummary, dump_tickets, dump_to_file};
use serde_json::{Value, json};

fn records(db: &std::path::Path) -> (DumpSummary, Vec<Value>) {
    let mut out = Vec::new();
    let summary = dump_tickets(db, &mut out).unwrap();
    let records = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (summary, records)
}

#[test]
fn records_name_serialisation_checksum_and_errors() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let approved = create(&store, "nyxmon", &ticket_payload("Approved", None, None));
    let checksum = approve(&store, &approved).unwrap()["approved_payload_checksum"].clone();
    let pending = create(&store, "nyxmon", &ticket_payload("Pending", None, None));
    let tampered = create(&store, "nyxmon", &ticket_payload("Tampered", None, None));
    approve(&store, &tampered).unwrap();
    execute(
        &store,
        "UPDATE tickets SET title = 'x' WHERE id = ?",
        [&tampered],
    );
    let bad_agent = create(&store, "nyxmon", &ticket_payload("Bad agent", None, None));
    execute(
        &store,
        "UPDATE tickets SET execution_plan_json = '[{\"role\":\"r\",\"agent\":\"sh\",\"prompt_markdown\":\"p\"}]' WHERE id = ?",
        [&bad_agent],
    );
    let corrupt = create(&store, "nyxmon", &ticket_payload("Corrupt", None, None));
    execute(
        &store,
        "UPDATE tickets SET context_json = '{broken' WHERE id = ?",
        [&corrupt],
    );

    let db = store.db_path().to_owned();
    let before = std::fs::read(&db).unwrap();
    let (summary, records) = records(&db);
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert_eq!(
        summary,
        DumpSummary {
            tickets: 5,
            approved: 2,
            matching: 1
        }
    );
    let by_id = |id: &str| {
        records
            .iter()
            .find(|record| record["id"] == id)
            .unwrap()
            .clone()
    };
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["rowid"], json!(index + 1));
    }

    let record = by_id(&approved);
    assert_eq!(
        record["ticket"],
        Value::Object(store.get_ticket(&approved).unwrap())
    );
    assert_eq!(record["ticket_error"], Value::Null);
    assert_eq!(record["approval_checksum"], checksum);
    assert_eq!(record["approved_payload_checksum"], checksum);
    assert_eq!(record["approval_checksum_matches"], true);

    let record = by_id(&pending);
    assert_eq!(
        record["approval_checksum"],
        record["ticket"]["payload_checksum"]
    );
    assert_eq!(record["approved_payload_checksum"], Value::Null);
    assert_eq!(record["approval_checksum_matches"], false);

    let record = by_id(&tampered);
    assert_ne!(
        record["approval_checksum"],
        record["approved_payload_checksum"]
    );
    assert_eq!(record["approval_checksum_matches"], false);

    let record = by_id(&bad_agent);
    assert!(record["ticket"].is_object());
    assert_eq!(record["approval_checksum"], Value::Null);
    assert_eq!(record["approval_checksum_error"], "invalid_execution_plan");

    let record = by_id(&corrupt);
    assert_eq!(record["ticket"], Value::Null);
    assert_eq!(record["ticket_error"], "unhandled");
    assert_eq!(record["approval_checksum_error"], "unhandled");
    assert_eq!(record["approval_checksum_matches"], false);
}

#[test]
fn dump_file_is_new_and_private() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    create(&store, "nyxmon", &ticket_payload("One", None, None));
    let dump = directory.path().join("dump.jsonl");
    let summary = dump_to_file(store.db_path(), &dump).unwrap();
    assert_eq!(summary.tickets, 1);
    assert_eq!(
        std::fs::metadata(&dump).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read_to_string(&dump).unwrap().lines().count(), 1);
    // Never overwritten.
    std::fs::write(&dump, "keep").unwrap();
    assert!(dump_to_file(store.db_path(), &dump).is_err());
    assert_eq!(std::fs::read_to_string(&dump).unwrap(), "keep");
    // A missing database is an error and is not created; the failed dump is
    // removed.
    let missing = directory.path().join("missing.sqlite3");
    let other = directory.path().join("other.jsonl");
    assert!(dump_to_file(&missing, &other).is_err());
    assert!(!missing.exists());
    assert!(!other.exists());
}
