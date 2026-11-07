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

/// Fail after a complete first line, or only at the final flush.
struct FailingWriter {
    bytes: Vec<u8>,
    fail_flush: bool,
    failed: bool,
}

impl std::io::Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.fail_flush && self.bytes.contains(&b'\n') {
            self.failed = true;
            return Err(std::io::Error::other("injected second-record write"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        assert!(self.fail_flush, "write failure must occur before flush");
        self.failed = true;
        Err(std::io::Error::other("injected final flush"))
    }
}

#[test]
fn write_and_flush_failures_do_not_return_a_summary() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    for title in ["First", "Second"] {
        create(&store, "nyxmon", &ticket_payload(title, None, None));
    }
    let before = common::snapshot(&store);
    for fail_flush in [false, true] {
        let mut writer = FailingWriter {
            bytes: Vec::new(),
            fail_flush,
            failed: false,
        };
        let error = dump_tickets(store.db_path(), &mut writer).unwrap_err();
        assert!(matches!(error, opsgate_store::StoreError::Io(_)));
        assert!(writer.failed, "the injected failure was not reached");
        assert_eq!(
            writer.bytes.iter().filter(|&&byte| byte == b'\n').count(),
            if fail_flush { 2 } else { 1 }
        );
        assert_eq!(common::snapshot(&store), before);
    }
    assert_eq!(records(store.db_path()).0.tickets, 2);
}

struct GatedWriter {
    bytes: Vec<u8>,
    first_record: Option<std::sync::mpsc::Sender<()>>,
    mutated: std::sync::mpsc::Receiver<()>,
}

impl std::io::Write for GatedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        if self.bytes.contains(&b'\n')
            && let Some(first) = self.first_record.take()
        {
            first.send(()).unwrap();
            self.mutated
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("WAL writer must commit while the dump reader is paused");
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn concurrent_dump_records_and_counters_share_one_read_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    create(&store, "nyxmon", &ticket_payload("First", None, None));
    let changed = create(
        &store,
        "nyxmon",
        &ticket_payload("Changed later", None, None),
    );
    approve(&store, &changed).unwrap();
    let deleted = create(
        &store,
        "nyxmon",
        &ticket_payload("Deleted later", None, None),
    );
    approve(&store, &deleted).unwrap();
    let before = records(store.db_path());
    assert_eq!(
        before.0,
        DumpSummary {
            tickets: 3,
            approved: 2,
            matching: 2
        }
    );
    let (first_tx, first_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut writer = GatedWriter {
        bytes: Vec::new(),
        first_record: Some(first_tx),
        mutated: done_rx,
    };
    let (summary, inserted) = std::thread::scope(|scope| {
        let changed = &changed;
        let deleted = &deleted;
        let store = &store;
        let mutation = scope.spawn(move || {
            first_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            execute(
                store,
                "UPDATE tickets SET title = 'Altered during dump' WHERE id = ?",
                [changed],
            );
            execute(store, "DELETE FROM tickets WHERE id = ?", [deleted]);
            let inserted = create(
                store,
                "nyxmon",
                &ticket_payload("Inserted during dump", None, None),
            );
            approve(store, &inserted).unwrap();
            done_tx.send(()).unwrap();
            inserted
        });
        let summary = dump_tickets(store.db_path(), &mut writer).unwrap();
        (summary, mutation.join().unwrap())
    });
    let exported: Vec<Value> = std::str::from_utf8(&writer.bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!((summary, exported), before);
    let (summary, after) = records(store.db_path());
    assert_eq!(
        summary,
        DumpSummary {
            tickets: 3,
            approved: 2,
            matching: 1
        }
    );
    assert!(!after.iter().any(|row| row["id"] == deleted));
    assert!(after.iter().any(|row| row["id"] == inserted));
    let changed = after.iter().find(|row| row["id"] == changed).unwrap();
    assert_eq!(changed["ticket"]["title"], "Altered during dump");
    assert_eq!(changed["approval_checksum_matches"], false);
}

#[test]
fn failed_file_dump_removes_only_its_owned_output() {
    let directory = tempfile::tempdir().unwrap();
    // A real readable SQLite source whose ticket SELECT fails. No full disk,
    // permissions assumptions, or OS-specific failure device is needed.
    let db = directory.path().join("invalid-source.sqlite3");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch("CREATE TABLE sentinel (value TEXT); INSERT INTO sentinel VALUES ('keep');")
        .unwrap();
    drop(connection);
    let before = std::fs::read(&db).unwrap();
    let output = directory.path().join("failed.jsonl");
    assert!(matches!(
        dump_to_file(&db, &output),
        Err(opsgate_store::StoreError::Sqlite(_))
    ));
    assert!(!output.exists(), "failed dump must not look published");
    assert_eq!(std::fs::read(&db).unwrap(), before);
    std::fs::write(&output, b"existing evidence").unwrap();
    assert!(dump_to_file(&db, &output).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"existing evidence");
    assert_eq!(std::fs::read(&db).unwrap(), before);
}
