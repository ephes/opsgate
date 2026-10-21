//! `check-db` (PLAN.md 3.1, D-15): schema and stored rows checked read-only,
//! counts reported, nothing written.

mod common;

use std::path::Path;

use opsgate_store::check::check_db;
use rusqlite::Connection;
use serde_json::json;

fn database_with_tickets(directory: &Path) -> std::path::PathBuf {
    let store = common::store(directory);
    let submitter = common::submitter(&store, "nyxmon");
    for (task_ref, context) in [("a", json!({"x": 0.95})), ("b", json!({}))] {
        let payload = common::object(json!({
            "title": "T", "summary": "S", "task_ref": task_ref, "context": context,
            "execution_plan": [{"role": "investigator", "agent": "codex", "prompt_markdown": "p"}],
        }));
        store
            .create_ticket(&payload, &submitter, None, None)
            .unwrap();
    }
    Connection::open(store.db_path())
        .unwrap()
        .execute_batch(
            "UPDATE tickets SET state = 'expired' WHERE task_ref = 'b'; \
             INSERT INTO runner_heartbeats VALUES ('macstudio', '2026-10-18T09:00:00Z', '2026-10-18T09:00:00Z');",
        )
        .unwrap();
    store.db_path().to_owned()
}

fn files(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn healthy_database_reports_counts_and_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = database_with_tickets(directory.path());
    let before = std::fs::read(&path).unwrap();
    let report = check_db(&path).unwrap();
    assert!(report.is_ok(), "{report}");
    assert_eq!(report.tickets, 2);
    assert_eq!(
        report.ticket_states,
        [
            ("expired".to_owned(), 1),
            ("pending_approval".to_owned(), 1)
        ]
    );
    assert_eq!(
        (
            report.audit_events,
            report.ui_session_state,
            report.runner_heartbeats
        ),
        (2, 1, 1)
    );
    let text = report.to_string();
    assert!(text.contains("schema: ok\n"), "{text}");
    assert!(text.contains("rows: ok\n"), "{text}");
    assert!(
        text.contains("tickets: 2 (expired 1, pending_approval 1)\n"),
        "{text}"
    );
    // The database file is untouched; SQLite may have created the WAL side
    // files a reader needs.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for (name, _) in files(directory.path()) {
        assert!(
            [
                "opsgate.sqlite3",
                "opsgate.sqlite3-wal",
                "opsgate.sqlite3-shm"
            ]
            .contains(&name.as_str()),
            "{name}"
        );
    }
}

#[test]
fn uncheckpointed_wal_is_read_and_never_checkpointed() {
    let directory = tempfile::tempdir().unwrap();
    let path = database_with_tickets(directory.path());
    // A writer that leaves committed data in the WAL (as after a crash).
    let writer = Connection::open(&path).unwrap();
    writer
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
    writer
        .execute_batch(
            "PRAGMA wal_autocheckpoint=0; \
             INSERT INTO runner_heartbeats VALUES ('wal-only', '2026-10-21T00:00:00Z', '2026-10-21T00:00:00Z');",
        )
        .unwrap();
    drop(writer);
    let wal = directory.path().join("opsgate.sqlite3-wal");
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    let main_before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(&wal).unwrap();

    let report = check_db(&path).unwrap();
    assert!(report.is_ok(), "{report}");
    assert_eq!(report.runner_heartbeats, 2, "the WAL content is read");
    assert_eq!(std::fs::read(&path).unwrap(), main_before);
    assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
}

#[test]
fn a_changed_collation_or_constraint_is_a_schema_difference() {
    // `table_xinfo` shows neither; the SQL text does. A NOCASE `task_ref`
    // would make the dedupe index treat `ABC` and `abc` as one.
    for (from, to) in [
        (
            "                    task_ref TEXT,\n",
            "                    task_ref TEXT COLLATE NOCASE,\n",
        ),
        (
            "session_generation INTEGER NOT NULL,",
            "session_generation INTEGER NOT NULL CHECK (session_generation > 0),",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("opsgate.sqlite3");
        let connection = Connection::open(&path).unwrap();
        let script = opsgate_store::schema::INIT_SCRIPT.replace(from, to);
        assert_ne!(script, opsgate_store::schema::INIT_SCRIPT);
        connection.execute_batch(&script).unwrap();
        opsgate_store::schema::apply(&connection).unwrap();
        let report = check_db(&path).unwrap();
        assert_eq!(report.schema_problems.len(), 1, "{to}: {report}");
        assert!(report.schema_problems[0].ends_with(": definition differs"));
    }
}

#[test]
fn python_schema_fixture_passes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("python.sqlite3");
    Connection::open(&path)
        .unwrap()
        .execute_batch(include_str!("../../../fixtures/schema.sql"))
        .unwrap();
    let report = check_db(&path).unwrap();
    assert!(report.is_ok(), "{report}");
    assert_eq!(report.tickets, 0);
}

#[test]
fn schema_differences_are_reported() {
    for (sql, expected) in [
        (
            "DROP INDEX idx_tickets_open_dedupe",
            "missing index idx_tickets_open_dedupe",
        ),
        (
            "CREATE INDEX extra ON tickets(source)",
            "unexpected index extra",
        ),
        ("CREATE TABLE extra (x)", "unexpected table extra"),
        ("CREATE VIEW v AS SELECT 1", "unexpected view v"),
        (
            "DROP INDEX idx_tickets_open_dedupe; CREATE UNIQUE INDEX idx_tickets_open_dedupe ON tickets(source, task_ref)",
            "index idx_tickets_open_dedupe: definition differs",
        ),
        (
            "ALTER TABLE tickets ADD COLUMN extra TEXT",
            "table tickets: definition differs",
        ),
        (
            "DROP TABLE runner_heartbeats; CREATE TABLE runner_heartbeats (runner_host TEXT PRIMARY KEY, last_heartbeat_at TEXT, updated_at TEXT NOT NULL)",
            "table runner_heartbeats: definition differs",
        ),
        ("DROP TABLE audit_events", "missing table audit_events"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = database_with_tickets(directory.path());
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        let report = check_db(&path).unwrap();
        assert!(!report.is_ok(), "{sql}");
        assert!(
            report
                .schema_problems
                .iter()
                .any(|problem| problem.starts_with(expected)),
            "{sql}: {:?}",
            report.schema_problems
        );
        assert!(report.to_string().contains("rows: not checked"));
    }
}

#[test]
fn unreadable_rows_are_reported() {
    for (sql, expected) in [
        (
            "UPDATE tickets SET context_json = '{\"x\": NaN}' WHERE task_ref = 'a'",
            "context_json: invalid JSON",
        ),
        (
            "UPDATE tickets SET context_json = '{\"x\": 1e400}' WHERE task_ref = 'a'",
            "context_json: JSON number out of range (D-2)",
        ),
        (
            "UPDATE tickets SET execution_plan_json = 'not json' WHERE task_ref = 'a'",
            "execution_plan_json: invalid JSON",
        ),
        (
            "UPDATE tickets SET tmux_sessions_json = X'5B5D' WHERE task_ref = 'a'",
            "a BLOB value",
        ),
        (
            "UPDATE tickets SET title = X'FF' WHERE task_ref = 'a'",
            "a BLOB value",
        ),
        (
            "UPDATE tickets SET expires_at = 'tomorrow' WHERE task_ref = 'a'",
            "expires_at:",
        ),
        (
            "UPDATE tickets SET max_duration_seconds = 'n/a' WHERE task_ref = 'a'",
            "max_duration_seconds: not an integer",
        ),
        (
            "UPDATE audit_events SET metadata_json = '{' WHERE id = 1",
            "audit_events 1: metadata_json: invalid JSON",
        ),
        (
            "UPDATE audit_events SET actor = X'00' WHERE id = 2",
            "audit_events 2: actor: a BLOB value",
        ),
        (
            "UPDATE ui_session_state SET session_generation = 'x'",
            "ui_session_state row 1: session_generation: not an integer",
        ),
        (
            "UPDATE runner_heartbeats SET updated_at = X'00'",
            "runner_heartbeats row 1: updated_at: a BLOB value",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = database_with_tickets(directory.path());
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        let report = check_db(&path).unwrap();
        assert!(report.schema_problems.is_empty(), "{report}");
        assert!(
            report
                .row_problems
                .iter()
                .any(|problem| problem.contains(expected)),
            "{sql}: {:?}",
            report.row_problems
        );
        assert!(!report.is_ok(), "{sql}");
        // Stored values are never printed.
        assert!(!report.to_string().contains("NaN") && !report.to_string().contains("tomorrow"));
    }
}

#[test]
fn many_problems_are_capped_in_the_report() {
    let directory = tempfile::tempdir().unwrap();
    let path = database_with_tickets(directory.path());
    let connection = Connection::open(&path).unwrap();
    for index in 0..60 {
        connection
            .execute(
                "INSERT INTO audit_events (ticket_id, event_type, actor, timestamp, metadata_json) VALUES ('t', 'e', 'a', 't', ?)",
                [format!("{{{index}")],
            )
            .unwrap();
    }
    let report = check_db(&path).unwrap();
    assert_eq!(report.row_problems.len(), 60);
    assert!(report.to_string().contains("… and 10 more"));
}

#[test]
fn missing_or_foreign_files_are_errors() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.sqlite3");
    assert!(check_db(&missing).is_err());
    assert!(!missing.exists(), "check-db never creates a database");
    let text = directory.path().join("text.sqlite3");
    std::fs::write(
        &text,
        "this is not a database, just text that is long enough to have a header",
    )
    .unwrap();
    assert!(check_db(&text).is_err());
}

#[test]
fn write_protected_database_is_checked() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = database_with_tickets(directory.path());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let before = std::fs::read(&path).unwrap();
    let report = check_db(&path).unwrap();
    assert!(report.is_ok(), "{report}");
    assert_eq!(report.tickets, 2);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
