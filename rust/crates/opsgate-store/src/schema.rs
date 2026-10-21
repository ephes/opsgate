//! The schema of PLAN.md 4.10: `service.py:OpsGateService.init_db` with the
//! same DDL text, so a database initialised by either implementation is
//! identical (`fixtures/schema.sql`; the pytest
//! `test_rust_store_ddl_is_the_python_ddl` checks that the constants below
//! are Python's text).
//!
//! Ported Python: `init_db`, `OPEN_TICKET_DEDUPE_INDEX`.

use rusqlite::Connection;

/// The script `init_db` passes to `executescript`, verbatim (indentation
/// included: SQLite keeps it in `sqlite_master`).
pub const INIT_SCRIPT: &str = r#"
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    task_ref TEXT,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    execution_plan_json TEXT NOT NULL,
                    policy_requirements_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    payload_checksum TEXT NOT NULL,
                    approved_payload_checksum TEXT,
                    state TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    expires_at TEXT,
                    max_duration_seconds INTEGER NOT NULL,
                    tmux_sessions_json TEXT NOT NULL DEFAULT '[]',
                    runner_host TEXT,
                    last_heartbeat_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    result TEXT,
                    result_detail TEXT,
                    archived_at TEXT,
                    archived_by TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    previous_state TEXT,
                    new_state TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS ui_session_state (
                    username TEXT PRIMARY KEY,
                    session_generation INTEGER NOT NULL,
                    password_fingerprint TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runner_heartbeats (
                    runner_host TEXT PRIMARY KEY,
                    last_heartbeat_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tickets_state ON tickets(state);
                CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON tickets(created_at);
                "#;

/// The `tickets` table as `init_db` created it before archiving existed
/// (commits `650aa4f` to `bf5a735^`, March 2026; production's first tickets
/// date from then). `init_db` migrates it with [`ADD_ARCHIVED_AT`] and
/// [`ADD_ARCHIVED_BY`]; `check-db` accepts the migrated table text besides
/// the fresh one. Verbatim, like [`INIT_SCRIPT`].
pub const PRE_ARCHIVE_TICKETS_TABLE: &str = r#"
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    task_ref TEXT,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    execution_plan_json TEXT NOT NULL,
                    policy_requirements_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    payload_checksum TEXT NOT NULL,
                    approved_payload_checksum TEXT,
                    state TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    expires_at TEXT,
                    max_duration_seconds INTEGER NOT NULL,
                    tmux_sessions_json TEXT NOT NULL DEFAULT '[]',
                    runner_host TEXT,
                    last_heartbeat_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    result TEXT,
                    result_detail TEXT
                );
"#;

/// The migration `init_db` runs when `tickets` lacks `archived_at`.
pub const ADD_ARCHIVED_AT: &str = "ALTER TABLE tickets ADD COLUMN archived_at TEXT";

/// The migration `init_db` runs when `tickets` lacks `archived_by`.
pub const ADD_ARCHIVED_BY: &str = "ALTER TABLE tickets ADD COLUMN archived_by TEXT";

/// The archive index `init_db` creates after the migrations.
pub const ARCHIVED_AT_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_tickets_archived_at ON tickets(archived_at, created_at)";

/// `init_db` drops the open-ticket dedupe index on every start …
pub const DROP_OPEN_TICKET_DEDUPE_INDEX: &str = "DROP INDEX IF EXISTS idx_tickets_open_dedupe";

/// … and re-creates it (`OPEN_TICKET_DEDUPE_INDEX`, verbatim): at most one
/// open ticket per `(source, task_ref)` outside archived tickets (4.7.1).
pub const OPEN_TICKET_DEDUPE_INDEX: &str = r#"
CREATE UNIQUE INDEX idx_tickets_open_dedupe
    ON tickets(source, task_ref)
    WHERE task_ref IS NOT NULL
      AND archived_at IS NULL
      AND state IN ('pending_approval', 'approved', 'running');
"#;

/// The DDL part of `init_db`, statement by statement as Python runs it, each
/// in autocommit mode: the tables and indexes, the archive columns when
/// missing, the archive index, then the dedupe index dropped and re-created.
/// Idempotent: on a database initialised by either implementation only the
/// dedupe index is re-created.
pub fn apply(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(INIT_SCRIPT)?;
    let columns = ticket_columns(connection)?;
    if !columns.iter().any(|name| name == "archived_at") {
        connection.execute_batch(ADD_ARCHIVED_AT)?;
    }
    if !columns.iter().any(|name| name == "archived_by") {
        connection.execute_batch(ADD_ARCHIVED_BY)?;
    }
    connection.execute_batch(ARCHIVED_AT_INDEX)?;
    connection.execute_batch(DROP_OPEN_TICKET_DEDUPE_INDEX)?;
    connection.execute_batch(OPEN_TICKET_DEDUPE_INDEX)?;
    Ok(())
}

/// The column names of `tickets` (`PRAGMA table_info(tickets)`).
fn ticket_columns(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare("PRAGMA table_info(tickets)")?;
    let names = statement.query_map([], |row| row.get::<_, String>("name"))?;
    names.collect()
}

/// One schema object as `sqlite_master` stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaObject {
    /// `table` or `index` (also `view`/`trigger` in a foreign database).
    pub kind: String,
    pub name: String,
    pub table: String,
    pub sql: String,
}

/// The objects of `sqlite_master` that have SQL of their own, without
/// SQLite's internal ones (`sqlite_sequence`, autoindexes): tables first,
/// then the other kinds, each by name — the order of `fixtures/schema.sql`.
pub fn objects(connection: &Connection) -> rusqlite::Result<Vec<SchemaObject>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master \
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
         ORDER BY type != 'table', type, name",
    )?;
    let objects = statement.query_map([], |row| {
        Ok(SchemaObject {
            kind: row.get(0)?,
            name: row.get(1)?,
            table: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    objects.collect()
}

/// SQL text with every run of whitespace collapsed to one space and the ends
/// trimmed: how the contract test and `check-db` compare statements (4.10).
pub fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}
