//! `opsgate check-db --db <path>` (PLAN.md 3.1, D-15): verify a database
//! read-only before Rust serves it — the schema matches 4.10, every stored
//! row is readable under the Rust rules (JSON of 4.6 incl. the D-2 cases,
//! storage classes, `expires_at` of 4.9) — and report the counts. Nothing is
//! written; no record content or secret is printed (only row positions, audit
//! event ids, bounded escaped state/schema names and fixed error categories).

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use opsgate_core::json::{canonical_json, parse};
use opsgate_core::time::parse_iso_datetime;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row};

use crate::error::StoreError;
use crate::schema::{self, SchemaObject, normalize_sql};

/// Problems listed in the report; the rest are counted.
const MAX_LISTED_PROBLEMS: usize = 50;

/// Stored labels are inert and at most 128 UTF-8 bytes, including truncation.
/// Escape each scalar as a unit so neither UTF-8 nor an escape is cut in half.
fn safe_field(text: &str) -> String {
    const LIMIT: usize = 128;
    let mut output = String::new();
    for character in text.chars() {
        let escaped = character.escape_debug().to_string();
        if output.len() + escaped.len() > LIMIT - "…".len() {
            output.push('…');
            break;
        }
        output.push_str(&escaped);
    }
    output
}

/// The result of [`check_db`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub path: PathBuf,
    /// Differences from the schema `init_db` creates.
    pub schema_problems: Vec<String>,
    /// Stored values Rust cannot read (checked only when the schema matches).
    pub row_problems: Vec<String>,
    /// Exact number of failed row checks, including those not retained.
    pub row_problem_count: usize,
    /// Tickets per state, by state.
    pub ticket_states: Vec<(String, i64)>,
    pub tickets: i64,
    pub audit_events: i64,
    pub ui_session_state: i64,
    pub runner_heartbeats: i64,
}

impl CheckReport {
    fn row_problem(&mut self, message: fmt::Arguments<'_>) {
        self.row_problem_count += 1;
        if self.row_problems.len() < MAX_LISTED_PROBLEMS {
            self.row_problems.push(message.to_string());
        }
    }

    /// Whether the database can be served by Rust as it is.
    pub fn is_ok(&self) -> bool {
        self.schema_problems.is_empty() && self.row_problem_count == 0
    }
}

impl fmt::Display for CheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "database: {}", self.path.display())?;
        let status = |problems: &[String]| if problems.is_empty() { "ok" } else { "FAILED" };
        writeln!(f, "schema: {}", status(&self.schema_problems))?;
        let list = |f: &mut fmt::Formatter<'_>, problems: &[String], total: usize| -> fmt::Result {
            for problem in problems.iter().take(MAX_LISTED_PROBLEMS) {
                writeln!(f, "  {problem}")?;
            }
            let listed = problems.len().min(MAX_LISTED_PROBLEMS);
            if total > listed {
                writeln!(f, "  … and {} more", total - listed)?;
            }
            Ok(())
        };
        list(f, &self.schema_problems, self.schema_problems.len())?;
        if !self.schema_problems.is_empty() {
            return writeln!(f, "rows: not checked (schema differs)");
        }
        writeln!(
            f,
            "rows: {}",
            if self.row_problem_count == 0 {
                "ok"
            } else {
                "FAILED"
            }
        )?;
        list(f, &self.row_problems, self.row_problem_count)?;
        let states = self
            .ticket_states
            .iter()
            .map(|(state, count)| format!("{state} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(f, "tickets: {} ({states})", self.tickets)?;
        writeln!(f, "audit_events: {}", self.audit_events)?;
        writeln!(f, "ui_session_state: {}", self.ui_session_state)?;
        writeln!(f, "runner_heartbeats: {}", self.runner_heartbeats)
    }
}

/// Opens the database read-only (`SQLITE_OPEN_READONLY`, `query_only`):
/// never created, migrated or checkpointed, so the database file itself is
/// never written — a read-write connection would checkpoint committed WAL
/// content into it when it closes as the last connection. Like any SQLite
/// reader of a WAL database it reads the `-wal` file and may create the
/// `-wal`/`-shm` side files when they are missing (owned by the database's
/// owner when run as root); it cannot remove them, and the next API
/// connection uses them as usual.
pub(crate) fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA query_only=ON;")?;
    Ok(connection)
}

/// Checks the database at `path` (see the module documentation). An `Err`
/// means the file could not be opened or read as a SQLite database at all.
pub fn check_db(path: &Path) -> Result<CheckReport, StoreError> {
    check_db_inner(path, || {})
}

// Test seam at the count/scan boundary; production always supplies a no-op.
fn check_db_inner(path: &Path, after_counts: impl FnOnce()) -> Result<CheckReport, StoreError> {
    let mut connection = open_read_only(path)?;
    // BEGIN DEFERRED on a query-only connection: the first schema read pins
    // every later count and row projection to the same generation. RAII also
    // releases the snapshot on schema differences and read errors.
    let snapshot = connection.transaction()?;
    let connection = &snapshot;
    let mut report = CheckReport {
        path: path.to_owned(),
        schema_problems: schema_problems(connection)?,
        ..CheckReport::default()
    };
    if !report.schema_problems.is_empty() {
        return Ok(report);
    }
    check_tickets(connection, &mut report, after_counts)?;
    check_audit_events(connection, &mut report)?;
    report.ui_session_state = check_rows(
        connection,
        "ui_session_state",
        &["username", "password_fingerprint", "updated_at"],
        &["session_generation"],
        &mut report,
    )?;
    report.runner_heartbeats = check_rows(
        connection,
        "runner_heartbeats",
        &["runner_host", "last_heartbeat_at", "updated_at"],
        &[],
        &mut report,
    )?;
    Ok(report)
}

/// The differences between the database's schema and the one `init_db`
/// creates, compared by the SQL text of every object (whitespace collapsed,
/// so column types, collations, constraints and index definitions all
/// count) against reference databases initialised in memory with the same
/// DDL. A `tickets` table created before archiving and migrated by
/// `init_db`'s `ALTER TABLE` (SQLite appends the two columns to its text) is
/// the other accepted form ([`schema::PRE_ARCHIVE_TICKETS_TABLE`]).
fn schema_problems(connection: &Connection) -> Result<Vec<String>, StoreError> {
    let reference = Connection::open_in_memory()?;
    schema::apply(&reference)?;
    let expected = schema::objects(&reference)?;
    let migrated = Connection::open_in_memory()?;
    migrated.execute_batch(schema::PRE_ARCHIVE_TICKETS_TABLE)?;
    schema::apply(&migrated)?;
    let accepted_too = schema::objects(&migrated)?;
    let actual = schema::objects(connection)?;
    let find = |objects: &[SchemaObject], wanted: &SchemaObject| {
        objects
            .iter()
            .find(|object| object.kind == wanted.kind && object.name == wanted.name)
            .cloned()
    };
    let same = |found: &SchemaObject, wanted: &SchemaObject| {
        found.table == wanted.table && normalize_sql(&found.sql) == normalize_sql(&wanted.sql)
    };
    let mut problems = Vec::new();
    for object in &expected {
        let Some(found) = find(&actual, object) else {
            problems.push(format!(
                "missing {} {}",
                safe_field(&object.kind),
                safe_field(&object.name)
            ));
            continue;
        };
        let migrated_form = find(&accepted_too, object);
        if !same(&found, object) && !migrated_form.is_some_and(|form| same(&found, &form)) {
            problems.push(format!(
                "{} {}: definition differs",
                safe_field(&object.kind),
                safe_field(&object.name)
            ));
        }
    }
    for object in &actual {
        if find(&expected, object).is_none() {
            problems.push(format!(
                "unexpected {} {}",
                safe_field(&object.kind),
                safe_field(&object.name)
            ));
        }
    }
    Ok(problems)
}

// Audit-only admission; service/runner JSON contracts are unchanged.
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_JSON_TOKENS: usize = 10_000;

/// A non-allocating lexical work bound, not a second JSON parser. Count every
/// container, key and scalar token (including duplicate members); ignore syntax
/// inside strings. The existing parser still owns all syntax/number semantics.
/// Admission completes before either a Value tree or canonical copy is built.
fn admit_json(text: &str) -> Result<(), &'static str> {
    if text.len() > MAX_JSON_BYTES {
        return Err("not safely audited: JSON exceeds 1048576 bytes");
    }
    let (mut quoted, mut escaped, mut atom) = (false, false, false);
    let (mut depth, mut tokens) = (0_usize, 0_usize);
    for byte in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                atom = false;
                tokens += 1;
            }
            b'[' | b'{' => {
                depth += 1;
                tokens += 1;
                atom = false;
                if depth > opsgate_core::json::MAX_DEPTH {
                    return Err("not safely audited: JSON exceeds 64 container levels");
                }
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                atom = false;
            }
            b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => atom = false,
            _ if !atom => {
                tokens += 1;
                atom = true;
            }
            _ => {}
        }
        if tokens > MAX_JSON_TOKENS {
            return Err("not safely audited: JSON exceeds 10000 tokens");
        }
    }
    Ok(())
}

fn json_problem(text: &str) -> Option<String> {
    if let Err(problem) = admit_json(text) {
        return Some(problem.to_owned());
    }
    match parse(text) {
        Err(error) => Some(error.to_string()),
        // A decoded value must also be writable: infinity is not (D-2).
        Ok(value) => canonical_json(&value)
            .err()
            .map(|error| format!("{error} (D-2)")),
    }
}

/// Borrow text from SQLite instead of materializing an entire TicketRow or
/// cloning unrelated prompts, identifiers, metadata and other stored columns.
fn check_text_column<'row>(
    row: &'row Row<'_>,
    table: &str,
    key: &str,
    column: &str,
    required: bool,
    report: &mut CheckReport,
) -> Result<Option<&'row str>, StoreError> {
    let reason = match row.get_ref(column)? {
        ValueRef::Null if !required => return Ok(None),
        ValueRef::Null => "NULL in a NOT NULL column",
        ValueRef::Text(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => return Ok(Some(text)),
            Err(_) => "text is not UTF-8",
        },
        ValueRef::Blob(_) => "a BLOB value in a text column",
        _ => "a numeric value in a text column",
    };
    report.row_problem(format_args!("{table} {key}: {column}: {reason}"));
    Ok(None)
}

fn check_tickets(
    connection: &Connection,
    report: &mut CheckReport,
    after_counts: impl FnOnce(),
) -> Result<(), StoreError> {
    let mut statement =
        connection.prepare("SELECT state, COUNT(*) FROM tickets GROUP BY state ORDER BY state")?;
    let states = statement.query_map([], |row| {
        Ok((
            match row.get_ref(0)? {
                ValueRef::Text(bytes) => {
                    safe_field(std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>"))
                }
                ValueRef::Null => "<NULL>".to_owned(),
                _ => "<non-text>".to_owned(),
            },
            row.get::<_, i64>(1)?,
        ))
    })?;
    report.ticket_states = states.collect::<rusqlite::Result<_>>()?;
    report.tickets = report.ticket_states.iter().map(|(_, count)| count).sum();
    drop(statement);
    after_counts();

    let mut statement =
        connection.prepare("SELECT rowid AS _rowid, * FROM tickets ORDER BY rowid")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let key = format!("rowid {}", row.get::<_, i64>("_rowid")?);
        for (column, required) in [
            ("id", true),
            ("source", true),
            ("task_ref", false),
            ("title", true),
            ("summary", true),
            ("payload_checksum", true),
            ("approved_payload_checksum", false),
            ("state", true),
            ("created_by", true),
            ("created_at", true),
            ("approved_by", false),
            ("approved_at", false),
            ("runner_host", false),
            ("last_heartbeat_at", false),
            ("started_at", false),
            ("finished_at", false),
            ("result", false),
            ("result_detail", false),
            ("archived_at", false),
            ("archived_by", false),
        ] {
            check_text_column(row, "tickets", &key, column, required, report)?;
        }
        for column in [
            "execution_plan_json",
            "policy_requirements_json",
            "context_json",
            "tmux_sessions_json",
        ] {
            if let Some(text) = check_text_column(row, "tickets", &key, column, true, report)?
                && let Some(problem) = json_problem(text)
            {
                report.row_problem(format_args!("tickets {key}: {column}: {problem}"));
            }
        }
        if !matches!(row.get_ref("max_duration_seconds")?, ValueRef::Integer(_)) {
            report.row_problem(format_args!(
                "tickets {key}: max_duration_seconds: not an integer"
            ));
        }
        if let Some(text) = check_text_column(row, "tickets", &key, "expires_at", false, report)? {
            // Bound the timestamp helper's replacement string as well.
            if text.len() > 256 {
                report.row_problem(format_args!(
                    "tickets {key}: expires_at: not safely audited: exceeds 256 bytes"
                ));
            } else if !opsgate_core::pytext::strip(text).is_empty()
                && let Err(error) = parse_iso_datetime(text)
            {
                report.row_problem(format_args!("tickets {key}: expires_at: {error}"));
            }
        }
    }
    Ok(())
}

fn check_audit_events(connection: &Connection, report: &mut CheckReport) -> Result<(), StoreError> {
    let mut statement = connection.prepare("SELECT * FROM audit_events ORDER BY id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        report.audit_events += 1;
        let id = match row.get_ref("id")? {
            ValueRef::Integer(id) => id.to_string(),
            _ => "?".to_owned(),
        };
        for (column, required) in [
            ("ticket_id", true),
            ("event_type", true),
            ("actor", true),
            ("timestamp", true),
            ("source_ip", false),
            ("user_agent", false),
            ("previous_state", false),
            ("new_state", false),
        ] {
            check_text_column(row, "audit_events", &id, column, required, report)?;
        }
        if let Some(text) =
            check_text_column(row, "audit_events", &id, "metadata_json", true, report)?
            && let Some(problem) = json_problem(text)
        {
            report.row_problem(format_args!("audit_events {id}: metadata_json: {problem}"));
        }
    }
    Ok(())
}

/// Checks the storage classes of a small table and returns its row count.
fn check_rows(
    connection: &Connection,
    table: &'static str,
    text_columns: &[&str],
    integer_columns: &[&str],
    report: &mut CheckReport,
) -> Result<i64, StoreError> {
    let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        // Rows are named by position: usernames and host names are not
        // printed.
        let key = format!("row {count}");
        for column in text_columns {
            check_text_column(row, table, &key, column, false, report)?;
        }
        for column in integer_columns {
            if !matches!(row.get_ref(*column)?, ValueRef::Integer(_)) {
                report.row_problem(format_args!("{table} {key}: {column}: not an integer"));
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_admission_ignores_escaped_string_content() {
        let text = serde_json::to_string(&"[{},0\\\"".repeat(20_000)).unwrap();
        assert_eq!(admit_json(&text), Ok(()));
        assert_eq!(json_problem(&text), None);
        // Keys, scalar values and nested containers all consume work; keys
        // later replaced by duplicates still consume the same allowance.
        assert_eq!(
            admit_json(&format!("{{{}}}", vec!["\"k\":0"; 5000].join(","))),
            Err("not safely audited: JSON exceeds 10000 tokens")
        );
    }

    #[test]
    fn audit_uses_one_snapshot_across_counts_rows_and_tables() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.sqlite3");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        schema::apply(&writer).unwrap();
        let before = std::fs::read(&path).unwrap();
        let report = check_db_inner(&path, || {
            writer
                .execute_batch(
                    "BEGIN IMMEDIATE;
                 INSERT INTO tickets (id, source, title, summary, execution_plan_json,
                    policy_requirements_json, context_json, payload_checksum, state,
                    created_by, created_at, max_duration_seconds)
                 VALUES ('synthetic', 'test', 't', 's', '[]', '{}', 'invalid',
                    'hash', 'expired', 'test', 'now', 1);
                 INSERT INTO audit_events (ticket_id, event_type, actor, timestamp)
                    VALUES ('synthetic', 'test', 'test', 'now');
                 INSERT INTO runner_heartbeats VALUES ('test', 'now', 'now');
                 INSERT INTO ui_session_state VALUES ('test', 1, 'synthetic', 'now');
                 COMMIT;",
                )
                .unwrap();
        })
        .unwrap();
        assert!(report.is_ok(), "{report}");
        assert_eq!(
            (
                report.tickets,
                report.audit_events,
                report.ui_session_state,
                report.runner_heartbeats
            ),
            (0, 0, 0, 0),
            "{report}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let later = check_db(&path).unwrap();
        assert!(!later.is_ok());
        assert_eq!(
            (
                later.tickets,
                later.audit_events,
                later.ui_session_state,
                later.runner_heartbeats
            ),
            (1, 1, 1, 1)
        );
    }
}
