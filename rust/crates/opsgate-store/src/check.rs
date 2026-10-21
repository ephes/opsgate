//! `opsgate check-db --db <path>` (PLAN.md 3.1, D-15): verify a database
//! read-only before Rust serves it — the schema matches 4.10, every stored
//! row is readable under the Rust rules (JSON of 4.6 incl. the D-2 cases,
//! storage classes, `expires_at` of 4.9) — and report the counts. Nothing is
//! written; no stored value or secret is printed (only ticket ids, audit
//! event ids, column names and what is wrong).

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use opsgate_core::json::{canonical_json, parse};
use opsgate_core::time::parse_iso_datetime;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use crate::error::StoreError;
use crate::schema::{self, SchemaObject, normalize_sql};
use crate::ticket::{TicketRow, text_column};

/// Problems listed in the report; the rest are counted.
const MAX_LISTED_PROBLEMS: usize = 50;

/// The result of [`check_db`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub path: PathBuf,
    /// Differences from the schema `init_db` creates.
    pub schema_problems: Vec<String>,
    /// Stored values Rust cannot read (checked only when the schema matches).
    pub row_problems: Vec<String>,
    /// Tickets per state, by state.
    pub ticket_states: Vec<(String, i64)>,
    pub tickets: i64,
    pub audit_events: i64,
    pub ui_session_state: i64,
    pub runner_heartbeats: i64,
}

impl CheckReport {
    /// Whether the database can be served by Rust as it is.
    pub fn is_ok(&self) -> bool {
        self.schema_problems.is_empty() && self.row_problems.is_empty()
    }
}

impl fmt::Display for CheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "database: {}", self.path.display())?;
        let status = |problems: &[String]| if problems.is_empty() { "ok" } else { "FAILED" };
        writeln!(f, "schema: {}", status(&self.schema_problems))?;
        let list = |f: &mut fmt::Formatter<'_>, problems: &[String]| -> fmt::Result {
            for problem in problems.iter().take(MAX_LISTED_PROBLEMS) {
                writeln!(f, "  {problem}")?;
            }
            if problems.len() > MAX_LISTED_PROBLEMS {
                writeln!(f, "  … and {} more", problems.len() - MAX_LISTED_PROBLEMS)?;
            }
            Ok(())
        };
        list(f, &self.schema_problems)?;
        if !self.schema_problems.is_empty() {
            return writeln!(f, "rows: not checked (schema differs)");
        }
        writeln!(f, "rows: {}", status(&self.row_problems))?;
        list(f, &self.row_problems)?;
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
fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
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
    let connection = open_read_only(path)?;
    let mut report = CheckReport {
        path: path.to_owned(),
        schema_problems: schema_problems(&connection)?,
        ..CheckReport::default()
    };
    if !report.schema_problems.is_empty() {
        return Ok(report);
    }
    check_tickets(&connection, &mut report)?;
    check_audit_events(&connection, &mut report)?;
    report.ui_session_state = check_rows(
        &connection,
        "ui_session_state",
        &["username", "password_fingerprint", "updated_at"],
        &["session_generation"],
        &mut report.row_problems,
    )?;
    report.runner_heartbeats = check_rows(
        &connection,
        "runner_heartbeats",
        &["runner_host", "last_heartbeat_at", "updated_at"],
        &[],
        &mut report.row_problems,
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
            problems.push(format!("missing {} {}", object.kind, object.name));
            continue;
        };
        let migrated_form = find(&accepted_too, object);
        if !same(&found, object) && !migrated_form.is_some_and(|form| same(&found, &form)) {
            problems.push(format!(
                "{} {}: definition differs",
                object.kind, object.name
            ));
        }
    }
    for object in &actual {
        if find(&expected, object).is_none() {
            problems.push(format!("unexpected {} {}", object.kind, object.name));
        }
    }
    Ok(problems)
}

/// A decoded JSON value must also be writable again (the checksum and the
/// stored columns): a float that overflows to infinity is not (D-2).
fn json_problem(value: &Value) -> Option<String> {
    canonical_json(value)
        .err()
        .map(|error| format!("{error} (D-2)"))
}

fn check_tickets(connection: &Connection, report: &mut CheckReport) -> Result<(), StoreError> {
    let mut statement =
        connection.prepare("SELECT state, COUNT(*) FROM tickets GROUP BY state ORDER BY state")?;
    let states = statement.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?.unwrap_or_default(),
            row.get::<_, i64>(1)?,
        ))
    })?;
    report.ticket_states = states.collect::<rusqlite::Result<_>>()?;
    report.tickets = report.ticket_states.iter().map(|(_, count)| count).sum();

    let mut statement =
        connection.prepare("SELECT rowid AS _rowid, * FROM tickets ORDER BY rowid")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let ticket = match TicketRow::from_row(row) {
            Ok(ticket) => ticket,
            Err(error) => {
                let rowid: i64 = row.get("_rowid")?;
                report
                    .row_problems
                    .push(format!("tickets rowid {rowid}: {error}"));
                continue;
            }
        };
        let id = &ticket.id;
        for (column, text) in [
            ("execution_plan_json", &ticket.execution_plan_json),
            ("policy_requirements_json", &ticket.policy_requirements_json),
            ("context_json", &ticket.context_json),
            ("tmux_sessions_json", &ticket.tmux_sessions_json),
        ] {
            match parse(text) {
                Err(error) => report
                    .row_problems
                    .push(format!("tickets {id}: {column}: {error}")),
                Ok(value) => {
                    if let Some(problem) = json_problem(&value) {
                        report
                            .row_problems
                            .push(format!("tickets {id}: {column}: {problem}"));
                    }
                }
            }
        }
        if !matches!(
            ticket.max_duration_seconds,
            rusqlite::types::Value::Integer(_)
        ) {
            report.row_problems.push(format!(
                "tickets {id}: max_duration_seconds: not an integer"
            ));
        }
        if let Some(expires_at) = ticket.expires_at.as_deref()
            && !opsgate_core::pytext::strip(expires_at).is_empty()
            && let Err(error) = parse_iso_datetime(expires_at)
        {
            report
                .row_problems
                .push(format!("tickets {id}: expires_at: {error}"));
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
        let key = Some(id.as_str());
        for column in [
            "ticket_id",
            "event_type",
            "actor",
            "timestamp",
            "source_ip",
            "user_agent",
            "previous_state",
            "new_state",
        ] {
            if let Err(error) = text_column(row, "audit_events", key, column) {
                report.row_problems.push(error.to_string());
            }
        }
        match text_column(row, "audit_events", key, "metadata_json") {
            Err(error) => report.row_problems.push(error.to_string()),
            Ok(None) => report
                .row_problems
                .push(format!("audit_events {}: metadata_json: NULL", id)),
            Ok(Some(text)) => {
                let problem = match parse(&text) {
                    Err(error) => Some(error.to_string()),
                    Ok(value) => json_problem(&value),
                };
                if let Some(problem) = problem {
                    report
                        .row_problems
                        .push(format!("audit_events {}: metadata_json: {problem}", id));
                }
            }
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
    problems: &mut Vec<String>,
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
            if let Err(error) = text_column(row, table, Some(&key), column) {
                problems.push(error.to_string());
            }
        }
        for column in integer_columns {
            if !matches!(row.get_ref(*column)?, ValueRef::Integer(_)) {
                problems.push(format!("{table} {key}: {column}: not an integer"));
            }
        }
    }
    Ok(count)
}
