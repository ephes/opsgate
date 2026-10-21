//! Ticket rows and their JSON shape (PLAN.md 4.6, 4.7): `SELECT * FROM
//! tickets`, `_serialize_ticket`, `get_ticket`, `list_tickets`.
//!
//! Ported Python (`service.py`): `OPEN_TICKET_STATES`, `TERMINAL_STATES`,
//! `ARCHIVABLE_STATES`, `_select_ticket`, `_serialize_ticket`, `get_ticket`,
//! `list_tickets`.

use opsgate_core::error::ServiceError;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::{Map, Number, Value};

use crate::error::{StoreError, Unreadable};

/// `OPEN_TICKET_STATES`: at most one of these per `(source, task_ref)`
/// outside archived tickets (the dedupe index).
pub const OPEN_TICKET_STATES: [&str; 3] = ["pending_approval", "approved", "running"];

/// `TERMINAL_STATES`.
pub const TERMINAL_STATES: [&str; 5] = ["succeeded", "failed", "rejected", "canceled", "expired"];

/// `ARCHIVABLE_STATES`: the terminal states and `pending_approval`.
pub fn is_archivable_state(state: &str) -> bool {
    TERMINAL_STATES.contains(&state) || state == "pending_approval"
}

/// `state in TERMINAL_STATES`.
pub fn is_terminal_state(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

/// `state in OPEN_TICKET_STATES`.
pub fn is_open_state(state: &str) -> bool {
    OPEN_TICKET_STATES.contains(&state)
}

/// One row of `tickets` as stored. The JSON columns keep their text; they
/// are decoded when the row is serialised (or validated by claim, S3b).
#[derive(Debug, Clone, PartialEq)]
pub struct TicketRow {
    pub id: String,
    pub source: String,
    pub task_ref: Option<String>,
    pub title: String,
    pub summary: String,
    pub execution_plan_json: String,
    pub policy_requirements_json: String,
    pub context_json: String,
    pub payload_checksum: String,
    pub approved_payload_checksum: Option<String>,
    pub state: String,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
    pub expires_at: Option<String>,
    /// An `INTEGER` column, but SQLite keeps a value of another storage
    /// class that does not convert; Python passes it through unchanged.
    pub max_duration_seconds: SqlValue,
    pub tmux_sessions_json: String,
    pub runner_host: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub result: Option<String>,
    pub result_detail: Option<String>,
    pub archived_at: Option<String>,
    pub archived_by: Option<String>,
}

/// Reads a text column. Every text column of the schema has `TEXT`
/// affinity, so SQLite stores numbers given to it as text; only `NULL` and a
/// BLOB remain, and a BLOB (or text that is not UTF-8) is unreadable, as it
/// is in Python (`bytes` is no JSON value; `sqlite3` fails to decode the
/// text).
pub(crate) fn text_column(
    row: &Row<'_>,
    table: &'static str,
    key: Option<&str>,
    column: &str,
) -> Result<Option<String>, StoreError> {
    let unreadable = |reason: &str| Unreadable {
        table,
        key: key.map(str::to_owned),
        column: column.to_owned(),
        reason: reason.to_owned(),
    };
    match row.get_ref(column)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map(|text| Some(text.to_owned()))
            .map_err(|_| unreadable("text is not UTF-8").into()),
        // Impossible under `TEXT` affinity; kept apart from the text values.
        ValueRef::Integer(_) | ValueRef::Real(_) => {
            Err(unreadable("a numeric value in a text column").into())
        }
        ValueRef::Blob(_) => Err(unreadable("a BLOB value in a text column").into()),
    }
}

/// A text column declared `NOT NULL`.
fn required_text(row: &Row<'_>, key: Option<&str>, column: &str) -> Result<String, StoreError> {
    text_column(row, "tickets", key, column)?.ok_or_else(|| {
        Unreadable {
            table: "tickets",
            key: key.map(str::to_owned),
            column: column.to_owned(),
            reason: "NULL in a NOT NULL column".to_owned(),
        }
        .into()
    })
}

impl TicketRow {
    /// Reads a row of `SELECT * FROM tickets` by column name.
    pub fn from_row(row: &Row<'_>) -> Result<Self, StoreError> {
        let id = required_text(row, None, "id")?;
        let key = Some(id.as_str());
        let text = |column: &str| text_column(row, "tickets", key, column);
        let required = |column: &str| required_text(row, key, column);
        Ok(Self {
            source: required("source")?,
            task_ref: text("task_ref")?,
            title: required("title")?,
            summary: required("summary")?,
            execution_plan_json: required("execution_plan_json")?,
            policy_requirements_json: required("policy_requirements_json")?,
            context_json: required("context_json")?,
            payload_checksum: required("payload_checksum")?,
            approved_payload_checksum: text("approved_payload_checksum")?,
            state: required("state")?,
            created_by: required("created_by")?,
            created_at: required("created_at")?,
            approved_by: text("approved_by")?,
            approved_at: text("approved_at")?,
            expires_at: text("expires_at")?,
            max_duration_seconds: row.get("max_duration_seconds")?,
            tmux_sessions_json: required("tmux_sessions_json")?,
            runner_host: text("runner_host")?,
            last_heartbeat_at: text("last_heartbeat_at")?,
            started_at: text("started_at")?,
            finished_at: text("finished_at")?,
            result: text("result")?,
            result_detail: text("result_detail")?,
            archived_at: text("archived_at")?,
            archived_by: text("archived_by")?,
            id,
        })
    }

    fn unreadable(&self, column: &str, reason: impl Into<String>) -> StoreError {
        Unreadable {
            table: "tickets",
            key: Some(self.id.clone()),
            column: column.to_owned(),
            reason: reason.into(),
        }
        .into()
    }

    /// `json.loads(row[column])` of one of the JSON columns (Rust's rules of
    /// 4.6: D-2 texts are unreadable).
    pub fn json_column(&self, column: &str, text: &str) -> Result<Value, StoreError> {
        opsgate_core::json::parse(text).map_err(|error| self.unreadable(column, error.to_string()))
    }

    /// `bool(row["archived_at"])`.
    pub fn is_archived(&self) -> bool {
        self.archived_at
            .as_deref()
            .is_some_and(|text| !text.is_empty())
    }

    /// `_serialize_ticket`: the stored columns with the JSON columns decoded
    /// and the derived flags `is_archived`, `is_terminal`, `is_archivable`
    /// (4.6).
    pub fn serialize(&self) -> Result<Map<String, Value>, StoreError> {
        let execution_plan = self.json_column("execution_plan_json", &self.execution_plan_json)?;
        let policy_requirements =
            self.json_column("policy_requirements_json", &self.policy_requirements_json)?;
        let context = self.json_column("context_json", &self.context_json)?;
        let tmux_sessions = self.json_column("tmux_sessions_json", &self.tmux_sessions_json)?;
        let max_duration_seconds = match &self.max_duration_seconds {
            SqlValue::Null => Value::Null,
            SqlValue::Integer(value) => Value::from(*value),
            // SQLite stores no NaN; an infinity has no JSON form either way.
            SqlValue::Real(value) => Number::from_f64(*value)
                .map(Value::Number)
                .ok_or_else(|| self.unreadable("max_duration_seconds", "not a finite number"))?,
            SqlValue::Text(text) => Value::String(text.clone()),
            SqlValue::Blob(_) => {
                return Err(self.unreadable("max_duration_seconds", "a BLOB value"));
            }
        };
        let text = |value: &str| Value::String(value.to_owned());
        let optional = |value: &Option<String>| value.as_deref().map_or(Value::Null, text);
        let is_archived = self.is_archived();
        let mut ticket = Map::new();
        ticket.insert("id".into(), text(&self.id));
        ticket.insert("source".into(), text(&self.source));
        ticket.insert("task_ref".into(), optional(&self.task_ref));
        ticket.insert("title".into(), text(&self.title));
        ticket.insert("summary".into(), text(&self.summary));
        ticket.insert("execution_plan".into(), execution_plan);
        ticket.insert("policy_requirements".into(), policy_requirements);
        ticket.insert("context".into(), context);
        ticket.insert("payload_checksum".into(), text(&self.payload_checksum));
        ticket.insert(
            "approved_payload_checksum".into(),
            optional(&self.approved_payload_checksum),
        );
        ticket.insert("state".into(), text(&self.state));
        ticket.insert("created_by".into(), text(&self.created_by));
        ticket.insert("created_at".into(), text(&self.created_at));
        ticket.insert("approved_by".into(), optional(&self.approved_by));
        ticket.insert("approved_at".into(), optional(&self.approved_at));
        ticket.insert("expires_at".into(), optional(&self.expires_at));
        ticket.insert("max_duration_seconds".into(), max_duration_seconds);
        ticket.insert("tmux_sessions".into(), tmux_sessions);
        ticket.insert("runner_host".into(), optional(&self.runner_host));
        ticket.insert(
            "last_heartbeat_at".into(),
            optional(&self.last_heartbeat_at),
        );
        ticket.insert("started_at".into(), optional(&self.started_at));
        ticket.insert("finished_at".into(), optional(&self.finished_at));
        ticket.insert("result".into(), optional(&self.result));
        ticket.insert("result_detail".into(), optional(&self.result_detail));
        ticket.insert("archived_at".into(), optional(&self.archived_at));
        ticket.insert("archived_by".into(), optional(&self.archived_by));
        ticket.insert("is_archived".into(), Value::Bool(is_archived));
        ticket.insert(
            "is_terminal".into(),
            Value::Bool(is_terminal_state(&self.state)),
        );
        ticket.insert(
            "is_archivable".into(),
            Value::Bool(is_archivable_state(&self.state) && !is_archived),
        );
        Ok(ticket)
    }
}

/// `_select_ticket`: the row with this id, if any.
pub(crate) fn select_ticket(
    connection: &Connection,
    ticket_id: &str,
) -> Result<Option<TicketRow>, StoreError> {
    let mut statement = connection.prepare("SELECT * FROM tickets WHERE id = ?")?;
    let row = statement
        .query_row([ticket_id], |row| Ok(TicketRow::from_row(row)))
        .optional()?;
    row.transpose()
}

/// Reads every row of a `SELECT * FROM tickets …` query.
pub(crate) fn select_tickets(
    connection: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<TicketRow>, StoreError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(params)?;
    let mut tickets = Vec::new();
    while let Some(row) = rows.next()? {
        tickets.push(TicketRow::from_row(row)?);
    }
    Ok(tickets)
}

/// `ServiceError("Ticket not found", 404, "ticket_not_found")`.
pub fn ticket_not_found() -> ServiceError {
    ServiceError::new("Ticket not found", 404, "ticket_not_found")
}

/// Which tickets `list_tickets` returns (`LIST_ARCHIVED_*`; the UI's `view`
/// `active`, `archived`, `all`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArchivedFilter {
    /// `exclude`: not archived (the default).
    #[default]
    Exclude,
    /// `only`: archived.
    Only,
    /// `include`: all.
    Include,
}

impl ArchivedFilter {
    fn where_clause(self) -> &'static str {
        match self {
            Self::Exclude => "WHERE archived_at IS NULL",
            Self::Only => "WHERE archived_at IS NOT NULL",
            Self::Include => "",
        }
    }
}

/// `list_tickets`: the newest `limit` tickets by `created_at` (text order,
/// 4.9), filtered by archive state.
pub(crate) fn list_tickets(
    connection: &Connection,
    limit: i64,
    archived: ArchivedFilter,
) -> Result<Vec<Map<String, Value>>, StoreError> {
    let sql = format!(
        "SELECT * FROM tickets {} ORDER BY created_at DESC LIMIT ?",
        archived.where_clause()
    );
    select_tickets(connection, &sql, [limit])?
        .iter()
        .map(TicketRow::serialize)
        .collect()
}
