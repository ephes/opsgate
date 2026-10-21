//! `opsgate check-db --db <path> --dump <file>` (PLAN.md 11.2 step 1): the
//! data-parity record of a database copy. One JSON line per ticket, in
//! `rowid` order, with its serialisation as `GET /api/v1/tickets/<id>`
//! returns it, the payload checksum approval recomputes from the stored
//! fields, and whether that matches the stored `approved_payload_checksum`.
//! `rust/parity/shadow/serialize_python.py` writes the same records with the
//! Python service and `rust/parity/shadow/compare_dump.py` compares both;
//! zero differences and every approval that matched in Python matching in
//! Rust is the acceptance of 11.2.
//!
//! Record keys (values compared semantically, formatting is P2):
//!
//! - `rowid`, `id` (`null` when the row cannot be read at all);
//! - `ticket`: the serialised ticket, or `null` with `ticket_error`;
//! - `approval_checksum`: hex, or `null` with `approval_checksum_error`
//!   (the `ServiceError` code, or `"unhandled"` where Python raises any
//!   other exception: Rust's unreadable values);
//! - `approved_payload_checksum`: as stored;
//! - `approval_checksum_matches`: the stored checksum is non-empty and
//!   equals the recomputed one (what the claim's tamper check requires,
//!   4.7.3).
//!
//! The database is opened read-only as `check-db` opens it; nothing is
//! written to it. The dump contains prompts and contexts: it is created new
//! (never overwriting a file) with mode 0600.

use std::io::Write;
use std::path::Path;

use rusqlite::types::ValueRef;
use serde_json::{Map, Value};

use crate::check::open_read_only;
use crate::error::StoreError;
use crate::ticket::TicketRow;
use crate::transitions::approval_checksum;

/// What a failure is recorded as: the domain error's code, or
/// `"unhandled"` (a 500 in the API).
fn error_kind(error: &StoreError) -> Value {
    Value::from(error.service().map_or("unhandled", |error| error.code))
}

/// The record of one `tickets` row.
fn record(rowid: i64, row: Result<TicketRow, StoreError>) -> Map<String, Value> {
    let mut record = Map::new();
    record.insert("rowid".into(), Value::from(rowid));
    let row = match row {
        Ok(row) => row,
        Err(error) => {
            for key in [
                "id",
                "ticket",
                "approval_checksum",
                "approved_payload_checksum",
            ] {
                record.insert(key.into(), Value::Null);
            }
            record.insert("ticket_error".into(), error_kind(&error));
            record.insert("approval_checksum_error".into(), error_kind(&error));
            record.insert("approval_checksum_matches".into(), Value::Bool(false));
            return record;
        }
    };
    record.insert("id".into(), Value::String(row.id.clone()));
    match row.serialize() {
        Ok(ticket) => {
            record.insert("ticket".into(), Value::Object(ticket));
            record.insert("ticket_error".into(), Value::Null);
        }
        Err(error) => {
            record.insert("ticket".into(), Value::Null);
            record.insert("ticket_error".into(), error_kind(&error));
        }
    }
    let stored = row.approved_payload_checksum.clone();
    let matches = match approval_checksum(&row) {
        Ok(checksum) => {
            let matches = stored
                .as_deref()
                .is_some_and(|stored| !stored.is_empty() && stored == checksum);
            record.insert("approval_checksum".into(), Value::String(checksum));
            record.insert("approval_checksum_error".into(), Value::Null);
            matches
        }
        Err(error) => {
            record.insert("approval_checksum".into(), Value::Null);
            record.insert("approval_checksum_error".into(), error_kind(&error));
            false
        }
    };
    record.insert(
        "approved_payload_checksum".into(),
        stored.map_or(Value::Null, Value::String),
    );
    record.insert("approval_checksum_matches".into(), Value::Bool(matches));
    record
}

/// Counts of a dump.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DumpSummary {
    pub tickets: usize,
    /// Tickets with a stored approval checksum.
    pub approved: usize,
    /// Of those, the ones whose recomputed checksum matches.
    pub matching: usize,
}

/// Writes the records of every ticket of the database at `path` to `out`
/// (JSON lines).
pub fn dump_tickets(path: &Path, out: &mut impl Write) -> Result<DumpSummary, StoreError> {
    let connection = open_read_only(path)?;
    let mut statement =
        connection.prepare("SELECT rowid AS _rowid, * FROM tickets ORDER BY rowid")?;
    let mut rows = statement.query([])?;
    let mut summary = DumpSummary::default();
    while let Some(row) = rows.next()? {
        let rowid = match row.get_ref("_rowid")? {
            ValueRef::Integer(rowid) => rowid,
            _ => -1,
        };
        let record = record(rowid, TicketRow::from_row(row));
        summary.tickets += 1;
        if record["approved_payload_checksum"]
            .as_str()
            .is_some_and(|stored| !stored.is_empty())
        {
            summary.approved += 1;
        }
        if record["approval_checksum_matches"] == Value::Bool(true) {
            summary.matching += 1;
        }
        let line = serde_json::to_string(&Value::Object(record))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        writeln!(out, "{line}")?;
    }
    out.flush()?;
    Ok(summary)
}

/// [`dump_tickets`] into a new file `dump` (mode 0600; an existing file is
/// an error, never overwritten). A dump that fails is removed again.
pub fn dump_to_file(path: &Path, dump: &Path) -> Result<DumpSummary, StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(dump)?;
    let mut writer = std::io::BufWriter::new(file);
    let written = dump_tickets(path, &mut writer).and_then(|summary| {
        writer
            .into_inner()
            .map_err(|error| error.into_error())?
            .sync_all()?;
        Ok(summary)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(dump);
    }
    written
}
