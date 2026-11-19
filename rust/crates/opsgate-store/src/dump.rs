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
//! written to it. The dump contains prompts and contexts and is staged with
//! mode 0600 before being published under a new name.

use std::fs::File;
use std::io::{self, BufWriter, Write};
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

/// [`dump_tickets`] into a private sibling file, then publish it at `dump`
/// without overwriting. Sync the file before publication and the directory
/// before returning success.
pub fn dump_to_file(path: &Path, dump: &Path) -> Result<DumpSummary, StoreError> {
    publish_dump(dump, |file| dump_tickets(path, &mut BufWriter::new(file)))
}

fn publish_dump(
    dump: &Path,
    write: impl FnOnce(&mut File) -> Result<DumpSummary, StoreError>,
) -> Result<DumpSummary, StoreError> {
    // Fail early for existing destinations, including dangling symlinks.
    match dump.symlink_metadata() {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = dump
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)?;
    let mut staged = tempfile::Builder::new()
        .prefix(".opsgate-dump-")
        .tempfile_in(parent)?;
    let summary = write(staged.as_file_mut())?;
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(dump)
        .map_err(|error| error.error)?;
    directory.sync_all()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_dump_leaves_destination_unpublished() {
        const CHILD_DESTINATION: &str = "OPSGATE_INTERRUPTED_DUMP_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_DESTINATION) {
            let _ = publish_dump(Path::new(&path), |file| {
                file.write_all(b"{\"rowid\":1}\n{\"rowid\":2}\n{\"rowid\":3}\n")
                    .unwrap();
                // Exit without running file or staging destructors.
                std::process::exit(17);
            });
            panic!("dump writer did not run");
        }

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("dump.jsonl");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dump::tests::interrupted_dump_leaves_destination_unpublished",
            ])
            .env(CHILD_DESTINATION, &destination)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(17));
        assert!(
            !destination.exists(),
            "interrupted dump exposed incomplete output"
        );
        publish_dump(&destination, |_| Ok(DumpSummary::default())).unwrap();
    }

    #[test]
    fn dump_promotion_preserves_competing_output() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("dump.jsonl");
        let result = publish_dump(&destination, |file| {
            file.write_all(b"staged output")?;
            std::fs::File::create_new(&destination)?.write_all(b"competing output")?;
            Ok(DumpSummary::default())
        });
        assert!(
            matches!(result, Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"competing output");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
