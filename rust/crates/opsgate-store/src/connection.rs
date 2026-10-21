//! Connections as `service.py:OpsGateService._connection` and
//! `_write_transaction` open them (PLAN.md 4.7, 4.10): one connection per
//! operation, journal mode WAL, foreign keys on, a 5 s busy timeout, and
//! mutating operations inside `BEGIN IMMEDIATE`.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

/// `sqlite3.connect(path, timeout=30)`: a path, never a URI (Python passes
/// `uri=False`), created when missing.
const READ_WRITE_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_CREATE)
    .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// The statements `_connection` runs on every new connection, verbatim. The
/// 30 s timeout of `sqlite3.connect` applies while they run (switching an
/// existing database to WAL waits for its lock); the last one lowers it to
/// 5 s for everything after.
const CONNECTION_PRAGMAS: &str =
    "PRAGMA journal_mode=WAL;\nPRAGMA foreign_keys=ON;\nPRAGMA busy_timeout=5000;";

/// `_connection()`: open (and create) the database and apply the pragmas.
pub(crate) fn connect(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(path, READ_WRITE_FLAGS)?;
    connection.busy_timeout(Duration::from_secs(30))?;
    connection.execute_batch(CONNECTION_PRAGMAS)?;
    Ok(connection)
}

/// `_write_transaction()`: `BEGIN IMMEDIATE`, so the read, the state check
/// and the write of an operation are serialised against every other writer.
/// Dropping the transaction without committing rolls it back.
pub(crate) fn write_transaction(connection: &mut Connection) -> rusqlite::Result<Transaction<'_>> {
    connection.transaction_with_behavior(TransactionBehavior::Immediate)
}
