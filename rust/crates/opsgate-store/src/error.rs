//! Errors of the store: a domain [`ServiceError`] (status and code, PLAN.md
//! 4.4) or a failure Python lets escape as an unhandled exception (a SQLite
//! error, an I/O error creating the database directory, a stored row that
//! cannot be read), which the web layer answers with 500 (4.4).

use std::fmt;

use opsgate_core::error::ServiceError;

/// Why a store operation failed.
#[derive(Debug)]
pub enum StoreError {
    /// A rejected operation (`ServiceError`): `{"error", "message"}` with its
    /// status on `/api/…`, a flash on UI routes.
    Service(ServiceError),
    /// SQLite failed (busy beyond the timeout, I/O, corruption). Python:
    /// `sqlite3.Error`, unhandled → 500.
    Sqlite(rusqlite::Error),
    /// Creating the database directory failed (`Path.mkdir`, at start).
    Io(std::io::Error),
    /// A stored value that neither Python nor Rust can use as stored, or that
    /// Rust cannot read (D-2): undecodable JSON, a value of the wrong
    /// storage class, an unparsable `expires_at`. Python: unhandled → 500.
    Unreadable(Unreadable),
}

/// The stored value [`StoreError::Unreadable`] is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// `tickets`, `audit_events`, …
    pub table: &'static str,
    /// The row's key where it has one (ticket id, audit event id).
    pub key: Option<String>,
    pub column: String,
    /// What is wrong with the value (never the value itself).
    pub reason: String,
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.table)?;
        if let Some(key) = &self.key {
            write!(f, " {key}")?;
        }
        write!(f, ": {}: {}", self.column, self.reason)
    }
}

impl StoreError {
    /// The domain error, if this is one; everything else is a 500.
    pub fn service(&self) -> Option<&ServiceError> {
        match self {
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(error) => write!(f, "{} ({}): {}", error.code, error.status, error),
            Self::Sqlite(error) => write!(f, "SQLite: {error}"),
            Self::Io(error) => write!(f, "I/O: {error}"),
            Self::Unreadable(unreadable) => write!(f, "unreadable stored value: {unreadable}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Service(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Unreadable(_) => None,
        }
    }
}

impl From<ServiceError> for StoreError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Unreadable> for StoreError {
    fn from(unreadable: Unreadable) -> Self {
        Self::Unreadable(unreadable)
    }
}
