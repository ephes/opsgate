//! `service.py:ServiceError`: a domain error with an HTTP status and a stable
//! error code (PLAN.md 4.4). Status and code are the contract (P1); the
//! message is free text (P2), kept equal to Python's where that is free.

/// A rejected operation: `{"error": code, "message": message}` with `status`
/// on `/api/…`, a flash message on UI routes (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ServiceError {
    /// `ServiceError(message, status_code, error_code)`, Python's argument
    /// order.
    pub fn new(message: impl Into<String>, status: u16, code: &'static str) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}
