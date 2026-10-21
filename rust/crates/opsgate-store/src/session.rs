//! The approver's session generation (PLAN.md 4.5.2): one row per username in
//! `ui_session_state`, created at start, bumped when the password hash
//! changed and on logout; a session is valid only with the current
//! generation.
//!
//! Ported Python (`service.py`): `_ui_password_fingerprint`,
//! `_sync_ui_session_state`, `get_ui_session_generation`,
//! `revoke_ui_sessions`.

use opsgate_core::error::ServiceError;
use opsgate_core::json::sha256_hex;
use opsgate_core::time::{isoformat_z, utc_now};
use rusqlite::{Connection, OptionalExtension};
use subtle::ConstantTimeEq;

use crate::connection::write_transaction;
use crate::error::StoreError;

/// `_ui_password_fingerprint`: SHA-256 hex of the bcrypt hash string, so
/// switching implementations with an unchanged password keeps the
/// generation (4.5.2).
pub fn password_fingerprint(password_bcrypt: &str) -> String {
    sha256_hex(password_bcrypt.as_bytes())
}

/// `_sync_ui_session_state`: create the row with generation 1, or bump the
/// generation when the stored fingerprint differs (constant-time compare).
pub(crate) fn sync(
    connection: &mut Connection,
    username: &str,
    password_bcrypt: &str,
) -> Result<(), StoreError> {
    let fingerprint = password_fingerprint(password_bcrypt);
    let now = isoformat_z(&utc_now());
    let transaction = write_transaction(connection)?;
    let stored: Option<String> = transaction
        .query_row(
            "SELECT session_generation, password_fingerprint FROM ui_session_state WHERE username = ?",
            [username],
            |row| row.get::<_, String>(1),
        )
        .optional()?;
    match stored {
        None => {
            transaction.execute(
                "INSERT INTO ui_session_state (username, session_generation, password_fingerprint, updated_at) \
                 VALUES (?, 1, ?, ?)",
                (username, &fingerprint, &now),
            )?;
        }
        Some(stored) if !bool::from(stored.as_bytes().ct_eq(fingerprint.as_bytes())) => {
            transaction.execute(
                "UPDATE ui_session_state SET session_generation = session_generation + 1, \
                 password_fingerprint = ?, updated_at = ? WHERE username = ?",
                (&fingerprint, &now, username),
            )?;
        }
        Some(_) => {}
    }
    transaction.commit()?;
    Ok(())
}

/// `get_ui_session_generation`: the current generation, `None` without a row.
pub(crate) fn generation(
    connection: &Connection,
    username: &str,
) -> Result<Option<i64>, StoreError> {
    Ok(connection
        .query_row(
            "SELECT session_generation FROM ui_session_state WHERE username = ?",
            [username],
            |row| row.get(0),
        )
        .optional()?)
}

/// `revoke_ui_sessions`: bump the generation (every outstanding session of
/// `username` becomes invalid) and return the new one; without a row nothing
/// changes and the answer is 400 `unknown_approver`.
pub(crate) fn revoke(connection: &mut Connection, username: &str) -> Result<i64, StoreError> {
    let now = isoformat_z(&utc_now());
    let transaction = write_transaction(connection)?;
    transaction.execute(
        "UPDATE ui_session_state SET session_generation = session_generation + 1, updated_at = ? \
         WHERE username = ?",
        (&now, username),
    )?;
    let generation = generation(&transaction, username)?;
    transaction.commit()?;
    generation.ok_or_else(|| ServiceError::new("Unknown approver", 400, "unknown_approver").into())
}
