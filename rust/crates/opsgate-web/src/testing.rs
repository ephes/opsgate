//! Test helpers for the web tests of this and later slices (S4b, S5): an
//! authenticated approver session without going through `POST /login`, and
//! reading the session a response set. Minting a cookie needs the session
//! key, i.e. `OPSGATE_SESSION_SECRET`, so these helpers give a test nothing
//! a holder of the secret could not do anyway.

use axum::http::HeaderMap;
use axum::http::header::SET_COOKIE;

use crate::session::{COOKIE_NAME, SessionData, signed_in};
use crate::state::AppState;

/// An approver session: the `Cookie` header value and its CSRF token (as
/// rendered into forms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestSession {
    pub cookie: String,
    pub csrf_token: String,
}

/// The `Cookie` header value carrying `data`.
pub fn session_cookie(state: &AppState, data: &SessionData) -> String {
    format!("{COOKIE_NAME}={}", data.encrypt(state.session_key()))
}

/// A session of the configured approver as `POST /login` creates it: signed
/// in now with the stored session generation and a new CSRF token.
pub fn approver_session(state: &AppState) -> Result<TestSession, Box<dyn std::error::Error>> {
    let username = state.settings().ui_username.clone();
    let generation = state
        .store()
        .ui_session_generation(&username)?
        .ok_or("no session generation for the approver")?;
    let data = signed_in(&username, generation)?;
    Ok(TestSession {
        cookie: session_cookie(state, &data),
        csrf_token: data.csrf_token.clone().unwrap_or_default(),
    })
}

/// What the `Set-Cookie` header of a response does to the session cookie:
/// `None` without one, `Some(None)` for a deletion, `Some(Some(data))` for a
/// new session value.
pub fn session_from_response(state: &AppState, headers: &HeaderMap) -> Option<Option<SessionData>> {
    let header = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{COOKIE_NAME}=")))?;
    let value = header
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value)
        .unwrap_or_default();
    if value.is_empty() {
        return Some(None);
    }
    Some(SessionData::decrypt(value, state.session_key()))
}
