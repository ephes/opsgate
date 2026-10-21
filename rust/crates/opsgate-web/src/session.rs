//! The approver session (PLAN.md 4.5.2, D-1): Flask's session dict in an
//! encrypted cookie, flashes, the session CSRF token, and the approver
//! check `get_session_user`.
//!
//! The state is the content of Flask's session: `username`, `auth_at`,
//! `session_generation`, `csrf_token` and `_flashes`. It travels in the
//! cookie `session` as JSON, encrypted and authenticated with the `cookie`
//! crate's private jar (AES-256-GCM, the cookie name as associated data;
//! axum-extra's `PrivateCookieJar` wraps the same jar) under a key derived
//! from `OPSGATE_SESSION_SECRET` with HKDF-SHA256 and a fixed label. A
//! cookie that is missing, does not decrypt or does not decode is an empty
//! session.
//!
//! As with Flask's `SecureCookieSessionInterface`, the cookie is written
//! only when the session changed during the request: a non-empty session is
//! set (`HttpOnly`, `SameSite=Lax`, `Secure` iff
//! `OPSGATE_SESSION_COOKIE_SECURE`, `Path=/`, no `Expires`/`Max-Age`), a
//! session emptied during the request is deleted with the same attributes.
//! Any write, also `clear()` of an empty session, counts as a change.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cookie::time::{Duration, OffsetDateTime};
use cookie::{Cookie, CookieJar, Key, SameSite};
use hkdf::Hkdf;
use opsgate_core::time::{isoformat_z, parse_iso_datetime, utc_now};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::AppError;
use crate::state::AppState;

/// The session cookie's name (Flask's default).
pub const COOKIE_NAME: &str = "session";

/// HKDF `info` of the cookie key: changing it signs every approver out.
const KEY_LABEL: &[u8] = b"opsgate session cookie v1 (rust/PLAN.md 4.5.2)";

/// The cookie key for `OPSGATE_SESSION_SECRET` (HKDF-SHA256 without salt,
/// 64 bytes: the private jar uses the second half for AES-256-GCM).
pub fn session_key(secret: &str) -> Key {
    let mut master = [0_u8; 64];
    Hkdf::<Sha256>::new(None, secret.as_bytes())
        .expand(KEY_LABEL, &mut master)
        .unwrap_or_else(|_| unreachable!("64 bytes are a valid HKDF-SHA256 output length"));
    Key::from(&master)
}

/// The content of a session (Flask's session dict).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// `isoformat_z` of the sign-in time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// `(category, message)` pairs not shown yet.
    #[serde(rename = "_flashes", default, skip_serializing_if = "Vec::is_empty")]
    pub flashes: Vec<(String, String)>,
}

impl SessionData {
    /// `not session`.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The cookie value of this session under `key`.
    pub fn encrypt(&self, key: &Key) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut jar = CookieJar::new();
        jar.private_mut(key).add(Cookie::new(COOKIE_NAME, json));
        jar.get(COOKIE_NAME)
            .map(|cookie| cookie.value().to_owned())
            .unwrap_or_default()
    }

    /// The session in an encrypted cookie value, or `None` when the value
    /// does not decrypt under `key` or does not decode.
    pub fn decrypt(value: &str, key: &Key) -> Option<Self> {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new(COOKIE_NAME, value.to_owned()));
        let cookie = jar.private(key).get(COOKIE_NAME)?;
        serde_json::from_str(cookie.value()).ok()
    }

    /// The session of a request: the first `session` cookie of its `Cookie`
    /// headers, decrypted; empty when there is none or it is unusable.
    pub fn from_headers(headers: &HeaderMap, key: &Key) -> Self {
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| Cookie::split_parse(value.to_owned()))
            .filter_map(Result::ok)
            .find(|cookie| cookie.name() == COOKIE_NAME)
            .and_then(|cookie| Self::decrypt(cookie.value(), key))
            .unwrap_or_default()
    }
}

/// The session of one request with its change flag and the flashes
/// `get_flashed_messages` already took.
#[derive(Debug, Default)]
struct SessionState {
    data: SessionData,
    modified: bool,
    shown_flashes: Option<Vec<(String, String)>>,
}

/// The request's session, shared by the layers, the handlers and the
/// template functions of one request.
#[derive(Debug, Clone, Default)]
pub struct SessionHandle(Arc<Mutex<SessionState>>);

impl SessionHandle {
    /// A handle on `data`, unchanged so far.
    pub fn new(data: SessionData) -> Self {
        Self(Arc::new(Mutex::new(SessionState {
            data,
            ..SessionState::default()
        })))
    }

    /// The handle [`session_layer`] put into the request (an empty one when
    /// the layer did not run).
    pub fn of(request: &Request) -> Self {
        request
            .extensions()
            .get::<SessionHandle>()
            .cloned()
            .unwrap_or_default()
    }

    /// As [`SessionHandle::of`] for request parts.
    pub fn from_parts(parts: &Parts) -> Self {
        parts
            .extensions
            .get::<SessionHandle>()
            .cloned()
            .unwrap_or_default()
    }

    fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the session's content.
    pub fn data(&self) -> SessionData {
        self.lock().data.clone()
    }

    /// Whether the session changed during the request.
    pub fn is_modified(&self) -> bool {
        self.lock().modified
    }

    /// Changes the session (any change marks it modified).
    pub fn update<T>(&self, change: impl FnOnce(&mut SessionData) -> T) -> T {
        let mut state = self.lock();
        state.modified = true;
        change(&mut state.data)
    }

    /// `session.clear()`.
    pub fn clear(&self) {
        self.update(|data| *data = SessionData::default());
    }

    /// `ensure_csrf_token`: the session's CSRF token, created
    /// (`secrets.token_urlsafe(32)`) when the session has none.
    pub fn ensure_csrf_token(&self) -> Result<String, AppError> {
        let mut state = self.lock();
        if let Some(token) = state
            .data
            .csrf_token
            .as_ref()
            .filter(|token| !token.is_empty())
        {
            return Ok(token.clone());
        }
        let token = new_csrf_token()?;
        state.modified = true;
        state.data.csrf_token = Some(token.clone());
        Ok(token)
    }

    /// `flash(message, category)`.
    pub fn flash(&self, message: &str, category: &str) {
        self.update(|data| {
            data.flashes.push((category.to_owned(), message.to_owned()));
        });
    }

    /// `get_flashed_messages()`: the first call of a request takes the
    /// flashes out of the session (a change only when there were any); later
    /// calls of the same request return the same list.
    pub fn flashed_messages(&self) -> Vec<(String, String)> {
        let mut state = self.lock();
        if let Some(shown) = &state.shown_flashes {
            return shown.clone();
        }
        let flashes = if state.data.flashes.is_empty() {
            Vec::new()
        } else {
            state.modified = true;
            std::mem::take(&mut state.data.flashes)
        };
        state.shown_flashes = Some(flashes.clone());
        flashes
    }

    /// The `Set-Cookie` header the response needs, if any.
    pub fn set_cookie_header(&self, key: &Key, secure: bool) -> Option<HeaderValue> {
        let state = self.lock();
        if !state.modified {
            return None;
        }
        let mut cookie = if state.data.is_empty() {
            let mut cookie = Cookie::new(COOKIE_NAME, "");
            cookie.set_max_age(Duration::ZERO);
            cookie.set_expires(OffsetDateTime::UNIX_EPOCH);
            cookie
        } else {
            Cookie::new(COOKIE_NAME, state.data.encrypt(key))
        };
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Lax);
        cookie.set_secure(secure);
        cookie.set_path("/");
        HeaderValue::try_from(cookie.to_string()).ok()
    }
}

/// A new CSRF token: 32 random bytes, URL-safe base64 without padding
/// (`secrets.token_urlsafe(32)`, 43 characters).
fn new_csrf_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| AppError::Internal(format!("random source: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The layer: opens the session from the request's cookie, hands the
/// [`SessionHandle`] to everything inside, and writes the cookie afterwards.
pub async fn session_layer(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let handle = SessionHandle::new(SessionData::from_headers(
        request.headers(),
        state.session_key(),
    ));
    request.extensions_mut().insert(handle.clone());
    let mut response = next.run(request).await;
    if let Some(cookie) =
        handle.set_cookie_header(state.session_key(), state.settings().session_cookie_secure)
    {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

/// The largest `OPSGATE_UI_SESSION_TIMEOUT_SECONDS` magnitude Python's
/// `timedelta(seconds=…)` accepts (999 999 999 days); beyond it Python
/// raises `OverflowError` for every session check (500).
const MAX_TIMEDELTA_SECONDS: i64 = 999_999_999 * 86_400 + 86_399;

/// `get_session_user`: the approver's name if the session is authenticated
/// (PLAN.md 4.5.2), else `None`. A session that names the approver but
/// fails a later check (no or unparsable `auth_at`, timed out, no integer
/// generation or one that differs from the stored generation) is cleared.
pub async fn session_user(
    state: &AppState,
    session: &SessionHandle,
) -> Result<Option<String>, AppError> {
    let data = session.data();
    let configured = &state.settings().ui_username;
    let Some(username) = data.username.filter(|name| name == configured) else {
        return Ok(None);
    };
    let Some(auth_at) = data.auth_at.and_then(|raw| parse_iso_datetime(&raw).ok()) else {
        session.clear();
        return Ok(None);
    };
    let timeout = state.settings().session_timeout_seconds;
    if !(-MAX_TIMEDELTA_SECONDS..=MAX_TIMEDELTA_SECONDS).contains(&timeout) {
        return Err(AppError::Internal(
            "OPSGATE_UI_SESSION_TIMEOUT_SECONDS is outside Python's timedelta range".to_owned(),
        ));
    }
    if timed_out(utc_now() - auth_at, timeout) {
        session.clear();
        return Ok(None);
    }
    let lookup = username.clone();
    let current = state
        .blocking(move |store| store.ui_session_generation(&lookup))
        .await?;
    match (data.session_generation, current) {
        (Some(generation), Some(current)) if generation == current => Ok(Some(username)),
        _ => {
            session.clear();
            Ok(None)
        }
    }
}

/// `elapsed > timedelta(seconds=timeout)`, compared in microseconds.
fn timed_out(elapsed: chrono::TimeDelta, timeout: i64) -> bool {
    let elapsed = i128::from(elapsed.num_microseconds().unwrap_or(i64::MAX));
    elapsed > i128::from(timeout) * 1_000_000
}

/// The approver of an authenticated session, or `None` (`get_session_user`
/// as an extractor, for routes that treat both cases themselves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalApprover(pub Option<String>);

impl FromRequestParts<AppState> for OptionalApprover {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let session = SessionHandle::from_parts(parts);
        Ok(Self(session_user(state, &session).await?))
    }
}

/// The approver of a cookie-authenticated API call
/// (`require_approver_session`): without an authenticated session the
/// request fails with 401 `auth_required`, then the API-CSRF check
/// ([`crate::csrf::enforce_api_session_csrf`], 403 `csrf_required` or
/// `invalid_csrf`) runs, both before the body is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver(pub String);

impl FromRequestParts<AppState> for Approver {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let Some(user) = OptionalApprover::from_request_parts(parts, state).await?.0 else {
            return Err(AppError::service(
                "Authentication required",
                401,
                "auth_required",
            ));
        };
        crate::csrf::enforce_api_session_csrf(
            parts,
            &SessionHandle::from_parts(parts),
            state.settings(),
        )?;
        Ok(Self(user))
    }
}

/// The session content of a freshly signed-in approver (`ui_login` after a
/// successful check): the session cleared, then `username`, `auth_at`, the
/// stored generation and a new CSRF token.
pub fn signed_in(username: &str, generation: i64) -> Result<SessionData, AppError> {
    Ok(SessionData {
        username: Some(username.to_owned()),
        auth_at: Some(isoformat_z(&utc_now())),
        session_generation: Some(generation),
        csrf_token: Some(new_csrf_token()?),
        flashes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trip_and_tampering() {
        let key = session_key("x".repeat(32).as_str());
        let data = SessionData {
            username: Some("opsgate-admin".to_owned()),
            csrf_token: Some("token".to_owned()),
            flashes: vec![("error".to_owned(), "Invalid form token".to_owned())],
            ..SessionData::default()
        };
        let value = data.encrypt(&key);
        assert_eq!(SessionData::decrypt(&value, &key), Some(data.clone()));
        assert_eq!(
            SessionData::decrypt(&value, &session_key("y".repeat(32).as_str())),
            None
        );
        let mut tampered = value.into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            SessionData::decrypt(std::str::from_utf8(&tampered).unwrap(), &key),
            None
        );
        assert_eq!(SessionData::decrypt("not a cookie", &key), None);
    }

    #[test]
    fn the_first_session_cookie_counts() {
        let key = session_key("secret-secret-secret-secret");
        let first = SessionData {
            csrf_token: Some("a".to_owned()),
            ..SessionData::default()
        };
        let second = SessionData {
            csrf_token: Some("b".to_owned()),
            ..SessionData::default()
        };
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::try_from(format!(
                "other=1; session={}; session={}",
                first.encrypt(&key),
                second.encrypt(&key)
            ))
            .unwrap(),
        );
        assert_eq!(SessionData::from_headers(&headers, &key), first);
        assert!(SessionData::from_headers(&HeaderMap::new(), &key).is_empty());
    }

    #[test]
    fn changes_and_cookie_headers() {
        let key = session_key("secret-secret-secret-secret");
        let session = SessionHandle::default();
        assert_eq!(session.set_cookie_header(&key, false), None);
        // Reading flashes of a session without any is no change.
        assert!(session.flashed_messages().is_empty());
        assert_eq!(session.set_cookie_header(&key, false), None);

        let token = session.ensure_csrf_token().unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(session.ensure_csrf_token().unwrap(), token);
        let header = session.set_cookie_header(&key, true).unwrap();
        let header = header.to_str().unwrap();
        assert!(header.starts_with("session="), "{header}");
        for attribute in ["HttpOnly", "SameSite=Lax", "Secure", "Path=/"] {
            assert!(header.contains(attribute), "{header}");
        }
        assert!(!header.contains("Max-Age") && !header.contains("Expires"));

        session.clear();
        let header = session.set_cookie_header(&key, false).unwrap();
        let header = header.to_str().unwrap();
        assert!(header.starts_with("session=;"), "{header}");
        for attribute in [
            "HttpOnly",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=0",
            "Expires=",
        ] {
            assert!(header.contains(attribute), "{header}");
        }
        assert!(!header.contains("Secure"), "{header}");
    }

    #[test]
    fn flashes_are_taken_once_per_request() {
        let session = SessionHandle::default();
        session.flash("first", "error");
        let shown = session.flashed_messages();
        assert_eq!(shown, vec![("error".to_owned(), "first".to_owned())]);
        // A flash after the first call stays for the next request.
        session.flash("second", "error");
        assert_eq!(session.flashed_messages(), shown);
        assert_eq!(
            session.data().flashes,
            vec![("error".to_owned(), "second".to_owned())]
        );
    }

    #[test]
    fn timeout_comparison_is_exact() {
        let second = chrono::TimeDelta::seconds(1);
        assert!(!timed_out(second * 60, 60));
        assert!(timed_out(
            second * 60 + chrono::TimeDelta::microseconds(1),
            60
        ));
        assert!(timed_out(chrono::TimeDelta::zero(), -1));
    }
}
