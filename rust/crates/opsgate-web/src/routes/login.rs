//! Login and logout (`ui_login`, `ui_logout`, PLAN.md 4.5.3).
//!
//! `GET`/`HEAD /login` renders the form with the sanitised `next` of the
//! query string; it never counts as an attempt and never flashes; its only
//! side effect is the session's CSRF token (created by the render when the
//! session has none).
//!
//! `POST /login` (after the UI-CSRF layer): the client (its address or
//! `unknown`) locked by the [`crate::throttle`] → 429 with the login page
//! and the flash "Too many failed login attempts. Try again later.", even
//! for correct credentials. Otherwise the stripped username and **always**
//! the bcrypt check ([`crate::password`]); a failure is counted, flashed
//! ("Invalid username or password") and redirected to `/login` (with
//! `?next=` if any); a success needs the stored session generation (else
//! 500 `session_state_missing`, a UI error), resets the throttle, replaces
//! the session (`username`, `auth_at`, the generation, a new CSRF token) and
//! redirects to `next` or `/tickets`. The form's `next` wins over the
//! query's.
//!
//! `POST /logout` (after the UI-CSRF layer): an authenticated session bumps
//! the stored generation (every session of the approver is revoked, also
//! copies of the cookie); the session is cleared either way; 302 `/login`.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use minijinja::value::Value as JinjaValue;
use opsgate_core::pytext::strip;

use crate::client;
use crate::error::{AppError, redirect};
use crate::form::FormData;
use crate::password::{checkpw, credentials_match};
use crate::session::{SessionHandle, session_user, signed_in};
use crate::state::AppState;
use crate::templates::Context;
use crate::urls::{UrlArg, url_for};

/// `sanitize_next_path`: a local path to go to after signing in, or
/// `None`. Stripped; empty, not starting with exactly one `/`, or containing
/// CR, LF, TAB or NUL → `None`.
///
/// Python also runs `urlsplit` and refuses a value with a scheme or a
/// network location; for a value that passes the other checks neither can
/// be present, so the check is implied. Values for which `urlsplit` raises
/// (unbalanced brackets in a network location, …) make Python answer 500;
/// Rust treats them as no `next` (D-18).
pub fn sanitize_next_path(raw: Option<&str>) -> Option<String> {
    let next_path = strip(raw?);
    if next_path.is_empty()
        || !next_path.starts_with('/')
        || next_path.starts_with("//")
        || next_path.contains(['\r', '\n', '\t', '\0'])
    {
        return None;
    }
    Some(next_path.to_owned())
}

/// The `next` of the request's query string, sanitised.
pub fn query_next_path(request: &Request) -> Option<String> {
    sanitize_next_path(FormData::from_query(request.uri().query()).get("next"))
}

/// The login page with `next_path` and `status`.
pub fn login_page_response(
    state: &AppState,
    session: &SessionHandle,
    next_path: Option<String>,
    status: StatusCode,
) -> Result<Response, AppError> {
    let mut context = Context::new();
    context.insert(
        "next_path".to_owned(),
        next_path.map_or_else(|| JinjaValue::from(()), JinjaValue::from),
    );
    state
        .templates()
        .page("login.html", session, context, status)
}

/// `GET`/`HEAD /login`.
pub async fn login_page(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let next_path = query_next_path(&request);
    login_page_response(
        &state,
        &SessionHandle::of(&request),
        next_path,
        StatusCode::OK,
    )
}

/// `POST /login`.
pub async fn login_submit(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let session = SessionHandle::of(&request);
    let query_next = query_next_path(&request);
    // The UI-CSRF layer parsed the form and passed it on.
    let form = request
        .extensions()
        .get::<FormData>()
        .cloned()
        .unwrap_or_default();
    let username = strip(form.get("username").unwrap_or_default()).to_owned();
    let password = form.get("password").unwrap_or_default().to_owned();
    let next_path = sanitize_next_path(form.get("next")).or(query_next);
    let (parts, _body) = request.into_parts();
    let client_ip = client::view(&parts, state.settings()).remote_addr;
    let throttle_key = if client_ip.is_empty() {
        "unknown".to_owned()
    } else {
        client_ip
    };

    if state.login_throttle().is_locked(&throttle_key) {
        session.flash("Too many failed login attempts. Try again later.", "error");
        return login_page_response(&state, &session, next_path, StatusCode::TOO_MANY_REQUESTS);
    }

    let configured_username = state.settings().ui_username.clone();
    let password_bcrypt = state.settings().ui_password_bcrypt.clone();
    let checked_username = username.clone();
    // bcrypt is CPU work: off the async workers, as the store's calls.
    let matches = tokio::task::spawn_blocking(move || {
        credentials_match(
            &checked_username,
            &password,
            &configured_username,
            &password_bcrypt,
            checkpw,
        )
    })
    .await
    .map_err(|error| AppError::Internal(format!("password check task: {error}")))?;

    if !matches {
        state.login_throttle().record_failure(&throttle_key);
        session.flash("Invalid username or password", "error");
        let next = next_path.map_or(UrlArg::None, UrlArg::Text);
        let target = url_for("ui_login", &[("next", next)])
            .map_err(|error| AppError::Internal(format!("url_for: {error}")))?;
        return Ok(redirect(&target));
    }

    let lookup = username.clone();
    let Some(generation) = state
        .blocking(move |store| store.ui_session_generation(&lookup))
        .await?
    else {
        return Err(AppError::service(
            "Approver session state is missing",
            500,
            "session_state_missing",
        ));
    };
    state.login_throttle().reset(&throttle_key);
    let fresh = signed_in(&username, generation)?;
    session.update(|data| *data = fresh);
    Ok(redirect(
        &next_path.unwrap_or_else(|| "/tickets".to_owned()),
    ))
}

/// `POST /logout`.
pub async fn logout(State(state): State<AppState>, request: Request) -> Result<Response, AppError> {
    let session = SessionHandle::of(&request);
    if let Some(user) = session_user(&state, &session).await? {
        // Revoke server-side so a copied cookie stops working too; only an
        // authenticated session may do this, so an anonymous caller cannot
        // sign the approver out.
        state
            .blocking(move |store| store.revoke_ui_sessions(&user))
            .await?;
    }
    session.clear();
    Ok(redirect("/login"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_path_sanitising() {
        for (raw, expected) in [
            (Some("/tickets/abc"), Some("/tickets/abc")),
            (
                Some("  /tickets?view=all \u{a0}"),
                Some("/tickets?view=all"),
            ),
            (Some("https://example.com/x"), None),
            (Some("//evil.example/x"), None),
            (Some("javascript:alert(1)"), None),
            (Some("/tickets/a\r\nb"), None),
            (Some("/tickets/a\tb"), None),
            (Some("/tickets/a\0b"), None),
            (Some("tickets"), None),
            (Some("   "), None),
            (Some("/"), Some("/")),
            (Some("/a:b//c"), Some("/a:b//c")),
            (Some("\u{1}/x"), None),
            (None, None),
        ] {
            assert_eq!(sanitize_next_path(raw).as_deref(), expected, "{raw:?}");
        }
    }
}
