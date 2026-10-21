//! The login page (`ui_login` for `GET`/`HEAD`, PLAN.md 4.5.3): the form
//! with the sanitised `next` of the query string. It never counts as an
//! attempt and never flashes; its only side effect is the session's CSRF
//! token (created by the render when the session has none). `POST /login`
//! is slice S4b's.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use minijinja::value::Value as JinjaValue;
use opsgate_core::pytext::strip;

use crate::error::AppError;
use crate::form::FormData;
use crate::session::SessionHandle;
use crate::state::AppState;
use crate::templates::Context;

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
