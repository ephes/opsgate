//! The routes of PLAN.md 4.3. Slice S4a: the bearer routes and health
//! ([`api`]) and the login page ([`login`]); slices S4b and S5 add theirs
//! here. Every route sits behind the layers of [`crate::app`].
//!
//! Routing follows Werkzeug's rules: `{ticket_id}` is one path segment, no
//! trailing-slash variants, `HEAD` answers every `GET` route, an unknown
//! path is 404 and a known path with another method 405 (bodies P2, D-9).

pub mod api;
pub mod login;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};

use crate::state::AppState;

/// The routes with their state.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(api::health))
        .route("/api/v1/tickets", post(api::create_ticket))
        .route("/api/v1/tickets/{ticket_id}", get(api::get_ticket))
        .route("/api/v1/runner/claim", post(api::runner_claim))
        .route(
            "/api/v1/runner/{ticket_id}/status",
            post(api::runner_status),
        )
        .route("/login", get(login::login_page))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state)
}
