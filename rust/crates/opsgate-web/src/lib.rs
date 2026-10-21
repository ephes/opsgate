//! HTTP API and web UI of the OpsGate Rust port (`rust/PLAN.md` section 0):
//! network gate, authentication, sessions, CSRF, the routes of 4.3 and the
//! Jinja templates shared with the Python implementation (6.3).
//!
//! Slice S4a lands the shared foundations: the router ([`app`]) with the
//! request processing order of 4.4 (path decoding, security headers, the
//! session cookie, error mapping, the network gate, the UI-CSRF check), the
//! JSON body rules (4.6), the approver session ([`session`]), the template
//! environment ([`templates`]), `GET`/`HEAD /login` and the bearer routes
//! (ticket create and get, runner claim and status, health). Slice S4b adds
//! `POST /login` with the bcrypt check and the login throttle ([`password`],
//! [`throttle`]), `POST /logout` with the revocation, the API-CSRF check
//! ([`csrf::enforce_api_session_csrf`]) and the cookie-authenticated API
//! actions; slice S5 adds its routes to [`routes::router`] and gets every
//! layer for free.

pub mod body;
pub mod client;
pub mod csrf;
pub mod error;
pub mod form;
pub mod gate;
pub mod headers;
pub mod password;
pub mod path;
pub mod routes;
pub mod session;
pub mod state;
pub mod templates;
pub mod testing;
pub mod throttle;
pub mod urls;

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;
use axum::middleware::{from_fn, from_fn_with_state};
use tokio::net::TcpListener;

pub use error::AppError;
pub use state::AppState;

/// Largest request body read (D-5): 8 MiB, larger bodies are answered 413.
pub const BODY_LIMIT: usize = 8 * 1024 * 1024;

/// The whole application: the routes of [`routes::router`] behind the
/// request processing order of PLAN.md 4.4. The layers wrap the router as a
/// whole, so they also apply to unknown paths (404) and wrong methods (405),
/// as Flask's `before_request` and `after_request` hooks do.
///
/// Outermost first: path decoding ([`path`], before routing, as Werkzeug
/// matches the decoded path), security headers ([`headers`], on every
/// response), the session cookie ([`session`]), error mapping ([`error`]),
/// the network gate ([`gate`]), the UI-CSRF check ([`csrf`]), then the
/// routes.
pub fn app(state: AppState) -> Router {
    let routes = routes::router(state.clone());
    Router::new()
        .fallback_service(routes)
        .layer(from_fn(csrf::enforce_ui_csrf))
        .layer(from_fn_with_state(
            state.clone(),
            gate::enforce_network_gate,
        ))
        .layer(from_fn(error::map_errors))
        .layer(from_fn_with_state(state, session::session_layer))
        .layer(from_fn(headers::add_security_headers))
        .layer(from_fn(path::decode_path))
}

/// Serves [`app`] on `listener` until `shutdown` completes; requests in
/// flight then finish (the caller bounds how long it waits, PLAN.md 4.1).
pub async fn serve(
    listener: TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
