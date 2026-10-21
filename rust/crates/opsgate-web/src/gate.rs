//! The network gate (`enforce_tailscale_context`, PLAN.md 4.4 step 2).
//!
//! Before every request except `GET /api/v1/health` (the path only, any
//! method): with `OPSGATE_REQUIRE_TAILSCALE_CONTEXT`, a client address
//! outside every configured network is refused with 403, as JSON
//! (`{"error": "forbidden", "message": "Access denied"}`) on `/api/…` and
//! as the `forbidden.html` page elsewhere. The address is the socket peer's
//! (forwarded headers never count, 4.4 step 1); a scope id (`%…`) is
//! ignored; an empty address is refused; an IPv4-mapped IPv6 address does
//! not match an IPv4 network (Python's `ipaddress`).

use std::net::IpAddr;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use serde_json::json;

use crate::client;
use crate::error::{AppError, json_response};
use crate::path::RequestPath;
use crate::session::SessionHandle;
use crate::state::AppState;
use crate::templates::Context;

/// The path exempt from the gate.
pub const HEALTH_PATH: &str = "/api/v1/health";

/// `is_allowed_network` for the client address `client_ip`.
pub fn is_allowed_network(client_ip: &str, networks: &[IpNet]) -> bool {
    if client_ip.is_empty() {
        return false;
    }
    let host = client_ip.split('%').next().unwrap_or_default();
    host.parse::<IpAddr>()
        .is_ok_and(|address| networks.iter().any(|network| network.contains(&address)))
}

/// The layer.
pub async fn enforce_network_gate(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = RequestPath::of(&request);
    if path == HEALTH_PATH || !state.settings().require_tailscale_context {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let client_ip = client::view(&parts, state.settings()).remote_addr;
    if is_allowed_network(&client_ip, &state.settings().allowed_networks) {
        return next.run(Request::from_parts(parts, body)).await;
    }
    if path.starts_with("/api/") {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "forbidden", "message": "Access denied"}),
        );
    }
    let session = SessionHandle::from_parts(&parts);
    state
        .templates()
        .page(
            "forbidden.html",
            &session,
            Context::new(),
            StatusCode::FORBIDDEN,
        )
        .unwrap_or_else(AppError::into_response)
}
