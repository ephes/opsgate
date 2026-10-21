//! The routes of PLAN.md 4.3. Slice S4a: the bearer routes and health
//! ([`api`]) and the login page ([`login`]); slice S4b: `POST /login`,
//! `POST /logout` and the approver's API actions; slice S5 adds its routes
//! here. Every route sits behind the layers of [`crate::app`].
//!
//! Routing follows Werkzeug's rules: `{ticket_id}` is one path segment, no
//! trailing-slash variants, `HEAD` answers every `GET` route, an unknown
//! path is 404 and a known path with another method 405 (bodies P2, D-9).
//! Like Flask, every route also answers `OPTIONS` with 200 and an `Allow`
//! header ([`allow`]; later slices add it to their routes too). A path with
//! repeated slashes that matches a route once they are merged
//! (`/api//v1/health`) is a 308 redirect to the merged URL, or 405 when the
//! method is not the route's (Werkzeug's `merge_slashes`); it is answered
//! after the gate and the UI-CSRF check, as Werkzeug's routing exceptions
//! are.

pub mod api;
pub mod login;

use std::sync::LazyLock;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{ALLOW, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use percent_encoding::utf8_percent_encode;
use regex::Regex;
use tower::ServiceExt;

use crate::client;
use crate::error::redirect_with_status;
use crate::path::{PATH_SAFE, RequestPath};
use crate::state::AppState;

/// The `Allow` value of a `GET` route.
const GET_ALLOW: &str = "GET, HEAD, OPTIONS";
/// The `Allow` value of a `POST` route.
const POST_ALLOW: &str = "OPTIONS, POST";
/// The `Allow` value of a `GET` and `POST` route.
const GET_POST_ALLOW: &str = "GET, HEAD, OPTIONS, POST";

/// The routes with their state.
pub fn router(state: AppState) -> Router {
    let routes = Router::new()
        .route("/api/v1/health", allow(get(api::health), GET_ALLOW))
        .route(
            "/api/v1/tickets",
            allow(post(api::create_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}",
            allow(get(api::get_ticket), GET_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}/approve",
            allow(post(api::approve_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}/reject",
            allow(post(api::reject_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}/cancel",
            allow(post(api::cancel_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}/archive",
            allow(post(api::archive_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/tickets/{ticket_id}/unarchive",
            allow(post(api::unarchive_ticket), POST_ALLOW),
        )
        .route(
            "/api/v1/runner/claim",
            allow(post(api::runner_claim), POST_ALLOW),
        )
        .route(
            "/api/v1/runner/{ticket_id}/status",
            allow(post(api::runner_status), POST_ALLOW),
        )
        .route(
            "/login",
            allow(
                get(login::login_page).post(login::login_submit),
                GET_POST_ALLOW,
            ),
        )
        .route("/logout", allow(post(login::logout), POST_ALLOW));
    let probe = routes.clone().with_state(state.clone());
    routes
        .fallback(move |request: Request| not_found(probe.clone(), request))
        .with_state(state)
}

/// `route` plus Flask's automatic `OPTIONS` (200, empty body, `Allow`) and
/// the answer to the repeated-slash probe of [`not_found`]. Every route of
/// [`router`] goes through it.
pub fn allow(route: MethodRouter<AppState>, methods: &'static str) -> MethodRouter<AppState> {
    route
        .options(
            // Flask's empty response keeps its default `text/html` type.
            move || async move {
                (
                    StatusCode::OK,
                    [
                        (ALLOW, HeaderValue::from_static(methods)),
                        (
                            CONTENT_TYPE,
                            HeaderValue::from_static("text/html; charset=utf-8"),
                        ),
                    ],
                )
            },
        )
        .route_layer(from_fn(answer_probe))
}

/// Marks a request that only asks whether a route would take it.
#[derive(Debug, Clone, Copy)]
struct Probe;

/// Answers a [`Probe`] request with 204 instead of running the route (a
/// method router's route layer runs only for the methods the route has, so
/// a probe with another method gets the route's 405).
async fn answer_probe(request: Request, next: Next) -> Response {
    if request.extensions().get::<Probe>().is_some() {
        return StatusCode::NO_CONTENT.into_response();
    }
    next.run(request).await
}

static REPEATED_SLASHES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("/{2,}").unwrap_or_else(|error| panic!("pattern: {error}")));

/// No route matched: 404, unless merging repeated slashes finds a route
/// (Werkzeug's `merge_slashes`): then 308 to the merged URL (absolute, with
/// the query string) if the route takes the method, else its 405.
async fn not_found(probe: Router, request: Request) -> Response {
    let path = RequestPath::of(&request);
    if !path.contains("//") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let merged =
        utf8_percent_encode(&REPEATED_SLASHES.replace_all(&path, "/"), PATH_SAFE).to_string();
    let Ok(uri) = Uri::try_from(merged.as_str()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut question = Request::builder()
        .method(request.method().clone())
        .uri(uri)
        .body(Body::empty())
        .unwrap_or_default();
    question.extensions_mut().insert(Probe);
    let answer = match probe.oneshot(question).await {
        Ok(answer) => answer,
        Err(never) => match never {},
    };
    match answer.status() {
        StatusCode::NO_CONTENT => {
            let host =
                client::header(request.headers(), "host").unwrap_or_else(|| "localhost".to_owned());
            let query = request
                .uri()
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default();
            redirect_with_status(
                &format!("http://{host}{merged}{query}"),
                StatusCode::PERMANENT_REDIRECT,
            )
        }
        StatusCode::METHOD_NOT_ALLOWED => answer,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
