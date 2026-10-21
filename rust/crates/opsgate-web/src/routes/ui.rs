//! The approver's pages and form actions (PLAN.md 4.3, 4.11; slice S5):
//! `GET /`, `GET|POST /tickets` (the ticket list and the manual ticket
//! form), `GET /tickets/{id}` (the detail page), `GET
//! /tickets/{id}/steps/{n}/log` (the step log page) and the `POST` actions
//! approve, reject, cancel, archive and unarchive.
//!
//! Every route sits behind the layers of [`crate::app`]: the network gate,
//! the UI-CSRF check (every `POST` here; the parsed form travels in the
//! request extensions) and the error mapping, which turns a
//! `ServiceError` into a flash and a redirect to the ticket's detail page
//! (actions, step log) or to `/tickets` (4.4). Without an approver session
//! the pages and actions redirect to `/login` (the detail and step log pages
//! with `next` set to the request path), as in Python.

use std::sync::LazyLock;

use axum::Router;
use axum::extract::rejection::RawPathParamsRejection;
use axum::extract::{Path, RawPathParams, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use minijinja::value::Value as JinjaValue;
use opsgate_core::log_preview::read_step_log;
use opsgate_core::pytext::{py_lower, strip};
use opsgate_core::settings::{MAX_DURATION_SECONDS, py_int_decimal};
use opsgate_core::validate::{SUPPORTED_AGENTS, py_truthy, require_reviewer_step_floor_for_source};
use opsgate_store::{ArchivedFilter, Store, StoreError, Ticket};
use regex::Regex;
use serde_json::Value;

use crate::body::read_body;
use crate::client::{self, user_agent};
use crate::error::{AppError, redirect};
use crate::form::FormData;
use crate::manual_form::{self, ROLE_PROMPT_SCAFFOLDING, prompt_scaffolding_for_role};
use crate::path::RequestPath;
use crate::routes::{GET_ALLOW, POST_ALLOW, allow};
use crate::session::{SessionHandle, session_user};
use crate::state::AppState;
use crate::step_logs::{resolve_log_path, session_for_step, session_views};
use crate::templates::{Context, to_template_value};
use crate::urls::{UrlArg, url_for};

/// The `Allow` value of `/tickets`.
const TICKETS_ALLOW: &str = "GET, HEAD, OPTIONS, POST";

/// The routes of this module.
pub fn routes() -> Router<AppState> {
    let step_log = Router::new()
        .route(
            "/tickets/{ticket_id}/steps/{step_number}/log",
            allow(get(step_log_page), GET_ALLOW),
        )
        .route_layer(from_fn(require_int_step));
    Router::new()
        .route("/", allow(get(root), GET_ALLOW))
        .route(
            "/tickets",
            allow(get(tickets_page).post(create_manual_ticket), TICKETS_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}",
            allow(get(ticket_detail_page), GET_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}/approve",
            allow(post(approve), POST_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}/reject",
            allow(post(reject), POST_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}/cancel",
            allow(post(cancel), POST_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}/archive",
            allow(post(archive), POST_ALLOW),
        )
        .route(
            "/tickets/{ticket_id}/unarchive",
            allow(post(unarchive), POST_ALLOW),
        )
        .merge(step_log)
}

/// `url_for(endpoint, **args)` of a handler: a build error is a 500.
fn url(endpoint: &str, args: &[(&str, UrlArg)]) -> Result<String, AppError> {
    url_for(endpoint, args).map_err(|error| AppError::Internal(format!("url_for: {error}")))
}

/// `redirect(url_for("ui_login"))`.
fn to_login() -> Result<Response, AppError> {
    Ok(redirect(&url("ui_login", &[])?))
}

/// `redirect(url_for("ui_login", next=request.path))`.
fn to_login_with_next(path: &str) -> Result<Response, AppError> {
    Ok(redirect(&url("ui_login", &[("next", UrlArg::from(path))])?))
}

/// `get_session_user()` of the request.
async fn approver(state: &AppState, parts: &Parts) -> Result<Option<String>, AppError> {
    session_user(state, &SessionHandle::from_parts(parts)).await
}

/// Runs file-system work on the blocking pool.
async fn blocking_fs<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|error| Err(AppError::Internal(format!("file task: {error}"))))
}

/// `GET /` (`ui_root`): to the ticket list with an approver session, else to
/// the login page.
pub async fn root(State(state): State<AppState>, request: Request) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    match approver(&state, &parts).await? {
        Some(_) => Ok(redirect(&url("ui_tickets", &[])?)),
        None => to_login(),
    }
}

/// The list's `view` (`active`, `archived`, `all`): the query's `view`
/// stripped and lowercased, `active` for anything else.
fn ticket_view(query: Option<&str>) -> &'static str {
    let args = FormData::from_query(query);
    let view = py_lower(strip(args.get("view").unwrap_or("active")));
    match view.as_str() {
        "archived" => "archived",
        "all" => "all",
        _ => "active",
    }
}

/// The operator's reviewer floor (`require_reviewer_step_floor_for_source`).
fn operator_requires_reviewer(state: &AppState) -> bool {
    require_reviewer_step_floor_for_source(&state.settings().submitter_policies, "operator")
}

/// `render_tickets_page`: the 100 newest tickets of the query's `view`, the
/// manual ticket form with `form_data`, with `status`.
async fn render_tickets_page(
    state: &AppState,
    parts: &Parts,
    form_data: Value,
    status: StatusCode,
) -> Result<Response, AppError> {
    let view = ticket_view(parts.uri.query());
    let filter = match view {
        "archived" => ArchivedFilter::Only,
        "all" => ArchivedFilter::Include,
        _ => ArchivedFilter::Exclude,
    };
    let tickets = state
        .blocking(move |store| store.list_tickets(100, filter))
        .await?;
    let floor = operator_requires_reviewer(state);
    let mut context = Context::new();
    context.insert(
        "tickets".to_owned(),
        to_template_value(&Value::Array(
            tickets.into_iter().map(Value::Object).collect(),
        )),
    );
    context.insert("ticket_view".to_owned(), JinjaValue::from(view));
    context.insert("form_data".to_owned(), to_template_value(&form_data));
    context.insert(
        "operator_requires_reviewer".to_owned(),
        JinjaValue::from(floor),
    );
    context.insert(
        "max_duration_seconds_limit".to_owned(),
        JinjaValue::from(MAX_DURATION_SECONDS),
    );
    context.insert(
        "role_agent_defaults".to_owned(),
        to_template_value(&manual_form::role_agent_defaults()),
    );
    context.insert(
        "role_prompt_scaffolding".to_owned(),
        to_template_value(&Value::Object(ROLE_PROMPT_SCAFFOLDING.clone())),
    );
    context.insert(
        "supported_agents".to_owned(),
        JinjaValue::from(SUPPORTED_AGENTS.to_vec()),
    );
    context.insert(
        "prompt_scaffolding_for_role".to_owned(),
        JinjaValue::from_function(|role: JinjaValue| {
            let role = role
                .as_str()
                .map_or_else(|| role.to_string(), str::to_owned);
            to_template_value(prompt_scaffolding_for_role(&role))
        }),
    );
    state.templates().page(
        "tickets.html",
        &SessionHandle::from_parts(parts),
        context,
        status,
    )
}

/// `GET /tickets` (`ui_tickets`): the ticket list and the manual ticket
/// form. Werkzeug parses a form body of any method, so a `GET` with one
/// fills the form with it.
pub async fn tickets_page(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    if approver(&state, &parts).await?.is_none() {
        return to_login();
    }
    let form = FormData::from_body(&parts.headers, &read_body(body).await?);
    let form_data = manual_form::form_data(&form, operator_requires_reviewer(&state))?;
    render_tickets_page(&state, &parts, form_data, StatusCode::OK).await
}

/// `POST /tickets` (`ui_tickets`): creates a manual ticket from the form
/// (source `operator`, created by the approver) and redirects to it with the
/// flash "Ticket created and queued for approval"; a rejected form renders
/// the list again with status 400, the error flashed and the form as sent.
pub async fn create_manual_ticket(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let Some(approver) = approver(&state, &parts).await? else {
        return to_login();
    };
    let form = parts
        .extensions
        .get::<FormData>()
        .cloned()
        .unwrap_or_default();
    let floor = operator_requires_reviewer(&state);
    let form_data = manual_form::form_data(&form, floor)?;
    let created = match manual_form::payload(&form, floor) {
        Ok(payload) => {
            let client_ip = client::view(&parts, state.settings()).remote_addr;
            let agent = user_agent(&parts.headers);
            state
                .blocking(move |store| {
                    store.create_manual_ticket(
                        &payload,
                        &approver,
                        Some(&client_ip),
                        agent.as_deref(),
                    )
                })
                .await
        }
        Err(error) => Err(error),
    };
    let session = SessionHandle::from_parts(&parts);
    match created {
        Ok(ticket) => {
            session.flash("Ticket created and queued for approval", "success");
            let id = ticket.get("id").and_then(Value::as_str).unwrap_or_default();
            Ok(redirect(&url(
                "ui_ticket_detail",
                &[("ticket_id", UrlArg::from(id))],
            )?))
        }
        Err(AppError::Service(error)) => {
            session.flash(&error.message, "error");
            render_tickets_page(&state, &parts, form_data, StatusCode::BAD_REQUEST).await
        }
        Err(other) => Err(other),
    }
}

/// `GET /tickets/{id}` (`ui_ticket_detail`): the ticket with its step
/// sessions and log previews, the actions its state offers and the link
/// back to the active or archived list.
pub async fn ticket_detail_page(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    let path = RequestPath::of(&request);
    let (parts, _body) = request.into_parts();
    if approver(&state, &parts).await?.is_none() {
        return to_login_with_next(&path);
    }
    let ticket = state
        .blocking(move |store| store.get_ticket(&ticket_id))
        .await?;
    let archived = ticket.get("is_archived").is_some_and(py_truthy);
    let back = url(
        "ui_tickets",
        &[(
            "view",
            UrlArg::from(if archived { "archived" } else { "active" }),
        )],
    )?;
    let execution_data_dir = state.settings().execution_data_dir.clone();
    let (ticket, views) = blocking_fs(move || {
        let views = session_views(&execution_data_dir, &ticket)?;
        Ok((ticket, views))
    })
    .await?;
    let mut context = Context::new();
    context.insert(
        "ticket".to_owned(),
        to_template_value(&Value::Object(ticket)),
    );
    context.insert("tickets_back_href".to_owned(), JinjaValue::from(back));
    context.insert(
        "session_views".to_owned(),
        to_template_value(&Value::Array(views)),
    );
    state.templates().page(
        "ticket_detail.html",
        &SessionHandle::from_parts(&parts),
        context,
        StatusCode::OK,
    )
}

/// Werkzeug's `<int:…>` converter: `\d+` (any Unicode decimal digits, as
/// Python's `re`) converted with `int()`; a value `int()` rejects (more than
/// 4300 digits) does not match either.
static INT_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A\d+\z").unwrap_or_else(|error| panic!("pattern: {error}")));

/// The step number of the step log path as `int()` gives it, or `None` when
/// the segment does not match the `<int:step_number>` converter.
fn int_step(segment: &str) -> Option<String> {
    INT_SEGMENT
        .is_match(segment)
        .then(|| py_int_decimal(segment))
        .flatten()
}

/// The step log route matches only when its step segment is an integer
/// (for every method, so `OPTIONS` and other methods are 404 too).
async fn require_int_step(
    params: Result<RawPathParams, RawPathParamsRejection>,
    request: Request,
    next: Next,
) -> Response {
    let matches = params.is_ok_and(|params| {
        params
            .iter()
            .find(|(name, _)| *name == "step_number")
            .and_then(|(_, value)| int_step(value))
            .is_some()
    });
    if matches {
        next.run(request).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `GET /tickets/{id}/steps/{n}/log` (`ui_ticket_step_log`): the final 2 MiB
/// of the step's log file (4.12). No step `n` (or `n` = 0) is 404
/// `log_not_found`, a log path outside the ticket's artifact root 400
/// `invalid_log_path`, a missing file 404 `log_not_found`; each is flashed
/// on the detail page.
pub async fn step_log_page(
    State(state): State<AppState>,
    Path((ticket_id, step_segment)): Path<(String, String)>,
    request: Request,
) -> Result<Response, AppError> {
    let path = RequestPath::of(&request);
    let (parts, _body) = request.into_parts();
    if approver(&state, &parts).await?.is_none() {
        return to_login_with_next(&path);
    }
    let step_number = int_step(&step_segment)
        .ok_or_else(|| AppError::Internal("step segment is no integer".to_owned()))?;
    let lookup = ticket_id.clone();
    let ticket = state
        .blocking(move |store| store.get_ticket(&lookup))
        .await?;
    let execution_data_dir = state.settings().execution_data_dir.clone();
    let number = step_number.clone();
    let (ticket, meta, log_path, log_text) = blocking_fs(move || {
        let meta = session_for_step(&ticket, &number)?;
        let log_path = resolve_log_path(&execution_data_dir, &ticket_id, &meta)?;
        let log_text = read_step_log(&log_path)
            .map_err(|error| AppError::Internal(format!("step log: {error}")))?;
        Ok((ticket, meta, log_path, log_text))
    })
    .await?;
    let mut context = Context::new();
    context.insert(
        "ticket".to_owned(),
        to_template_value(&Value::Object(ticket)),
    );
    context.insert(
        "session".to_owned(),
        to_template_value(&Value::Object(meta)),
    );
    context.insert(
        "step_number".to_owned(),
        to_template_value(&crate::pyint::decimal_value(&step_number)),
    );
    context.insert("log_text".to_owned(), JinjaValue::from(log_text));
    context.insert(
        "log_path".to_owned(),
        JinjaValue::from(log_path.to_string_lossy().into_owned()),
    );
    state.templates().page(
        "ticket_log.html",
        &SessionHandle::from_parts(&parts),
        context,
        StatusCode::OK,
    )
}

/// An approver action of the detail page or the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Approve,
    Reject,
    Cancel,
    Archive,
    Unarchive,
}

/// What the store records about the caller of an action.
struct Caller {
    approver: String,
    client_ip: String,
    user_agent: Option<String>,
}

impl Action {
    fn run(
        self,
        store: &Store,
        ticket_id: &str,
        caller: &Caller,
        reason: &str,
    ) -> Result<Ticket, StoreError> {
        let ip = Some(caller.client_ip.as_str());
        let agent = caller.user_agent.as_deref();
        let approver = caller.approver.as_str();
        match self {
            Self::Approve => store.approve_ticket(ticket_id, approver, ip, agent),
            Self::Reject => store.reject_ticket(ticket_id, approver, reason, ip, agent),
            Self::Cancel => store.cancel_ticket(ticket_id, approver, reason, ip, agent),
            Self::Archive => store.archive_ticket(ticket_id, approver, ip, agent),
            Self::Unarchive => store.unarchive_ticket(ticket_id, approver, ip, agent),
        }
    }
}

/// `ui_ticket_action_redirect_path`: the form's `redirect_to` if it
/// sanitises (`sanitize_next_path`) and starts with `/tickets`, else the
/// ticket's detail page.
fn action_redirect_path(form: &FormData, ticket_id: &str) -> Result<String, AppError> {
    match crate::routes::login::sanitize_next_path(form.get("redirect_to")) {
        Some(target) if target.starts_with("/tickets") => Ok(target),
        _ => url(
            "ui_ticket_detail",
            &[("ticket_id", UrlArg::from(ticket_id))],
        ),
    }
}

/// The `POST /tickets/{id}/<action>` routes (`ui_ticket_approve`, …): without
/// an approver session to the login page; reject and cancel take the form's
/// `reason` (stripped; empty stores the default reason); then to the detail
/// page, or for archive and unarchive to [`action_redirect_path`]. A
/// rejected action is flashed on the detail page (error mapping, 4.4).
async fn act(
    state: AppState,
    ticket_id: String,
    request: Request,
    action: Action,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let Some(approver) = approver(&state, &parts).await? else {
        return to_login();
    };
    let form = parts
        .extensions
        .get::<FormData>()
        .cloned()
        .unwrap_or_default();
    let reason = strip(form.get("reason").unwrap_or_default()).to_owned();
    let caller = Caller {
        approver,
        client_ip: client::view(&parts, state.settings()).remote_addr,
        user_agent: user_agent(&parts.headers),
    };
    let id = ticket_id.clone();
    state
        .blocking(move |store| action.run(store, &id, &caller, &reason))
        .await?;
    let target = match action {
        Action::Archive | Action::Unarchive => action_redirect_path(&form, &ticket_id)?,
        Action::Approve | Action::Reject | Action::Cancel => url(
            "ui_ticket_detail",
            &[("ticket_id", UrlArg::from(ticket_id.as_str()))],
        )?,
    };
    Ok(redirect(&target))
}

/// `POST /tickets/{id}/approve`.
pub async fn approve(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    act(state, ticket_id, request, Action::Approve).await
}

/// `POST /tickets/{id}/reject` (form field `reason`).
pub async fn reject(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    act(state, ticket_id, request, Action::Reject).await
}

/// `POST /tickets/{id}/cancel` (form field `reason`).
pub async fn cancel(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    act(state, ticket_id, request, Action::Cancel).await
}

/// `POST /tickets/{id}/archive` (form field `redirect_to`).
pub async fn archive(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    act(state, ticket_id, request, Action::Archive).await
}

/// `POST /tickets/{id}/unarchive` (form field `redirect_to`).
pub async fn unarchive(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    act(state, ticket_id, request, Action::Unarchive).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views() {
        for (query, expected) in [
            (None, "active"),
            (Some("view=archived"), "archived"),
            (Some("view=%20ALL%20"), "all"),
            (Some("view=archived&view=all"), "archived"),
            (Some("view=other"), "active"),
            (Some("view="), "active"),
        ] {
            assert_eq!(ticket_view(query), expected, "{query:?}");
        }
    }

    #[test]
    fn int_steps() {
        assert_eq!(int_step("1").as_deref(), Some("1"));
        assert_eq!(int_step("007").as_deref(), Some("7"));
        assert_eq!(int_step("0").as_deref(), Some("0"));
        assert_eq!(int_step("\u{661}\u{662}").as_deref(), Some("12"));
        assert_eq!(int_step(&"1".repeat(4300)).map(|n| n.len()), Some(4300));
        for segment in ["", "a", "1a", "-1", "+1", " 1", "1_0", &"1".repeat(4301)] {
            assert_eq!(int_step(segment), None, "{segment:?}");
        }
    }
}
