//! The API routes (PLAN.md 4.3). Bearer routes and health (S4a):
//! `GET /api/v1/health`, `POST /api/v1/tickets`, `GET /api/v1/tickets/{id}`,
//! `POST /api/v1/runner/claim`, `POST /api/v1/runner/{id}/status`. The
//! approver's cookie-authenticated actions (S4b):
//! `POST /api/v1/tickets/{id}/{approve,reject,cancel,archive,unarchive}`.
//!
//! Each route makes its checks in Python's order: the token or the approver
//! session (401) and, for the approver, the API-CSRF check (403) before the
//! body is read, then the body (400 `invalid_json`), then the store. The
//! client address of the audit rows is the socket peer's (4.4 step 1).

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::body::{
    object_or_empty, parse_request_json, read_body, require_object, runner_host, text_field,
};
use crate::client::{self, authenticate_submitter, bearer_token, is_runner_token, user_agent};
use crate::error::{AppError, json_response};
use crate::session::{Approver, SessionHandle, session_user};
use crate::state::AppState;

/// `api_health`: the health JSON (4.6); exempt from the gate.
pub async fn health(State(state): State<AppState>) -> Result<Response, AppError> {
    let health = state.blocking(|store| store.health()).await?;
    Ok(json_response(StatusCode::OK, &Value::Object(health)))
}

/// What the store records about the caller.
struct Caller {
    client_ip: String,
    user_agent: Option<String>,
}

impl Caller {
    fn of(parts: &Parts, state: &AppState) -> Self {
        Self {
            client_ip: client::view(parts, state.settings()).remote_addr,
            user_agent: user_agent(&parts.headers),
        }
    }
}

/// The request's JSON (`parse_request_json`), reading the body now.
async fn request_json(parts: &Parts, body: axum::body::Body) -> Result<Option<Value>, AppError> {
    let bytes = read_body(body).await?;
    parse_request_json(&parts.headers, &bytes)
}

/// `api_create_ticket`: 401 `invalid_submit_token`, 400 `invalid_json`,
/// then the validation of 4.7.1; 201 with the ticket.
pub async fn create_ticket(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let token = bearer_token(&parts.headers);
    let submitter = authenticate_submitter(state.settings(), token.as_deref())
        .cloned()
        .ok_or_else(|| AppError::service("Submit token required", 401, "invalid_submit_token"))?;
    let payload = require_object(request_json(&parts, body).await?)?;
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.create_ticket(
                &payload,
                &submitter,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::CREATED, &Value::Object(ticket)))
}

/// `api_get_ticket`: a submitter token, an approver session or the runner
/// token (else 401 `auth_required`); 404 `ticket_not_found`; then a
/// submitter of another source gets 403 `forbidden`.
pub async fn get_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let token = bearer_token(&parts.headers);
    let submitter = authenticate_submitter(state.settings(), token.as_deref()).cloned();
    let approver = session_user(&state, &SessionHandle::from_parts(&parts)).await?;
    if submitter.is_none()
        && approver.is_none()
        && !is_runner_token(state.settings(), token.as_deref())
    {
        return Err(AppError::service(
            "Authentication required",
            401,
            "auth_required",
        ));
    }
    let ticket = state
        .blocking(move |store| store.get_ticket(&ticket_id))
        .await?;
    if let Some(submitter) = submitter
        && ticket.get("source") != Some(&Value::String(submitter.source))
    {
        return Err(AppError::service(
            "Submit token cannot access this ticket",
            403,
            "forbidden",
        ));
    }
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

fn require_runner_token(state: &AppState, parts: &Parts) -> Result<(), AppError> {
    if is_runner_token(state.settings(), bearer_token(&parts.headers).as_deref()) {
        Ok(())
    } else {
        Err(AppError::service(
            "Runner token required",
            401,
            "invalid_runner_token",
        ))
    }
}

/// `api_runner_claim`: 401 `invalid_runner_token`; an optional JSON object
/// (`{runner_host}`; falsy is `{}`, D-4); 200 `{"ticket": null|ticket}`.
pub async fn runner_claim(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    require_runner_token(&state, &parts)?;
    let payload = object_or_empty(request_json(&parts, body).await?)?;
    let caller = Caller::of(&parts, &state);
    let host = runner_host(&payload, &caller.client_ip)?;
    let ticket = state
        .blocking(move |store| {
            store.claim_ticket(&host, Some(&caller.client_ip), caller.user_agent.as_deref())
        })
        .await?;
    let ticket = ticket.map_or(Value::Null, Value::Object);
    Ok(json_response(StatusCode::OK, &json!({ "ticket": ticket })))
}

/// `api_runner_status`: 401 `invalid_runner_token`; a JSON object (400
/// `invalid_json`); then the rules of 4.7.4; 200 with the ticket.
pub async fn runner_status(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    require_runner_token(&state, &parts)?;
    let payload: Map<String, Value> = require_object(request_json(&parts, body).await?)?;
    let caller = Caller::of(&parts, &state);
    let host = runner_host(&payload, &caller.client_ip)?;
    let ticket = state
        .blocking(move |store| {
            store.update_runner_status(
                &ticket_id,
                &host,
                &payload,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

/// The `reason` of a reject or cancel body: `parse_request_json() or {}`
/// (falsy is `{}`, D-4), then `str(payload.get("reason", "")).strip()`
/// (D-2, D-3).
async fn reason(parts: &Parts, body: axum::body::Body) -> Result<String, AppError> {
    let payload = object_or_empty(request_json(parts, body).await?)?;
    text_field(&payload, "reason")
}

/// `api_approve_ticket`: 401 `auth_required`, 403 `csrf_required` or
/// `invalid_csrf`, then the approval (4.7.2); 200 with the ticket. The body
/// is never read.
pub async fn approve_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Approver(approver): Approver,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.approve_ticket(
                &ticket_id,
                &approver,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

/// `api_reject_ticket`: as approve, with the optional `reason` of the body.
pub async fn reject_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Approver(approver): Approver,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let reason = reason(&parts, body).await?;
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.reject_ticket(
                &ticket_id,
                &approver,
                &reason,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

/// `api_cancel_ticket`: as reject.
pub async fn cancel_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Approver(approver): Approver,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let reason = reason(&parts, body).await?;
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.cancel_ticket(
                &ticket_id,
                &approver,
                &reason,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

/// `api_archive_ticket`: as approve.
pub async fn archive_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Approver(approver): Approver,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.archive_ticket(
                &ticket_id,
                &approver,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}

/// `api_unarchive_ticket`: as approve.
pub async fn unarchive_ticket(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    Approver(approver): Approver,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _body) = request.into_parts();
    let caller = Caller::of(&parts, &state);
    let ticket = state
        .blocking(move |store| {
            store.unarchive_ticket(
                &ticket_id,
                &approver,
                Some(&caller.client_ip),
                caller.user_agent.as_deref(),
            )
        })
        .await?;
    Ok(json_response(StatusCode::OK, &Value::Object(ticket)))
}
