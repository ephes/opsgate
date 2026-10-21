//! Step sessions and their logs on the ticket pages (PLAN.md 4.12):
//! `build_ticket_session_views` (the detail page's session cards with log
//! previews), `get_ticket_session_for_step` and `resolve_session_log_path`
//! (the step log page).
//!
//! A session entry's step number is `int(step_index) + 1` when the index is
//! not negative; `int()` failing with `TypeError`/`ValueError` means no
//! number, an infinite float (`OverflowError`) is Python's unhandled error
//! (500). These functions touch the file system: call them off the async
//! runtime.

use std::path::PathBuf;

use opsgate_core::log_preview::{PREVIEW_LINE_LIMIT, read_tail_lines};
use opsgate_core::paths::resolve_session_log_path;
use opsgate_core::pytext::{py_str, strip};
use serde_json::{Map, Value};

use crate::error::AppError;
use crate::pyint::{PyIntOf, decimal_value, increment, py_int_of};
use crate::urls::{UrlArg, url_for};

/// `str(value)` of a session entry's value. Arrays, objects and numbers
/// that overflow to infinity are written as their JSON text where Python
/// writes their `repr`; both are relative paths (`[…`, `{…`, `inf`), which
/// resolve outside the ticket's artifact root as long as the server's
/// working directory is not inside it.
fn text_of(value: &Value) -> String {
    py_str(value).map_or_else(|_| value.to_string(), std::borrow::Cow::into_owned)
}

/// The entry's step index as `int(meta.get("step_index", -1))`:
/// `Ok(None)` when `int()` fails with `TypeError`/`ValueError`.
fn step_index(meta: &Map<String, Value>) -> Result<Option<String>, AppError> {
    match meta
        .get("step_index")
        .map_or(PyIntOf::Value("-1".to_owned()), py_int_of)
    {
        PyIntOf::Value(decimal) => Ok(Some(decimal)),
        PyIntOf::Invalid => Ok(None),
        PyIntOf::Overflow => Err(AppError::Internal(
            "int() of an infinite step_index (OverflowError)".to_owned(),
        )),
    }
}

/// `step_index + 1` if the entry has a step index of at least 0.
fn step_number(meta: &Map<String, Value>) -> Result<Option<String>, AppError> {
    Ok(step_index(meta)?
        .filter(|index| !index.starts_with('-'))
        .map(|index| increment(&index)))
}

/// `resolve_session_log_path` for a session entry: the resolved log file,
/// or 404 `log_not_found` / 400 `invalid_log_path` (containment before
/// existence, P1); a path that cannot be resolved at all (NUL) is 500.
pub fn resolve_log_path(
    execution_data_dir: &str,
    ticket_id: &str,
    meta: &Map<String, Value>,
) -> Result<PathBuf, AppError> {
    let raw = meta.get("log_path").map(text_of).unwrap_or_default();
    resolve_session_log_path(execution_data_dir, ticket_id, &raw).map_err(|error| {
        match error.code() {
            Some(code) => AppError::service(error.to_string(), error.status(), code),
            None => AppError::Internal(format!("step log path: {error}")),
        }
    })
}

/// The ticket's `tmux_sessions` when it is a list (else none).
fn sessions(ticket: &Map<String, Value>) -> &[Value] {
    match ticket.get("tmux_sessions") {
        Some(Value::Array(sessions)) => sessions,
        _ => &[],
    }
}

/// `build_ticket_session_views`: one view per object entry of
/// `tmux_sessions` (other entries skipped): the entry plus `step_number`
/// (or `None`), `log_url` (the step log page when there is a number),
/// `log_available` (the log resolved and there is a number) and
/// `log_preview` (the last 40 lines, 4.12; empty when the log does not
/// resolve). An unreadable log file is 500, as in Python.
pub fn session_views(
    execution_data_dir: &str,
    ticket: &Map<String, Value>,
) -> Result<Vec<Value>, AppError> {
    let ticket_id = ticket
        .get("id")
        .map(text_of)
        .map(|id| strip(&id).to_owned())
        .unwrap_or_default();
    let mut views = Vec::new();
    for meta in sessions(ticket) {
        let Value::Object(meta) = meta else {
            continue;
        };
        let mut view = meta.clone();
        let number = step_number(meta)?;
        let log_url = match &number {
            Some(number) => Value::from(
                url_for(
                    "ui_ticket_step_log",
                    &[
                        ("ticket_id", UrlArg::from(ticket_id.as_str())),
                        ("step_number", UrlArg::from(number.as_str())),
                    ],
                )
                .map_err(|error| AppError::Internal(format!("url_for: {error}")))?,
            ),
            None => Value::Null,
        };
        view.insert(
            "step_number".to_owned(),
            number.as_deref().map_or(Value::Null, decimal_value),
        );
        view.insert("log_preview".to_owned(), Value::from(""));
        view.insert("log_available".to_owned(), Value::Bool(false));
        view.insert("log_url".to_owned(), log_url);
        match resolve_log_path(execution_data_dir, &ticket_id, meta) {
            Ok(path) => {
                let lines = read_tail_lines(&path, PREVIEW_LINE_LIMIT)
                    .map_err(|error| AppError::Internal(format!("step log preview: {error}")))?;
                view.insert("log_available".to_owned(), Value::Bool(number.is_some()));
                view.insert("log_preview".to_owned(), Value::from(lines.join("\n")));
            }
            Err(AppError::Service(_)) => {}
            Err(other) => return Err(other),
        }
        views.push(Value::Object(view));
    }
    Ok(views)
}

/// `ServiceError("Step log does not exist", 404, "log_not_found")`.
fn step_log_missing() -> AppError {
    AppError::service("Step log does not exist", 404, "log_not_found")
}

/// `get_ticket_session_for_step`: the first object entry of
/// `tmux_sessions` whose `int(step_index)` is `step_number - 1`
/// (`step_number` is a decimal from the URL); entries whose index `int()`
/// rejects are skipped; a step number of 0 or no entry is 404
/// `log_not_found`.
pub fn session_for_step(
    ticket: &Map<String, Value>,
    step_number: &str,
) -> Result<Map<String, Value>, AppError> {
    if step_number == "0" {
        return Err(step_log_missing());
    }
    for meta in sessions(ticket) {
        let Value::Object(meta) = meta else {
            continue;
        };
        if self::step_number(meta)?.as_deref() == Some(step_number) {
            return Ok(meta.clone());
        }
    }
    Err(step_log_missing())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ticket(sessions: Value) -> Map<String, Value> {
        json!({"id": "t1", "tmux_sessions": sessions})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn step_numbers() {
        let number = |meta: Value| step_number(meta.as_object().unwrap()).unwrap();
        assert_eq!(number(json!({})), None);
        assert_eq!(number(json!({"step_index": 0})), Some("1".to_owned()));
        assert_eq!(number(json!({"step_index": "2"})), Some("3".to_owned()));
        assert_eq!(number(json!({"step_index": 1.9})), Some("2".to_owned()));
        assert_eq!(number(json!({"step_index": -0.5})), Some("1".to_owned()));
        assert_eq!(number(json!({"step_index": true})), Some("2".to_owned()));
        assert_eq!(number(json!({"step_index": -1})), None);
        assert_eq!(number(json!({"step_index": "abc"})), None);
        assert_eq!(number(json!({"step_index": null})), None);
        let infinite: Value = serde_json::from_str("{\"step_index\": 1e400}").unwrap();
        assert!(step_number(infinite.as_object().unwrap()).is_err());
    }

    #[test]
    fn step_lookup() {
        let ticket = ticket(json!([
            "junk",
            {"step_index": "x", "session_name": "bad"},
            {"step_index": 1, "session_name": "second"},
            {"step_index": "1", "session_name": "duplicate"},
            {"step_index": 0, "session_name": "first"},
        ]));
        let name = |n: &str| {
            session_for_step(&ticket, n)
                .map(|meta| meta["session_name"].clone())
                .map_err(|error| error.to_string())
        };
        assert_eq!(name("1").unwrap(), "first");
        assert_eq!(name("2").unwrap(), "second");
        assert!(name("0").unwrap_err().contains("log_not_found"));
        assert!(name("3").unwrap_err().contains("log_not_found"));
        assert!(session_for_step(&self::ticket(json!("not a list")), "1").is_err());
    }

    #[test]
    fn views_without_logs() {
        let directory = tempfile::tempdir().unwrap();
        let exec = directory.path().to_str().unwrap();
        let views = session_views(
            exec,
            &ticket(json!([
                {"step_index": 0, "log_path": ""},
                {"step_index": "x", "log_path": "/etc/passwd"},
                7,
            ])),
        )
        .unwrap();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0]["step_number"], json!(1));
        assert_eq!(views[0]["log_url"], json!("/tickets/t1/steps/1/log"));
        assert_eq!(views[0]["log_available"], json!(false));
        assert_eq!(views[1]["step_number"], Value::Null);
        assert_eq!(views[1]["log_url"], Value::Null);
        assert_eq!(views[1]["log_preview"], json!(""));
        // A NUL character cannot be resolved: Python's unhandled ValueError.
        assert!(matches!(
            session_views(
                exec,
                &ticket(json!([{"step_index": 0, "log_path": "/a\u{0}b"}]))
            ),
            Err(AppError::Internal(_))
        ));
    }
}
