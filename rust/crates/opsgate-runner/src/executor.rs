//! The ticket executor (`TicketExecutor`, PLAN.md 4.13.4 and 4.13.5).
//!
//! One executor runs one claimed ticket: its steps in order, each in a tmux
//! session that runs `run_step.sh`, polled every second until the step
//! writes its exit code. The executor reports to the API (`step_started`,
//! heartbeats, `step_finished`, the final state) and keeps the artifacts of
//! 4.13.2. `_run_step` also holds the resume rules (4.13.5): a step whose
//! metadata, exit code or live session exists is never launched again.
//!
//! Errors leave `run` as an [`ExecutorError`]; the supervisor (S6b) decides
//! what they mean (`_run_worker`). Shutdown is the stop token: observed
//! before each step, at each poll and during the post-status retry wait
//! (stop-aware sleeps, D-16). HTTP requests are not cancelled, so a request
//! in flight finishes (≤ 15 s) before the shutdown actions run, as in Python.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use opsgate_core::pytext;
use opsgate_core::settings::RunnerSettings;
use opsgate_core::time::{isoformat_z, parse_iso_datetime};
use serde_json::Value;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::api::{JsonObject, RunnerApi, RunnerApiError};
use crate::artifacts::{self, StepPaths};
use crate::commands::{self, AgentCommandError};
use crate::tmux::{Tmux, TmuxError};
use crate::values::{py_int, text_or, truthy};
use crate::{blocking, is_terminal};

/// The poll interval of a running step (`time.sleep(1.0)`).
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The wait between post-status attempts (`stop_event.wait(1)`).
const RETRY_WAIT: Duration = Duration::from_secs(1);

/// Attempts of one status update (`_post_status`).
const STATUS_ATTEMPTS: usize = 3;

/// The wall clock of the executor (`utc_now`; tests inject their own).
pub trait Clock: Send + Sync {
    /// The current UTC time at microsecond resolution.
    fn now(&self) -> DateTime<Utc>;
}

/// [`opsgate_core::time::utc_now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        opsgate_core::time::utc_now()
    }
}

impl<T: Clock> Clock for Arc<T> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

/// Why `run` stopped with an error (Python: the exception leaving
/// `TicketExecutor.run`).
#[derive(Debug)]
pub enum ExecutorError {
    /// An API call failed (`RunnerApiError`).
    Api(RunnerApiError),
    /// A filesystem operation failed (`OSError`).
    Io(std::io::Error),
    /// tmux could not be run or `new-session` failed (`OSError`,
    /// `CalledProcessError`).
    Tmux(TmuxError),
    /// The ticket from the API cannot be executed as given (`ValueError`,
    /// `TypeError`, `AttributeError`, `OverflowError` in Python).
    InvalidTicket(&'static str),
}

impl ExecutorError {
    /// The error kind named in `runner_unhandled_exception:<kind>` (D-13).
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Api(_) => "RunnerApiError",
            Self::Io(_) => "IoError",
            Self::Tmux(_) => "TmuxError",
            Self::InvalidTicket(_) => "InvalidTicket",
        }
    }

    /// The API error, if this is one.
    pub fn api_error(&self) -> Option<&RunnerApiError> {
        match self {
            Self::Api(error) => Some(error),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(error) => error.fmt(f),
            Self::Io(error) => write!(f, "artifact I/O failed: {error}"),
            Self::Tmux(error) => error.fmt(f),
            Self::InvalidTicket(what) => write!(f, "ticket cannot be executed: {what}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

impl From<RunnerApiError> for ExecutorError {
    fn from(error: RunnerApiError) -> Self {
        Self::Api(error)
    }
}

impl From<std::io::Error> for ExecutorError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TmuxError> for ExecutorError {
    fn from(error: TmuxError) -> Self {
        Self::Tmux(error)
    }
}

/// One status update (`_post_status` arguments). Empty `state`, `result`
/// and `result_detail` are left out of the payload; `tmux_sessions: None`
/// leaves the key out, `Some(&[])` sends an empty list.
#[derive(Debug, Clone, Copy)]
pub struct StatusUpdate<'a> {
    pub event: &'a str,
    pub state: &'a str,
    pub result: &'a str,
    pub result_detail: &'a str,
    pub tmux_sessions: Option<&'a [Value]>,
}

impl<'a> StatusUpdate<'a> {
    /// An update with only `event` (plus `runner_host`).
    pub fn event(event: &'a str) -> Self {
        Self {
            event,
            state: "",
            result: "",
            result_detail: "",
            tmux_sessions: None,
        }
    }
}

/// How a step ended (`StepOutcome`).
#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    Succeeded(JsonObject),
    Failed(String),
    Timeout(String),
    Canceled,
}

/// The step being run.
struct Step<'a> {
    index: usize,
    total: usize,
    fields: &'a JsonObject,
    paths: &'a StepPaths,
    deadline: DateTime<Utc>,
}

/// `TicketExecutor`.
pub struct TicketExecutor<A, T, C = SystemClock> {
    settings: Arc<RunnerSettings>,
    api: A,
    tmux: T,
    clock: C,
    stop: CancellationToken,
    ticket_id: String,
    artifacts_root: PathBuf,
    ticket_root: PathBuf,
}

impl<A: RunnerApi, T: Tmux, C: Clock> TicketExecutor<A, T, C> {
    /// The executor of `ticket_id`.
    pub fn new(
        settings: Arc<RunnerSettings>,
        api: A,
        tmux: T,
        clock: C,
        stop: CancellationToken,
        ticket_id: impl Into<String>,
    ) -> Self {
        let ticket_id = ticket_id.into();
        let artifacts_root = artifacts::py_path_join(&settings.session_artifacts_dir, &ticket_id);
        let ticket_root = artifacts::py_path_join(&settings.tickets_dir, &ticket_id);
        Self {
            settings,
            api,
            tmux,
            clock,
            stop,
            ticket_id,
            artifacts_root,
            ticket_root,
        }
    }

    /// `<session_artifacts_dir>/<ticket_id>`.
    pub fn artifacts_root(&self) -> &Path {
        &self.artifacts_root
    }

    /// `_prepare_step_paths(step_index, step)`: the role is
    /// `str(step.get("role", "step"))`.
    pub fn step_paths(&self, step_index: usize, step: &JsonObject) -> StepPaths {
        StepPaths::new(
            &self.artifacts_root,
            step_index,
            &text_or(step, "role", "step"),
        )
    }

    /// `TicketExecutor.run(initial_ticket)`.
    pub async fn run(&self, initial_ticket: Option<JsonObject>) -> Result<(), ExecutorError> {
        let ticket = match initial_ticket {
            Some(ticket) if !ticket.is_empty() => ticket,
            _ => self.api.get_ticket(&self.ticket_id).await?,
        };
        let state = text_or(&ticket, "state", "");
        if is_terminal(&state) || state != "running" {
            return Ok(());
        }

        let started_at_raw = text_or(&ticket, "started_at", "");
        let started_at_raw = pytext::strip(&started_at_raw);
        let started_at = if started_at_raw.is_empty() {
            self.clock.now()
        } else {
            parse_iso_datetime(started_at_raw)
                .map_err(|_| ExecutorError::InvalidTicket("started_at is not a timestamp"))?
        };
        let default_duration = self.settings.max_duration_seconds_default();
        let mut max_duration = match ticket.get("max_duration_seconds") {
            Some(value) if truthy(value) => py_int(value).ok_or(ExecutorError::InvalidTicket(
                "max_duration_seconds is not an integer",
            ))?,
            _ => default_duration,
        };
        if max_duration <= 0 {
            max_duration = default_duration;
        }
        let deadline = TimeDelta::try_seconds(max_duration)
            .and_then(|duration| started_at.checked_add_signed(duration))
            .ok_or(ExecutorError::InvalidTicket(
                "max_duration_seconds is out of range",
            ))?;

        let plan = match ticket.get("execution_plan") {
            Some(Value::Array(plan)) if !plan.is_empty() => plan,
            _ => {
                self.post_status(StatusUpdate {
                    event: "invalid_plan",
                    state: "failed",
                    result: "failure",
                    result_detail: "invalid_execution_plan",
                    tmux_sessions: Some(&[]),
                })
                .await?;
                return Ok(());
            }
        };

        let mut tmux_sessions = match ticket.get("tmux_sessions") {
            Some(Value::Array(sessions)) => sessions.clone(),
            _ => Vec::new(),
        };
        // Summaries of steps that already succeeded are collected exactly
        // once, as the loop walks past them.
        let mut prior_summaries: Vec<Value> = Vec::new();

        for (step_index, step) in plan.iter().enumerate() {
            if self.stop.is_cancelled() {
                return Ok(());
            }
            let latest = self.api.get_ticket(&self.ticket_id).await?;
            if is_terminal(&text_or(&latest, "state", "")) {
                self.kill_running_sessions(&tmux_sessions).await?;
                return Ok(());
            }

            let step = step
                .as_object()
                .ok_or(ExecutorError::InvalidTicket("plan step is not an object"))?;
            let paths = self.step_paths(step_index, step);
            let summary_path = paths.summary_path.clone();
            let existing = blocking(move || Ok(artifacts::load_json_object(&summary_path))).await?;
            if let Some(existing) = existing
                && pytext::py_lower(&text_or(&existing, "status", "")) == "succeeded"
            {
                prior_summaries.push(Value::Object(existing));
                continue;
            }

            let outcome = self
                .run_step(
                    &Step {
                        index: step_index,
                        total: plan.len(),
                        fields: step,
                        paths: &paths,
                        deadline,
                    },
                    &prior_summaries,
                    &mut tmux_sessions,
                )
                .await?;

            match outcome {
                Outcome::Succeeded(summary) => prior_summaries.push(Value::Object(summary)),
                Outcome::Canceled => return Ok(()),
                Outcome::Timeout(detail) => {
                    self.kill_running_sessions(&tmux_sessions).await?;
                    self.post_status(StatusUpdate {
                        event: "timeout",
                        state: "failed",
                        result: "timeout",
                        result_detail: &detail,
                        tmux_sessions: Some(tmux_sessions.as_slice()),
                    })
                    .await?;
                    return Ok(());
                }
                Outcome::Failed(detail) => {
                    self.post_status(StatusUpdate {
                        event: "step_failed",
                        state: "failed",
                        result: "failure",
                        result_detail: &detail,
                        tmux_sessions: Some(tmux_sessions.as_slice()),
                    })
                    .await?;
                    return Ok(());
                }
            }
        }

        self.post_status(StatusUpdate {
            event: "ticket_succeeded",
            state: "succeeded",
            result: "success",
            result_detail: &format!("completed_{}_steps", plan.len()),
            tmux_sessions: Some(tmux_sessions.as_slice()),
        })
        .await?;
        Ok(())
    }

    /// `_run_step`.
    async fn run_step(
        &self,
        step: &Step<'_>,
        prior_summaries: &[Value],
        tmux_sessions: &mut Vec<Value>,
    ) -> Result<Outcome, ExecutorError> {
        let paths = step.paths;
        let number = step.index + 1;
        {
            let step_dir = paths.step_dir.clone();
            let ticket_root = self.ticket_root.clone();
            blocking(move || {
                std::fs::create_dir_all(&step_dir)?;
                std::fs::create_dir_all(&ticket_root)
            })
            .await?;
        }

        let step_role = text_or(step.fields, "role", "step");
        let step_agent = text_or(step.fields, "agent", "");
        let prompt_markdown = text_or(step.fields, "prompt_markdown", "");
        let session_name = commands::session_name(&self.ticket_id, step.index, &step_role);
        let attach_command = commands::build_attach_command(
            &self.settings.tmux_socket_label,
            &session_name,
            &self.settings.tmux_tmpdir,
        )
        .map_err(|_| ExecutorError::InvalidTicket("NUL character in a session name"))?;

        // Resume rule (4.13.5): metadata is written (status "running") before
        // a step is ever launched, so its presence means an earlier runner
        // started this step, and it is never launched a second time: an
        // existing exit code is adopted, a live session is re-attached and
        // polled, otherwise the step fails as interrupted. The marker is the
        // file's existence: unreadable metadata still counts (fail closed).
        let metadata_path = paths.metadata_path.clone();
        let (metadata_present, previous_meta) = blocking(move || {
            let present = metadata_path.exists();
            let previous = if present {
                artifacts::load_json_object(&metadata_path)
            } else {
                None
            };
            Ok((present, previous))
        })
        .await?;
        let mut exit_code_present = self.exists(&paths.exit_code_path).await?;
        let session_alive = if exit_code_present {
            false
        } else {
            self.tmux.has_session(&session_name).await?
        };
        if !exit_code_present && !session_alive {
            // The session may have written its exit code and ended between
            // the two checks.
            exit_code_present = self.exists(&paths.exit_code_path).await?;
        }
        let resuming = metadata_present || exit_code_present || session_alive;

        if !resuming {
            let mut context = JsonObject::new();
            context.insert("ticket_id".into(), Value::from(self.ticket_id.as_str()));
            context.insert("step_index".into(), Value::from(step.index));
            context.insert("step_role".into(), Value::from(step_role.as_str()));
            context.insert("step_agent".into(), Value::from(step_agent.as_str()));
            context.insert(
                "prior_step_summaries".into(),
                Value::Array(prior_summaries.to_vec()),
            );
            let context = Value::Object(context);
            let context_path = paths.context_path.clone();
            let ticket_context_path = self.ticket_root.join("context.json");
            let prompt_path = paths.prompt_path.clone();
            let previous_summary_path = paths.previous_summary_path.clone();
            let previous_summary = prior_summaries.last().map(artifacts::artifact_json);
            blocking(move || {
                artifacts::atomic_write_json(&context_path, &context)?;
                artifacts::atomic_write_json(&ticket_context_path, &context)?;
                std::fs::write(&prompt_path, format!("{prompt_markdown}\n"))?;
                if let Some(previous_summary) = previous_summary {
                    std::fs::write(&previous_summary_path, previous_summary)?;
                }
                Ok(())
            })
            .await?;
        }

        let mut started_at = isoformat_z(&self.clock.now());
        if let Some(previous) = &previous_meta {
            let previous_started_at = text_or(previous, "started_at", "");
            let previous_started_at = pytext::strip(&previous_started_at);
            if !previous_started_at.is_empty() {
                started_at = previous_started_at.to_owned();
            }
        }

        let mut session_meta = JsonObject::new();
        session_meta.insert("step_index".into(), Value::from(step.index));
        session_meta.insert("role".into(), Value::from(step_role.as_str()));
        session_meta.insert("agent".into(), Value::from(step_agent.as_str()));
        session_meta.insert("session_name".into(), Value::from(session_name.as_str()));
        session_meta.insert("attach_command".into(), Value::from(attach_command));
        session_meta.insert("prompt_path".into(), path_value(&paths.prompt_path));
        session_meta.insert("context_path".into(), path_value(&paths.context_path));
        session_meta.insert("log_path".into(), path_value(&paths.log_path));
        session_meta.insert("summary_path".into(), path_value(&paths.summary_path));
        session_meta.insert("status".into(), Value::from("running"));
        session_meta.insert("started_at".into(), Value::from(started_at.as_str()));
        if resuming {
            session_meta.insert(
                "resumed_at".into(),
                Value::from(isoformat_z(&self.clock.now())),
            );
        }

        if resuming && !exit_code_present && !session_alive {
            session_meta.insert("status".into(), Value::from("interrupted"));
            session_meta.insert(
                "finished_at".into(),
                Value::from(isoformat_z(&self.clock.now())),
            );
            self.write_json(&paths.metadata_path, Value::Object(session_meta.clone()))
                .await?;
            upsert_tmux_session(tmux_sessions, &session_meta)?;
            return Ok(Outcome::Failed(format!("step_{number}_interrupted")));
        }

        self.write_json(&paths.metadata_path, Value::Object(session_meta.clone()))
            .await?;
        let entry = upsert_tmux_session(tmux_sessions, &session_meta)?;
        let started_detail = format!(
            "step_{number}_{}",
            if resuming { "resumed" } else { "started" }
        );
        self.post_status(StatusUpdate {
            result_detail: &started_detail,
            tmux_sessions: Some(&tmux_sessions[..]),
            ..StatusUpdate::event("step_started")
        })
        .await?;

        if !resuming {
            match commands::build_agent_command(&step_agent, &paths.prompt_path) {
                Err(AgentCommandError::Unsupported { .. }) => {
                    self.finish_entry(tmux_sessions, entry, "failed", paths)
                        .await?;
                    return Ok(Outcome::Failed(format!(
                        "unsupported_agent_{}",
                        commands::slugify(&step_agent)
                    )));
                }
                Err(AgentCommandError::Nul) => {
                    return Err(ExecutorError::InvalidTicket("NUL character in a path"));
                }
                Ok(command) => {
                    let script =
                        commands::step_script(&command, &paths.log_path, &paths.exit_code_path)
                            .map_err(|_| ExecutorError::InvalidTicket("NUL character in a path"))?;
                    let script_path = paths.script_path.clone();
                    blocking(move || {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::write(&script_path, script)?;
                        std::fs::set_permissions(
                            &script_path,
                            std::fs::Permissions::from_mode(0o750),
                        )
                    })
                    .await?;
                }
            }
            self.tmux
                .new_session(&session_name, &paths.script_path)
                .await?;
        }

        let heartbeat_seconds = self.settings.runner_heartbeat_interval_seconds.max(1);
        let heartbeat_interval = Duration::from_secs(u64::try_from(heartbeat_seconds).unwrap_or(1));
        let mut next_heartbeat = Instant::now() + heartbeat_interval;

        // An exit code that already exists (adopted on resume) skips the poll.
        if !exit_code_present {
            loop {
                if self.stop.is_cancelled() {
                    if self.exists(&paths.exit_code_path).await? {
                        // The step finished just before shutdown; its exit code is
                        // left for the next runner to adopt.
                        return Ok(Outcome::Canceled);
                    }
                    self.tmux.kill_session(&session_name).await?;
                    self.finish_entry(tmux_sessions, entry, "interrupted", paths)
                        .await?;
                    return Ok(Outcome::Canceled);
                }

                if self.clock.now() >= step.deadline {
                    self.tmux.kill_session(&session_name).await?;
                    self.finish_entry(tmux_sessions, entry, "timeout", paths)
                        .await?;
                    return Ok(Outcome::Timeout("max_duration_seconds_exceeded".into()));
                }

                let latest_state = match self.api.get_ticket(&self.ticket_id).await {
                    Ok(latest) => text_or(&latest, "state", ""),
                    // An unreachable API never stops a running step.
                    Err(_) => "running".to_owned(),
                };
                if latest_state == "canceled" {
                    self.tmux.kill_session(&session_name).await?;
                    self.finish_entry(tmux_sessions, entry, "canceled", paths)
                        .await?;
                    return Ok(Outcome::Canceled);
                }
                if is_terminal(&latest_state) {
                    self.tmux.kill_session(&session_name).await?;
                    return Ok(Outcome::Failed(format!("ticket_entered_{latest_state}")));
                }

                if self.exists(&paths.exit_code_path).await? {
                    break;
                }
                if !self.tmux.has_session(&session_name).await? {
                    return Ok(Outcome::Failed(
                        "session_terminated_without_exit_code".into(),
                    ));
                }

                let now = Instant::now();
                if now >= next_heartbeat {
                    let detail = format!("running_step_{number}_of_{}", step.total);
                    self.post_status(StatusUpdate {
                        result_detail: &detail,
                        tmux_sessions: Some(&tmux_sessions[..]),
                        ..StatusUpdate::event("heartbeat")
                    })
                    .await?;
                    next_heartbeat = now + heartbeat_interval;
                }

                self.sleep(POLL_INTERVAL).await;
            }
        }

        self.finish_step(
            step,
            &step_role,
            &step_agent,
            &session_name,
            &started_at,
            tmux_sessions,
            entry,
        )
        .await
    }

    /// The end of `_run_step` once the exit code exists: the log facts in the
    /// session entry, `summary.json`, the final metadata and, on success,
    /// `step_finished`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_step(
        &self,
        step: &Step<'_>,
        step_role: &str,
        step_agent: &str,
        session_name: &str,
        started_at: &str,
        tmux_sessions: &mut [Value],
        entry: usize,
    ) -> Result<Outcome, ExecutorError> {
        let paths = step.paths;
        let number = step.index + 1;
        let exit_code_path = paths.exit_code_path.clone();
        let log_path = paths.log_path.clone();
        let (exit_code, log_size, log_sha256, tail) = blocking(move || {
            let exit_code = read_exit_code(&exit_code_path)?;
            let (log_size, log_sha256) = if log_path.exists() {
                (
                    std::fs::metadata(&log_path)?.len(),
                    Some(artifacts::sha256_file(&log_path)?),
                )
            } else {
                (0, None)
            };
            let tail = opsgate_core::log_preview::read_tail_lines(
                &log_path,
                opsgate_core::log_preview::PREVIEW_LINE_LIMIT,
            )?;
            Ok((exit_code, log_size, log_sha256, tail))
        })
        .await?;

        let finished_at = isoformat_z(&self.clock.now());
        let log_sha256 = log_sha256.map_or(Value::Null, Value::from);
        let entry_object = entry_mut(tmux_sessions, entry)?;
        entry_object.insert("finished_at".into(), Value::from(finished_at.as_str()));
        entry_object.insert("log_path".into(), path_value(&paths.log_path));
        entry_object.insert("log_size_bytes".into(), Value::from(log_size));
        entry_object.insert("log_sha256".into(), log_sha256.clone());

        let status = if exit_code == 0 {
            "succeeded"
        } else {
            "failed"
        };
        let mut summary = JsonObject::new();
        summary.insert("ticket_id".into(), Value::from(self.ticket_id.as_str()));
        summary.insert("step_index".into(), Value::from(step.index));
        summary.insert("role".into(), Value::from(step_role));
        summary.insert("agent".into(), Value::from(step_agent));
        summary.insert("session_name".into(), Value::from(session_name));
        summary.insert("started_at".into(), Value::from(started_at));
        summary.insert("finished_at".into(), Value::from(finished_at));
        summary.insert("exit_code".into(), Value::from(exit_code));
        summary.insert("status".into(), Value::from(status));
        summary.insert("log_path".into(), path_value(&paths.log_path));
        summary.insert("log_size_bytes".into(), Value::from(log_size));
        summary.insert("log_sha256".into(), log_sha256);
        summary.insert("summary_markdown".into(), Value::from(tail.join("\n")));
        self.write_json(&paths.summary_path, Value::Object(summary.clone()))
            .await?;

        let entry_object = entry_mut(tmux_sessions, entry)?;
        entry_object.insert("status".into(), Value::from(status));
        entry_object.insert("summary_path".into(), path_value(&paths.summary_path));
        let metadata = Value::Object(entry_object.clone());
        self.write_json(&paths.metadata_path, metadata).await?;

        if exit_code != 0 {
            return Ok(Outcome::Failed(format!(
                "step_{number}_exit_code_{exit_code}"
            )));
        }
        let detail = format!("step_{number}_finished");
        self.post_status(StatusUpdate {
            result_detail: &detail,
            tmux_sessions: Some(&tmux_sessions[..]),
            ..StatusUpdate::event("step_finished")
        })
        .await?;
        Ok(Outcome::Succeeded(summary))
    }

    /// The session entry gets `status` and `finished_at` and is written as
    /// the step's metadata (the early ends of `_run_step`).
    async fn finish_entry(
        &self,
        tmux_sessions: &mut [Value],
        entry: usize,
        status: &str,
        paths: &StepPaths,
    ) -> Result<(), ExecutorError> {
        let finished_at = isoformat_z(&self.clock.now());
        let entry_object = entry_mut(tmux_sessions, entry)?;
        entry_object.insert("status".into(), Value::from(status));
        entry_object.insert("finished_at".into(), Value::from(finished_at));
        let metadata = Value::Object(entry_object.clone());
        self.write_json(&paths.metadata_path, metadata).await
    }

    /// `_post_status`: up to three attempts one second apart (the wait ends
    /// early on shutdown); a 409 `invalid_state`/`state_changed` means the
    /// ticket moved on and counts as done; any other status below 500, or a
    /// failure of the last attempt, is returned.
    pub async fn post_status(&self, update: StatusUpdate<'_>) -> Result<(), RunnerApiError> {
        let mut payload = JsonObject::new();
        payload.insert(
            "runner_host".into(),
            Value::from(self.settings.runner_host.as_str()),
        );
        payload.insert("event".into(), Value::from(update.event));
        for (key, value) in [
            ("state", update.state),
            ("result", update.result),
            ("result_detail", update.result_detail),
        ] {
            if !value.is_empty() {
                payload.insert(key.into(), Value::from(value));
            }
        }
        if let Some(sessions) = update.tmux_sessions {
            payload.insert("tmux_sessions".into(), Value::Array(sessions.to_vec()));
        }
        let mut attempt = 1;
        loop {
            match self.api.update_status(&self.ticket_id, &payload).await {
                Ok(_) => return Ok(()),
                Err(error)
                    if error.status_code == 409
                        && matches!(
                            error.error_code.as_str(),
                            "invalid_state" | "state_changed"
                        ) =>
                {
                    return Ok(());
                }
                Err(error) if error.status_code < 500 || attempt == STATUS_ATTEMPTS => {
                    return Err(error);
                }
                Err(_) => {
                    attempt += 1;
                    self.sleep(RETRY_WAIT).await;
                }
            }
        }
    }

    /// `_kill_running_sessions`: kill the session of every entry whose status
    /// is `running`.
    async fn kill_running_sessions(&self, tmux_sessions: &[Value]) -> Result<(), ExecutorError> {
        for entry in tmux_sessions {
            let entry = entry.as_object().ok_or(ExecutorError::InvalidTicket(
                "tmux session entry is not an object",
            ))?;
            if pytext::py_lower(&text_or(entry, "status", "")) == "running" {
                let session_name = text_or(entry, "session_name", "");
                let session_name = pytext::strip(&session_name);
                if !session_name.is_empty() {
                    self.tmux.kill_session(session_name).await?;
                }
            }
        }
        Ok(())
    }

    /// A stop-aware sleep.
    async fn sleep(&self, duration: Duration) {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = self.stop.cancelled() => {}
        }
    }

    /// `path.exists()` (errors count as missing, as in Python).
    async fn exists(&self, path: &Path) -> Result<bool, ExecutorError> {
        let path = path.to_owned();
        Ok(blocking(move || Ok(path.exists())).await?)
    }

    /// `_atomic_write_json(path, value)`.
    async fn write_json(&self, path: &Path, value: Value) -> Result<(), ExecutorError> {
        let path = path.to_owned();
        Ok(blocking(move || artifacts::atomic_write_json(&path, &value)).await?)
    }
}

/// `str(path)`.
fn path_value(path: &Path) -> Value {
    Value::from(path.to_string_lossy().into_owned())
}

/// `int(exit_code_path.read_text().strip())`, 1 for text that is not an
/// integer (also not UTF-8); read errors are returned. An integer outside
/// `i64` (impossible for a shell exit status) also counts as 1.
fn read_exit_code(path: &Path) -> std::io::Result<i64> {
    let data = std::fs::read(path)?;
    Ok(std::str::from_utf8(&data)
        .ok()
        .and_then(crate::values::parse_py_int)
        .unwrap_or(1))
}

/// `_upsert_tmux_session`: merge `entry` into the existing entry with the same
/// `step_index` (`int(existing.get("step_index", -1))`) or append a copy; the
/// position of the entry is returned.
fn upsert_tmux_session(
    tmux_sessions: &mut Vec<Value>,
    entry: &JsonObject,
) -> Result<usize, ExecutorError> {
    let step_index = entry
        .get("step_index")
        .and_then(py_int)
        .ok_or(ExecutorError::InvalidTicket("step_index is not an integer"))?;
    for (position, existing) in tmux_sessions.iter_mut().enumerate() {
        let existing = existing
            .as_object_mut()
            .ok_or(ExecutorError::InvalidTicket(
                "tmux session entry is not an object",
            ))?;
        let existing_index = match existing.get("step_index") {
            None => -1,
            Some(value) => py_int(value).ok_or(ExecutorError::InvalidTicket(
                "tmux session step_index is not an integer",
            ))?,
        };
        if existing_index == step_index {
            for (key, value) in entry {
                existing.insert(key.clone(), value.clone());
            }
            return Ok(position);
        }
    }
    tmux_sessions.push(Value::Object(entry.clone()));
    Ok(tmux_sessions.len() - 1)
}

fn entry_mut(tmux_sessions: &mut [Value], entry: usize) -> Result<&mut JsonObject, ExecutorError> {
    tmux_sessions
        .get_mut(entry)
        .and_then(Value::as_object_mut)
        .ok_or(ExecutorError::InvalidTicket("tmux session entry vanished"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sessions(value: Value) -> Vec<Value> {
        value.as_array().unwrap().clone()
    }

    #[test]
    fn upsert_merges_by_step_index() {
        let mut list = sessions(json!([
            {"step_index": 0, "status": "succeeded", "extra": 1},
            {"step_index": "1", "status": "running"}
        ]));
        let entry = json!({"step_index": 1, "status": "failed"});
        let position = upsert_tmux_session(&mut list, entry.as_object().unwrap()).unwrap();
        assert_eq!(position, 1);
        assert_eq!(list[1], json!({"step_index": 1, "status": "failed"}));
        let entry = json!({"step_index": 2, "status": "running"});
        assert_eq!(
            upsert_tmux_session(&mut list, entry.as_object().unwrap()).unwrap(),
            2
        );
        let entry = json!({"step_index": 0, "status": "running"});
        upsert_tmux_session(&mut list, entry.as_object().unwrap()).unwrap();
        assert_eq!(
            list[0],
            json!({"step_index": 0, "status": "running", "extra": 1})
        );
    }

    #[test]
    fn upsert_fails_on_entries_python_cannot_read() {
        let entry = json!({"step_index": 1});
        let mut list = sessions(json!(["x"]));
        assert!(upsert_tmux_session(&mut list, entry.as_object().unwrap()).is_err());
        let mut list = sessions(json!([{"step_index": null}]));
        assert!(upsert_tmux_session(&mut list, entry.as_object().unwrap()).is_err());
        // An entry after the match is never looked at.
        let mut list = sessions(json!([{"step_index": 1}, "x"]));
        assert_eq!(
            upsert_tmux_session(&mut list, entry.as_object().unwrap()).unwrap(),
            0
        );
        let mut list = sessions(json!([{}]));
        assert_eq!(
            upsert_tmux_session(&mut list, entry.as_object().unwrap()).unwrap(),
            1
        );
    }

    #[test]
    fn exit_code_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exit_code");
        for (content, expected) in [
            (&b"0\n"[..], 0),
            (b"7\n", 7),
            (b" 130 ", 130),
            (b"", 1),
            (b"x", 1),
            (b"\xff", 1),
            (b"99999999999999999999", 1),
        ] {
            std::fs::write(&path, content).unwrap();
            assert_eq!(read_exit_code(&path).unwrap(), expected, "{content:?}");
        }
        std::fs::remove_file(&path).unwrap();
        assert!(read_exit_code(&path).is_err());
    }
}
