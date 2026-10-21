//! Runner of the OpsGate Rust port (`rust/PLAN.md` section 0 and 4.13): API
//! client, tmux adapter, artifacts, executor and supervisor.
//!
//! Slice S6a landed the API client ([`api`], 4.13.1), the tmux adapter
//! ([`tmux`]), artifact paths and atomic writes ([`artifacts`], 4.13.2,
//! 4.13.7), the agent commands and the step script ([`commands`], 4.13.3)
//! and the ticket executor ([`executor`], 4.13.4 and the resume rules of
//! 4.13.5 inside `_run_step`). Slice S6b adds the supervisor (4.13.6) and the
//! `runner` command.
//!
//! Ported Python: `src/opsgate/runner.py` (`RunnerApiClient`, `_slugify`,
//! `_atomic_write_json`, `_sha256`, `_build_agent_command`,
//! `_build_attach_command`, `TicketExecutor`).

pub mod api;
pub mod artifacts;
pub mod commands;
pub mod executor;
pub mod tmux;
mod values;

pub use api::{HttpApiClient, JsonObject, RunnerApi, RunnerApiError};
pub use executor::{Clock, ExecutorError, StatusUpdate, SystemClock, TicketExecutor};
pub use tmux::{Tmux, TmuxCli, TmuxError};

/// Ticket states after which the runner does nothing more
/// (`service.TERMINAL_STATES`).
pub const TERMINAL_STATES: [&str; 5] = ["succeeded", "failed", "rejected", "canceled", "expired"];

/// Whether `state` is one of [`TERMINAL_STATES`].
pub fn is_terminal(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

/// Run filesystem work on tokio's blocking pool (PLAN.md 6.1). A panic in the
/// closure is re-raised; a task the runtime dropped during shutdown is an
/// I/O error.
pub(crate) async fn blocking<R, F>(work: F) -> std::io::Result<R>
where
    F: FnOnce() -> std::io::Result<R> + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(std::io::Error::other("blocking task canceled")),
    }
}
