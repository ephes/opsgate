//! The tmux adapter (PLAN.md 4.13.3, 4.13.8): `tmux -L <label> …` children.
//!
//! Python runs `subprocess.run(["tmux", "-L", label, …])` with the process
//! environment, into which the env file was merged (4.2). The Rust runner
//! cannot change its own environment without `unsafe`, so [`TmuxCli`] starts
//! every child with exactly the merged [`Environment`]
//! (`env_clear().envs(…)`): a tmux server started by the first
//! `new-session` and the agent steps it runs see the same variables as under
//! Python (minus `__PYVENV_LAUNCHER__`, D-11). `tmux` itself is looked up
//! through that environment's `PATH`.

use std::future::Future;
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Output, Stdio};
use std::sync::Arc;

use opsgate_core::settings::Environment;
use tokio::process::Command;

use crate::commands;

/// A tmux call that failed.
#[derive(Debug)]
pub enum TmuxError {
    /// `tmux` could not be started (Python: `FileNotFoundError`/`OSError`).
    Spawn(io::Error),
    /// `new-session` exited non-zero (Python: `CalledProcessError`).
    Failed(ExitStatus),
    /// An argument contains a NUL character (cannot reach a shell word).
    InvalidArgument,
}

impl std::fmt::Display for TmuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "tmux could not be started: {error}"),
            Self::Failed(status) => write!(f, "tmux new-session failed: {status}"),
            Self::InvalidArgument => f.write_str("tmux argument contains a NUL character"),
        }
    }
}

impl std::error::Error for TmuxError {}

/// The tmux operations of the executor (`TicketExecutor._tmux_*`).
pub trait Tmux: Send + Sync {
    /// `has-session -t <name>`: exit status 0.
    fn has_session(
        &self,
        session_name: &str,
    ) -> impl Future<Output = Result<bool, TmuxError>> + Send;

    /// `new-session -d -s <name> "/bin/bash <script>"`; a non-zero exit is an
    /// error.
    fn new_session(
        &self,
        session_name: &str,
        script_path: &Path,
    ) -> impl Future<Output = Result<(), TmuxError>> + Send;

    /// `kill-session -t <name>`; the exit status is ignored.
    fn kill_session(
        &self,
        session_name: &str,
    ) -> impl Future<Output = Result<(), TmuxError>> + Send;
}

impl<T: Tmux> Tmux for Arc<T> {
    fn has_session(
        &self,
        session_name: &str,
    ) -> impl Future<Output = Result<bool, TmuxError>> + Send {
        (**self).has_session(session_name)
    }

    fn new_session(
        &self,
        session_name: &str,
        script_path: &Path,
    ) -> impl Future<Output = Result<(), TmuxError>> + Send {
        (**self).new_session(session_name, script_path)
    }

    fn kill_session(
        &self,
        session_name: &str,
    ) -> impl Future<Output = Result<(), TmuxError>> + Send {
        (**self).kill_session(session_name)
    }
}

/// The real `tmux` binary on socket label `OPSGATE_TMUX_SOCKET_LABEL`.
#[derive(Debug, Clone)]
pub struct TmuxCli {
    socket_label: String,
    environment: Arc<Environment>,
}

impl TmuxCli {
    /// tmux on `socket_label`, children started with `environment`.
    pub fn new(socket_label: impl Into<String>, environment: Arc<Environment>) -> Self {
        Self {
            socket_label: socket_label.into(),
            environment,
        }
    }

    /// The socket label (`tmux -L <label>`).
    pub fn socket_label(&self) -> &str {
        &self.socket_label
    }

    /// `subprocess.run(["tmux", "-L", label, *args], capture_output=True)`.
    pub async fn run(&self, args: &[&str]) -> Result<Output, TmuxError> {
        Command::new("tmux")
            .arg("-L")
            .arg(&self.socket_label)
            .args(args)
            .env_clear()
            .envs(self.environment.vars())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(TmuxError::Spawn)
    }
}

impl Tmux for TmuxCli {
    async fn has_session(&self, session_name: &str) -> Result<bool, TmuxError> {
        let output = self.run(&["has-session", "-t", session_name]).await?;
        Ok(output.status.success())
    }

    async fn new_session(&self, session_name: &str, script_path: &Path) -> Result<(), TmuxError> {
        let script = script_path.to_string_lossy();
        let quoted = commands::quote(&script).map_err(|_| TmuxError::InvalidArgument)?;
        let command = format!("/bin/bash {quoted}");
        let output = self
            .run(&["new-session", "-d", "-s", session_name, &command])
            .await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(TmuxError::Failed(output.status))
        }
    }

    async fn kill_session(&self, session_name: &str) -> Result<(), TmuxError> {
        self.run(&["kill-session", "-t", session_name]).await?;
        Ok(())
    }
}
