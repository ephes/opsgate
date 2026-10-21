//! The supervisor (`OpsGateRunner`, PLAN.md 4.13.6): the claim loop, one
//! worker per ticket, restart recovery, verified tmux cleanup and the runner
//! state files.
//!
//! `run_forever` runs one recovery pass that also looks at the artifact
//! directories, then loops until the stop token is cancelled: reap finished
//! workers (removing the state files of those marked for cleanup), a recovery
//! pass over the state files and the tmux sessions, the disable file (sleep,
//! or end with `--once`), claims while fewer than `max_parallel_jobs` workers
//! run, and a sleep of the poll interval. Afterwards it waits for every
//! worker (`_wait_for_workers`). Workers are tokio tasks (Python: threads);
//! each runs a [`TicketExecutor`] and decides what its error means
//! (`_run_worker`).
//!
//! Python's failure classes are kept: an error the Python runner does not
//! catch (an unreadable state file, a failing state-file write or removal, a
//! `tmux` that cannot be started for another reason than a missing binary
//! during discovery) ends `run_forever` with a [`SupervisorError`], and the
//! process exits 1 (Python: a traceback and exit 1); launchd restarts it.
//!
//! The sleeps end at shutdown (D-16); HTTP requests in flight finish first.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use opsgate_core::pytext;
use opsgate_core::settings::RunnerSettings;
use opsgate_core::time::isoformat_z;
use regex::Regex;
use serde_json::Value;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api::{JsonObject, RunnerApi};
use crate::artifacts;
use crate::executor::{Clock, ExecutorError, SystemClock, TicketExecutor};
use crate::tmux::{Tmux, TmuxError};
use crate::values::text_or;
use crate::{blocking, is_terminal};

/// How long `_wait_for_workers` waits for a worker before it reaps again
/// (`worker.join(timeout=0.5)`).
const WORKER_JOIN_WAIT: Duration = Duration::from_millis(500);

/// The tmux diagnostics that mean "no server, so no sessions"
/// (`_tmux_sessions_for_ticket`).
const ABSENT_SERVER_DIAGNOSTICS: [&str; 3] = [
    "no server running",
    "No such file or directory",
    "Connection refused",
];

/// `TICKET_ID_RE`. Python's `$` also matches before a final newline; `\n?$`
/// keeps that for the artifact directory names it is applied to.
static TICKET_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\n?$")
        .expect("valid ticket id pattern")
});

/// `TMUX_TICKET_RE` (`re.match`, so anchored at the start; `\d` is Unicode
/// in both).
static TMUX_TICKET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^job-([0-9a-fA-F-]{36})-\d{2}-").expect("valid tmux session pattern")
});

/// An error that ends `run_forever` (Python: an exception the supervisor
/// does not catch).
#[derive(Debug)]
pub enum SupervisorError {
    /// A runner state file or directory could not be read, written or
    /// removed (`OSError`, `UnicodeDecodeError`).
    Io(io::Error),
    /// `tmux ls` could not be started for another reason than a missing
    /// binary during discovery (`OSError`).
    Tmux(TmuxError),
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "runner state I/O failed: {error}"),
            Self::Tmux(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<io::Error> for SupervisorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Why the sessions of a ticket could not be shown to be gone
/// (`_kill_tmux_sessions_for_ticket` raising).
#[derive(Debug)]
pub enum CleanupError {
    /// `tmux` is missing, or `ls` failed with another diagnostic than an
    /// absent server (`RuntimeError`).
    Unverifiable,
    /// `tmux` could not be started (`OSError`).
    Tmux(TmuxError),
    /// Sessions of the ticket are still listed after the kills.
    Remain,
}

impl std::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverifiable => f.write_str("Cannot verify tmux cleanup"),
            Self::Tmux(error) => error.fmt(f),
            Self::Remain => f.write_str("Ticket sessions remain after cleanup"),
        }
    }
}

impl std::error::Error for CleanupError {}

/// The workers and their cleanup marks (`workers`, `_worker_cleanup`, under
/// one lock as in Python).
#[derive(Default)]
struct Workers {
    handles: HashMap<String, JoinHandle<()>>,
    cleanup: HashMap<String, bool>,
}

struct Inner<A, T, C> {
    settings: Arc<RunnerSettings>,
    api: A,
    tmux: T,
    clock: C,
    stop: CancellationToken,
    state_dir: PathBuf,
    workers: Mutex<Workers>,
    worker_done: Notify,
    artifacts_scanned: AtomicBool,
}

/// `OpsGateRunner`. Cloning gives another handle to the same supervisor.
pub struct Supervisor<A, T, C = SystemClock> {
    inner: Arc<Inner<A, T, C>>,
}

impl<A, T, C> Clone for Supervisor<A, T, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<A, T, C> Supervisor<A, T, C>
where
    A: RunnerApi + Clone + 'static,
    T: Tmux + Clone + 'static,
    C: Clock + Clone + 'static,
{
    /// `OpsGateRunner(settings)`: creates `<execution_data_dir>/runner-state`
    /// (`mkdir -p`). The executors of the workers get clones of `api`,
    /// `tmux`, `clock` and `stop`; cancelling `stop` is the stop flag.
    pub fn new(
        settings: Arc<RunnerSettings>,
        api: A,
        tmux: T,
        clock: C,
        stop: CancellationToken,
    ) -> io::Result<Self> {
        let state_dir = artifacts::py_path_join(&settings.execution_data_dir, "runner-state");
        std::fs::create_dir_all(&state_dir)?;
        Ok(Self {
            inner: Arc::new(Inner {
                settings,
                api,
                tmux,
                clock,
                stop,
                state_dir,
                workers: Mutex::new(Workers::default()),
                worker_done: Notify::new(),
                artifacts_scanned: AtomicBool::new(false),
            }),
        })
    }

    /// `<execution_data_dir>/runner-state`.
    pub fn state_dir(&self) -> &Path {
        &self.inner.state_dir
    }

    /// `_worker_state_path(ticket_id)`: `<state_dir>/<ticket_id>.json`.
    pub fn state_path(&self, ticket_id: &str) -> PathBuf {
        self.inner.state_dir.join(format!("{ticket_id}.json"))
    }

    /// `run_forever(once=…)`.
    pub async fn run_forever(&self, once: bool) -> Result<(), SupervisorError> {
        let include_artifacts = !self.inner.artifacts_scanned.swap(true, Ordering::SeqCst);
        self.recover_inflight_tickets(include_artifacts).await?;
        let settings = &self.inner.settings;
        let poll_interval = seconds(settings.runner_poll_interval_seconds);
        let max_parallel_jobs = usize::try_from(settings.max_parallel_jobs).unwrap_or(usize::MAX);

        while !self.inner.stop.is_cancelled() {
            self.reap_finished_workers().await?;
            self.recover_inflight_tickets(false).await?;

            let disable_file = PathBuf::from(&settings.disable_file_path);
            if blocking(move || Ok(disable_file.exists())).await? {
                if once {
                    break;
                }
                self.sleep(poll_interval).await;
                continue;
            }

            let mut claimed_any = false;
            while self.active_worker_count() < max_parallel_jobs && !self.inner.stop.is_cancelled()
            {
                let claimed = match self.inner.api.claim_ticket(&settings.runner_host).await {
                    Ok(claimed) => claimed,
                    Err(error) => {
                        tracing::warn!(
                            "Runner claim failed: status={} category={}",
                            error.status_code,
                            error.error_code
                        );
                        break;
                    }
                };
                let Some(ticket) = claimed else {
                    break;
                };
                claimed_any = true;
                let ticket_id = pytext::strip(&text_or(&ticket, "id", "")).to_owned();
                if ticket_id.is_empty() {
                    continue;
                }
                self.write_state_file(&ticket_id).await?;
                self.start_worker(ticket_id, Some(ticket));
            }

            if once {
                if claimed_any {
                    self.wait_for_workers().await?;
                }
                break;
            }
            self.sleep(poll_interval).await;
        }

        self.wait_for_workers().await
    }

    /// `_write_state_file(ticket_id)`: `{ticket_id, runner_host,
    /// updated_at}`, published atomically (4.13.7).
    pub async fn write_state_file(&self, ticket_id: &str) -> io::Result<()> {
        let mut state = JsonObject::new();
        state.insert("ticket_id".into(), Value::from(ticket_id));
        state.insert(
            "runner_host".into(),
            Value::from(self.inner.settings.runner_host.as_str()),
        );
        state.insert(
            "updated_at".into(),
            Value::from(isoformat_z(&self.inner.clock.now())),
        );
        let path = self.state_path(ticket_id);
        blocking(move || artifacts::atomic_write_json(&path, &Value::Object(state))).await
    }

    /// `_remove_state_file(ticket_id)` (`unlink(missing_ok=True)`).
    pub async fn remove_state_file(&self, ticket_id: &str) -> io::Result<()> {
        let path = self.state_path(ticket_id);
        blocking(move || match std::fs::remove_file(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        })
        .await
    }

    /// `_start_worker`: a worker task for `ticket_id`, unless one is still
    /// running for it.
    pub fn start_worker(&self, ticket_id: String, initial_ticket: Option<JsonObject>) {
        let mut workers = self.workers();
        if workers
            .handles
            .get(&ticket_id)
            .is_some_and(|handle| !handle.is_finished())
        {
            return;
        }
        let supervisor = self.clone();
        let worker_ticket_id = ticket_id.clone();
        let handle = tokio::spawn(async move {
            supervisor
                .run_worker(&worker_ticket_id, initial_ticket)
                .await;
            supervisor.inner.worker_done.notify_waiters();
        });
        workers.handles.insert(ticket_id, handle);
    }

    /// `_run_worker`: runs the ticket's executor and marks the state file
    /// for removal when the ticket needs no recovery any more.
    ///
    /// - success → marked;
    /// - API error ≥ 500 → `Runner API unavailable: status=<s>
    ///   category=<c>`, the state file stays (an outage is resumable);
    /// - any other error → one log line (D-12), the ticket's sessions are
    ///   killed and verified gone, then `failed`/`failed`/`failure`/
    ///   `runner_unhandled_exception:<kind>` is posted (D-13); marked only if
    ///   both worked;
    /// - finally, when not marked: a ticket the API reports terminal has its
    ///   sessions killed and is marked once that is verified.
    pub async fn run_worker(&self, ticket_id: &str, initial_ticket: Option<JsonObject>) {
        let inner = &self.inner;
        let executor = TicketExecutor::new(
            inner.settings.clone(),
            inner.api.clone(),
            inner.tmux.clone(),
            inner.clock.clone(),
            inner.stop.clone(),
            ticket_id,
        );
        let mut remove_state = false;
        match executor.run(initial_ticket).await {
            Ok(()) => remove_state = true,
            Err(error) => match error.api_error() {
                Some(api_error) if api_error.status_code >= 500 => {
                    tracing::warn!(
                        "Runner API unavailable: status={} category={}",
                        api_error.status_code,
                        api_error.error_code
                    );
                }
                _ => {
                    tracing::error!(
                        "Runner worker failed: ticket={ticket_id} kind={} error={error}",
                        error.kind_name()
                    );
                    remove_state = self.report_worker_failure(ticket_id, &error).await;
                }
            },
        }
        if !remove_state
            && let Ok(latest) = inner.api.get_ticket(ticket_id).await
            && is_terminal(&text_or(&latest, "state", ""))
            && self.kill_tmux_sessions_for_ticket(ticket_id).await.is_ok()
        {
            remove_state = true;
        }
        self.workers()
            .cleanup
            .insert(ticket_id.to_owned(), remove_state);
    }

    /// The cleanup and report after an unexpected worker error; whether both
    /// succeeded.
    async fn report_worker_failure(&self, ticket_id: &str, error: &ExecutorError) -> bool {
        if self.kill_tmux_sessions_for_ticket(ticket_id).await.is_err() {
            return false;
        }
        let mut payload = JsonObject::new();
        payload.insert(
            "runner_host".into(),
            Value::from(self.inner.settings.runner_host.as_str()),
        );
        payload.insert("event".into(), Value::from("failed"));
        payload.insert("state".into(), Value::from("failed"));
        payload.insert("result".into(), Value::from("failure"));
        payload.insert(
            "result_detail".into(),
            Value::from(format!("runner_unhandled_exception:{}", error.kind_name())),
        );
        self.inner
            .api
            .update_status(ticket_id, &payload)
            .await
            .is_ok()
    }

    /// The cleanup mark a finished worker left (`_worker_cleanup[ticket_id]`)
    /// and that `reap_finished_workers` has not consumed yet.
    pub fn cleanup_mark(&self, ticket_id: &str) -> Option<bool> {
        self.workers().cleanup.get(ticket_id).copied()
    }

    /// `_recover_inflight_tickets(include_artifacts=…)`.
    ///
    /// Candidates: the ids of the state files (a file that is not JSON, not
    /// an object or has no `ticket_id` is deleted), the tickets of the tmux
    /// sessions named `job-<uuid>-NN-…` and, with `include_artifacts`, the
    /// artifact directories named like a ticket id. In sorted order, until
    /// `max_parallel_jobs` workers run: a ticket the API cannot return is
    /// skipped (its state file stays); one that is not `running` has its
    /// sessions killed (verified; else skipped) and its state file removed;
    /// a running one gets a fresh state file and a worker.
    pub async fn recover_inflight_tickets(
        &self,
        include_artifacts: bool,
    ) -> Result<(), SupervisorError> {
        let state_dir = self.inner.state_dir.clone();
        let mut candidates: BTreeSet<String> = blocking(move || state_file_ids(&state_dir))
            .await?
            .into_iter()
            .collect();
        candidates.extend(self.discover_ticket_ids_from_tmux().await?);
        if include_artifacts {
            candidates.extend(self.discover_ticket_ids_from_artifacts().await?);
        }

        let max_parallel_jobs =
            usize::try_from(self.inner.settings.max_parallel_jobs).unwrap_or(usize::MAX);
        for ticket_id in candidates {
            if self.active_worker_count() >= max_parallel_jobs {
                break;
            }
            let Ok(ticket) = self.inner.api.get_ticket(&ticket_id).await else {
                continue;
            };
            let state = pytext::py_lower(pytext::strip(&text_or(&ticket, "state", "")));
            // Terminal and other non-running states are handled alike.
            if state != "running" {
                if self
                    .kill_tmux_sessions_for_ticket(&ticket_id)
                    .await
                    .is_err()
                {
                    continue;
                }
                self.remove_state_file(&ticket_id).await?;
                continue;
            }
            self.write_state_file(&ticket_id).await?;
            self.start_worker(ticket_id, Some(ticket));
        }
        Ok(())
    }

    /// `_discover_ticket_ids_from_tmux`: the ticket ids of the sessions `tmux
    /// ls` lists. A missing `tmux` or a failing `ls` (no server) means none.
    pub async fn discover_ticket_ids_from_tmux(&self) -> Result<BTreeSet<String>, SupervisorError> {
        let listing = match self.inner.tmux.list_sessions().await {
            Ok(listing) => listing,
            Err(TmuxError::Spawn(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(error) => return Err(SupervisorError::Tmux(error)),
        };
        if !listing.success {
            return Ok(BTreeSet::new());
        }
        Ok(session_names(&listing.stdout)
            .filter_map(|name| {
                let candidate = TMUX_TICKET_RE.captures(name)?.get(1)?.as_str();
                TICKET_ID_RE
                    .is_match(candidate)
                    .then(|| candidate.to_owned())
            })
            .collect())
    }

    /// `_discover_ticket_ids_from_artifacts`: the directories (symlinks
    /// followed) under `session_artifacts_dir` named like a ticket id.
    pub async fn discover_ticket_ids_from_artifacts(&self) -> io::Result<BTreeSet<String>> {
        let root = PathBuf::from(&self.inner.settings.session_artifacts_dir);
        blocking(move || {
            let mut discovered = BTreeSet::new();
            if !root.exists() {
                return Ok(discovered);
            }
            for entry in std::fs::read_dir(&root)? {
                let entry = entry?;
                if !entry.path().is_dir() {
                    continue;
                }
                if let Some(name) = entry.file_name().to_str()
                    && TICKET_ID_RE.is_match(name)
                {
                    discovered.insert(name.to_owned());
                }
            }
            Ok(discovered)
        })
        .await
    }

    /// `_tmux_sessions_for_ticket`: the listed sessions named
    /// `job-<ticket_id>-…`. No server means none; a missing `tmux` or another
    /// `ls` failure is an error.
    pub async fn tmux_sessions_for_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<Vec<String>, CleanupError> {
        let listing = match self.inner.tmux.list_sessions().await {
            Ok(listing) => listing,
            Err(TmuxError::Spawn(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CleanupError::Unverifiable);
            }
            Err(error) => return Err(CleanupError::Tmux(error)),
        };
        if !listing.success {
            if ABSENT_SERVER_DIAGNOSTICS
                .iter()
                .any(|diagnostic| listing.stderr.contains(diagnostic))
            {
                return Ok(Vec::new());
            }
            return Err(CleanupError::Unverifiable);
        }
        let prefix = format!("job-{ticket_id}-");
        Ok(session_names(&listing.stdout)
            .filter(|name| name.starts_with(&prefix))
            .map(str::to_owned)
            .collect())
    }

    /// `_kill_tmux_sessions_for_ticket`: kill every session of the ticket,
    /// then verify that none is listed any more.
    pub async fn kill_tmux_sessions_for_ticket(&self, ticket_id: &str) -> Result<(), CleanupError> {
        for session_name in self.tmux_sessions_for_ticket(ticket_id).await? {
            self.inner
                .tmux
                .kill_session(&session_name)
                .await
                .map_err(CleanupError::Tmux)?;
        }
        if self.tmux_sessions_for_ticket(ticket_id).await?.is_empty() {
            Ok(())
        } else {
            Err(CleanupError::Remain)
        }
    }

    /// `_active_worker_count`: workers whose task has not finished.
    pub fn active_worker_count(&self) -> usize {
        self.workers()
            .handles
            .values()
            .filter(|handle| !handle.is_finished())
            .count()
    }

    /// `_reap_finished_workers`: forget finished workers and remove the
    /// state files of those marked for cleanup.
    pub async fn reap_finished_workers(&self) -> io::Result<()> {
        let to_remove: Vec<String> = {
            let mut workers = self.workers();
            let finished: Vec<String> = workers
                .handles
                .iter()
                .filter(|(_, handle)| handle.is_finished())
                .map(|(ticket_id, _)| ticket_id.clone())
                .collect();
            finished
                .into_iter()
                .filter(|ticket_id| {
                    workers.handles.remove(ticket_id);
                    workers.cleanup.remove(ticket_id).unwrap_or(false)
                })
                .collect()
        };
        for ticket_id in to_remove {
            self.remove_state_file(&ticket_id).await?;
        }
        Ok(())
    }

    /// `_wait_for_workers`: reap until no worker runs. The workers that
    /// finished last are reaped too.
    pub async fn wait_for_workers(&self) -> Result<(), SupervisorError> {
        loop {
            let notified = self.inner.worker_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.reap_finished_workers().await?;
            if self.active_worker_count() == 0 {
                self.reap_finished_workers().await?;
                return Ok(());
            }
            let _ = tokio::time::timeout(WORKER_JOIN_WAIT, notified).await;
        }
    }

    /// A sleep that ends when the stop token is cancelled (D-16).
    async fn sleep(&self, duration: Duration) {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = self.inner.stop.cancelled() => {}
        }
    }

    fn workers(&self) -> MutexGuard<'_, Workers> {
        // A worker never panics while holding the lock (no code in the
        // critical sections can), so the data is consistent either way.
        self.inner
            .workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Seconds of a positive setting as a duration.
fn seconds(value: i64) -> Duration {
    Duration::from_secs(u64::try_from(value).unwrap_or(1))
}

/// The session names of `tmux ls` output: per line (`str.splitlines()`) the
/// text before the first `:`, stripped.
fn session_names(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .split(pytext::is_line_boundary)
        .map(|line| pytext::strip(line.split(':').next().unwrap_or("")))
}

/// The ticket ids of the state files (`runner-state/*.json`, hidden files
/// included, as `Path.glob`). A file that is not JSON (a BOM included), not
/// an object or has no non-blank `ticket_id` is deleted. A directory that
/// cannot be listed has no files (`glob` ignores the error); a file that
/// cannot be read or is not UTF-8 is an error (Python: `OSError`,
/// `UnicodeDecodeError`, not caught).
fn state_file_ids(state_dir: &Path) -> io::Result<Vec<String>> {
    use std::os::unix::ffi::OsStrExt;

    let Ok(entries) = std::fs::read_dir(state_dir) else {
        return Ok(Vec::new());
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().as_bytes().ends_with(b".json"))
        .map(|entry| entry.path())
        .collect();
    files.sort();

    let mut ids = Vec::new();
    for path in files {
        let text = String::from_utf8(std::fs::read(&path)?).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "runner state file is not UTF-8")
        })?;
        let ticket_id = match opsgate_core::json::parse(&text) {
            Ok(Value::Object(state)) => pytext::strip(&text_or(&state, "ticket_id", "")).to_owned(),
            _ => String::new(),
        };
        if ticket_id.is_empty() {
            match std::fs::remove_file(&path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
            continue;
        }
        ids.push(ticket_id);
    }
    Ok(ids)
}

/// Cancel `stop` on SIGTERM and SIGINT (`install_signal_handlers`), for the
/// life of the runtime. Must be called inside a tokio runtime.
pub fn install_signal_handlers(stop: CancellationToken) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            stop.cancel();
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_id_pattern_follows_python() {
        let id = "aaaaaaaa-1111-4111-8111-111111111111";
        assert!(TICKET_ID_RE.is_match(id));
        assert!(TICKET_ID_RE.is_match(&id.to_uppercase()));
        // Python's `$` matches before a final newline.
        assert!(TICKET_ID_RE.is_match(&format!("{id}\n")));
        assert!(!TICKET_ID_RE.is_match(&format!("{id}\n\n")));
        assert!(!TICKET_ID_RE.is_match(&format!("{id}x")));
        assert!(!TICKET_ID_RE.is_match("aaaaaaaa-1111-4111-8111-11111111111"));
        assert!(!TICKET_ID_RE.is_match("gaaaaaaa-1111-4111-8111-111111111111"));
    }

    #[test]
    fn tmux_session_pattern_follows_python() {
        let id = "aaaaaaaa-1111-4111-8111-111111111111";
        let captured = |name: &str| {
            TMUX_TICKET_RE
                .captures(name)
                .and_then(|captures| captures.get(1))
                .map(|group| group.as_str().to_owned())
        };
        assert_eq!(
            captured(&format!("job-{id}-01-investigator")).as_deref(),
            Some(id)
        );
        assert_eq!(captured(&format!("job-{id}-12-")).as_deref(), Some(id));
        // `\d` is Unicode in Python's `re` (str patterns) and in `regex`.
        assert_eq!(
            captured(&format!("job-{id}-\u{661}\u{662}-x")).as_deref(),
            Some(id)
        );
        assert_eq!(captured(&format!("job-{id}-1-x")), None);
        assert_eq!(captured(&format!("xjob-{id}-01-x")), None);
        // 36 characters of the class that are not a ticket id.
        let dashes = "-".repeat(36);
        assert_eq!(
            captured(&format!("job-{dashes}-01-x")).as_deref(),
            Some(dashes.as_str())
        );
        assert!(!TICKET_ID_RE.is_match(&dashes));
    }

    #[test]
    fn session_names_split_like_python() {
        let stdout =
            "job-a: 1 windows (created x)\r\n  job-b : 1 windows\n\nplain\u{2028}job-c:x:y\n";
        assert_eq!(
            session_names(stdout)
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>(),
            ["job-a", "job-b", "plain", "job-c"]
        );
    }

    #[test]
    fn state_file_ids_delete_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        let write = |name: &str, text: &[u8]| std::fs::write(state.join(name), text).unwrap();
        write("a.json", br#"{"ticket_id": " id-a "}"#);
        write(".hidden.json", br#"{"ticket_id": "id-hidden"}"#);
        write("number.json", br#"{"ticket_id": 7}"#);
        write("not-json.json", b"{");
        write("bom.json", "\u{feff}{\"ticket_id\": \"x\"}".as_bytes());
        write("array.json", b"[]");
        write("blank.json", br#"{"ticket_id": "  "}"#);
        write("missing.json", br#"{"id": "x"}"#);
        write("other.txt", br#"{"ticket_id": "id-txt"}"#);
        write("tmpabc", b"{");
        let mut ids = state_file_ids(state).unwrap();
        ids.sort();
        assert_eq!(ids, ["7", "id-a", "id-hidden"]);
        let mut left: Vec<String> = std::fs::read_dir(state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                ".hidden.json",
                "a.json",
                "number.json",
                "other.txt",
                "tmpabc"
            ]
        );

        // Not UTF-8, and a directory named like a state file: errors.
        write("z.json", b"\xff");
        assert_eq!(
            state_file_ids(state).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::remove_file(state.join("z.json")).unwrap();
        std::fs::create_dir(state.join("dir.json")).unwrap();
        assert!(state_file_ids(state).is_err());

        // A missing directory has no state files.
        assert!(state_file_ids(&state.join("missing")).unwrap().is_empty());
    }
}
