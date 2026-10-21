//! Fakes shared by the runner tests: an in-memory API, a scripted tmux and a
//! clock that follows tokio's (paused) time (PLAN.md 7.1).

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use opsgate_core::settings::{Environment, RunnerSettings, load_runner_settings_with_host};
use opsgate_runner::{
    Clock, JsonObject, RunnerApi, RunnerApiError, SessionListing, Tmux, TmuxError,
};
use serde_json::Value;

/// `CLOCK_START` of `tests/test_runner.py`.
pub fn clock_start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

/// The wall clock as `CLOCK_START` plus the tokio time elapsed since
/// creation (the Python tests' patched `utc_now`).
#[derive(Clone, Copy)]
pub struct TestClock {
    start: tokio::time::Instant,
}

impl TestClock {
    pub fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
        }
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        clock_start() + (tokio::time::Instant::now() - self.start)
    }
}

/// `_runner_settings(tmp_path)` with an optional heartbeat interval.
pub fn runner_settings(root: &Path, heartbeat: i64) -> RunnerSettings {
    let execution = root.join("execution");
    let execution = execution.to_str().unwrap();
    let mut environment = Environment::from_vars([
        (
            "OPSGATE_RUNNER_TOKEN",
            "runner-token-000000000000".to_owned(),
        ),
        ("OPSGATE_RUNNER_HOST", "runner-a".to_owned()),
        ("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS", "1".to_owned()),
        (
            "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS",
            heartbeat.to_string(),
        ),
        ("OPSGATE_MAX_PARALLEL_JOBS", "2".to_owned()),
        ("OPSGATE_EXECUTION_DATA_DIR", execution.to_owned()),
        ("OPSGATE_TMUX_SOCKET_LABEL", "remediation".to_owned()),
        ("TMUX_TMPDIR", format!("{execution}/tmux")),
    ]);
    load_runner_settings_with_host(&mut environment, || "unused".to_owned()).unwrap()
}

/// A ticket in state `running` started `elapsed` seconds before
/// `CLOCK_START`.
pub fn running_ticket(ticket_id: &str, plan: Value, elapsed: i64, max_duration: i64) -> JsonObject {
    let started_at = clock_start() - chrono::TimeDelta::seconds(elapsed);
    let ticket = serde_json::json!({
        "id": ticket_id,
        "state": "running",
        "started_at": opsgate_core::time::isoformat_z(&started_at),
        "max_duration_seconds": max_duration,
        "execution_plan": plan,
        "tmux_sessions": [],
    });
    ticket.as_object().unwrap().clone()
}

type UpdateHook = Box<dyn FnMut(&JsonObject) -> Result<(), RunnerApiError> + Send>;
type GetHook = Box<dyn FnMut(&mut JsonObject) -> Result<(), RunnerApiError> + Send>;

/// `FakeApi` of `tests/test_runner.py`: `get_ticket` returns the ticket,
/// `update_status` records the payload and applies state, result, detail
/// and sessions. Hooks can fail calls or change the ticket.
#[derive(Default)]
pub struct FakeApi {
    pub ticket: Mutex<JsonObject>,
    pub updates: Mutex<Vec<JsonObject>>,
    pub update_attempts: AtomicUsize,
    pub get_calls: AtomicUsize,
    update_hook: Mutex<Option<UpdateHook>>,
    get_hook: Mutex<Option<GetHook>>,
}

impl FakeApi {
    pub fn new(ticket: JsonObject) -> Arc<Self> {
        Arc::new(Self {
            ticket: Mutex::new(ticket),
            ..Self::default()
        })
    }

    pub fn on_update(
        &self,
        hook: impl FnMut(&JsonObject) -> Result<(), RunnerApiError> + Send + 'static,
    ) {
        *self.update_hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn on_get(
        &self,
        hook: impl FnMut(&mut JsonObject) -> Result<(), RunnerApiError> + Send + 'static,
    ) {
        *self.get_hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn ticket_field(&self, key: &str) -> Value {
        self.ticket
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or(Value::Null)
    }

    pub fn set_state(&self, state: &str) {
        self.ticket
            .lock()
            .unwrap()
            .insert("state".into(), Value::from(state));
    }

    pub fn updates(&self) -> Vec<JsonObject> {
        self.updates.lock().unwrap().clone()
    }

    pub fn details(&self) -> Vec<String> {
        self.updates()
            .iter()
            .map(|update| {
                update
                    .get("result_detail")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            })
            .collect()
    }

    pub fn events(&self) -> Vec<String> {
        self.updates()
            .iter()
            .map(|update| update["event"].as_str().unwrap().to_owned())
            .collect()
    }
}

impl RunnerApi for FakeApi {
    async fn claim_ticket(&self, _runner_host: &str) -> Result<Option<JsonObject>, RunnerApiError> {
        Ok(None)
    }

    async fn get_ticket(&self, _ticket_id: &str) -> Result<JsonObject, RunnerApiError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        let mut ticket = self.ticket.lock().unwrap();
        if let Some(hook) = self.get_hook.lock().unwrap().as_mut() {
            hook(&mut ticket)?;
        }
        Ok(ticket.clone())
    }

    async fn update_status(
        &self,
        _ticket_id: &str,
        payload: &JsonObject,
    ) -> Result<JsonObject, RunnerApiError> {
        self.update_attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.update_hook.lock().unwrap().as_mut() {
            hook(payload)?;
        }
        self.updates.lock().unwrap().push(payload.clone());
        let mut ticket = self.ticket.lock().unwrap();
        for key in ["state", "result", "result_detail", "tmux_sessions"] {
            if let Some(value) = payload.get(key) {
                ticket.insert(key.into(), value.clone());
            }
        }
        Ok(ticket.clone())
    }
}

/// What `tmux ls` of [`FakeTmux`] does.
#[derive(Debug, Clone, Default)]
pub enum Listing {
    /// Lists `FakeTmux::sessions` (exit 0).
    #[default]
    Sessions,
    /// `tmux` is not on `PATH` (spawn error `NotFound`).
    MissingBinary,
    /// `tmux` cannot be started for another reason.
    SpawnFails,
    /// Exits 1 with this diagnostic on stderr.
    Fails(&'static str),
}

type TmuxHook = Box<dyn Fn(&FakeTmux) + Send + Sync>;
type LaunchHook = Box<dyn Fn(&FakeTmux, &Path) + Send + Sync>;

/// `StubTicketExecutor`'s tmux: `has_session` answers a flag, `new_session`
/// records the launch and (with `auto_exit_code`) writes `session.log` and
/// `exit_code` next to the script, `kill_session` records the name.
///
/// For the supervisor, `list_sessions` follows [`Listing`] and lists
/// `sessions`, which `kill_session` empties unless `sticky` is set; `calls`
/// records `ls` and `kill-session <name>` in order.
#[derive(Default)]
pub struct FakeTmux {
    pub has_session: AtomicBool,
    pub auto_exit_code: Option<i32>,
    pub launched: Mutex<Vec<String>>,
    pub scripts: Mutex<Vec<PathBuf>>,
    pub killed: Mutex<Vec<String>>,
    pub probes: AtomicUsize,
    pub sessions: Mutex<Vec<String>>,
    pub sticky: AtomicBool,
    pub listing: Mutex<Listing>,
    pub calls: Mutex<Vec<String>>,
    on_probe: Option<TmuxHook>,
    on_launch: Option<LaunchHook>,
}

impl FakeTmux {
    pub fn new(has_session: bool, auto_exit_code: Option<i32>) -> Self {
        Self {
            has_session: AtomicBool::new(has_session),
            auto_exit_code,
            ..Self::default()
        }
    }

    /// Runs before every `has_session` answer.
    pub fn on_probe(mut self, hook: impl Fn(&FakeTmux) + Send + Sync + 'static) -> Self {
        self.on_probe = Some(Box::new(hook));
        self
    }

    /// Runs after every launch.
    pub fn on_launch(mut self, hook: impl Fn(&FakeTmux, &Path) + Send + Sync + 'static) -> Self {
        self.on_launch = Some(Box::new(hook));
        self
    }

    pub fn launched(&self) -> Vec<String> {
        self.launched.lock().unwrap().clone()
    }

    pub fn killed(&self) -> Vec<String> {
        self.killed.lock().unwrap().clone()
    }

    /// Sessions `tmux ls` lists.
    pub fn with_sessions(self, sessions: &[&str]) -> Self {
        *self.sessions.lock().unwrap() = sessions.iter().map(|name| (*name).to_owned()).collect();
        self
    }

    pub fn set_listing(&self, listing: Listing) {
        *self.listing.lock().unwrap() = listing;
    }

    pub fn sessions(&self) -> Vec<String> {
        self.sessions.lock().unwrap().clone()
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Tmux for FakeTmux {
    async fn has_session(&self, _session_name: &str) -> Result<bool, TmuxError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = &self.on_probe {
            hook(self);
        }
        Ok(self.has_session.load(Ordering::SeqCst))
    }

    async fn new_session(&self, session_name: &str, script_path: &Path) -> Result<(), TmuxError> {
        self.launched.lock().unwrap().push(session_name.to_owned());
        self.sessions.lock().unwrap().push(session_name.to_owned());
        self.scripts.lock().unwrap().push(script_path.to_owned());
        if let Some(code) = self.auto_exit_code {
            let step_dir = script_path.parent().unwrap();
            std::fs::write(step_dir.join("session.log"), "ok\n").unwrap();
            std::fs::write(step_dir.join("exit_code"), format!("{code}\n")).unwrap();
        }
        if let Some(hook) = &self.on_launch {
            hook(self, script_path);
        }
        Ok(())
    }

    async fn kill_session(&self, session_name: &str) -> Result<(), TmuxError> {
        self.killed.lock().unwrap().push(session_name.to_owned());
        self.calls
            .lock()
            .unwrap()
            .push(format!("kill-session {session_name}"));
        if !self.sticky.load(Ordering::SeqCst) {
            self.sessions
                .lock()
                .unwrap()
                .retain(|name| name != session_name);
        }
        Ok(())
    }

    async fn list_sessions(&self) -> Result<SessionListing, TmuxError> {
        self.calls.lock().unwrap().push("ls".to_owned());
        let listing = self.listing.lock().unwrap().clone();
        match listing {
            Listing::Sessions => Ok(SessionListing {
                success: true,
                stdout: self
                    .sessions()
                    .iter()
                    .map(|name| format!("{name}: 1 windows (created Thu Jan  1 00:00:00 2026)\n"))
                    .collect(),
                stderr: String::new(),
            }),
            Listing::MissingBinary => Err(TmuxError::Spawn(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            ))),
            Listing::SpawnFails => Err(TmuxError::Spawn(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
            Listing::Fails(diagnostic) => Ok(SessionListing {
                success: false,
                stdout: String::new(),
                stderr: format!("{diagnostic}\n"),
            }),
        }
    }
}

/// Read a JSON file.
pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

type FleetGetHook = Box<dyn FnMut(&str) -> Result<(), RunnerApiError> + Send>;
type FleetUpdateHook = Box<dyn FnMut(&str, &JsonObject) -> Result<(), RunnerApiError> + Send>;

/// An API with several tickets for the supervisor tests: scripted claim
/// results (an empty script claims nothing), tickets by id (an unknown id is
/// `404 http_error`), recorded `GET`s and status updates, which change the
/// ticket like [`FakeApi`]. Hooks run before a call and can fail it.
#[derive(Default)]
pub struct FleetApi {
    pub tickets: Mutex<BTreeMap<String, JsonObject>>,
    pub claims: Mutex<VecDeque<Result<Option<JsonObject>, RunnerApiError>>>,
    pub claim_calls: AtomicUsize,
    pub gets: Mutex<Vec<String>>,
    pub updates: Mutex<Vec<(String, JsonObject)>>,
    get_hook: Mutex<Option<FleetGetHook>>,
    update_hook: Mutex<Option<FleetUpdateHook>>,
}

impl FleetApi {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, ticket: JsonObject) {
        let id = ticket["id"].as_str().unwrap().to_owned();
        self.tickets.lock().unwrap().insert(id, ticket);
    }

    pub fn queue_claim(&self, claim: Result<Option<JsonObject>, RunnerApiError>) {
        self.claims.lock().unwrap().push_back(claim);
    }

    pub fn on_get(&self, hook: impl FnMut(&str) -> Result<(), RunnerApiError> + Send + 'static) {
        *self.get_hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn on_update(
        &self,
        hook: impl FnMut(&str, &JsonObject) -> Result<(), RunnerApiError> + Send + 'static,
    ) {
        *self.update_hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn state(&self, ticket_id: &str) -> Value {
        self.tickets.lock().unwrap()[ticket_id]["state"].clone()
    }

    pub fn gets(&self) -> Vec<String> {
        self.gets.lock().unwrap().clone()
    }

    pub fn updates(&self) -> Vec<(String, JsonObject)> {
        self.updates.lock().unwrap().clone()
    }

    /// The `(ticket id, event, result_detail)` of every recorded update.
    pub fn events(&self) -> Vec<(String, String, String)> {
        self.updates()
            .into_iter()
            .map(|(id, update)| {
                let text = |key: &str| {
                    update
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                (id, text("event"), text("result_detail"))
            })
            .collect()
    }
}

impl RunnerApi for FleetApi {
    async fn claim_ticket(&self, runner_host: &str) -> Result<Option<JsonObject>, RunnerApiError> {
        assert_eq!(runner_host, "runner-a");
        self.claim_calls.fetch_add(1, Ordering::SeqCst);
        let claim = self.claims.lock().unwrap().pop_front().unwrap_or(Ok(None));
        if let Ok(Some(ticket)) = &claim
            && let Some(Value::String(id)) = ticket.get("id")
        {
            self.tickets
                .lock()
                .unwrap()
                .insert(id.clone(), ticket.clone());
        }
        claim
    }

    async fn get_ticket(&self, ticket_id: &str) -> Result<JsonObject, RunnerApiError> {
        self.gets.lock().unwrap().push(ticket_id.to_owned());
        if let Some(hook) = self.get_hook.lock().unwrap().as_mut() {
            hook(ticket_id)?;
        }
        self.tickets
            .lock()
            .unwrap()
            .get(ticket_id)
            .cloned()
            .ok_or_else(|| RunnerApiError::new("not found", 404, "http_error"))
    }

    async fn update_status(
        &self,
        ticket_id: &str,
        payload: &JsonObject,
    ) -> Result<JsonObject, RunnerApiError> {
        if let Some(hook) = self.update_hook.lock().unwrap().as_mut() {
            hook(ticket_id, payload)?;
        }
        self.updates
            .lock()
            .unwrap()
            .push((ticket_id.to_owned(), payload.clone()));
        let mut tickets = self.tickets.lock().unwrap();
        let ticket = tickets.entry(ticket_id.to_owned()).or_default();
        for key in ["state", "result", "result_detail", "tmux_sessions"] {
            if let Some(value) = payload.get(key) {
                ticket.insert(key.into(), value.clone());
            }
        }
        Ok(ticket.clone())
    }
}
