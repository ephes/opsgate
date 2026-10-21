//! The supervisor against a fake API with several tickets and a scripted
//! tmux, on paused tokio time (ports of `tests/test_runner.py`, PLAN.md
//! 4.13.6). The workers run the real executor; the Python tests' exploding
//! executors are tickets the executor cannot run (`started_at` that is not a
//! timestamp: `runner_unhandled_exception:InvalidTicket`).

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{FakeTmux, FleetApi, Listing, TestClock, read_json, runner_settings, running_ticket};
use opsgate_runner::{CleanupError, JsonObject, RunnerApiError, Supervisor, SupervisorError};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

type TestSupervisor = Supervisor<Arc<FleetApi>, Arc<FakeTmux>, TestClock>;

const A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
const B: &str = "bbbbbbbb-2222-4222-8222-222222222222";
const C: &str = "cccccccc-3333-4333-8333-333333333333";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    api: Arc<FleetApi>,
    tmux: Arc<FakeTmux>,
    stop: CancellationToken,
    supervisor: TestSupervisor,
}

impl Fixture {
    fn new(tmux: FakeTmux) -> Self {
        Self::with_heartbeat(tmux, 1)
    }

    fn with_heartbeat(tmux: FakeTmux, heartbeat: i64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let settings = Arc::new(runner_settings(&root, heartbeat));
        let api = FleetApi::new();
        let tmux = Arc::new(tmux);
        let stop = CancellationToken::new();
        let supervisor = Supervisor::new(
            settings,
            api.clone(),
            tmux.clone(),
            TestClock::new(),
            stop.clone(),
        )
        .unwrap();
        Self {
            _dir: dir,
            root,
            api,
            tmux,
            stop,
            supervisor,
        }
    }

    fn state_exists(&self, ticket_id: &str) -> bool {
        self.supervisor.state_path(ticket_id).exists()
    }

    fn state_files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.supervisor.state_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn exec_dir(&self) -> PathBuf {
        self.root.join("execution")
    }

    async fn wait_idle(&self) {
        while self.supervisor.active_worker_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn one_step() -> Value {
    json!([{"role": "investigator", "agent": "codex", "prompt_markdown": "inspect"}])
}

/// A running ticket the executor rejects before any API call.
fn unrunnable(ticket_id: &str) -> JsonObject {
    json!({"id": ticket_id, "state": "running", "started_at": "not a timestamp"})
        .as_object()
        .unwrap()
        .clone()
}

fn ticket(ticket_id: &str, state: &str) -> JsonObject {
    json!({"id": ticket_id, "state": state})
        .as_object()
        .unwrap()
        .clone()
}

fn session(ticket_id: &str) -> String {
    format!("job-{ticket_id}-01-investigator")
}

fn outage(status_code: u16) -> RunnerApiError {
    RunnerApiError::new("outage", status_code, "http_error")
}

// ----- _run_worker -----------------------------------------------------------

/// `test_worker_keeps_state_file_when_status_update_unavailable`.
#[tokio::test(start_paused = true)]
async fn worker_keeps_state_file_when_status_update_unavailable() {
    let f = Fixture::new(FakeTmux::default());
    f.supervisor.write_state_file(A).await.unwrap();
    f.api
        .on_update(|_, _| Err(RunnerApiError::new("down", 503, "unavailable")));
    f.api
        .on_get(|_| Err(RunnerApiError::new("down", 503, "unavailable")));

    f.supervisor.run_worker(A, Some(unrunnable(A))).await;

    assert!(f.state_exists(A));
    assert_eq!(f.supervisor.cleanup_mark(A), Some(false));
    // Cleanup ran (and was verified) before the report was tried.
    assert_eq!(f.tmux.calls(), ["ls", "ls"]);
}

/// `test_worker_exception_report_includes_runner_host`.
#[tokio::test(start_paused = true)]
async fn worker_exception_report_includes_runner_host() {
    let f = Fixture::new(FakeTmux::default());
    f.api.insert(ticket(A, "failed"));

    f.supervisor.run_worker(A, Some(unrunnable(A))).await;

    let updates = f.api.updates();
    assert_eq!(updates.len(), 1);
    assert_eq!(
        Value::Object(updates[0].1.clone()),
        json!({
            "runner_host": "runner-a",
            "event": "failed",
            "state": "failed",
            "result": "failure",
            "result_detail": "runner_unhandled_exception:InvalidTicket",
        })
    );
    assert_eq!(f.supervisor.cleanup_mark(A), Some(true));
}

/// `test_worker_success_marks_state_for_cleanup`: the state file stays
/// until the worker is reaped.
#[tokio::test(start_paused = true)]
async fn worker_success_marks_state_for_cleanup() {
    let f = Fixture::new(FakeTmux::default());
    f.supervisor.write_state_file(A).await.unwrap();

    // Not running: the executor returns without doing anything.
    f.supervisor
        .run_worker(A, Some(ticket(A, "approved")))
        .await;

    assert!(f.state_exists(A));
    assert_eq!(f.supervisor.cleanup_mark(A), Some(true));
    assert!(f.api.gets().is_empty());
    assert!(f.api.updates().is_empty());
}

/// `test_reap_finished_workers_cleans_state_files`.
#[tokio::test(start_paused = true)]
async fn reap_finished_workers_cleans_state_files() {
    let f = Fixture::new(FakeTmux::default());
    f.supervisor.write_state_file(A).await.unwrap();
    f.supervisor.write_state_file(B).await.unwrap();
    f.api
        .on_get(|_| Err(RunnerApiError::new("down", 503, "transport_error")));
    f.supervisor
        .start_worker(A.to_owned(), Some(ticket(A, "succeeded")));
    // An outage keeps B's state file.
    let mut b = running_ticket(B, one_step(), 0, 120);
    b.insert("id".into(), Value::from(B));
    f.supervisor.start_worker(B.to_owned(), Some(b));
    f.wait_idle().await;
    assert_eq!(f.supervisor.cleanup_mark(A), Some(true));
    assert_eq!(f.supervisor.cleanup_mark(B), Some(false));

    f.supervisor.reap_finished_workers().await.unwrap();

    assert!(!f.state_exists(A));
    assert!(f.state_exists(B));
    assert_eq!(f.supervisor.cleanup_mark(A), None);
    assert_eq!(f.supervisor.cleanup_mark(B), None);
    assert_eq!(f.supervisor.active_worker_count(), 0);
}

/// `test_worker_cleans_session_before_terminal_failure`: the failure is
/// reported only after the ticket's sessions were killed and verified gone;
/// if that fails, nothing is reported and the state file stays for recovery.
#[tokio::test(start_paused = true)]
async fn worker_cleans_session_before_terminal_failure() {
    for cleanup_fails in [false, true] {
        let f = Fixture::new(FakeTmux::default().with_sessions(&[&session(A)]));
        f.tmux.sticky.store(cleanup_fails, Ordering::SeqCst);
        f.api.insert(ticket(A, "running"));
        f.supervisor.write_state_file(A).await.unwrap();
        let tmux = f.tmux.clone();
        f.api.on_update(move |_, _| {
            assert!(tmux.sessions().is_empty(), "reported before cleanup");
            Ok(())
        });

        f.supervisor.run_worker(A, Some(unrunnable(A))).await;

        assert_eq!(
            f.supervisor.cleanup_mark(A),
            Some(!cleanup_fails),
            "{cleanup_fails}"
        );
        assert_eq!(!f.api.updates().is_empty(), !cleanup_fails);
        assert!(f.state_exists(A));
        assert_eq!(f.tmux.killed(), [session(A)]);
        let expected_state = if cleanup_fails { "running" } else { "failed" };
        assert_eq!(f.api.state(A), expected_state);
    }
}

/// `test_status_outage_retries_and_retains_execution`: one failed attempt
/// is retried and the ticket completes; three end the worker as an outage
/// (state file kept, not marked, nothing launched).
#[tokio::test(start_paused = true)]
async fn status_outage_retries_and_retains_execution() {
    for failures in [1, 3] {
        let f = Fixture::new(FakeTmux::new(false, Some(0)));
        let mut ticket = running_ticket(A, one_step(), 0, 120);
        ticket.insert("id".into(), Value::from(A));
        f.api.insert(ticket.clone());
        f.supervisor.write_state_file(A).await.unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = attempts.clone();
        f.api.on_update(move |_, payload| {
            let mut seen = seen.lock().unwrap();
            seen.push(payload["event"].as_str().unwrap().to_owned());
            if seen.len() <= failures {
                Err(outage(500))
            } else {
                Ok(())
            }
        });

        f.supervisor.run_worker(A, Some(ticket)).await;

        let started = attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|event| *event == "step_started")
            .count();
        assert_eq!(started, if failures == 1 { 2 } else { 3 });
        assert_eq!(
            f.api.state(A),
            if failures == 1 {
                "succeeded"
            } else {
                "running"
            }
        );
        assert_eq!(f.supervisor.cleanup_mark(A), Some(failures == 1));
        assert!(f.state_exists(A));
        assert_eq!(f.tmux.launched().is_empty(), failures == 3);
    }
}

/// `test_running_heartbeat_outage_never_fails_live_session`: a heartbeat
/// outage never kills or fails the live session; a lasting one ends the
/// worker as an outage with the session left running.
#[tokio::test(start_paused = true)]
async fn running_heartbeat_outage_never_fails_live_session() {
    for outage_persists in [false, true] {
        // A live session: the step is re-attached, not launched.
        let f = Fixture::new(FakeTmux::new(true, None));
        let mut ticket = running_ticket(A, one_step(), 0, 120);
        ticket.insert("id".into(), Value::from(A));
        f.api.insert(ticket.clone());
        f.supervisor.write_state_file(A).await.unwrap();
        let exit_code = f
            .exec_dir()
            .join("sessions")
            .join(A)
            .join("steps/01-investigator/exit_code");
        let heartbeats = Arc::new(std::sync::Mutex::new(0_usize));
        let counted = heartbeats.clone();
        f.api.on_update(move |_, payload| {
            assert_ne!(payload.get("state"), Some(&json!("failed")));
            if payload["event"] == "heartbeat" {
                let mut count = counted.lock().unwrap();
                *count += 1;
                if outage_persists || *count == 1 {
                    return Err(outage(500));
                }
                std::fs::write(&exit_code, "0\n").unwrap();
            }
            Ok(())
        });

        f.supervisor.run_worker(A, Some(ticket)).await;

        assert_eq!(
            *heartbeats.lock().unwrap(),
            if outage_persists { 3 } else { 2 }
        );
        assert_eq!(
            f.api.state(A),
            if outage_persists {
                "running"
            } else {
                "succeeded"
            }
        );
        assert!(f.tmux.killed().is_empty());
        assert!(f.tmux.launched().is_empty());
        assert_eq!(f.supervisor.cleanup_mark(A), Some(!outage_persists));
    }
}

/// `test_permanent_api_error_stops_session_before_failure`: an API error
/// below 500 is not an outage; the sessions are killed before `failed` is
/// reported.
#[tokio::test(start_paused = true)]
async fn permanent_api_error_stops_session_before_failure() {
    for status_code in [400, 404, 409] {
        let f = Fixture::new(FakeTmux::default().with_sessions(&[&session(A)]));
        let mut ticket = running_ticket(A, one_step(), 0, 120);
        ticket.insert("id".into(), Value::from(A));
        f.api.insert(ticket.clone());
        f.api
            .on_get(move |_| Err(RunnerApiError::new("rejected", status_code, "http_error")));
        let tmux = f.tmux.clone();
        f.api.on_update(move |_, payload| {
            assert_eq!(tmux.killed(), [session(A)]);
            assert!(tmux.sessions().is_empty());
            assert_eq!(payload["event"], "failed");
            Ok(())
        });

        f.supervisor.run_worker(A, Some(ticket)).await;

        assert_eq!(f.api.state(A), "failed", "{status_code}");
        assert_eq!(
            f.api.events(),
            [(
                A.to_owned(),
                "failed".to_owned(),
                "runner_unhandled_exception:RunnerApiError".to_owned()
            )]
        );
        assert_eq!(f.supervisor.cleanup_mark(A), Some(true));
    }
}

/// The `finally` of `_run_worker`: after an outage, a ticket the API now
/// reports terminal has its sessions killed and the state file marked; if
/// the sessions cannot be verified gone, it is not marked.
#[tokio::test(start_paused = true)]
async fn worker_outage_with_terminal_ticket_marks_for_cleanup() {
    for cleanup_fails in [false, true] {
        let f = Fixture::new(FakeTmux::default().with_sessions(&[&session(A)]));
        f.tmux.sticky.store(cleanup_fails, Ordering::SeqCst);
        let mut ticket = running_ticket(A, one_step(), 0, 120);
        ticket.insert("id".into(), Value::from(A));
        f.api.insert(ticket.clone());
        let api = f.api.clone();
        let mut first = true;
        f.api.on_get(move |_| {
            if std::mem::take(&mut first) {
                // The API goes away and comes back with the ticket canceled.
                api.tickets.lock().unwrap().get_mut(A).unwrap()["state"] = json!("canceled");
                return Err(RunnerApiError::new("down", 503, "transport_error"));
            }
            Ok(())
        });

        f.supervisor.run_worker(A, Some(ticket)).await;

        assert!(f.api.updates().is_empty());
        assert_eq!(f.api.gets(), [A, A]);
        assert_eq!(f.tmux.killed(), [session(A)]);
        assert_eq!(f.supervisor.cleanup_mark(A), Some(!cleanup_fails));
    }
}

// ----- recovery ----------------------------------------------------------------

/// `test_recovery_restarts_only_running_tickets`: only the running ticket
/// gets a worker (with the ticket recovery fetched); the sessions of the
/// others are killed and their state files removed.
#[tokio::test(start_paused = true)]
async fn recovery_restarts_only_running_tickets() {
    let f = Fixture::new(FakeTmux::new(false, Some(0)).with_sessions(&[
        &session(A),
        &session(B),
        &session(C),
    ]));
    let mut running = running_ticket(A, one_step(), 0, 120);
    running.insert("id".into(), Value::from(A));
    f.api.insert(running);
    f.api.insert(ticket(B, "approved"));
    f.api.insert(ticket(C, "succeeded"));
    for ticket_id in [A, B, C] {
        f.supervisor.write_state_file(ticket_id).await.unwrap();
    }

    f.supervisor.recover_inflight_tickets(true).await.unwrap();

    assert_eq!(f.tmux.killed(), [session(B), session(C)]);
    assert!(f.state_exists(A));
    assert!(!f.state_exists(B));
    assert!(!f.state_exists(C));
    f.supervisor.wait_for_workers().await.unwrap();
    // The worker started from the fetched ticket (no initial GET of its
    // own): one GET by recovery, then the executor's before the step and in
    // its first poll.
    let gets = f.api.gets();
    assert_eq!(gets[0], A);
    let count = |id: &str| gets.iter().filter(|get| *get == id).count();
    assert_eq!((count(A), count(B), count(C)), (3, 1, 1));
    assert!(f.api.events().iter().all(|(id, _, _)| id == A));
    assert_eq!(f.api.state(A), "succeeded");
    assert!(!f.state_exists(A));
}

/// `test_discover_ticket_ids_from_tmux_handles_missing_binary`, plus the
/// session-name parsing and the failures Python does not catch.
#[tokio::test(start_paused = true)]
async fn discover_ticket_ids_from_tmux() {
    let f = Fixture::new(FakeTmux::default().with_sessions(&[
        &session(B),
        &format!("job-{}-02-reviewer", A.to_uppercase()),
        &format!("job-{}-1-reviewer", C),
        "job-------------------------------------01-x",
        "job-not-a-ticket-01-x",
        "other",
    ]));
    let found: Vec<String> = f
        .supervisor
        .discover_ticket_ids_from_tmux()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(found, [A.to_uppercase(), B.to_owned()]);

    f.tmux.set_listing(Listing::MissingBinary);
    assert!(
        f.supervisor
            .discover_ticket_ids_from_tmux()
            .await
            .unwrap()
            .is_empty()
    );
    f.tmux
        .set_listing(Listing::Fails("no server running on /tmp/x"));
    assert!(
        f.supervisor
            .discover_ticket_ids_from_tmux()
            .await
            .unwrap()
            .is_empty()
    );
    f.tmux.set_listing(Listing::Fails("Permission denied"));
    assert!(
        f.supervisor
            .discover_ticket_ids_from_tmux()
            .await
            .unwrap()
            .is_empty()
    );
    f.tmux.set_listing(Listing::SpawnFails);
    assert!(matches!(
        f.supervisor.discover_ticket_ids_from_tmux().await,
        Err(SupervisorError::Tmux(_))
    ));
}

/// `test_recovery_transport_outage_isolated_and_state_retained`: every
/// candidate is tried once; a ticket the API cannot return keeps its state
/// file.
#[tokio::test(start_paused = true)]
async fn recovery_transport_outage_isolated_and_state_retained() {
    let f = Fixture::new(FakeTmux::default());
    for ticket_id in [A, B] {
        f.supervisor.write_state_file(ticket_id).await.unwrap();
    }
    f.api
        .on_get(|_| Err(RunnerApiError::new("offline", 503, "transport_error")));

    f.supervisor.recover_inflight_tickets(false).await.unwrap();

    assert_eq!(f.api.gets(), [A, B]);
    assert!(f.state_exists(A) && f.state_exists(B));
    assert_eq!(f.supervisor.active_worker_count(), 0);
}

/// Recovery stops at `max_parallel_jobs` (2) running workers; a ticket with
/// a live worker gets no second one, and its state file is refreshed.
#[tokio::test(start_paused = true)]
async fn recovery_respects_worker_limit_and_live_workers() {
    // Live sessions without exit codes: the workers poll until stopped.
    let f = Fixture::new(FakeTmux::new(true, None));
    for ticket_id in [A, B, C] {
        let mut running = running_ticket(ticket_id, one_step(), 0, 3600);
        running.insert("id".into(), Value::from(ticket_id));
        f.api.insert(running);
        f.supervisor.write_state_file(ticket_id).await.unwrap();
    }

    f.supervisor.recover_inflight_tickets(false).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(f.supervisor.active_worker_count(), 2);
    let gets = f.api.gets();
    assert_eq!(gets[..2], [A, B]);
    assert!(!gets.contains(&C.to_owned()));

    // At the limit, recovery fetches nothing (the workers' polls go on).
    f.supervisor.recover_inflight_tickets(false).await.unwrap();
    assert!(!f.api.gets().contains(&C.to_owned()));

    // Shutdown: the steps are interrupted, the workers end normally and are
    // marked, so their state files go; C's stays.
    f.stop.cancel();
    f.supervisor.wait_for_workers().await.unwrap();
    assert_eq!(f.state_files(), [format!("{C}.json")]);
    let mut killed = f.tmux.killed();
    killed.sort();
    assert_eq!(killed, [session(A), session(B)]);
    let metadata = read_json(
        &f.exec_dir()
            .join("sessions")
            .join(A)
            .join("steps/01-investigator/session_metadata.json"),
    );
    assert_eq!(metadata["status"], "interrupted");
}

/// The first pass also looks at the artifact directories (named like a
/// ticket id, symlinks followed); later passes do not.
#[tokio::test(start_paused = true)]
async fn first_recovery_pass_includes_artifact_directories() {
    let f = Fixture::new(FakeTmux::default());
    let sessions = f.exec_dir().join("sessions");
    std::fs::create_dir_all(sessions.join(A)).unwrap();
    std::fs::create_dir_all(sessions.join("not-a-ticket")).unwrap();
    std::fs::write(sessions.join(B), "a file").unwrap();
    std::fs::create_dir_all(f.root.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(f.root.join("elsewhere"), sessions.join(C)).unwrap();
    f.api.insert(ticket(A, "succeeded"));
    f.api.insert(ticket(C, "expired"));
    std::fs::write(f.exec_dir().join(".disabled"), "").unwrap();

    f.supervisor.run_forever(true).await.unwrap();

    assert_eq!(f.api.gets(), [A, C]);
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 0);

    // A second run of the same supervisor does not scan them again.
    f.supervisor.run_forever(true).await.unwrap();
    assert_eq!(f.api.gets(), [A, C]);
}

// ----- verified cleanup -----------------------------------------------------

/// `test_cleanup_accepts_absent_tmux_server`.
#[tokio::test(start_paused = true)]
async fn cleanup_accepts_absent_tmux_server() {
    for diagnostic in [
        "no server running on /tmp/tmux-0/remediation",
        "error connecting to /tmp/x (No such file or directory)",
        "error connecting to /tmp/x (Connection refused)",
    ] {
        let f = Fixture::new(FakeTmux::default());
        f.tmux.set_listing(Listing::Fails(diagnostic));
        f.supervisor.kill_tmux_sessions_for_ticket(A).await.unwrap();
        assert_eq!(f.tmux.calls(), ["ls", "ls"]);
    }
}

/// `test_cleanup_rejects_unverifiable_tmux`.
#[tokio::test(start_paused = true)]
async fn cleanup_rejects_unverifiable_tmux() {
    for listing in [
        Listing::MissingBinary,
        Listing::Fails("Permission denied"),
        Listing::SpawnFails,
    ] {
        let f = Fixture::new(FakeTmux::default());
        f.tmux.set_listing(listing.clone());
        let error = f.supervisor.kill_tmux_sessions_for_ticket(A).await;
        assert!(
            matches!(
                error,
                Err(CleanupError::Unverifiable | CleanupError::Tmux(_))
            ),
            "{listing:?}"
        );
    }
}

/// `test_cleanup_verifies_sessions_are_gone`: only the ticket's sessions
/// are killed, and a session that survives is an error.
#[tokio::test(start_paused = true)]
async fn cleanup_verifies_sessions_are_gone() {
    let f = Fixture::new(
        FakeTmux::default().with_sessions(&["job-ticket-01-investigator", "job-other-01-reviewer"]),
    );
    f.tmux.sticky.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.supervisor.kill_tmux_sessions_for_ticket("ticket").await,
        Err(CleanupError::Remain)
    ));
    assert_eq!(
        f.tmux.calls(),
        ["ls", "kill-session job-ticket-01-investigator", "ls"]
    );

    f.tmux.sticky.store(false, Ordering::SeqCst);
    f.supervisor
        .kill_tmux_sessions_for_ticket("ticket")
        .await
        .unwrap();
    assert_eq!(f.tmux.sessions(), ["job-other-01-reviewer"]);
}

// ----- run_forever -------------------------------------------------------------

/// `--once`: one recovery pass and one claim round; the claimed ticket runs
/// to its end and its state file is removed before the supervisor returns.
#[tokio::test(start_paused = true)]
async fn once_claims_runs_and_waits_for_workers() {
    let f = Fixture::new(FakeTmux::new(false, Some(0)));
    let mut claimed = running_ticket(A, one_step(), 0, 120);
    claimed.insert("id".into(), Value::from(A));
    f.api.queue_claim(Ok(Some(claimed)));

    f.supervisor.run_forever(true).await.unwrap();

    assert_eq!(f.api.state(A), "succeeded");
    // The second claim of the round found the queue empty.
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 2);
    assert!(f.state_files().is_empty());
    assert_eq!(f.supervisor.active_worker_count(), 0);
}

/// `--once` ends without claiming when the disable file exists, and after an
/// empty or failed claim.
#[tokio::test(start_paused = true)]
async fn once_ends_on_disable_file_and_empty_or_failed_claims() {
    let f = Fixture::new(FakeTmux::default());
    std::fs::write(f.exec_dir().join(".disabled"), "").unwrap();
    f.supervisor.run_forever(true).await.unwrap();
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 0);

    std::fs::remove_file(f.exec_dir().join(".disabled")).unwrap();
    f.supervisor.run_forever(true).await.unwrap();
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 1);

    f.api
        .queue_claim(Err(RunnerApiError::new("down", 503, "transport_error")));
    f.api.queue_claim(Ok(Some(ticket(A, "running"))));
    f.supervisor.run_forever(true).await.unwrap();
    // A failed claim ends the round.
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 2);
    assert!(f.state_files().is_empty());
}

/// A claimed ticket without an id is skipped and the next one claimed.
#[tokio::test(start_paused = true)]
async fn claimed_ticket_without_id_is_skipped() {
    let f = Fixture::new(FakeTmux::new(false, Some(0)));
    f.api.queue_claim(Ok(Some(
        json!({"id": "  ", "state": "running"})
            .as_object()
            .unwrap()
            .clone(),
    )));
    let mut claimed = running_ticket(A, one_step(), 0, 120);
    claimed.insert("id".into(), Value::from(A));
    f.api.queue_claim(Ok(Some(claimed)));

    f.supervisor.run_forever(true).await.unwrap();

    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 3);
    assert_eq!(f.api.state(A), "succeeded");
    assert!(f.state_files().is_empty());
}

/// The loop claims while fewer than `max_parallel_jobs` workers run and
/// writes a state file per claimed ticket; at shutdown it waits for the
/// workers, whose interrupted steps end them normally.
#[tokio::test(start_paused = true)]
async fn loop_claims_up_to_the_worker_limit_until_stopped() {
    // Live sessions without exit codes: the steps run until stopped.
    let f = Fixture::with_heartbeat(FakeTmux::new(true, None), 30);
    for ticket_id in [A, B, C] {
        let mut claimed = running_ticket(ticket_id, one_step(), 0, 3600);
        claimed.insert("id".into(), Value::from(ticket_id));
        f.api.queue_claim(Ok(Some(claimed)));
    }
    let supervisor = f.supervisor.clone();
    let run = tokio::spawn(async move { supervisor.run_forever(false).await });

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 2);
    assert_eq!(f.supervisor.active_worker_count(), 2);
    assert_eq!(f.state_files(), [format!("{A}.json"), format!("{B}.json")]);
    let state = read_json(&f.supervisor.state_path(A));
    assert_eq!(state["ticket_id"], A);
    assert_eq!(state["runner_host"], "runner-a");
    assert!(state["updated_at"].as_str().unwrap().ends_with('Z'));

    f.stop.cancel();
    run.await.unwrap().unwrap();
    assert_eq!(f.supervisor.active_worker_count(), 0);
    assert!(f.state_files().is_empty());
    assert_eq!(f.api.claim_calls.load(Ordering::SeqCst), 2);
}

/// A state-file write that fails ends the supervisor with an error (Python:
/// an uncaught `OSError`).
#[tokio::test(start_paused = true)]
async fn failing_state_file_write_is_fatal() {
    let f = Fixture::new(FakeTmux::default());
    std::fs::remove_dir(f.supervisor.state_dir()).unwrap();
    std::fs::write(f.supervisor.state_dir(), "not a directory").unwrap();
    f.api.queue_claim(Ok(Some(ticket(A, "running"))));
    assert!(matches!(
        f.supervisor.run_forever(true).await,
        Err(SupervisorError::Io(_))
    ));
    assert_eq!(f.supervisor.active_worker_count(), 0);
}
