//! The ticket executor against a fake API and a scripted tmux, on paused
//! tokio time (ports of `tests/test_runner.py`, PLAN.md 4.13.4, 4.13.5).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{FakeApi, FakeTmux, TestClock, read_json, runner_settings, running_ticket};
use opsgate_runner::artifacts::StepPaths;
use opsgate_runner::{ExecutorError, RunnerApiError, StatusUpdate, TicketExecutor};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

type Executor = TicketExecutor<Arc<FakeApi>, Arc<FakeTmux>, TestClock>;

struct Fixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    api: Arc<FakeApi>,
    tmux: Arc<FakeTmux>,
    stop: CancellationToken,
    executor: Executor,
}

impl Fixture {
    fn new(ticket_id: &str, ticket: serde_json::Map<String, Value>, tmux: FakeTmux) -> Self {
        Self::with_heartbeat(ticket_id, ticket, tmux, 1)
    }

    fn with_heartbeat(
        ticket_id: &str,
        ticket: serde_json::Map<String, Value>,
        tmux: FakeTmux,
        heartbeat: u32,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let settings = Arc::new(runner_settings(&root, heartbeat));
        let api = FakeApi::new(ticket);
        let tmux = Arc::new(tmux);
        let stop = CancellationToken::new();
        let executor = TicketExecutor::new(
            settings,
            api.clone(),
            tmux.clone(),
            TestClock::new(),
            stop.clone(),
            ticket_id,
        );
        Self {
            _dir: dir,
            root,
            api,
            tmux,
            stop,
            executor,
        }
    }

    fn ticket(&self) -> serde_json::Map<String, Value> {
        self.api.ticket.lock().unwrap().clone()
    }

    async fn run(&self) -> Result<(), ExecutorError> {
        self.executor.run(Some(self.ticket())).await
    }

    fn paths(&self, index: usize, step: &Value) -> StepPaths {
        self.executor.step_paths(index, step.as_object().unwrap())
    }

    fn sessions_dir(&self, ticket_id: &str) -> std::path::PathBuf {
        self.root.join("execution/sessions").join(ticket_id)
    }
}

fn two_steps() -> Value {
    json!([
        {"role": "investigator", "agent": "codex", "prompt_markdown": "echo step-1"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "echo step-2"},
    ])
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// `test_ticket_executor_runs_steps_sequentially`, plus the artifacts and
/// the status sequence of a fresh two-step run.
#[tokio::test(start_paused = true)]
async fn ticket_executor_runs_steps_sequentially() {
    let id = "aaaaaaaa-1111-4111-8111-111111111111";
    let plan = two_steps();
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(0)),
    );
    f.run().await.unwrap();

    assert_eq!(f.api.ticket_field("state"), "succeeded");
    assert_eq!(f.api.ticket_field("result"), "success");
    assert_eq!(f.api.ticket_field("result_detail"), "completed_2_steps");
    assert_eq!(
        f.api.events(),
        [
            "step_started",
            "step_finished",
            "step_started",
            "step_finished",
            "ticket_succeeded"
        ]
    );
    assert_eq!(
        f.api.details(),
        [
            "step_1_started",
            "step_1_finished",
            "step_2_started",
            "step_2_finished",
            "completed_2_steps"
        ]
    );
    for update in f.api.updates() {
        assert_eq!(update["runner_host"], "runner-a");
        assert!(update["tmux_sessions"].is_array());
    }
    assert_eq!(
        f.tmux.launched(),
        [
            format!("job-{id}-01-investigator"),
            format!("job-{id}-02-reviewer")
        ]
    );

    let root = f.sessions_dir(id);
    let first = f.paths(0, &plan[0]);
    let second = f.paths(1, &plan[1]);
    assert_eq!(first.step_dir, root.join("steps/01-investigator"));
    for paths in [&first, &second] {
        assert!(paths.summary_path.is_file());
        assert_eq!(mode(&paths.script_path), 0o750);
        assert_eq!(mode(&paths.summary_path), 0o600);
        assert_eq!(mode(&paths.metadata_path), 0o600);
    }
    assert_eq!(
        std::fs::read_to_string(&first.prompt_path).unwrap(),
        "echo step-1\n"
    );
    assert!(!first.previous_summary_path.exists());
    let script = std::fs::read_to_string(&second.script_path).unwrap();
    assert_eq!(
        script,
        format!(
            "#!/bin/bash\nset -uo pipefail\nclaude -p --dangerously-skip-permissions < {} 2>&1 | tee -a {}\ncmd_rc=${{PIPESTATUS[0]}}\nprintf \"%s\\n\" \"$cmd_rc\" > {}\nexit \"$cmd_rc\"\n",
            second.prompt_path.display(),
            second.log_path.display(),
            second.exit_code_path.display()
        )
    );

    let summary = read_json(&first.summary_path);
    let keys: Vec<&str> = summary
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "agent",
            "exit_code",
            "finished_at",
            "log_path",
            "log_sha256",
            "log_size_bytes",
            "role",
            "session_name",
            "started_at",
            "status",
            "step_index",
            "summary_markdown",
            "ticket_id"
        ]
    );
    assert_eq!(summary["status"], "succeeded");
    assert_eq!(summary["exit_code"], 0);
    assert_eq!(summary["log_size_bytes"], 3);
    assert_eq!(
        summary["log_sha256"],
        opsgate_core::json::sha256_hex(b"ok\n")
    );
    assert_eq!(summary["summary_markdown"], "ok");
    assert_eq!(summary["log_path"], first.log_path.to_str().unwrap());

    // Step 2 sees step 1's summary in its context and previous summary.
    let context = read_json(&root.join("context.json"));
    assert_eq!(
        context,
        json!({
            "ticket_id": id,
            "step_index": 1,
            "step_role": "reviewer",
            "step_agent": "claude",
            "prior_step_summaries": [summary.clone()],
        })
    );
    assert_eq!(
        read_json(&f.root.join("execution/jobs").join(id).join("context.json")),
        context
    );
    let previous: Value =
        serde_json::from_str(&std::fs::read_to_string(&second.previous_summary_path).unwrap())
            .unwrap();
    assert_eq!(previous, summary);

    let metadata = read_json(&first.metadata_path);
    assert_eq!(metadata["status"], "succeeded");
    assert_eq!(
        metadata["summary_path"],
        first.summary_path.to_str().unwrap()
    );
    assert_eq!(
        metadata["attach_command"],
        format!(
            "sudo -u ops env TMUX_TMPDIR={}/execution/tmux tmux -L remediation attach -t job-{id}-01-investigator",
            f.root.display()
        )
    );
    assert_eq!(metadata["started_at"], "2026-01-01T00:00:00Z");
    assert!(metadata.get("resumed_at").is_none());
    let sessions = f.api.ticket_field("tmux_sessions");
    assert_eq!(sessions.as_array().unwrap().len(), 2);
    assert_eq!(sessions[0], metadata);
    assert_eq!(sessions[1]["status"], "succeeded");
}

/// `test_ticket_executor_reports_timeout_result[0|10]`.
#[tokio::test(start_paused = true)]
async fn ticket_executor_reports_timeout_result() {
    for elapsed in [0, 10] {
        let id = "bbbbbbbb-2222-4222-8222-222222222222";
        let plan =
            json!([{"role": "investigator", "agent": "codex", "prompt_markdown": "sleep 10"}]);
        let f = Fixture::new(
            id,
            running_ticket(id, plan.clone(), elapsed, 1),
            FakeTmux::new(true, None),
        );
        f.run().await.unwrap();
        assert_eq!(f.api.ticket_field("state"), "failed");
        assert_eq!(f.api.ticket_field("result"), "timeout");
        assert_eq!(
            f.api.ticket_field("result_detail"),
            "max_duration_seconds_exceeded"
        );
        assert_eq!(f.api.events().last().unwrap(), "timeout");
        assert!(!f.tmux.killed().is_empty());
        let metadata = read_json(&f.paths(0, &plan[0]).metadata_path);
        assert_eq!(metadata["status"], "timeout");
        assert!(metadata.get("finished_at").is_some());
    }
}

/// `test_ticket_executor_reports_step_failure_detail`.
#[tokio::test(start_paused = true)]
async fn ticket_executor_reports_step_failure_detail() {
    let id = "dddddddd-4444-4444-8444-444444444444";
    let plan = json!([{"role": "reviewer", "agent": "claude", "prompt_markdown": "exit 7"}]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(7)),
    );
    f.run().await.unwrap();
    assert_eq!(f.api.ticket_field("state"), "failed");
    assert_eq!(f.api.ticket_field("result"), "failure");
    assert_eq!(f.api.ticket_field("result_detail"), "step_1_exit_code_7");
    assert_eq!(f.api.events(), ["step_started", "step_failed"]);
    let paths = f.paths(0, &plan[0]);
    assert_eq!(read_json(&paths.summary_path)["exit_code"], 7);
    assert_eq!(read_json(&paths.summary_path)["status"], "failed");
    assert_eq!(read_json(&paths.metadata_path)["status"], "failed");
}

/// `test_ticket_executor_rejects_unsupported_agent`.
#[tokio::test(start_paused = true)]
async fn ticket_executor_rejects_unsupported_agent() {
    let id = "eeeeeeee-5555-4555-8555-555555555555";
    let plan = json!([{"role": "investigator", "agent": "shell", "prompt_markdown": "Inspect the service"}]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(0)),
    );
    f.run().await.unwrap();
    assert_eq!(f.api.ticket_field("state"), "failed");
    assert_eq!(f.api.ticket_field("result"), "failure");
    assert_eq!(
        f.api.ticket_field("result_detail"),
        "unsupported_agent_shell"
    );
    assert_eq!(f.api.events(), ["step_started", "step_failed"]);
    assert!(f.tmux.launched().is_empty());
    let paths = f.paths(0, &plan[0]);
    assert!(!paths.script_path.exists());
    let metadata = read_json(&paths.metadata_path);
    assert_eq!(metadata["status"], "failed");
    assert!(metadata.get("finished_at").is_some());
}

fn conflict(code: &str) -> RunnerApiError {
    RunnerApiError::new("conflict", 409, code)
}

/// `test_post_status_ignores_conflict_when_ticket_moved_on[invalid_state|state_changed]`.
#[tokio::test(start_paused = true)]
async fn post_status_ignores_conflict_when_ticket_moved_on() {
    for code in ["invalid_state", "state_changed"] {
        let id = "77777777-7777-4777-8777-777777777777";
        let f = Fixture::new(
            id,
            running_ticket(id, json!([]), 0, 120),
            FakeTmux::default(),
        );
        let reply = conflict(code);
        f.api.on_update(move |_| Err(reply.clone()));
        f.executor
            .post_status(StatusUpdate {
                state: "succeeded",
                result: "success",
                ..StatusUpdate::event("ticket_succeeded")
            })
            .await
            .unwrap();
        assert_eq!(f.api.update_attempts.load(Ordering::SeqCst), 1);
    }
}

/// `test_post_status_raises_other_conflicts`.
#[tokio::test(start_paused = true)]
async fn post_status_raises_other_conflicts() {
    let id = "77777777-7777-4777-8777-777777777777";
    let f = Fixture::new(
        id,
        running_ticket(id, json!([]), 0, 120),
        FakeTmux::default(),
    );
    f.api.on_update(|_| Err(conflict("runner_host_mismatch")));
    let error = f
        .executor
        .post_status(StatusUpdate::event("heartbeat"))
        .await
        .unwrap_err();
    assert_eq!(error.error_code, "runner_host_mismatch");
    assert_eq!(f.api.update_attempts.load(Ordering::SeqCst), 1);
}

/// Server errors are retried up to three times one second apart; the
/// payload carries only the given fields.
#[tokio::test(start_paused = true)]
async fn post_status_retries_server_errors() {
    for failures in [1_usize, 2, 3] {
        let id = "77777777-7777-4777-8777-777777777777";
        let f = Fixture::new(
            id,
            running_ticket(id, json!([]), 0, 120),
            FakeTmux::default(),
        );
        let mut seen = 0_usize;
        f.api.on_update(move |_| {
            seen += 1;
            if seen <= failures {
                Err(RunnerApiError::new("outage", 503, "transport_error"))
            } else {
                Ok(())
            }
        });
        let started = tokio::time::Instant::now();
        let result = f
            .executor
            .post_status(StatusUpdate::event("heartbeat"))
            .await;
        assert_eq!(result.is_ok(), failures < 3, "{failures}");
        assert_eq!(
            f.api.update_attempts.load(Ordering::SeqCst),
            failures.min(2) + 1
        );
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(u64::try_from(failures.min(2)).unwrap())
        );
        if failures < 3 {
            assert_eq!(
                Value::Object(f.api.updates()[0].clone()),
                json!({"runner_host": "runner-a", "event": "heartbeat"})
            );
        }
    }
}

/// The retry wait ends at shutdown (`stop_event.wait(1)` returns at once);
/// the remaining attempts are still made.
#[tokio::test(start_paused = true)]
async fn post_status_retry_wait_is_stop_aware() {
    let id = "77777777-7777-4777-8777-777777777777";
    let f = Fixture::new(
        id,
        running_ticket(id, json!([]), 0, 120),
        FakeTmux::default(),
    );
    f.api
        .on_update(|_| Err(RunnerApiError::new("outage", 500, "http_error")));
    f.stop.cancel();
    let started = tokio::time::Instant::now();
    f.executor
        .post_status(StatusUpdate::event("heartbeat"))
        .await
        .unwrap_err();
    assert_eq!(f.api.update_attempts.load(Ordering::SeqCst), 3);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// An empty or missing plan fails the ticket as `invalid_plan`.
#[tokio::test(start_paused = true)]
async fn invalid_plan_fails_the_ticket() {
    for plan in [json!([]), json!("x"), Value::Null] {
        let id = "77777777-7777-4777-8777-777777777777";
        let f = Fixture::new(id, running_ticket(id, plan, 0, 120), FakeTmux::default());
        f.run().await.unwrap();
        assert_eq!(
            Value::Object(f.api.updates()[0].clone()),
            json!({
                "runner_host": "runner-a",
                "event": "invalid_plan",
                "state": "failed",
                "result": "failure",
                "result_detail": "invalid_execution_plan",
                "tmux_sessions": [],
            })
        );
    }
}

/// Only a `running` ticket is executed; without an initial ticket (or an
/// empty one) the executor fetches it.
#[tokio::test(start_paused = true)]
async fn only_running_tickets_execute() {
    let id = "77777777-7777-4777-8777-777777777777";
    for state in ["approved", "succeeded", "canceled", ""] {
        let mut ticket = running_ticket(id, two_steps(), 0, 120);
        ticket.insert("state".into(), Value::from(state));
        let f = Fixture::new(id, ticket, FakeTmux::new(false, Some(0)));
        f.executor.run(None).await.unwrap();
        f.executor.run(Some(serde_json::Map::new())).await.unwrap();
        assert_eq!(f.api.get_calls.load(Ordering::SeqCst), 2);
        assert!(f.api.updates().is_empty());
        assert!(f.tmux.launched().is_empty());
    }
}

/// A ticket that is terminal before a step starts: the sessions recorded as
/// running are killed and nothing is reported.
#[tokio::test(start_paused = true)]
async fn terminal_ticket_before_a_step_kills_running_sessions() {
    let id = "77777777-7777-4777-8777-777777777777";
    let mut ticket = running_ticket(id, two_steps(), 0, 120);
    ticket.insert(
        "tmux_sessions".into(),
        json!([
            {"step_index": 0, "status": "running", "session_name": " job-a "},
            {"step_index": 1, "status": "succeeded", "session_name": "job-b"},
            {"step_index": 2, "status": "RUNNING", "session_name": ""},
        ]),
    );
    let f = Fixture::new(id, ticket.clone(), FakeTmux::new(false, Some(0)));
    f.api.set_state("canceled");
    f.executor.run(Some(ticket)).await.unwrap();
    assert_eq!(f.tmux.killed(), ["job-a"]);
    assert!(f.api.updates().is_empty());
}

/// A cancel seen while the step runs kills the session, marks it canceled
/// and reports nothing more.
#[tokio::test(start_paused = true)]
async fn cancel_during_a_step_kills_the_session() {
    let id = "77777777-7777-4777-8777-777777777777";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 0, 120),
        FakeTmux::new(false, None).on_launch(|tmux, _| {
            tmux.has_session.store(true, Ordering::SeqCst);
        }),
    );
    let mut calls = 0;
    f.api.on_get(move |ticket| {
        calls += 1;
        // Call 1 starts the step, the poll asks at t = 0, 1, 2 s.
        if calls == 4 {
            ticket.insert("state".into(), Value::from("canceled"));
        }
        Ok(())
    });
    f.run().await.unwrap();
    assert_eq!(f.tmux.killed(), [format!("job-{id}-01-implementer")]);
    assert_eq!(f.api.events(), ["step_started", "heartbeat"]);
    let metadata = read_json(&f.paths(0, &plan[0]).metadata_path);
    assert_eq!(metadata["status"], "canceled");
    assert!(metadata.get("finished_at").is_some());
}

/// Another terminal state seen while the step runs fails the step
/// (`ticket_entered_<state>`).
#[tokio::test(start_paused = true)]
async fn terminal_state_during_a_step_fails_it() {
    let id = "77777777-7777-4777-8777-777777777777";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 0, 120),
        FakeTmux::new(false, None).on_launch(|tmux, _| {
            tmux.has_session.store(true, Ordering::SeqCst);
        }),
    );
    let mut calls = 0;
    f.api.on_get(move |ticket| {
        calls += 1;
        if calls == 2 {
            ticket.insert("state".into(), Value::from("expired"));
        }
        Ok(())
    });
    f.run().await.unwrap();
    assert_eq!(f.tmux.killed().len(), 1);
    assert_eq!(f.api.events(), ["step_started", "step_failed"]);
    assert_eq!(f.api.details()[1], "ticket_entered_expired");
    assert_eq!(
        read_json(&f.paths(0, &plan[0]).metadata_path)["status"],
        "running"
    );
}

/// A session that ends without an exit code fails the step; an API error
/// while polling never does.
#[tokio::test(start_paused = true)]
async fn session_gone_without_exit_code_fails_the_step() {
    let id = "77777777-7777-4777-8777-777777777777";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let tmux = FakeTmux::new(false, None).on_launch(|tmux, _| {
        tmux.has_session.store(true, Ordering::SeqCst);
    });
    let f = Fixture::new(id, running_ticket(id, plan, 0, 120), tmux);
    let mut calls = 0;
    f.api.on_get(move |_| {
        calls += 1;
        if calls >= 2 {
            return Err(RunnerApiError::new("outage", 503, "transport_error"));
        }
        Ok(())
    });
    let tmux = f.tmux.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(3500)).await;
        tmux.has_session.store(false, Ordering::SeqCst);
    });
    f.run().await.unwrap();
    assert_eq!(
        f.api.details().last().unwrap(),
        "session_terminated_without_exit_code"
    );
    assert_eq!(f.api.events().last().unwrap(), "step_failed");
}

/// Heartbeats while a step runs: every `max(1, interval)` seconds of the
/// monotonic clock, `running_step_<n>_of_<total>`.
#[tokio::test(start_paused = true)]
async fn heartbeats_follow_the_interval() {
    let id = "77777777-7777-4777-8777-777777777777";
    let plan = json!([
        {"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "review"},
    ]);
    let tmux = FakeTmux::new(false, None).on_launch(|tmux, _| {
        tmux.has_session.store(true, Ordering::SeqCst);
    });
    let f = Fixture::with_heartbeat(id, running_ticket(id, plan.clone(), 0, 120), tmux, 3);
    let first_exit_code = f.paths(0, &plan[0]).exit_code_path;
    let tmux = f.tmux.clone();
    let mut calls = 0;
    f.api.on_get(move |_| {
        calls += 1;
        // Call 1 starts step 1, the poll asks at t = 0, 1, …: call 9 is t = 7.
        if calls == 9 {
            std::fs::write(&first_exit_code, "0\n").unwrap();
            tmux.has_session.store(false, Ordering::SeqCst);
        }
        Ok(())
    });
    tokio::select! {
        result = f.executor.run(Some(f.ticket())) => panic!("the second step never ends: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(18_500)) => {}
    }
    // Step 1 (t = 0..7): t = 3, 6; step 2 starts at t = 7: t = 10, 13, 16.
    assert_eq!(
        f.api.details(),
        [
            "step_1_started",
            "running_step_1_of_2",
            "running_step_1_of_2",
            "step_1_finished",
            "step_2_started",
            "running_step_2_of_2",
            "running_step_2_of_2",
            "running_step_2_of_2"
        ]
    );
    assert_eq!(f.api.events()[1..3], ["heartbeat", "heartbeat"]);
}

fn write_interrupted_step(
    f: &Fixture,
    id: &str,
    index: usize,
    step: &Value,
    exit_code: Option<i32>,
) -> StepPaths {
    let paths = f.paths(index, step);
    std::fs::create_dir_all(&paths.step_dir).unwrap();
    std::fs::write(
        &paths.metadata_path,
        serde_json::to_vec(&json!({
            "step_index": index,
            "role": step["role"],
            "agent": step["agent"],
            "session_name": format!("job-{id}-{:02}-{}", index + 1, step["role"].as_str().unwrap()),
            "status": "running",
            "started_at": "2026-01-01T00:00:00Z",
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &paths.prompt_path,
        format!("{}\n", step["prompt_markdown"].as_str().unwrap()),
    )
    .unwrap();
    std::fs::write(&paths.log_path, "original run output\n").unwrap();
    if let Some(code) = exit_code {
        std::fs::write(&paths.exit_code_path, format!("{code}\n")).unwrap();
    }
    paths
}

/// `test_ticket_executor_resumes_from_existing_step_summary`.
#[tokio::test(start_paused = true)]
async fn ticket_executor_resumes_from_existing_step_summary() {
    let id = "cccccccc-3333-4333-8333-333333333333";
    let plan = two_steps();
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(0)),
    );
    let first = f.paths(0, &plan[0]);
    std::fs::create_dir_all(&first.step_dir).unwrap();
    std::fs::write(
        &first.summary_path,
        "{\"status\":\"succeeded\",\"summary_markdown\":\"already done\"}\n",
    )
    .unwrap();
    f.run().await.unwrap();
    let details = f.api.details();
    assert!(!details.contains(&"step_1_started".to_owned()));
    assert!(details.contains(&"step_2_started".to_owned()));
    assert_eq!(f.api.ticket_field("state"), "succeeded");
}

/// `test_resume_adopts_existing_exit_code_without_relaunch[0|3]`.
#[tokio::test(start_paused = true)]
async fn resume_adopts_existing_exit_code_without_relaunch() {
    for (code, state, detail) in [
        (0, "succeeded", "completed_1_steps"),
        (3, "failed", "step_1_exit_code_3"),
    ] {
        let id = "77777777-7777-4777-8777-777777777777";
        let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
        let f = Fixture::new(
            id,
            running_ticket(id, plan.clone(), 1, 120),
            FakeTmux::new(false, Some(0)),
        );
        let paths = write_interrupted_step(&f, id, 0, &plan[0], Some(code));
        f.run().await.unwrap();
        assert!(f.tmux.launched().is_empty());
        assert!(!paths.script_path.exists());
        assert_eq!(f.api.ticket_field("state"), state);
        assert_eq!(f.api.ticket_field("result_detail"), detail);
        assert_eq!(f.api.details()[0], "step_1_resumed");
        let summary = read_json(&paths.summary_path);
        assert_eq!(summary["exit_code"], code);
        assert_eq!(summary["started_at"], "2026-01-01T00:00:00Z");
        assert_eq!(summary["summary_markdown"], "original run output");
        let metadata = read_json(&paths.metadata_path);
        assert!(metadata.get("resumed_at").is_some());
        assert_eq!(metadata["started_at"], "2026-01-01T00:00:00Z");
    }
}

/// `test_resume_fails_interrupted_step_without_relaunch`.
#[tokio::test(start_paused = true)]
async fn resume_fails_interrupted_step_without_relaunch() {
    let id = "88888888-8888-4888-8888-888888888888";
    let plan = json!([
        {"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "review"},
    ]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(0)),
    );
    let paths = write_interrupted_step(&f, id, 0, &plan[0], None);
    f.run().await.unwrap();
    assert!(f.tmux.launched().is_empty());
    assert!(!paths.script_path.exists());
    assert!(!paths.summary_path.exists());
    assert_eq!(f.api.ticket_field("state"), "failed");
    assert_eq!(f.api.ticket_field("result"), "failure");
    assert_eq!(f.api.ticket_field("result_detail"), "step_1_interrupted");
    let metadata = read_json(&paths.metadata_path);
    assert_eq!(metadata["status"], "interrupted");
    assert_eq!(metadata["started_at"], "2026-01-01T00:00:00Z");
    assert!(metadata.get("finished_at").is_some());
    assert!(!f.api.details().contains(&"step_2_started".to_owned()));
    assert_eq!(
        f.api.ticket_field("tmux_sessions")[0]["status"],
        "interrupted"
    );
}

/// `test_resume_reattaches_live_session_without_relaunch`.
#[tokio::test(start_paused = true)]
async fn resume_reattaches_live_session_without_relaunch() {
    let id = "99999999-9999-4999-8999-999999999999";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let dir_holder = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
    let target = dir_holder.clone();
    // The live session finishes while the resumed runner polls it.
    let tmux = FakeTmux::new(true, Some(0)).on_probe(move |_| {
        if let Some(path) = target.lock().unwrap().clone() {
            std::fs::write(path, "0\n").unwrap();
        }
    });
    let f = Fixture::new(id, running_ticket(id, plan.clone(), 1, 120), tmux);
    let paths = write_interrupted_step(&f, id, 0, &plan[0], None);
    *dir_holder.lock().unwrap() = Some(paths.exit_code_path.clone());
    f.run().await.unwrap();
    assert!(f.tmux.launched().is_empty());
    assert_eq!(f.api.ticket_field("state"), "succeeded");
    assert_eq!(f.api.details()[0], "step_1_resumed");
}

/// `test_resumed_summary_appears_once_in_next_step_context`.
#[tokio::test(start_paused = true)]
async fn resumed_summary_appears_once_in_next_step_context() {
    let id = "abababab-abab-4bab-8bab-abababababab";
    let plan = json!([
        {"role": "investigator", "agent": "codex", "prompt_markdown": "inspect"},
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "review"},
    ]);
    let f = Fixture::new(
        id,
        running_ticket(id, plan.clone(), 1, 120),
        FakeTmux::new(false, Some(0)),
    );
    let first = f.paths(0, &plan[0]);
    std::fs::create_dir_all(&first.step_dir).unwrap();
    std::fs::write(
        &first.summary_path,
        "{\"status\":\"succeeded\",\"summary_markdown\":\"already done\"}\n",
    )
    .unwrap();
    f.run().await.unwrap();
    let second = f.paths(1, &plan[1]);
    let context = read_json(&second.context_path);
    assert_eq!(context["step_index"], 1);
    assert_eq!(
        context["prior_step_summaries"],
        json!([{"status": "succeeded", "summary_markdown": "already done"}])
    );
    assert_eq!(f.tmux.launched().len(), 1);
    assert_eq!(f.api.ticket_field("state"), "succeeded");
}

/// `test_runner_shutdown_marks_running_step_interrupted`.
#[tokio::test(start_paused = true)]
async fn runner_shutdown_marks_running_step_interrupted() {
    let id = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let stop = Arc::new(std::sync::Mutex::new(None::<CancellationToken>));
    let token = stop.clone();
    let tmux = FakeTmux::new(false, None).on_launch(move |tmux, _| {
        tmux.has_session.store(true, Ordering::SeqCst);
        token.lock().unwrap().as_ref().unwrap().cancel();
    });
    let f = Fixture::new(id, running_ticket(id, plan.clone(), 1, 120), tmux);
    *stop.lock().unwrap() = Some(f.stop.clone());
    f.run().await.unwrap();
    let metadata = read_json(&f.paths(0, &plan[0]).metadata_path);
    assert_eq!(metadata["status"], "interrupted");
    assert_eq!(f.tmux.killed(), f.tmux.launched());
    assert_eq!(f.api.ticket_field("state"), "running");
    assert_eq!(f.api.events(), ["step_started"]);
}

/// A step whose exit code appears just before shutdown keeps its metadata
/// (`running`) for the next runner to adopt.
#[tokio::test(start_paused = true)]
async fn shutdown_after_exit_code_leaves_the_step_for_adoption() {
    let id = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let stop = Arc::new(std::sync::Mutex::new(None::<CancellationToken>));
    let token = stop.clone();
    let tmux = FakeTmux::new(false, None)
        .on_launch(|tmux, _| tmux.has_session.store(true, Ordering::SeqCst))
        .on_probe(move |tmux| {
            // Probe 1 is the resume check, probe 2 the first poll.
            if tmux.probes.load(Ordering::SeqCst) == 2 {
                let step_dir = tmux.scripts.lock().unwrap()[0].parent().unwrap().to_owned();
                std::fs::write(step_dir.join("exit_code"), "0\n").unwrap();
                token.lock().unwrap().as_ref().unwrap().cancel();
            }
        });
    let f = Fixture::new(id, running_ticket(id, plan.clone(), 1, 120), tmux);
    *stop.lock().unwrap() = Some(f.stop.clone());
    f.run().await.unwrap();
    let paths = f.paths(0, &plan[0]);
    assert_eq!(read_json(&paths.metadata_path)["status"], "running");
    assert!(!paths.summary_path.exists());
    assert!(f.tmux.killed().is_empty());
}

/// `test_resume_fails_closed_on_unreadable_metadata[malformed_json|invalid_utf8|read_error]`.
#[tokio::test(start_paused = true)]
async fn resume_fails_closed_on_unreadable_metadata() {
    for failure in ["malformed_json", "invalid_utf8", "read_error"] {
        let id = "efefefef-efef-4fef-8fef-efefefefefef";
        let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
        let f = Fixture::new(
            id,
            running_ticket(id, plan.clone(), 1, 120),
            FakeTmux::new(false, Some(0)),
        );
        let paths = write_interrupted_step(&f, id, 0, &plan[0], None);
        match failure {
            "malformed_json" => std::fs::write(&paths.metadata_path, "{not json").unwrap(),
            "invalid_utf8" => std::fs::write(&paths.metadata_path, b"\xff\xfe{").unwrap(),
            _ => std::fs::set_permissions(
                &paths.metadata_path,
                std::fs::Permissions::from_mode(0o000),
            )
            .unwrap(),
        }
        f.run().await.unwrap();
        assert!(f.tmux.launched().is_empty(), "{failure}");
        assert_eq!(f.api.ticket_field("state"), "failed");
        assert_eq!(f.api.ticket_field("result_detail"), "step_1_interrupted");
    }
}

/// `test_resume_adopts_exit_code_written_during_session_probe`.
#[tokio::test(start_paused = true)]
async fn resume_adopts_exit_code_written_during_session_probe() {
    let id = "fafafafa-fafa-4afa-8afa-fafafafafafa";
    let plan = json!([{"role": "implementer", "agent": "codex", "prompt_markdown": "deploy"}]);
    let holder = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
    let target = holder.clone();
    // The session writes its exit code and ends right as the runner probes it.
    let tmux = FakeTmux::new(false, Some(0)).on_probe(move |_| {
        if let Some(path) = target.lock().unwrap().clone() {
            std::fs::write(path, "0\n").unwrap();
        }
    });
    let f = Fixture::new(id, running_ticket(id, plan.clone(), 1, 120), tmux);
    let paths = write_interrupted_step(&f, id, 0, &plan[0], None);
    *holder.lock().unwrap() = Some(paths.exit_code_path.clone());
    f.run().await.unwrap();
    assert!(f.tmux.launched().is_empty());
    assert_eq!(f.api.ticket_field("state"), "succeeded");
}

/// API errors outside the poll loop leave `run` (the supervisor decides,
/// S6b); the error kinds are named for `runner_unhandled_exception`.
#[tokio::test(start_paused = true)]
async fn errors_leave_run() {
    let id = "77777777-7777-4777-8777-777777777777";
    let f = Fixture::new(
        id,
        running_ticket(id, two_steps(), 0, 120),
        FakeTmux::new(false, Some(0)),
    );
    f.api
        .on_get(|_| Err(RunnerApiError::new("outage", 503, "transport_error")));
    let error = f.run().await.unwrap_err();
    assert_eq!(error.api_error().unwrap().status_code, 503);
    assert_eq!(error.kind_name(), "RunnerApiError");

    let mut ticket = running_ticket(id, two_steps(), 0, 120);
    ticket.insert("started_at".into(), Value::Null);
    let f = Fixture::new(id, ticket, FakeTmux::new(false, Some(0)));
    assert_eq!(f.run().await.unwrap_err().kind_name(), "InvalidTicket");
}
