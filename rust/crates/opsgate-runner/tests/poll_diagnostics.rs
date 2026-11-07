//! Isolated tracing subscriber for the real executor's outage diagnostics.
mod common;
use common::{FakeApi, FakeTmux, TestClock, runner_settings, running_ticket};
use opsgate_runner::{RunnerApiError, TicketExecutor};
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use tokio_util::sync::CancellationToken;

/// Repeated failures and changed categories are bounded while owned work continues.
#[tokio::test(start_paused = true)]
async fn running_poll_outage_and_recovery_are_observable() {
    use std::io::Write;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct Log(Arc<Mutex<Vec<u8>>>);
    impl Write for Log {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let log = Log(Arc::default());
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let id = "77777777-7777-4777-8777-777777777777";
    let plan = json!([{"role": "investigator", "agent": "codex", "prompt_markdown": "inspect"}]);
    let dir = tempfile::tempdir().unwrap();
    let settings = Arc::new(runner_settings(dir.path(), 60));
    let api = FakeApi::new(running_ticket(id, plan.clone(), 0, 120));
    let tmux = Arc::new(FakeTmux::new(false, None).on_launch(|tmux, _| {
        tmux.has_session.store(true, Ordering::SeqCst);
    }));
    let executor = TicketExecutor::new(
        settings,
        api.clone(),
        tmux.clone(),
        TestClock::new(),
        CancellationToken::new(),
        id,
    );
    let exit = executor
        .step_paths(0, plan[0].as_object().unwrap())
        .exit_code_path;
    let mut calls = 0;
    api.on_get(move |_| {
        calls += 1;
        match calls {
            2..=4 => Err(RunnerApiError::new(
                "synthetic-secret",
                503,
                "transport_error",
            )),
            5..=7 => Err(RunnerApiError::new(
                "synthetic-secret",
                502,
                "invalid_response",
            )),
            8 => Err(RunnerApiError::new(
                "synthetic-secret",
                503,
                "transport_error",
            )),
            9 => {
                std::fs::write(&exit, "0").unwrap();
                Ok(())
            }
            _ => Ok(()),
        }
    });
    let ticket = api.ticket.lock().unwrap().clone();
    executor.run(Some(ticket)).await.unwrap();
    let output = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        output.matches("Runner ticket poll failed").count(),
        2,
        "{output}"
    );
    assert_eq!(
        output.matches("Runner ticket poll recovered").count(),
        1,
        "{output}"
    );
    assert!(output.contains("status=503 category=transport_error"));
    assert!(output.contains("status=502 category=invalid_response"));
    assert!(output.contains(id));
    assert!(!output.contains("synthetic-secret"));
    assert_eq!(api.get_calls.load(Ordering::SeqCst), 9);
    assert!(tmux.killed().is_empty());
    assert_eq!(tmux.launched().len(), 1);
    assert_eq!(api.ticket_field("state"), "succeeded");
}
