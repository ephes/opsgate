//! `opsgate runner [--once]` (`runner.run_runner`, PLAN.md 4.1, 4.13).
//!
//! Loads the runner settings from the process environment and the env file
//! before any thread starts (4.2), then runs the supervisor on a tokio
//! runtime with two worker threads (6.1). tmux and through it the agent
//! steps get the merged environment (4.13.8). SIGTERM and SIGINT stop the
//! runner: the supervisor and the workers finish their shutdown actions
//! (4.13.4) and the process exits 0.
//!
//! Exit codes: 0 after a normal stop (or the end of `--once`), 1 for a
//! configuration error (one line naming the setting, never its value) or an
//! error the supervisor does not handle (one line naming it; Python: a
//! traceback, D-12).

use std::process::ExitCode;
use std::sync::Arc;

use opsgate_core::settings::{Environment, RunnerSettings, load_runner_settings};
use opsgate_runner::{HttpApiClient, Supervisor, SystemClock, TmuxCli, install_signal_handlers};
use tokio_util::sync::CancellationToken;

use crate::cli::VERSION;

/// The runtime's worker threads (PLAN.md 6.1).
const WORKER_THREADS: usize = 2;

/// Runs the runner until it is stopped (or, with `once`, after one round).
pub fn run(once: bool) -> ExitCode {
    let mut environment = Environment::from_process();
    let settings = match load_runner_settings(&mut environment) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("opsgate runner: configuration error: {error}");
            return ExitCode::FAILURE;
        }
    };
    init_logging();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("opsgate runner: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(supervise(settings, environment, once))
}

/// Plain log lines on stderr (PLAN.md 4.15): timestamp, level, message.
pub(crate) fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

async fn supervise(settings: RunnerSettings, environment: Environment, once: bool) -> ExitCode {
    let settings = Arc::new(settings);
    let api = match HttpApiClient::new(&settings) {
        Ok(api) => api,
        Err(_) => {
            tracing::error!("opsgate runner: cannot create the API client");
            return ExitCode::FAILURE;
        }
    };
    let tmux = TmuxCli::new(settings.tmux_socket_label.clone(), Arc::new(environment));
    let stop = CancellationToken::new();
    if let Err(error) = install_signal_handlers(stop.clone()) {
        tracing::error!("opsgate runner: cannot install the signal handlers: {error}");
        return ExitCode::FAILURE;
    }
    let supervisor = match Supervisor::new(settings.clone(), api, tmux, SystemClock, stop) {
        Ok(supervisor) => supervisor,
        Err(error) => {
            tracing::error!(
                "opsgate runner: cannot create {}: {error}",
                supervisor_state_dir(&settings)
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        "opsgate runner starting: version={VERSION} implementation=rust runner_host={} \
         tmux_socket_label={} max_parallel_jobs={} once={once}",
        settings.runner_host,
        settings.tmux_socket_label,
        settings.max_parallel_jobs,
    );
    match supervisor.run_forever(once).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("opsgate runner stopped: {error}");
            ExitCode::FAILURE
        }
    }
}

fn supervisor_state_dir(settings: &RunnerSettings) -> String {
    opsgate_runner::artifacts::py_path_join(&settings.execution_data_dir, "runner-state")
        .display()
        .to_string()
}
