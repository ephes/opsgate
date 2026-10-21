//! `opsgate serve` (`python -m opsgate serve`, PLAN.md 4.1): the JSON API
//! and the web UI.
//!
//! Loads the API settings from the process environment and the env file
//! (4.2), applies the Rust-only overrides `--db`, `--bind-host` and
//! `--bind-port` (D-15), opens the database (`init_db` with the session
//! sync, 4.10), then serves HTTP on a tokio runtime with two worker threads
//! (6.1). SIGTERM and SIGINT stop accepting connections; requests in flight
//! get up to five seconds to finish, then the process exits 0.
//!
//! Exit codes: 0 after a signal, 1 for a configuration error (one line
//! naming the setting, never its value), a database that cannot be opened,
//! an address that cannot be bound, or a server error (one line each).

use std::process::ExitCode;
use std::time::Duration;

use opsgate_core::settings::{Environment, load_api_settings};
use opsgate_runner::install_signal_handlers;
use opsgate_store::Store;
use opsgate_web::AppState;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::cli::{ServeArgs, VERSION};
use crate::runner::init_logging;

/// The runtime's worker threads (PLAN.md 6.1).
const WORKER_THREADS: usize = 2;

/// How long requests in flight may take after a stop signal (4.1).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Runs the API until it is stopped.
pub fn run(args: ServeArgs) -> ExitCode {
    let mut environment = Environment::from_process();
    let mut settings = match load_api_settings(&mut environment) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("opsgate serve: configuration error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(db) = args.db {
        let Some(db) = db.to_str() else {
            eprintln!("opsgate serve: configuration error: --db must be UTF-8");
            return ExitCode::FAILURE;
        };
        settings.db_path = db.to_owned();
    }
    if let Some(host) = args.bind_host {
        settings.bind_host = host;
    }
    if let Some(port) = args.bind_port {
        settings.bind_port = i64::from(port);
    }
    let Ok(port) = u16::try_from(settings.bind_port) else {
        eprintln!("opsgate serve: configuration error: OPSGATE_BIND_PORT is not a port (0-65535)");
        return ExitCode::FAILURE;
    };
    init_logging();
    let host = settings.bind_host.clone();
    let store = match Store::open(settings) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!("opsgate serve: cannot open the database: {error}");
            return ExitCode::FAILURE;
        }
    };
    let state = match AppState::new(store) {
        Ok(state) => state,
        Err(error) => {
            tracing::error!("opsgate serve: templates: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("opsgate serve: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(serve(state, host, port))
}

async fn serve(state: AppState, host: String, port: u16) -> ExitCode {
    let listener = match TcpListener::bind((host.as_str(), port)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("opsgate serve: cannot listen on {host}:{port}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let stop = CancellationToken::new();
    if let Err(error) = install_signal_handlers(stop.clone()) {
        tracing::error!("opsgate serve: cannot install the signal handlers: {error}");
        return ExitCode::FAILURE;
    }
    let address = listener
        .local_addr()
        .map_or_else(|_| format!("{host}:{port}"), |address| address.to_string());
    tracing::info!(
        "opsgate serve starting: version={VERSION} implementation=rust bind={address} db={}",
        state.settings().db_path,
    );
    let mut server = tokio::spawn(opsgate_web::serve(
        listener,
        state,
        stop.clone().cancelled_owned(),
    ));
    tokio::select! {
        result = &mut server => return finished(result),
        () = stop.cancelled() => {}
    }
    match tokio::time::timeout(SHUTDOWN_GRACE, &mut server).await {
        Ok(result) => finished(result),
        Err(_) => {
            tracing::warn!(
                "opsgate serve: requests still in flight after {} s, stopping",
                SHUTDOWN_GRACE.as_secs()
            );
            server.abort();
            ExitCode::SUCCESS
        }
    }
}

fn finished(result: Result<std::io::Result<()>, tokio::task::JoinError>) -> ExitCode {
    match result {
        Ok(Ok(())) => {
            tracing::info!("opsgate serve stopped");
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            tracing::error!("opsgate serve stopped: {error}");
            ExitCode::FAILURE
        }
        Err(error) => {
            tracing::error!("opsgate serve stopped: {error}");
            ExitCode::FAILURE
        }
    }
}
