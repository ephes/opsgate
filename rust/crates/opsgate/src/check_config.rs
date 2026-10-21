//! `opsgate check-config api|runner` (PLAN.md 3.1, D-15, slice S8).
//!
//! Loads the settings exactly as `serve` or `runner` would at startup (the
//! process environment with `OPSGATE_ENV_FILE` applied, 4.2), including the
//! checks the commands make before they start serving or polling: the bind
//! port of `serve` and the runner's API client. Nothing is opened, bound,
//! created or contacted.
//!
//! Exit 0 with `opsgate check-config <target>: ok` and a few non-secret
//! values on stdout; exit 1 with one stderr line naming the setting (never a
//! value, as with `serve` and `runner`). Tokens, the session secret, the
//! password hash and the API base URL (which may carry credentials) are never
//! printed. The release checks (section 9) and the role's install task
//! (10.1 step 3) run it before anything points at a new binary.

use std::process::ExitCode;

use opsgate_core::settings::{Environment, load_api_settings, load_runner_settings};
use opsgate_runner::HttpApiClient;

use crate::cli::ConfigTarget;
use crate::serve::{BIND_PORT_ERROR, bind_port};

/// Runs the check for `target`.
pub fn run(target: ConfigTarget) -> ExitCode {
    let mut environment = Environment::from_process();
    let result = match target {
        ConfigTarget::Api => check_api(&mut environment),
        ConfigTarget::Runner => check_runner(&mut environment),
    };
    let name = match target {
        ConfigTarget::Api => "api",
        ConfigTarget::Runner => "runner",
    };
    match result {
        Ok(lines) => {
            println!("opsgate check-config {name}: ok");
            for (key, value) in lines {
                println!("{key}: {value}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("opsgate check-config {name}: configuration error: {error}");
            ExitCode::FAILURE
        }
    }
}

type Summary = Vec<(&'static str, String)>;

fn check_api(environment: &mut Environment) -> Result<Summary, String> {
    let settings = load_api_settings(environment).map_err(|error| error.to_string())?;
    let port = bind_port(&settings).ok_or_else(|| BIND_PORT_ERROR.to_owned())?;
    Ok(vec![
        ("service_name", settings.service_name.clone()),
        ("bind", format!("{}:{port}", settings.bind_host)),
        ("db_path", settings.db_path.clone()),
        ("execution_data_dir", settings.execution_data_dir.clone()),
        ("disable_file_path", settings.disable_file_path.clone()),
    ])
}

fn check_runner(environment: &mut Environment) -> Result<Summary, String> {
    let settings = load_runner_settings(environment).map_err(|error| error.to_string())?;
    HttpApiClient::new(&settings)
        .map_err(|_| "OPSGATE_RUNNER_API_BASE_URL: cannot create the API client".to_owned())?;
    Ok(vec![
        ("service_name", settings.service_name.clone()),
        ("runner_host", settings.runner_host.clone()),
        ("execution_data_dir", settings.execution_data_dir.clone()),
        ("tmux_socket_label", settings.tmux_socket_label.clone()),
        ("disable_file_path", settings.disable_file_path.clone()),
    ])
}
