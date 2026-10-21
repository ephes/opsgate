//! `rust/fixtures/settings.json` (PLAN.md 4.2): every environment set yields
//! the settings Python's `load_settings` / `load_runner_settings` produced,
//! or the same `SettingsError` message. Cases marked with a divergence (D-8,
//! D-10) and cases where Python raised something other than `SettingsError`
//! (a traceback, exit 1) expect the case's `rust_error`. The env-file cases
//! pin `load_env_file` itself: the resulting environment.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use ipnet::IpNet;
use opsgate_core::settings::{
    ApiSettings, Environment, RunnerSettings, SettingsError, load_api_settings,
    load_runner_settings_with_host,
};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("../../../fixtures/settings.json");
const HOSTNAME: &str = "fixture-system-hostname";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("settings.json parses")
}

fn api_json(settings: &ApiSettings) -> Value {
    json!({
        "service_name": settings.service_name,
        "bind_host": settings.bind_host,
        "bind_port": settings.bind_port,
        "db_path": settings.db_path,
        "session_secret": settings.session_secret,
        "trust_proxy_headers": settings.trust_proxy_headers,
        "session_cookie_secure": settings.session_cookie_secure,
        "session_timeout_seconds": settings.session_timeout_seconds,
        "ui_username": settings.ui_username,
        "ui_password_bcrypt": settings.ui_password_bcrypt,
        "max_duration_seconds_default": settings.max_duration_seconds_default(),
        "policy_floor_require_reviewer_step": settings.policy_floor_require_reviewer_step,
        "runner_token": settings.runner_token,
        "submitter_policies": settings.submitter_policies.iter().map(|policy| json!({
            "source": policy.source,
            "token": policy.token,
            "require_reviewer_step_floor": policy.require_reviewer_step_floor,
        })).collect::<Vec<_>>(),
        "require_tailscale_context": settings.require_tailscale_context,
        "allowed_cidrs": settings.allowed_cidrs,
        "execution_data_dir": settings.execution_data_dir,
        "disable_file_path": settings.disable_file_path,
    })
}

fn runner_json(settings: &RunnerSettings) -> Value {
    json!({
        "service_name": settings.service_name,
        "runner_token": settings.runner_token,
        "runner_host": settings.runner_host,
        "runner_api_base_url": settings.runner_api_base_url,
        "runner_poll_interval_seconds": settings.runner_poll_interval_seconds,
        "runner_heartbeat_interval_seconds": settings.runner_heartbeat_interval_seconds,
        "max_parallel_jobs": settings.max_parallel_jobs,
        "max_duration_seconds_default": settings.max_duration_seconds_default(),
        "execution_data_dir": settings.execution_data_dir,
        "tickets_dir": settings.tickets_dir,
        "session_artifacts_dir": settings.session_artifacts_dir,
        "tmux_socket_label": settings.tmux_socket_label,
        "tmux_tmpdir": settings.tmux_tmpdir,
        "disable_file_path": settings.disable_file_path,
    })
}

/// The placeholders of a case and their real paths in a fresh directory.
struct Placeholders {
    _directory: tempfile::TempDir,
    pairs: Vec<(&'static str, String)>,
}

impl Placeholders {
    fn new(case: &Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let env_file = directory.path().join("opsgate.env");
        if let Some(hex) = case["env_file_hex"].as_str() {
            std::fs::write(&env_file, decode_hex(hex)).unwrap();
        } else if let Some(content) = case["env_file"].as_str() {
            std::fs::write(&env_file, content).unwrap();
        }
        std::fs::create_dir(directory.path().join("envdir")).unwrap();
        let path = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
        let pairs = vec![
            ("{env_file}", path("opsgate.env")),
            ("{missing}", path("missing.env")),
            ("{directory}", path("envdir")),
        ];
        Self {
            _directory: directory,
            pairs,
        }
    }

    fn fill(&self, text: &str) -> String {
        self.pairs
            .iter()
            .fold(text.to_owned(), |text, (placeholder, real)| {
                text.replace(placeholder, real)
            })
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn environment(case: &Value, placeholders: &Placeholders) -> Environment {
    Environment::from_vars(
        case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), placeholders.fill(value.as_str().unwrap()))),
    )
}

enum Outcome {
    Settings(Value),
    Error(SettingsError),
}

fn run(case: &Value, placeholders: &Placeholders) -> Outcome {
    let mut env = environment(case, placeholders);
    let result = match case["loader"].as_str().unwrap() {
        "api" => load_api_settings(&mut env).map(|settings| {
            let mut value = api_json(&settings);
            value["allowed_networks"] = json!(
                settings
                    .allowed_networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
            value
        }),
        "runner" => load_runner_settings_with_host(&mut env, || HOSTNAME.to_owned())
            .map(|settings| runner_json(&settings)),
        other => panic!("unknown loader {other}"),
    };
    match result {
        Ok(value) => Outcome::Settings(value),
        Err(error) => Outcome::Error(error),
    }
}

/// Python's `str(ip_network(...))` and Rust's display may spell the same
/// network differently; compare them as networks.
fn normalise_networks(value: &mut Value) {
    if let Some(networks) = value.get_mut("allowed_networks") {
        let parsed: Vec<IpNet> = networks
            .as_array()
            .unwrap()
            .iter()
            .map(|network| network.as_str().unwrap().parse().unwrap())
            .collect();
        *networks = json!(parsed.iter().map(ToString::to_string).collect::<Vec<_>>());
    }
}

#[test]
fn settings_cases_match_python() {
    let fixture = fixture();
    let cases = fixture["settings_cases"].as_array().unwrap();
    assert!(cases.len() >= 80, "PLAN.md S2b: at least 80 settings cases");
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let placeholders = Placeholders::new(case);
        let outcome = run(case, &placeholders);
        let rust_error = case["rust_error"]
            .as_str()
            .map(|text| placeholders.fill(text));
        let python_other = case["error"]["python"] == "other";
        let expected_error = if case.get("divergence").is_some() || python_other {
            Some(rust_error.unwrap_or_else(|| panic!("{name}: rust_error missing")))
        } else {
            case["error"]["message"]
                .as_str()
                .map(|text| placeholders.fill(text))
        };
        match (outcome, expected_error) {
            (Outcome::Error(error), Some(expected)) if error.message() == expected => {}
            (Outcome::Settings(mut actual), None) => {
                let mut expected = case["settings"].clone();
                if expected["runner_host"] == "{hostname}" {
                    expected["runner_host"] = json!(HOSTNAME);
                }
                normalise_networks(&mut expected);
                normalise_networks(&mut actual);
                if actual != expected {
                    failures.push(format!(
                        "{name}: settings differ\n  rust:   {actual}\n  python: {expected}"
                    ));
                }
            }
            (Outcome::Error(error), expected) => failures.push(format!(
                "{name}: rust error {:?}, expected {expected:?}",
                error.message()
            )),
            (Outcome::Settings(actual), Some(expected)) => failures.push(format!(
                "{name}: rust accepted ({actual}), expected error {expected:?}"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// Every variable of PLAN.md 4.2, by the loader that reads it.
const API_VARIABLES: &[&str] = &[
    "OPSGATE_ENV_FILE",
    "OPSGATE_SERVICE_NAME",
    "OPSGATE_BIND_HOST",
    "OPSGATE_BIND_PORT",
    "OPSGATE_DB_PATH",
    "OPSGATE_UI_USERNAME",
    "OPSGATE_UI_PASSWORD_BCRYPT",
    "OPSGATE_SESSION_SECRET",
    "OPSGATE_TRUST_PROXY_HEADERS",
    "OPSGATE_SESSION_COOKIE_SECURE",
    "OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    "OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP",
    "OPSGATE_UI_SESSION_TIMEOUT_SECONDS",
    "OPSGATE_RUNNER_TOKEN",
    "OPSGATE_SUBMIT_TOKEN_OPENCLAW",
    "OPSGATE_SUBMIT_TOKEN_NYXMON",
    "OPSGATE_SUBMIT_TOKEN_OPERATOR",
    "OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP",
    "OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP",
    "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
    "OPSGATE_REQUIRE_TAILSCALE_CONTEXT",
    "OPSGATE_ALLOWED_CIDRS",
    "OPSGATE_EXECUTION_DATA_DIR",
    "OPSGATE_DISABLE_FILE_PATH",
];

const RUNNER_VARIABLES: &[&str] = &[
    "OPSGATE_ENV_FILE",
    "OPSGATE_SERVICE_NAME",
    "OPSGATE_RUNNER_TOKEN",
    "OPSGATE_BIND_PORT",
    "OPSGATE_RUNNER_API_BASE_URL",
    "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS",
    "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS",
    "OPSGATE_MAX_PARALLEL_JOBS",
    "OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    "OPSGATE_EXECUTION_DATA_DIR",
    "OPSGATE_TICKETS_DIR",
    "OPSGATE_SESSION_ARTIFACTS_DIR",
    "OPSGATE_TMUX_SOCKET_LABEL",
    "TMUX_TMPDIR",
    "OPSGATE_DISABLE_FILE_PATH",
    "OPSGATE_RUNNER_HOST",
];

#[test]
fn every_setting_and_the_override_rule_are_covered() {
    let fixture = fixture();
    let cases = fixture["settings_cases"].as_array().unwrap();
    for (loader, variables) in [("api", API_VARIABLES), ("runner", RUNNER_VARIABLES)] {
        for name in variables {
            assert!(
                cases
                    .iter()
                    .any(|case| case["loader"] == loader && case["env"].get(*name).is_some()),
                "no {loader} case sets {name}"
            );
        }
    }
    // A variable set in the process and in the env file takes the file's value.
    let overrides = cases
        .iter()
        .filter(|case| {
            case["name"]
                .as_str()
                .unwrap()
                .ends_with("env file overrides the process environment")
        })
        .count();
    assert_eq!(overrides, 2);
}

#[test]
fn env_file_cases_match_python() {
    let fixture = fixture();
    let cases = fixture["env_file_cases"].as_array().unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("opsgate.env");
        if case.get("missing").is_none() {
            std::fs::write(&path, decode_hex(case["content_hex"].as_str().unwrap())).unwrap();
        }
        let initial: Vec<(String, String)> = case["initial_env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
            .collect();
        let mut env = Environment::from_vars(initial);
        let result = env.load_env_file(Path::new(&path));
        let fill = |text: &str| text.replace("{env_file}", path.to_str().unwrap());
        match (result, case.get("result_env")) {
            (Ok(()), Some(expected)) => {
                let actual: BTreeMap<String, String> = env
                    .vars()
                    .map(|(key, value)| {
                        (
                            key.to_str().unwrap().to_owned(),
                            value.to_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                let expected: BTreeMap<String, String> = expected
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                    .collect();
                if actual != expected {
                    failures.push(format!("{name}: {actual:?} != {expected:?}"));
                }
            }
            (Err(error), None) => {
                let expected = case["rust_error"]
                    .as_str()
                    .or(case["error"]["message"].as_str())
                    .map(fill)
                    .unwrap_or_else(|| panic!("{name}: no expected message"));
                if error.message() != expected {
                    failures.push(format!(
                        "{name}: error {:?} != {expected:?}",
                        error.message()
                    ));
                }
            }
            (Ok(()), None) => failures.push(format!("{name}: accepted, Python failed")),
            (Err(error), Some(_)) => {
                failures.push(format!("{name}: failed with {:?}", error.message()))
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn environment_keeps_every_variable_for_children() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runner.env");
    std::fs::write(
        &path,
        "OPSGATE_RUNNER_TOKEN=runner-token-from-file-00\nEXTRA=1\n",
    )
    .unwrap();
    let mut env = Environment::from_vars([
        ("OPSGATE_ENV_FILE", path.to_str().unwrap()),
        ("PATH", "/usr/bin:/bin"),
        ("OPSGATE_RUNNER_TOKEN", "short"),
    ]);
    let settings = load_runner_settings_with_host(&mut env, || "h".to_owned()).unwrap();
    assert_eq!(settings.runner_token, "runner-token-from-file-00");
    let vars: Vec<(OsString, OsString)> = env
        .vars()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    assert_eq!(
        vars,
        [
            ("EXTRA".into(), "1".into()),
            ("OPSGATE_ENV_FILE".into(), path.as_os_str().to_owned()),
            (
                "OPSGATE_RUNNER_TOKEN".into(),
                "runner-token-from-file-00".into()
            ),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ]
    );
}

/// `tests/test_api.py::test_direct_settings_duration_default_is_validated`:
/// settings cannot carry a duration default outside 1..=31 536 000, also
/// when changed after loading (Python: `dataclasses.replace`). The Python
/// cases `True` and `1.5` cannot be expressed in Rust (the field is `i64`).
#[test]
fn direct_settings_duration_default_is_validated() {
    let mut env = Environment::from_vars([
        ("OPSGATE_UI_USERNAME", "admin"),
        ("OPSGATE_UI_PASSWORD_BCRYPT", "hash"),
        ("OPSGATE_SESSION_SECRET", "session-secret-0123456789"),
        ("OPSGATE_RUNNER_TOKEN", "runner-token-000000000000"),
        ("OPSGATE_SUBMIT_TOKEN_NYXMON", "nyxmon-token-000000000000"),
        (
            "OPSGATE_SUBMIT_TOKEN_OPERATOR",
            "operator-token-00000000000",
        ),
    ]);
    let api = load_api_settings(&mut env).unwrap();
    let runner = load_runner_settings_with_host(&mut env, || "h".to_owned()).unwrap();
    for duration in [0, -1, 31_536_001, i64::MAX] {
        let error = api
            .clone()
            .with_max_duration_seconds_default(duration)
            .unwrap_err();
        assert!(
            error
                .message()
                .contains("OPSGATE_MAX_DURATION_SECONDS_DEFAULT")
        );
        let error = runner
            .clone()
            .with_max_duration_seconds_default(duration)
            .unwrap_err();
        assert!(
            error
                .message()
                .contains("OPSGATE_MAX_DURATION_SECONDS_DEFAULT")
        );
    }
    for duration in [1, 31_536_000] {
        assert_eq!(
            api.clone()
                .with_max_duration_seconds_default(duration)
                .unwrap()
                .max_duration_seconds_default(),
            duration
        );
        assert_eq!(
            runner
                .clone()
                .with_max_duration_seconds_default(duration)
                .unwrap()
                .max_duration_seconds_default(),
            duration
        );
    }
}
