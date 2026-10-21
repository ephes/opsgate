//! API and runner settings (`rust/PLAN.md` 4.2), ported from
//! `src/opsgate/config.py`: `load_env_file`, `parse_bool`, `parse_int`,
//! `load_settings`, `load_runner_settings`. Pinned by
//! `rust/fixtures/settings.json`.
//!
//! The env file named by `OPSGATE_ENV_FILE` overwrites the process
//! environment, so every key of the file is also part of the environment the
//! runner's children inherit (4.13.8). Python assigns `os.environ`; the Rust
//! port cannot change its own process environment (`std::env::set_var` is
//! `unsafe` in edition 2024 and the workspace forbids `unsafe`), so the
//! merged set lives in an [`Environment`] that the settings are read from and
//! that the runner passes to its children explicitly
//! (`Command::env_clear().envs(environment.vars())`), the alternative the plan
//! names in 4.2.
//!
//! Error messages name the setting, never its value, and are Python's texts
//! where Python raises `SettingsError`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::IpNet;

use crate::pytext;

/// Upper bound of `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` and of a ticket's
/// `max_duration_seconds` (`config.py:MAX_DURATION_SECONDS`).
pub const MAX_DURATION_SECONDS: i64 = 31_536_000;

/// `OPSGATE_ALLOWED_CIDRS` when the variable is absent.
pub const DEFAULT_ALLOWED_CIDRS: [&str; 4] = [
    "127.0.0.1/32",
    "::1/128",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
];

const ENV_FILE_VARIABLE: &str = "OPSGATE_ENV_FILE";

/// Python's limit for decimal integer strings (`sys.get_int_max_str_digits()`,
/// counted without sign and underscores); longer strings raise `ValueError`.
const PY_INT_MAX_STR_DIGITS: usize = 4300;

/// A configuration error: the process prints the message and exits 1
/// (PLAN.md 4.1). The message names the setting and never contains its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    message: String,
}

impl SettingsError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The one-line description of the error.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SettingsError {}

/// The environment the settings are read from: a snapshot of the process
/// environment with the env file applied on top (see the module docs).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Environment {
    vars: BTreeMap<OsString, OsString>,
}

impl fmt::Debug for Environment {
    /// Names only: values may be secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.vars.keys()).finish()
    }
}

impl Environment {
    /// A snapshot of the current process environment.
    pub fn from_process() -> Self {
        Self::from_vars(std::env::vars_os())
    }

    /// An environment with exactly these variables (tests, shadow tooling).
    pub fn from_vars<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            vars: vars
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    /// Every variable, sorted by name: the environment a child process gets.
    pub fn vars(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.vars
            .iter()
            .map(|(key, value)| (key.as_os_str(), value.as_os_str()))
    }

    /// The value of `name`, or `None` when it is not set. A value that is not
    /// UTF-8 is an error naming the variable (Python would carry it on with
    /// surrogate escapes; D-8).
    pub fn get(&self, name: &str) -> Result<Option<&str>, SettingsError> {
        match self.vars.get(OsStr::new(name)) {
            None => Ok(None),
            Some(value) => value
                .to_str()
                .map(Some)
                .ok_or_else(|| SettingsError::new(format!("{name} must be valid UTF-8 text"))),
        }
    }

    /// `os.environ.get(name, default).strip()`.
    fn stripped_or(&self, name: &str, default: &str) -> Result<String, SettingsError> {
        Ok(pytext::strip(self.get(name)?.unwrap_or(default)).to_owned())
    }

    /// Set one variable (the env file's `os.environ[key] = value`).
    pub fn set(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) {
        self.vars.insert(key.into(), value.into());
    }

    /// Apply the file named by `OPSGATE_ENV_FILE` (stripped; blank or unset →
    /// nothing), as both Python loaders do first.
    pub fn apply_env_file_setting(&mut self) -> Result<(), SettingsError> {
        let path = pytext::strip(self.get(ENV_FILE_VARIABLE)?.unwrap_or("")).to_owned();
        if path.is_empty() {
            Ok(())
        } else {
            self.load_env_file(Path::new(&path))
        }
    }

    /// `config.load_env_file`: read `path` as UTF-8, split it into lines like
    /// Python's text mode plus `str.splitlines()`, skip blank, `#` and
    /// `=`-less lines, split at the first `=`, strip key and value, remove one
    /// pair of matching wrapping quotes, and set the variable (later lines
    /// win). Python fails on a name or value `os.environ` cannot hold (empty
    /// name, NUL character); so does this, with a message naming the file.
    pub fn load_env_file(&mut self, path: &Path) -> Result<(), SettingsError> {
        let shown = path.display();
        if std::fs::metadata(path).is_err() {
            return Err(SettingsError::new(format!(
                "Env file does not exist: {shown}"
            )));
        }
        let data = std::fs::read(path)
            .map_err(|_| SettingsError::new(format!("Env file could not be read: {shown}")))?;
        let text = String::from_utf8(data)
            .map_err(|_| SettingsError::new(format!("Env file is not valid UTF-8: {shown}")))?;
        // Text-mode newline translation (`\r\n`, `\r` → `\n`) followed by
        // `splitlines()` splits at exactly these characters; the empty pieces
        // this leaves between `\r` and `\n` are blank lines, which are skipped.
        for line in text.split(pytext::is_line_boundary) {
            let stripped = pytext::strip(line);
            if stripped.is_empty() || stripped.starts_with('#') {
                continue;
            }
            let Some((raw_key, raw_value)) = stripped.split_once('=') else {
                continue;
            };
            let key = pytext::strip(raw_key);
            let value = unquote(pytext::strip(raw_value));
            if key.is_empty() || key.contains('\0') {
                return Err(SettingsError::new(format!(
                    "Env file line has an invalid variable name: {shown}"
                )));
            }
            if value.contains('\0') {
                return Err(SettingsError::new(format!(
                    "Env file line contains a NUL character: {shown}"
                )));
            }
            self.set(key, value);
        }
        Ok(())
    }
}

/// One pair of matching wrapping quotes (`'` or `"`) removed from a value of
/// at least two characters.
fn unquote(value: &str) -> &str {
    let mut chars = value.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first), Some(last)) if first == last && (first == '"' || first == '\'') => {
            chars.as_str()
        }
        _ => value,
    }
}

/// `config.parse_bool`: blank or missing → `default`; `1/true/yes/on`,
/// `0/false/no/off` after strip and lower-casing; else an error naming the
/// variable.
pub fn parse_bool(
    value: Option<&str>,
    default: bool,
    env_name: &str,
) -> Result<bool, SettingsError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let stripped = pytext::strip(value);
    if stripped.is_empty() {
        return Ok(default);
    }
    match stripped.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(SettingsError::new(format!(
            "{env_name} must be a boolean (1/true/yes/on or 0/false/no/off)"
        ))),
    }
}

/// The result of Python's `int(text)` for a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyInt {
    Value(i64),
    /// A valid Python integer outside `i64`.
    OutOfRange,
}

/// Python `int(text)` for an already stripped text, restricted to ASCII
/// digits (D-8): optional sign, digits with single underscores between
/// digits, at most 4300 digits. `None` where Python raises `ValueError` (or,
/// for non-ASCII digits, accepts: D-8). The store reads a stored
/// `max_duration_seconds` text with it (`int(row[...])`, PLAN.md 4.7.2).
pub fn parse_py_int(text: &str) -> Option<PyInt> {
    let (negative, body) = match text.as_bytes().first() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => (false, text),
    };
    let mut digits = String::with_capacity(body.len());
    let mut previous_was_digit = false;
    for byte in body.bytes() {
        match byte {
            b'0'..=b'9' => {
                digits.push(char::from(byte));
                previous_was_digit = true;
            }
            b'_' if previous_was_digit => previous_was_digit = false,
            _ => return None,
        }
    }
    if digits.is_empty() || !previous_was_digit || digits.len() > PY_INT_MAX_STR_DIGITS {
        return None;
    }
    let signed = if negative {
        format!("-{digits}")
    } else {
        digits
    };
    Some(
        signed
            .parse::<i64>()
            .map_or(PyInt::OutOfRange, PyInt::Value),
    )
}

/// `config.parse_int` keeping integers outside `i64` apart: blank or missing
/// → `default`.
fn parse_int_raw(
    value: Option<&str>,
    default: i64,
    env_name: &str,
) -> Result<PyInt, SettingsError> {
    let Some(value) = value else {
        return Ok(PyInt::Value(default));
    };
    let stripped = pytext::strip(value);
    if stripped.is_empty() {
        return Ok(PyInt::Value(default));
    }
    parse_py_int(stripped).ok_or_else(|| int_error(env_name))
}

fn int_error(env_name: &str) -> SettingsError {
    SettingsError::new(format!("{env_name} must be an integer"))
}

/// `config.parse_int`; an integer outside `i64` is an error (D-8).
pub fn parse_int(value: Option<&str>, default: i64, env_name: &str) -> Result<i64, SettingsError> {
    match parse_int_raw(value, default, env_name)? {
        PyInt::Value(number) => Ok(number),
        PyInt::OutOfRange => Err(int_error(env_name)),
    }
}

/// `config.validate_duration_default`; an integer outside `i64` is outside
/// the bounds too, as in Python.
fn validate_duration_default(value: PyInt) -> Result<i64, SettingsError> {
    match value {
        PyInt::Value(number) if (1..=MAX_DURATION_SECONDS).contains(&number) => Ok(number),
        _ => Err(SettingsError::new(format!(
            "OPSGATE_MAX_DURATION_SECONDS_DEFAULT must be an integer from 1 to {MAX_DURATION_SECONDS}"
        ))),
    }
}

/// `ipaddress.ip_network(text, strict=False)`: `address[/prefix]`, IPv4
/// first, then IPv6 (with an optional `%scope`, dropped as Python does);
/// prefix ASCII digits within the address family's length; host bits are
/// cleared. Netmask and hostmask prefixes (`/255.0.0.0`) are rejected (D-8).
pub fn parse_network(text: &str) -> Option<IpNet> {
    let mut parts = text.split('/');
    let address = parts.next()?;
    let prefix = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let address: IpAddr = if let Ok(v4) = address.parse::<Ipv4Addr>() {
        IpAddr::V4(v4)
    } else {
        let without_scope = match address.split_once('%') {
            Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
            Some((address, _)) => address,
            None => address,
        };
        IpAddr::V6(without_scope.parse::<Ipv6Addr>().ok()?)
    };
    let max_prefix: u8 = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => max_prefix,
        Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            let trimmed = digits.trim_start_matches('0');
            if trimmed.len() > 3 {
                return None;
            }
            let value: u16 = if trimmed.is_empty() {
                0
            } else {
                trimmed.parse().ok()?
            };
            u8::try_from(value)
                .ok()
                .filter(|value| *value <= max_prefix)?
        }
        Some(_) => return None,
    };
    IpNet::new(address, prefix)
        .ok()
        .map(|network| network.trunc())
}

/// A submitter (`config.SubmitterPolicy`), in the order
/// `authenticate_submitter` tries them: openclaw (only with a token), nyxmon,
/// operator.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmitterPolicy {
    pub source: String,
    pub token: String,
    pub require_reviewer_step_floor: bool,
}

impl fmt::Debug for SubmitterPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitterPolicy")
            .field("source", &self.source)
            .field("token", &"<redacted>")
            .field(
                "require_reviewer_step_floor",
                &self.require_reviewer_step_floor,
            )
            .finish()
    }
}

/// The API settings (`config.OpsGateSettings`). `allowed_networks` are the
/// parsed `allowed_cidrs` the network gate matches against.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiSettings {
    pub service_name: String,
    pub bind_host: String,
    /// Not range-checked here, as in Python (binding fails later).
    pub bind_port: i64,
    pub db_path: String,
    pub session_secret: String,
    pub trust_proxy_headers: bool,
    pub session_cookie_secure: bool,
    pub session_timeout_seconds: i64,
    pub ui_username: String,
    pub ui_password_bcrypt: String,
    /// Private so every value passed the bounds check (Python validates in
    /// `__post_init__`); read with [`ApiSettings::max_duration_seconds_default`].
    max_duration_seconds_default: i64,
    pub policy_floor_require_reviewer_step: bool,
    pub runner_token: String,
    pub submitter_policies: Vec<SubmitterPolicy>,
    pub require_tailscale_context: bool,
    pub allowed_cidrs: Vec<String>,
    pub allowed_networks: Vec<IpNet>,
    pub execution_data_dir: String,
    pub disable_file_path: String,
}

impl fmt::Debug for ApiSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSettings")
            .field("service_name", &self.service_name)
            .field("bind_host", &self.bind_host)
            .field("bind_port", &self.bind_port)
            .field("db_path", &self.db_path)
            .field("session_secret", &"<redacted>")
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("session_cookie_secure", &self.session_cookie_secure)
            .field("session_timeout_seconds", &self.session_timeout_seconds)
            .field("ui_username", &self.ui_username)
            .field("ui_password_bcrypt", &"<redacted>")
            .field(
                "max_duration_seconds_default",
                &self.max_duration_seconds_default,
            )
            .field(
                "policy_floor_require_reviewer_step",
                &self.policy_floor_require_reviewer_step,
            )
            .field("runner_token", &"<redacted>")
            .field("submitter_policies", &self.submitter_policies)
            .field("require_tailscale_context", &self.require_tailscale_context)
            .field("allowed_cidrs", &self.allowed_cidrs)
            .field("execution_data_dir", &self.execution_data_dir)
            .field("disable_file_path", &self.disable_file_path)
            .finish_non_exhaustive()
    }
}

impl ApiSettings {
    /// `OPSGATE_MAX_DURATION_SECONDS_DEFAULT`, within 1..=[`MAX_DURATION_SECONDS`].
    pub fn max_duration_seconds_default(&self) -> i64 {
        self.max_duration_seconds_default
    }

    /// `dataclasses.replace(settings, max_duration_seconds_default=value)`:
    /// the bounds are checked as on construction.
    pub fn with_max_duration_seconds_default(mut self, value: i64) -> Result<Self, SettingsError> {
        self.max_duration_seconds_default = validate_duration_default(PyInt::Value(value))?;
        Ok(self)
    }
}

/// The runner settings (`config.RunnerSettings`).
#[derive(Clone, PartialEq, Eq)]
pub struct RunnerSettings {
    pub service_name: String,
    pub runner_token: String,
    pub runner_host: String,
    /// `http://…` without trailing slashes (D-10).
    pub runner_api_base_url: String,
    pub runner_poll_interval_seconds: i64,
    pub runner_heartbeat_interval_seconds: i64,
    pub max_parallel_jobs: i64,
    /// Private like [`ApiSettings`]'s; see [`RunnerSettings::max_duration_seconds_default`].
    max_duration_seconds_default: i64,
    pub execution_data_dir: String,
    pub tickets_dir: String,
    pub session_artifacts_dir: String,
    pub tmux_socket_label: String,
    /// Empty when unset; only used in the attach command.
    pub tmux_tmpdir: String,
    pub disable_file_path: String,
}

impl fmt::Debug for RunnerSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerSettings")
            .field("service_name", &self.service_name)
            .field("runner_token", &"<redacted>")
            .field("runner_host", &self.runner_host)
            .field("runner_api_base_url", &self.runner_api_base_url)
            .field(
                "runner_poll_interval_seconds",
                &self.runner_poll_interval_seconds,
            )
            .field(
                "runner_heartbeat_interval_seconds",
                &self.runner_heartbeat_interval_seconds,
            )
            .field("max_parallel_jobs", &self.max_parallel_jobs)
            .field(
                "max_duration_seconds_default",
                &self.max_duration_seconds_default,
            )
            .field("execution_data_dir", &self.execution_data_dir)
            .field("tickets_dir", &self.tickets_dir)
            .field("session_artifacts_dir", &self.session_artifacts_dir)
            .field("tmux_socket_label", &self.tmux_socket_label)
            .field("tmux_tmpdir", &self.tmux_tmpdir)
            .field("disable_file_path", &self.disable_file_path)
            .finish()
    }
}

impl RunnerSettings {
    /// `OPSGATE_MAX_DURATION_SECONDS_DEFAULT`, within 1..=[`MAX_DURATION_SECONDS`].
    pub fn max_duration_seconds_default(&self) -> i64 {
        self.max_duration_seconds_default
    }

    /// `dataclasses.replace(settings, max_duration_seconds_default=value)`:
    /// the bounds are checked as on construction.
    pub fn with_max_duration_seconds_default(mut self, value: i64) -> Result<Self, SettingsError> {
        self.max_duration_seconds_default = validate_duration_default(PyInt::Value(value))?;
        Ok(self)
    }
}

fn require_secret(value: &str, message: &str) -> Result<(), SettingsError> {
    if value.chars().count() < 20 {
        Err(SettingsError::new(message))
    } else {
        Ok(())
    }
}

/// `config.load_settings`: apply the env file, then read and check every
/// variable in Python's order (the first failing rule decides).
pub fn load_api_settings(environment: &mut Environment) -> Result<ApiSettings, SettingsError> {
    environment.apply_env_file_setting()?;
    let env = &*environment;

    let service_name = env.stripped_or("OPSGATE_SERVICE_NAME", "opsgate")?;
    let bind_host = env.stripped_or("OPSGATE_BIND_HOST", "0.0.0.0")?;
    let bind_port = parse_int(env.get("OPSGATE_BIND_PORT")?, 8711, "OPSGATE_BIND_PORT")?;

    let mut db_path = env.stripped_or("OPSGATE_DB_PATH", "")?;
    if db_path.is_empty() {
        db_path = "/usr/local/var/opsgate/run/opsgate.sqlite3".to_owned();
    }

    let ui_username = env.stripped_or("OPSGATE_UI_USERNAME", "")?;
    let ui_password_bcrypt = env.stripped_or("OPSGATE_UI_PASSWORD_BCRYPT", "")?;
    if ui_username.is_empty() || ui_password_bcrypt.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_UI_USERNAME and OPSGATE_UI_PASSWORD_BCRYPT are required",
        ));
    }

    let session_secret = env.stripped_or("OPSGATE_SESSION_SECRET", "")?;
    require_secret(
        &session_secret,
        "OPSGATE_SESSION_SECRET is required and must be at least 20 characters",
    )?;
    let trust_proxy_headers = parse_bool(
        env.get("OPSGATE_TRUST_PROXY_HEADERS")?,
        false,
        "OPSGATE_TRUST_PROXY_HEADERS",
    )?;
    let session_cookie_secure = parse_bool(
        env.get("OPSGATE_SESSION_COOKIE_SECURE")?,
        false,
        "OPSGATE_SESSION_COOKIE_SECURE",
    )?;

    let max_duration_default = parse_int_raw(
        env.get("OPSGATE_MAX_DURATION_SECONDS_DEFAULT")?,
        3600,
        "OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    )?;
    let policy_floor = parse_bool(
        env.get("OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP")?,
        false,
        "OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP",
    )?;
    let session_timeout_seconds = parse_int(
        env.get("OPSGATE_UI_SESSION_TIMEOUT_SECONDS")?,
        28800,
        "OPSGATE_UI_SESSION_TIMEOUT_SECONDS",
    )?;

    let runner_token = env.stripped_or("OPSGATE_RUNNER_TOKEN", "")?;
    require_secret(
        &runner_token,
        "OPSGATE_RUNNER_TOKEN is required and must be at least 20 characters",
    )?;

    let openclaw_token = env.stripped_or("OPSGATE_SUBMIT_TOKEN_OPENCLAW", "")?;
    let nyxmon_token = env.stripped_or("OPSGATE_SUBMIT_TOKEN_NYXMON", "")?;
    let operator_token = env.stripped_or("OPSGATE_SUBMIT_TOKEN_OPERATOR", "")?;
    if !openclaw_token.is_empty() {
        require_secret(
            &openclaw_token,
            "Submit token for openclaw must be at least 20 characters",
        )?;
    }
    require_secret(
        &nyxmon_token,
        "Submit token for nyxmon must be at least 20 characters",
    )?;
    require_secret(
        &operator_token,
        "Submit token for operator must be at least 20 characters",
    )?;

    // The openclaw policy is parsed (and rejected on a typo) even without its token.
    let openclaw_floor = parse_bool(
        env.get("OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP")?,
        policy_floor,
        "OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP",
    )?;
    let mut submitter_policies = Vec::with_capacity(3);
    if !openclaw_token.is_empty() {
        submitter_policies.push(SubmitterPolicy {
            source: "openclaw".to_owned(),
            token: openclaw_token,
            require_reviewer_step_floor: openclaw_floor,
        });
    }
    let nyxmon_floor = parse_bool(
        env.get("OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP")?,
        policy_floor,
        "OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP",
    )?;
    submitter_policies.push(SubmitterPolicy {
        source: "nyxmon".to_owned(),
        token: nyxmon_token,
        require_reviewer_step_floor: nyxmon_floor,
    });
    let operator_floor = parse_bool(
        env.get("OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP")?,
        policy_floor,
        "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
    )?;
    submitter_policies.push(SubmitterPolicy {
        source: "operator".to_owned(),
        token: operator_token,
        require_reviewer_step_floor: operator_floor,
    });

    let require_tailscale_context = parse_bool(
        env.get("OPSGATE_REQUIRE_TAILSCALE_CONTEXT")?,
        true,
        "OPSGATE_REQUIRE_TAILSCALE_CONTEXT",
    )?;
    let default_cidrs = DEFAULT_ALLOWED_CIDRS.join(",");
    let allowed_cidrs: Vec<String> = env
        .get("OPSGATE_ALLOWED_CIDRS")?
        .unwrap_or(&default_cidrs)
        .split(',')
        .map(pytext::strip)
        .filter(|cidr| !cidr.is_empty())
        .map(str::to_owned)
        .collect();
    if allowed_cidrs.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_ALLOWED_CIDRS must contain at least one CIDR",
        ));
    }

    let execution_data_dir =
        env.stripped_or("OPSGATE_EXECUTION_DATA_DIR", "/Users/ops/remediation")?;
    let mut disable_file_path = env.stripped_or("OPSGATE_DISABLE_FILE_PATH", "")?;
    if disable_file_path.is_empty() {
        disable_file_path = format!("{execution_data_dir}/.disabled");
    }

    // Python validates the CIDRs while building the settings object and the
    // duration bounds in its `__post_init__`, so these two come last.
    let allowed_networks = allowed_cidrs
        .iter()
        .map(|cidr| parse_network(cidr))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| SettingsError::new("OPSGATE_ALLOWED_CIDRS contains an invalid network"))?;
    let max_duration_seconds_default = validate_duration_default(max_duration_default)?;

    Ok(ApiSettings {
        service_name,
        bind_host,
        bind_port,
        db_path,
        session_secret,
        trust_proxy_headers,
        session_cookie_secure,
        session_timeout_seconds,
        ui_username,
        ui_password_bcrypt,
        max_duration_seconds_default,
        policy_floor_require_reviewer_step: policy_floor,
        runner_token,
        submitter_policies,
        require_tailscale_context,
        allowed_cidrs,
        allowed_networks,
        execution_data_dir,
        disable_file_path,
    })
}

/// `config.load_runner_settings`, with `socket.gethostname()` as the default
/// runner host.
pub fn load_runner_settings(
    environment: &mut Environment,
) -> Result<RunnerSettings, SettingsError> {
    load_runner_settings_with_host(environment, system_hostname)
}

/// The system host name (`socket.gethostname()`).
pub fn system_hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// [`load_runner_settings`] with an injected host-name source (called only
/// when `OPSGATE_RUNNER_HOST` is blank or unset).
pub fn load_runner_settings_with_host(
    environment: &mut Environment,
    hostname: impl FnOnce() -> String,
) -> Result<RunnerSettings, SettingsError> {
    environment.apply_env_file_setting()?;
    let env = &*environment;

    let service_name = env.stripped_or("OPSGATE_SERVICE_NAME", "opsgate")?;
    let runner_token = env.stripped_or("OPSGATE_RUNNER_TOKEN", "")?;
    require_secret(
        &runner_token,
        "OPSGATE_RUNNER_TOKEN is required and must be at least 20 characters",
    )?;

    let bind_port = parse_int(env.get("OPSGATE_BIND_PORT")?, 8711, "OPSGATE_BIND_PORT")?;
    let default_base_url = format!("http://127.0.0.1:{bind_port}");
    let base_url = env.stripped_or("OPSGATE_RUNNER_API_BASE_URL", &default_base_url)?;
    if base_url.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_RUNNER_API_BASE_URL must not be empty",
        ));
    }
    let runner_api_base_url = base_url.trim_end_matches('/').to_owned();
    // D-10: the runner speaks plain HTTP to the local API only.
    let is_http = runner_api_base_url
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        && runner_api_base_url.len() > 7;
    if !is_http {
        return Err(SettingsError::new(
            "OPSGATE_RUNNER_API_BASE_URL must be an http:// URL",
        ));
    }

    let runner_poll_interval_seconds = parse_int(
        env.get("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS")?,
        5,
        "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS",
    )?;
    let runner_heartbeat_interval_seconds = parse_int(
        env.get("OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS")?,
        30,
        "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS",
    )?;
    let max_parallel_jobs = parse_int(
        env.get("OPSGATE_MAX_PARALLEL_JOBS")?,
        3,
        "OPSGATE_MAX_PARALLEL_JOBS",
    )?;
    let max_duration_default = parse_int_raw(
        env.get("OPSGATE_MAX_DURATION_SECONDS_DEFAULT")?,
        3600,
        "OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    )?;
    if runner_poll_interval_seconds <= 0 {
        return Err(SettingsError::new(
            "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS must be > 0",
        ));
    }
    if runner_heartbeat_interval_seconds <= 0 {
        return Err(SettingsError::new(
            "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS must be > 0",
        ));
    }
    if max_parallel_jobs <= 0 {
        return Err(SettingsError::new("OPSGATE_MAX_PARALLEL_JOBS must be > 0"));
    }

    let execution_data_dir =
        env.stripped_or("OPSGATE_EXECUTION_DATA_DIR", "/Users/ops/remediation")?;
    if execution_data_dir.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_EXECUTION_DATA_DIR must not be empty",
        ));
    }

    let tickets_dir =
        env.stripped_or("OPSGATE_TICKETS_DIR", &format!("{execution_data_dir}/jobs"))?;
    let session_artifacts_dir = env.stripped_or(
        "OPSGATE_SESSION_ARTIFACTS_DIR",
        &format!("{execution_data_dir}/sessions"),
    )?;
    if tickets_dir.is_empty() || session_artifacts_dir.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_TICKETS_DIR and OPSGATE_SESSION_ARTIFACTS_DIR must not be empty",
        ));
    }

    let tmux_socket_label = env.stripped_or("OPSGATE_TMUX_SOCKET_LABEL", "remediation")?;
    if tmux_socket_label.is_empty() {
        return Err(SettingsError::new(
            "OPSGATE_TMUX_SOCKET_LABEL must not be empty",
        ));
    }
    let tmux_tmpdir = env.stripped_or("TMUX_TMPDIR", "")?;

    let mut disable_file_path = env.stripped_or("OPSGATE_DISABLE_FILE_PATH", "")?;
    if disable_file_path.is_empty() {
        disable_file_path = format!("{execution_data_dir}/.disabled");
    }

    let mut runner_host = env.stripped_or("OPSGATE_RUNNER_HOST", "")?;
    if runner_host.is_empty() {
        runner_host = hostname();
    }

    let max_duration_seconds_default = validate_duration_default(max_duration_default)?;

    Ok(RunnerSettings {
        service_name,
        runner_token,
        runner_host,
        runner_api_base_url,
        runner_poll_interval_seconds,
        runner_heartbeat_interval_seconds,
        max_parallel_jobs,
        max_duration_seconds_default,
        execution_data_dir,
        tickets_dir,
        session_artifacts_dir,
        tmux_socket_label,
        tmux_tmpdir,
        disable_file_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_int_grammar() {
        assert_eq!(parse_py_int("+8_712"), Some(PyInt::Value(8712)));
        assert_eq!(parse_py_int("-0"), Some(PyInt::Value(0)));
        assert_eq!(parse_py_int("007"), Some(PyInt::Value(7)));
        assert_eq!(parse_py_int("9223372036854775808"), Some(PyInt::OutOfRange));
        assert_eq!(
            parse_py_int("-9223372036854775808"),
            Some(PyInt::Value(i64::MIN))
        );
        for invalid in [
            "", "+", "-", "_1", "1_", "1__2", "+_1", "1.0", "0x1", "\u{ff11}", "1 2", "++1",
        ] {
            assert_eq!(parse_py_int(invalid), None, "{invalid:?}");
        }
        assert_eq!(parse_py_int(&"1".repeat(4300)), Some(PyInt::OutOfRange));
        assert_eq!(parse_py_int(&"1".repeat(4301)), None);
        assert_eq!(
            parse_py_int(&format!("{}1", "1_".repeat(2150))),
            Some(PyInt::OutOfRange)
        );
    }

    #[test]
    fn non_utf8_value_names_the_variable() {
        use std::os::unix::ffi::OsStringExt;
        let env = Environment::from_vars([(
            OsString::from("OPSGATE_BIND_HOST"),
            OsString::from_vec(vec![0xff]),
        )]);
        let error = env.get("OPSGATE_BIND_HOST").unwrap_err();
        assert_eq!(
            error.message(),
            "OPSGATE_BIND_HOST must be valid UTF-8 text"
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut env = Environment::from_vars([
            ("OPSGATE_UI_USERNAME", "admin"),
            ("OPSGATE_UI_PASSWORD_BCRYPT", "hash-secret-value"),
            ("OPSGATE_SESSION_SECRET", "session-secret-value-0000"),
            ("OPSGATE_RUNNER_TOKEN", "runner-secret-value-00000"),
            ("OPSGATE_SUBMIT_TOKEN_NYXMON", "nyxmon-secret-value-00000"),
            ("OPSGATE_SUBMIT_TOKEN_OPERATOR", "operator-secret-value-000"),
        ]);
        let api = format!("{:?} {env:?}", load_api_settings(&mut env).unwrap());
        let runner = format!(
            "{:?}",
            load_runner_settings_with_host(&mut env, || "h".to_owned()).unwrap()
        );
        for text in [api, runner] {
            assert!(!text.contains("secret-value"), "{text}");
        }
    }

    #[test]
    fn network_prefix_digits() {
        assert_eq!(parse_network("10.0.0.0/0000008"), "10.0.0.0/8".parse().ok());
        assert_eq!(parse_network("::/0128"), "::/128".parse().ok());
        assert_eq!(parse_network("10.0.0.0/00000000000000000000033"), None);
        assert_eq!(parse_network("10.0.0.0/256"), None);
        assert_eq!(parse_network("::/1000"), None);
    }
}
