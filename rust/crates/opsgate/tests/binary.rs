//! Process-level tests of the `opsgate` binary (PLAN.md 4.1, D-15):
//! `--version`, the stub commands and usage errors (slice S1), `check-db`
//! (slice S3a), `check-db --dump` (slice S3b), `runner` (slice S6b:
//! configuration errors, `--once`, the P1 log line of a failed claim,
//! SIGTERM/SIGINT) and `serve` (slice S4a: configuration errors, the
//! overrides, HTTP on the bound port, SIGTERM/SIGINT).

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_opsgate");

fn opsgate(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn version_prints_version_and_full_commit() {
    let expected = format!(
        "opsgate {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        env!("OPSGATE_GIT_COMMIT")
    );
    for flag in ["--version", "-V"] {
        let output = opsgate(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert_eq!(text(&output.stdout), expected, "{flag}");
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

/// Without an override, the embedded commit is the checked-out commit.
#[test]
fn version_commit_is_head_of_the_source_tree() {
    let head = Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| text(&output.stdout).trim().to_owned());
    match env!("OPSGATE_GIT_COMMIT_SOURCE") {
        "git" => assert_eq!(head.as_deref(), Some(env!("OPSGATE_GIT_COMMIT"))),
        "none" => {
            assert_eq!(env!("OPSGATE_GIT_COMMIT"), "unknown");
            assert_eq!(head, None);
        }
        source => assert_eq!(source, "env"),
    }
}

#[test]
fn check_db_reports_and_exits_0_or_1() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("opsgate.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../../../fixtures/schema.sql"))
        .unwrap();
    let db = path.to_str().unwrap();

    let output = opsgate(&["check-db", "--db", db]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = text(&output.stdout);
    assert!(
        stdout.starts_with(&format!("database: {db}\nschema: ok\nrows: ok\n")),
        "{stdout}"
    );
    assert!(stdout.contains("tickets: 0 ()\n"), "{stdout}");

    connection
        .execute_batch("DROP INDEX idx_tickets_state")
        .unwrap();
    let output = opsgate(&["check-db", "--db", db]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains("schema: FAILED\n  missing index idx_tickets_state\n"),
        "{stdout}"
    );

    let missing = directory.path().join("missing.sqlite3");
    let output = opsgate(&["check-db", "--db", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        text(&output.stderr).starts_with(&format!("opsgate check-db: {}: ", missing.display())),
        "{}",
        text(&output.stderr)
    );
    assert!(!missing.exists());
}

#[test]
fn check_db_dump_writes_records_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("opsgate.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../../../fixtures/schema.sql"))
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO tickets (id, source, title, summary, execution_plan_json, \
             policy_requirements_json, context_json, payload_checksum, state, created_by, \
             created_at, max_duration_seconds) VALUES ('t-1', 'nyxmon', 'T', 'S', \
             '[{\"agent\": \"codex\", \"prompt_markdown\": \"p\", \"role\": \"r\"}]', \
             '{}', '{}', 'x', 'pending_approval', 'submit:nyxmon', '2026-01-01T00:00:00Z', 60)",
        )
        .unwrap();
    let db = path.to_str().unwrap();
    let dump = directory.path().join("rust.jsonl");
    let dump_arg = dump.to_str().unwrap();

    let output = opsgate(&["check-db", "--db", db, "--dump", dump_arg]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(
        stdout.ends_with(&format!(
            "dump: {dump_arg} (1 tickets, 0 with an approval checksum, 0 matching)\n"
        )),
        "{stdout}"
    );
    let record: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&dump).unwrap().trim()).unwrap();
    assert_eq!(record["id"], "t-1");
    assert_eq!(record["ticket"]["title"], "T");

    // An existing dump is never overwritten.
    let output = opsgate(&["check-db", "--db", db, "--dump", dump_arg]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).starts_with(&format!("opsgate check-db: {dump_arg}: ")),
        "{}",
        text(&output.stderr)
    );

    // A different schema is reported and not dumped.
    connection
        .execute_batch("DROP INDEX idx_tickets_state")
        .unwrap();
    let other = directory.path().join("other.jsonl");
    let output = opsgate(&["check-db", "--db", db, "--dump", other.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("not dumped, the schema differs"));
    assert!(!other.exists());
}

#[test]
fn usage_errors_exit_2_with_a_clap_error() {
    for args in [
        &["unknown"][..],
        // The `serve` overrides need the `serve` command.
        &["--db", "/nonexistent/opsgate.sqlite3"],
        &["serve", "--once"],
        &["serve", "--bind-port", "65536"],
        &["check-config"],
        &["check-config", "web"],
        &["check-db"],
        &["runner", "extra"],
    ] {
        let output = opsgate(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = text(&output.stderr);
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
        assert!(stderr.contains("--help"), "{args:?}: {stderr}");
        assert!(!stderr.contains("not implemented"), "{args:?}: {stderr}");
    }
}

#[test]
fn help_lists_the_commands() {
    let output = opsgate(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = text(&output.stdout);
    for command in ["serve", "runner", "check-config", "check-db"] {
        assert!(stdout.contains(command), "{command}: {stdout}");
    }
}

// ----- runner (slice S6b) -----------------------------------------------------

const RUNNER_TOKEN: &str = "runner-secret-value-0000000";

/// A loopback port nothing listens on (bound and released).
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// The runner's env file in `root` (an API that refuses connections, no
/// `tmux` on `PATH`) and the process environment pointing at it.
fn runner_env(root: &Path, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let exec_dir = root.join("execution");
    let mut lines = vec![
        format!("OPSGATE_RUNNER_TOKEN={RUNNER_TOKEN}"),
        format!(
            "OPSGATE_RUNNER_API_BASE_URL=http://127.0.0.1:{}",
            closed_port()
        ),
        format!("OPSGATE_EXECUTION_DATA_DIR={}", exec_dir.display()),
        "OPSGATE_RUNNER_HOST=runner-binary-test".to_owned(),
        "OPSGATE_TMUX_SOCKET_LABEL=og-binary-test".to_owned(),
        "PATH=/nonexistent".to_owned(),
    ];
    lines.extend(extra.iter().map(|(key, value)| format!("{key}={value}")));
    let env_file = root.join("runner.env");
    std::fs::write(&env_file, lines.join("\n") + "\n").unwrap();
    vec![(
        "OPSGATE_ENV_FILE".to_owned(),
        env_file.display().to_string(),
    )]
}

fn runner_command(args: &[&str], env: &[(String, String)]) -> Command {
    let mut command = Command::new(BINARY);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)));
    command
}

#[test]
fn runner_configuration_errors_name_the_setting_and_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.env");
    let short_file = dir.path().join("short.env");
    std::fs::write(&short_file, "OPSGATE_RUNNER_TOKEN=too-short-secret\n").unwrap();
    for (env, named) in [
        (vec![], "OPSGATE_RUNNER_TOKEN"),
        (
            vec![("OPSGATE_ENV_FILE", missing.to_str().unwrap())],
            "Env file does not exist",
        ),
        (
            vec![("OPSGATE_ENV_FILE", short_file.to_str().unwrap())],
            "OPSGATE_RUNNER_TOKEN",
        ),
        (
            vec![
                ("OPSGATE_RUNNER_TOKEN", RUNNER_TOKEN),
                ("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS", "0"),
            ],
            "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS",
        ),
    ] {
        for args in [&["runner"][..], &["runner", "--once"]] {
            let output = Command::new(BINARY)
                .args(args)
                .env_clear()
                .envs(env.iter().copied())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1), "{env:?}");
            assert!(output.stdout.is_empty());
            let stderr = text(&output.stderr);
            assert_eq!(stderr.lines().count(), 1, "{stderr}");
            assert!(
                stderr.starts_with("opsgate runner: configuration error: "),
                "{stderr}"
            );
            assert!(stderr.contains(named), "{stderr}");
            assert!(!stderr.contains("too-short-secret"), "{stderr}");
        }
    }
}

/// `--once` with the disable file: one recovery pass, no claim, exit 0. The
/// state directory is created and the startup line names no secret.
#[test]
fn runner_once_with_disable_file_exits_without_claiming() {
    let dir = tempfile::tempdir().unwrap();
    let env = runner_env(dir.path(), &[]);
    let exec_dir = dir.path().join("execution");
    std::fs::create_dir_all(&exec_dir).unwrap();
    std::fs::write(exec_dir.join(".disabled"), "").unwrap();

    let output = runner_command(&["runner", "--once"], &env)
        .output()
        .unwrap();

    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(exec_dir.join("runner-state").is_dir());
    assert!(
        stderr.contains("implementation=rust runner_host=runner-binary-test"),
        "{stderr}"
    );
    assert!(!stderr.contains("Runner claim failed"), "{stderr}");
    assert!(!stderr.contains(RUNNER_TOKEN), "{stderr}");
}

/// `--once` against an unreachable API: the claim fails with the P1 log line
/// (4.15) and the runner exits 0.
#[test]
fn runner_once_logs_a_failed_claim() {
    let dir = tempfile::tempdir().unwrap();
    let env = runner_env(dir.path(), &[]);

    let output = runner_command(&["runner", "--once"], &env)
        .output()
        .unwrap();

    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let failures: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("Runner claim failed"))
        .collect();
    assert_eq!(failures.len(), 1, "{stderr}");
    assert!(
        failures[0].ends_with("Runner claim failed: status=503 category=transport_error"),
        "{stderr}"
    );
    assert!(!stderr.contains(RUNNER_TOKEN), "{stderr}");
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// SIGTERM and SIGINT stop the runner during its poll-interval sleep at once
/// (D-16; the interval here is an hour) with exit 0.
#[test]
fn runner_stops_on_sigterm_and_sigint() {
    for signal in ["TERM", "INT"] {
        let dir = tempfile::tempdir().unwrap();
        let env = runner_env(
            dir.path(),
            &[("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS", "3600")],
        );
        let stderr_path = dir.path().join("runner.err");
        let mut child = runner_command(&["runner"], &env)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap();
        // The first claim has failed once the loop runs (and the handlers
        // are installed).
        let deadline = Instant::now() + Duration::from_secs(30);
        while !std::fs::read_to_string(&stderr_path)
            .unwrap()
            .contains("Runner claim failed")
        {
            assert!(Instant::now() < deadline, "runner did not start");
            assert!(child.try_wait().unwrap().is_none(), "runner exited");
            std::thread::sleep(Duration::from_millis(20));
        }
        let killed = Command::new("kill")
            .args([&format!("-{signal}"), &child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let status = wait_for_exit(&mut child, Duration::from_secs(10));
        let stderr = std::fs::read_to_string(&stderr_path).unwrap();
        assert_eq!(status.and_then(|s| s.code()), Some(0), "{signal}: {stderr}");
    }
}

// ----- serve (slice S4a) ------------------------------------------------------

const SESSION_SECRET: &str = "serve-session-secret-0000000000";

/// The API's env file in `root` and the process environment pointing at it.
fn serve_env(root: &Path, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut lines = vec![
        format!(
            "OPSGATE_DB_PATH={}",
            root.join("env-db/opsgate.sqlite3").display()
        ),
        "OPSGATE_UI_USERNAME=opsgate-admin".to_owned(),
        "OPSGATE_UI_PASSWORD_BCRYPT=$2b$04$not.a.real.hash.for.the.binary.tests.xxxxxxxxxxxxxx"
            .to_owned(),
        format!("OPSGATE_SESSION_SECRET={SESSION_SECRET}"),
        format!("OPSGATE_RUNNER_TOKEN={RUNNER_TOKEN}"),
        "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000".to_owned(),
        "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000".to_owned(),
        format!("OPSGATE_EXECUTION_DATA_DIR={}", root.join("exec").display()),
        "OPSGATE_SERVICE_NAME=opsgate-binary-test".to_owned(),
        "OPSGATE_BIND_HOST=192.0.2.1".to_owned(),
        "OPSGATE_BIND_PORT=1".to_owned(),
    ];
    lines.extend(extra.iter().map(|(key, value)| format!("{key}={value}")));
    let env_file = root.join("api.env");
    std::fs::write(&env_file, lines.join("\n") + "\n").unwrap();
    vec![(
        "OPSGATE_ENV_FILE".to_owned(),
        env_file.display().to_string(),
    )]
}

/// `GET <path>` over a plain TCP connection: the status line and the body.
fn http_get(port: u16, path: &str) -> Option<(String, String)> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    Some((head.lines().next()?.to_owned(), body.to_owned()))
}

#[test]
fn serve_configuration_errors_name_the_setting_and_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.env");
    let short_dir = dir.path().join("short");
    let port_dir = dir.path().join("port");
    std::fs::create_dir_all(&short_dir).unwrap();
    std::fs::create_dir_all(&port_dir).unwrap();
    let short = serve_env(
        &short_dir,
        &[("OPSGATE_SESSION_SECRET", "too-short-secret")],
    );
    for (env, named) in [
        (vec![], "OPSGATE_"),
        (
            vec![("OPSGATE_ENV_FILE".to_owned(), missing.display().to_string())],
            "Env file does not exist",
        ),
        (short, "OPSGATE_SESSION_SECRET"),
        (
            serve_env(&port_dir, &[("OPSGATE_BIND_PORT", "70000")]),
            "OPSGATE_BIND_PORT",
        ),
    ] {
        let output = runner_command(&["serve"], &env).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{env:?}");
        assert!(output.stdout.is_empty());
        let stderr = text(&output.stderr);
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            stderr.starts_with("opsgate serve: configuration error: "),
            "{stderr}"
        );
        assert!(stderr.contains(named), "{stderr}");
        assert!(!stderr.contains("too-short-secret"), "{stderr}");
    }
}

/// `serve` with the overrides of D-15 answers HTTP on the given address,
/// initialises the given database, and stops with exit 0 on SIGTERM and
/// SIGINT. Its log names no secret.
#[test]
fn serve_answers_and_stops_on_signals() {
    for signal in ["TERM", "INT"] {
        let dir = tempfile::tempdir().unwrap();
        let env = serve_env(dir.path(), &[]);
        let db = dir.path().join("override/opsgate.sqlite3");
        let port = closed_port();
        let stderr_path = dir.path().join("serve.err");
        let mut child = runner_command(
            &[
                "serve",
                "--db",
                db.to_str().unwrap(),
                "--bind-host",
                "127.0.0.1",
                "--bind-port",
                &port.to_string(),
            ],
            &env,
        )
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let (status, body) = loop {
            if let Some(answer) = http_get(port, "/api/v1/health") {
                break answer;
            }
            assert!(Instant::now() < deadline, "serve did not answer");
            assert!(child.try_wait().unwrap().is_none(), "serve exited");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status, "HTTP/1.1 200 OK");
        let health: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(health["service"], "opsgate-binary-test");
        assert!(db.is_file());
        assert!(!dir.path().join("env-db").exists());
        let (status, _) = http_get(port, "/no-such-page").unwrap();
        assert_eq!(status, "HTTP/1.1 404 Not Found");

        let killed = Command::new("kill")
            .args([&format!("-{signal}"), &child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let status = wait_for_exit(&mut child, Duration::from_secs(10));
        let stderr = std::fs::read_to_string(&stderr_path).unwrap();
        assert_eq!(status.and_then(|s| s.code()), Some(0), "{signal}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "opsgate serve starting: version={} ({}) implementation=rust bind=127.0.0.1:{port}",
                env!("CARGO_PKG_VERSION"),
                env!("OPSGATE_GIT_COMMIT")
            )),
            "{stderr}"
        );
        assert!(stderr.contains("opsgate serve stopped"), "{stderr}");
        for secret in [SESSION_SECRET, RUNNER_TOKEN, "nyxmon-token-000000000000"] {
            assert!(!stderr.contains(secret), "{stderr}");
        }
    }
}

/// An address that cannot be bound is one log line and exit 1.
#[test]
fn serve_exits_1_when_the_address_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let env = serve_env(dir.path(), &[]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let output = runner_command(
        &["serve", "--bind-host", "127.0.0.1", "--bind-port", &port],
        &env,
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(&format!("opsgate serve: cannot listen on 127.0.0.1:{port}")),
        "{stderr}"
    );
}

/// A store operation blocked on a locked database cannot be cancelled; the
/// process still exits within the grace period after SIGTERM (4.1) instead
/// of waiting for it.
#[test]
fn serve_exits_within_the_grace_period_with_a_locked_database() {
    let dir = tempfile::tempdir().unwrap();
    let env = serve_env(dir.path(), &[]);
    let db = dir.path().join("locked/opsgate.sqlite3");
    let port = closed_port();
    let mut child = runner_command(
        &[
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &port.to_string(),
        ],
        &env,
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while http_get(port, "/api/v1/health").is_none() {
        assert!(Instant::now() < deadline, "serve did not answer");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Every connection of the server now waits for the lock.
    let lock = rusqlite::Connection::open(&db).unwrap();
    lock.execute_batch(
        "PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE probe_lock(x);",
    )
    .unwrap();
    let request = std::thread::spawn(move || {
        let _ = http_get(port, "/api/v1/health");
    });
    std::thread::sleep(Duration::from_millis(500));
    let stopped = Instant::now();
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = wait_for_exit(&mut child, Duration::from_secs(20));
    let elapsed = stopped.elapsed();
    assert_eq!(status.and_then(|s| s.code()), Some(0));
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
    drop(lock);
    request.join().unwrap();
}

// ----- check-config (slice S8) --------------------------------------------------

/// `check-config api|runner` with valid settings: exit 0, the `ok` line and
/// the non-secret values on stdout, nothing on stderr, no secret anywhere,
/// and nothing created (database, execution data directory).
#[test]
fn check_config_accepts_valid_settings_without_printing_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let api_env = serve_env(dir.path(), &[]);
    let output = runner_command(&["check-config", "api"], &api_env)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty());
    let stdout = text(&output.stdout);
    assert_eq!(
        stdout,
        format!(
            "opsgate check-config api: ok\nservice_name: opsgate-binary-test\nbind: 192.0.2.1:1\n\
             db_path: {}\nexecution_data_dir: {}\ndisable_file_path: {}\n",
            dir.path().join("env-db/opsgate.sqlite3").display(),
            dir.path().join("exec").display(),
            dir.path().join("exec/.disabled").display(),
        )
    );
    for secret in [SESSION_SECRET, RUNNER_TOKEN, "nyxmon-token", "$2b$"] {
        assert!(!stdout.contains(secret), "{secret}");
    }
    assert!(!dir.path().join("env-db").exists());
    assert!(!dir.path().join("exec").exists());

    let runner_env = runner_env(dir.path(), &[]);
    let output = runner_command(&["check-config", "runner"], &runner_env)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty());
    let stdout = text(&output.stdout);
    assert!(
        stdout.starts_with("opsgate check-config runner: ok\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("runner_host: runner-binary-test\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("tmux_socket_label: og-binary-test\n"),
        "{stdout}"
    );
    assert!(!stdout.contains(RUNNER_TOKEN), "{stdout}");
    assert!(!stdout.contains("127.0.0.1"), "{stdout}");
    assert!(!dir.path().join("execution").exists());
}

/// Invalid settings: exit 1, one stderr line naming the setting and never
/// its value, nothing on stdout. The API's settings are checked against the
/// API's rules and the runner's against the runner's.
#[test]
fn check_config_names_the_failing_setting_and_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.env");
    let short_dir = dir.path().join("short");
    let port_dir = dir.path().join("port");
    std::fs::create_dir_all(&short_dir).unwrap();
    std::fs::create_dir_all(&port_dir).unwrap();
    let missing_env = vec![("OPSGATE_ENV_FILE".to_owned(), missing.display().to_string())];
    let poll_dir = dir.path().join("poll");
    std::fs::create_dir_all(&poll_dir).unwrap();
    let runner_poll = runner_env(&poll_dir, &[("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS", "0")]);
    for (target, env, named) in [
        ("api", vec![], "OPSGATE_"),
        ("api", missing_env.clone(), "Env file does not exist"),
        (
            "api",
            serve_env(
                &short_dir,
                &[("OPSGATE_SESSION_SECRET", "too-short-secret")],
            ),
            "OPSGATE_SESSION_SECRET",
        ),
        (
            "api",
            serve_env(&port_dir, &[("OPSGATE_BIND_PORT", "70000")]),
            "OPSGATE_BIND_PORT",
        ),
        // The runner's env file is not an API configuration.
        ("api", runner_env(dir.path(), &[]), "OPSGATE_"),
        ("runner", vec![], "OPSGATE_RUNNER_TOKEN"),
        ("runner", missing_env, "Env file does not exist"),
        (
            "runner",
            runner_poll,
            "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS",
        ),
    ] {
        let output = runner_command(&["check-config", target], &env)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{target} {env:?}");
        assert!(output.stdout.is_empty(), "{target} {env:?}");
        let stderr = text(&output.stderr);
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            stderr.starts_with(&format!(
                "opsgate check-config {target}: configuration error: "
            )),
            "{stderr}"
        );
        assert!(stderr.contains(named), "{stderr}");
        for secret in ["too-short-secret", RUNNER_TOKEN, SESSION_SECRET] {
            assert!(!stderr.contains(secret), "{stderr}");
        }
    }
}
