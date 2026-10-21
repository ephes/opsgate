//! Process-level tests of the `opsgate` binary (PLAN.md 4.1, D-15):
//! `--version`, the stub commands and usage errors (slice S1), `check-db`
//! (slice S3a).

use std::process::{Command, Output};

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
fn unlanded_commands_are_stubs_that_exit_2() {
    for (args, name) in [
        (&[][..], "serve"),
        (&["serve"], "serve"),
        (
            &[
                "serve",
                "--db",
                "/nonexistent/opsgate.sqlite3",
                "--bind-host",
                "127.0.0.1",
                "--bind-port",
                "8712",
            ],
            "serve",
        ),
        (&["runner"], "runner"),
        (&["runner", "--once"], "runner"),
        (&["check-config", "api"], "check-config"),
        (&["check-config", "runner"], "check-config"),
    ] {
        let output = opsgate(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(
            text(&output.stderr),
            format!("opsgate {name}: not implemented yet (rust/PLAN.md section 12)\n"),
            "{args:?}"
        );
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
