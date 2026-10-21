//! Process-level tests of the `opsgate` binary skeleton (PLAN.md 4.1, D-15,
//! slice S1): `--version`, the stub commands and usage errors.

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
    if std::env::var_os("OPSGATE_GIT_COMMIT").is_some() {
        return;
    }
    let Ok(head) = Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
    else {
        return;
    };
    if !head.status.success() {
        return;
    }
    assert_eq!(text(&head.stdout).trim(), env!("OPSGATE_GIT_COMMIT"));
}

#[test]
fn every_command_is_a_stub_that_exits_2() {
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
        (
            &["check-db", "--db", "/nonexistent/opsgate.sqlite3"],
            "check-db",
        ),
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
fn usage_errors_exit_2_with_a_clap_error() {
    for args in [
        &["unknown"][..],
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
