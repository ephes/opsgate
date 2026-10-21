//! The executor with the real `tmux` on a private socket label and
//! `TMUX_TMPDIR`, fake `codex`/`claude` first on `PATH` (PLAN.md 7.1). The
//! tests skip when `tmux` is missing, unless `OPSGATE_REQUIRE_TMUX` is set
//! (CI sets it).

mod common;

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{FakeApi, TestClock, runner_settings, running_ticket};
use opsgate_core::settings::Environment;
use opsgate_runner::{TicketExecutor, Tmux, TmuxCli, TmuxError};
use serde_json::json;
use tokio_util::sync::CancellationToken;

/// The environment of the test's tmux children, built from an allowlist
/// so neither a real agent nor the caller's tmux or shell configuration can
/// be reached. `HOME` is a fresh directory (no `~/.tmux.conf`, which may set
/// a `default-shell` whose startup files reorder `PATH`), `SHELL` is
/// `/bin/sh`, and `PATH` holds only the fake agents, a link to `tmux` and
/// the system directories. `OPSGATE_TEST_MARKER` stands for a key of the
/// runner env file, which only this environment has (4.13.8).
fn environment(home: &Path, tmux_tmpdir: &Path, fake_bin: &Path) -> Environment {
    let mut path = OsString::from(fake_bin);
    path.push(":/usr/bin:/bin:/usr/sbin:/sbin");
    // An allowlist: anything else (exported shell functions such as
    // `BASH_FUNC_codex%%`, `ENV`, `BASH_ENV`, the caller's tmux) could put a
    // real agent in front of the fakes.
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            matches!(key.as_ref(), "USER" | "LOGNAME" | "LANG" | "TERM") || key.starts_with("LC_")
        })
        .collect();
    vars.push(("PATH".into(), path));
    vars.push(("HOME".into(), home.into()));
    vars.push(("SHELL".into(), "/bin/sh".into()));
    vars.push(("TMUX_TMPDIR".into(), tmux_tmpdir.into()));
    vars.push(("OPSGATE_TEST_MARKER".into(), "from-env-file".into()));
    Environment::from_vars(vars)
}

/// The `tmux` binary on the caller's `PATH`.
fn tmux_binary() -> Option<PathBuf> {
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", "command -v tmux"])
        .output()
        .ok()?;
    let found = String::from_utf8(output.stdout).ok()?;
    let found = PathBuf::from(found.trim());
    found.is_absolute().then_some(found)
}

fn tmux_available() -> bool {
    let found = tmux_binary().is_some();
    if !found {
        assert!(
            std::env::var_os("OPSGATE_REQUIRE_TMUX").is_none(),
            "tmux is required (OPSGATE_REQUIRE_TMUX) but not available"
        );
        eprintln!("skipped: tmux not found");
    }
    found
}

/// A private tmux server, killed when dropped.
struct PrivateTmux {
    _dir: tempfile::TempDir,
    fake_bin: PathBuf,
    label: String,
    environment: Arc<Environment>,
}

impl PrivateTmux {
    fn new(name: &str) -> Self {
        // Under /tmp: the socket path must stay below the 104-byte limit.
        let dir = tempfile::Builder::new()
            .prefix("og-")
            .tempdir_in("/tmp")
            .unwrap();
        let tmpdir = dir.path().join("t");
        std::fs::create_dir(&tmpdir).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let fake_bin = dir.path().join("bin");
        std::fs::create_dir(&fake_bin).unwrap();
        std::os::unix::fs::symlink(tmux_binary().unwrap(), fake_bin.join("tmux")).unwrap();
        write_script(
            &fake_bin.join("codex"),
            "#!/bin/sh\necho \"codex args: $*\"\necho \"prompt: $(cat)\"\necho \"marker: $OPSGATE_TEST_MARKER\"\nexit 0\n",
        );
        write_script(
            &fake_bin.join("claude"),
            "#!/bin/sh\ncat >/dev/null\necho \"claude args: $*\"\nexit 3\n",
        );
        let environment = Arc::new(environment(&home, &tmpdir, &fake_bin));
        Self {
            _dir: dir,
            fake_bin,
            label: format!("og-{name}-{}", std::process::id()),
            environment,
        }
    }

    fn cli(&self) -> TmuxCli {
        TmuxCli::new(self.label.clone(), self.environment.clone())
    }
}

impl Drop for PrivateTmux {
    fn drop(&mut self) {
        let _ = std::process::Command::new("tmux")
            .args(["-L", &self.label, "kill-server"])
            .env_clear()
            .envs(self.environment.vars())
            .output();
    }
}

fn write_script(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A two-step ticket through real tmux sessions: the step script runs the
/// agent from the inherited `PATH` with the prompt on stdin, tees its output
/// into `session.log` and writes `exit_code`; the second step fails with 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executor_runs_steps_in_real_tmux() {
    if !tmux_available() {
        return;
    }
    let tmux = PrivateTmux::new("exec");
    let dir = tempfile::tempdir().unwrap();
    let settings = Arc::new(runner_settings(dir.path(), 1));
    let id = "aaaaaaaa-1111-4111-8111-111111111111";
    let plan = json!([
        {"role": "investigator", "agent": "codex", "prompt_markdown": "inspect it's \"quoted\""},
        {"role": "reviewer", "agent": "Claude", "prompt_markdown": "review"},
    ]);
    let api = FakeApi::new(running_ticket(id, plan.clone(), 0, 120));
    let executor = TicketExecutor::new(
        settings,
        api.clone(),
        tmux.cli(),
        TestClock::new(),
        CancellationToken::new(),
        id,
    );
    let ticket = api.ticket.lock().unwrap().clone();
    let finished = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        executor.run(Some(ticket)),
    )
    .await;
    if finished.is_err() {
        let listing = std::process::Command::new("find")
            .arg(dir.path())
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&listing.stdout));
        let ls = tmux.cli().run(&["ls"]).await.unwrap();
        eprintln!(
            "ls: {} {}",
            String::from_utf8_lossy(&ls.stdout),
            String::from_utf8_lossy(&ls.stderr)
        );
        eprintln!("events: {:?}", api.events());
        panic!("executor did not finish");
    }
    finished.unwrap().unwrap();

    assert_eq!(api.ticket_field("state"), "failed");
    assert_eq!(api.ticket_field("result_detail"), "step_2_exit_code_3");
    let first = executor.step_paths(0, plan[0].as_object().unwrap());
    let second = executor.step_paths(1, plan[1].as_object().unwrap());
    let log = std::fs::read_to_string(&first.log_path).unwrap();
    assert!(
        log.contains(
            "codex args: exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox -"
        ),
        "{log}"
    );
    assert!(log.contains("prompt: inspect it's \"quoted\""), "{log}");
    assert!(log.contains("marker: from-env-file"), "{log}");
    assert_eq!(
        std::fs::read_to_string(&first.exit_code_path).unwrap(),
        "0\n"
    );
    assert_eq!(
        std::fs::read_to_string(&second.exit_code_path).unwrap(),
        "3\n"
    );
    assert!(
        std::fs::read_to_string(&second.log_path)
            .unwrap()
            .contains("claude args: -p --dangerously-skip-permissions")
    );
    let cli = tmux.cli();
    for paths in [&first, &second] {
        let metadata = common::read_json(&paths.metadata_path);
        let session = metadata["session_name"].as_str().unwrap();
        assert!(!cli.has_session(session).await.unwrap(), "{session}");
    }
    assert!(tmux.fake_bin.join("codex").exists());
}

/// `has-session`, `kill-session` and a failing `new-session` on a live
/// session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_probe_kill_and_failed_launch() {
    if !tmux_available() {
        return;
    }
    let tmux = PrivateTmux::new("kill");
    let cli = tmux.cli();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("run step.sh");
    write_script(&script, "#!/bin/bash\nsleep 30\n");
    let name = "job-aaaaaaaa-1111-4111-8111-111111111111-01-x";
    assert!(!cli.has_session(name).await.unwrap());
    cli.kill_session(name).await.unwrap();
    cli.new_session(name, &script).await.unwrap();
    assert!(cli.has_session(name).await.unwrap());
    match cli.new_session(name, &script).await {
        Err(TmuxError::Failed(status)) => assert!(!status.success()),
        other => panic!("duplicate session launched: {other:?}"),
    }
    cli.kill_session(name).await.unwrap();
    assert!(!cli.has_session(name).await.unwrap());
}

/// Without `tmux` on the inherited `PATH` every call is a spawn error
/// (Python: `FileNotFoundError`).
#[tokio::test]
async fn missing_tmux_binary_is_an_error() {
    let cli = TmuxCli::new(
        "og-missing",
        Arc::new(Environment::from_vars([("PATH", "/nonexistent")])),
    );
    assert!(matches!(
        cli.has_session("x").await,
        Err(TmuxError::Spawn(_))
    ));
    assert!(matches!(
        cli.kill_session("x").await,
        Err(TmuxError::Spawn(_))
    ));
    assert!(matches!(
        cli.new_session("x", Path::new("/tmp/x.sh")).await,
        Err(TmuxError::Spawn(_))
    ));
}
