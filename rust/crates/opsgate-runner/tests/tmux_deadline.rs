//! Fake native tmux client: no tmux server, shell, or platform process probes.
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use opsgate_core::settings::Environment;
use opsgate_runner::{Tmux, TmuxCli, TmuxError};

#[tokio::test]
async fn every_tmux_operation_kills_and_reaps_on_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("fake.rs");
    std::fs::write(&source, r#"
        fn main() {
            if std::env::var("HOLD_PIPE").as_deref() == Ok("parent") {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .env("HOLD_PIPE", "child").spawn().unwrap();
                return;
            }
            let _stream = std::net::TcpStream::connect(std::env::var("READY_ADDRESS").unwrap()).unwrap();
            println!("synthetic private diagnostic");
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    "#).unwrap();
    let binary = dir
        .path()
        .join(format!("tmux{}", std::env::consts::EXE_SUFFIX));
    assert!(
        std::process::Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    for operation in [
        "has-session",
        "new-session",
        "kill-session",
        "ls",
        "inherited-pipes",
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let cli = TmuxCli::with_timeout(
            "synthetic",
            Arc::new(Environment::from_vars([
                ("PATH", dir.path().as_os_str().to_owned()),
                (
                    "HOLD_PIPE",
                    if operation == "inherited-pipes" {
                        "parent".into()
                    } else {
                        "".into()
                    },
                ),
                (
                    "READY_ADDRESS",
                    listener.local_addr().unwrap().to_string().into(),
                ),
            ])),
            Duration::from_millis(500),
        );
        let started = Instant::now();
        let error = match operation {
            "has-session" => cli.has_session("synthetic").await.unwrap_err(),
            "new-session" => cli
                .new_session("synthetic", Path::new("synthetic"))
                .await
                .unwrap_err(),
            "kill-session" => cli.kill_session("synthetic").await.unwrap_err(),
            _ => cli.list_sessions().await.unwrap_err(),
        };
        assert!(matches!(error, TmuxError::Timeout), "{error}");
        assert_eq!(error.to_string(), "tmux command timed out");
        assert!(started.elapsed() < Duration::from_secs(3));
        let (mut peer, _) = listener.accept().expect("fake client started");
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "owned client still holds its socket"
        );
    }
}
