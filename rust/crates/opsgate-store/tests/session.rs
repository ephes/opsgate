//! Session generations through independent Store instances on one WAL database.
mod common;

use std::sync::Barrier;

use common::{APPROVER, error, snapshot};
use opsgate_store::{Store, password_fingerprint};
use rusqlite::Connection;
use serde_json::Map;

#[test]
fn concurrent_revocations_each_advance_the_generation() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let initial = store.ui_session_generation(APPROVER).unwrap().unwrap();
    const N: usize = 8;
    // Open before releasing the barrier, so startup sync is not the operation
    // being raced. Each public call opens its own SQLite connection as well.
    let peers: Vec<_> = (0..N)
        .map(|_| Store::open(store.settings().clone()).unwrap())
        .collect();
    let start = Barrier::new(N);
    let mut generations = std::thread::scope(|scope| {
        let handles: Vec<_> = peers
            .iter()
            .map(|peer| {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    peer.revoke_ui_sessions(APPROVER).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    generations.sort_unstable();
    assert_eq!(
        generations,
        (initial + 1..=initial + N as i64).collect::<Vec<_>>()
    );
    assert_eq!(
        store.ui_session_generation(APPROVER).unwrap(),
        Some(initial + N as i64)
    );
    let before = snapshot(&store);
    assert_eq!(
        error(store.revoke_ui_sessions("unknown")),
        (400, "unknown_approver")
    );
    assert_eq!(store.ui_session_generation("unknown").unwrap(), None);
    assert_eq!(snapshot(&store), before);
}

#[test]
fn concurrent_password_startups_bump_once_for_one_replacement_hash() {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    let initial = store.ui_session_generation(APPROVER).unwrap().unwrap();
    let mut settings = store.settings().clone();
    settings.ui_password_bcrypt = "$2b$12$synthetic.replacement.not.a.credential".to_owned();
    let expected = password_fingerprint(&settings.ui_password_bcrypt);
    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let peer = Store::open(settings.clone()).unwrap();
                    assert_eq!(
                        peer.ui_session_generation(APPROVER).unwrap(),
                        Some(initial + 1)
                    );
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let (generation, fingerprint): (i64, String) = Connection::open(store.db_path()).unwrap()
        .query_row("SELECT session_generation, password_fingerprint FROM ui_session_state WHERE username = ?", [APPROVER], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(generation, initial + 1);
    // Do not print password fingerprints in assertion diagnostics.
    assert!(
        fingerprint == expected,
        "replacement fingerprint was not retained"
    );
}

#[test]
fn unchanged_password_startup_preserves_a_concurrent_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("opsgate.sqlite3");
    let store = Store::open(common::settings(&path, &Map::new())).unwrap();
    let initial = store.ui_session_generation(APPROVER).unwrap().unwrap();
    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        let startup = scope.spawn(|| {
            start.wait();
            Store::open(store.settings().clone()).unwrap()
        });
        let logout = scope.spawn(|| {
            start.wait();
            store.revoke_ui_sessions(APPROVER).unwrap()
        });
        let peer = startup.join().unwrap();
        assert_eq!(logout.join().unwrap(), initial + 1);
        assert_eq!(
            peer.ui_session_generation(APPROVER).unwrap(),
            Some(initial + 1)
        );
    });
    assert_eq!(
        store.ui_session_generation(APPROVER).unwrap(),
        Some(initial + 1)
    );
}
