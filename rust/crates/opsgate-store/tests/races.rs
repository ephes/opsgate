//! Concurrent transitions (PLAN.md 4.7, 7.1), ported from
//! `tests/test_ticket_transition_races.py`: a second writer runs between a
//! transition's read and its write (the first pauses in the store's read
//! hook), or a transition works on a row read before a concurrent change.
//! `BEGIN IMMEDIATE` serialises the writers; the compare-and-set turns a
//! stale read into 409 `state_changed`.
//!
//! `OPSGATE_RACE_REPEAT=<n>` repeats every test n times (the S3b acceptance
//! runs them 100 times).

mod common;

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{APPROVER, audit, create, error, ticket_payload};
use opsgate_store::{ReadHook, Store, StoreError, Ticket, TicketRow};
use rusqlite::Connection;
use serde_json::json;

const RUNNER_HOST: &str = "runner-a";

/// How long the first writer pauses between its read and its write while
/// the second writer runs. With serialisation the second writer blocks on
/// the database lock until the first commits.
const INTERLEAVE_WINDOW: Duration = Duration::from_millis(500);

type Outcome = Result<Ticket, StoreError>;

fn repeat() -> usize {
    std::env::var("OPSGATE_RACE_REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
}

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = common::store(directory.path());
    (directory, store)
}

fn create_ticket(store: &Store) -> String {
    create(
        store,
        "nyxmon",
        &ticket_payload("Race", Some("race-1"), None),
    )
}

fn approve(store: &Store, id: &str) -> Outcome {
    store.approve_ticket(id, APPROVER, None, None)
}

fn cancel(store: &Store, id: &str) -> Outcome {
    store.cancel_ticket(id, APPROVER, "stop", None, None)
}

fn reject(store: &Store, id: &str) -> Outcome {
    store.reject_ticket(id, APPROVER, "no", None, None)
}

fn runner_finish(store: &Store, id: &str) -> Outcome {
    store.update_runner_status(
        id,
        RUNNER_HOST,
        &common::object(json!({"event": "ticket_succeeded", "state": "succeeded"})),
        None,
        None,
    )
}

fn claim(store: &Store) -> Option<Ticket> {
    store.claim_ticket(RUNNER_HOST, None, None).unwrap()
}

fn state(store: &Store, id: &str) -> String {
    store.get_ticket(id).unwrap()["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn transitions(store: &Store, id: &str) -> Vec<(String, Option<String>, Option<String>)> {
    audit(store, id)
        .into_iter()
        .map(|(event, previous, new, _)| (event, previous, new))
        .collect()
}

fn events(store: &Store, id: &str) -> Vec<String> {
    common::audit_event_types(store, id)
}

/// Runs `second` in another thread right after `first` has read the ticket;
/// `first` pauses in its read hook until `second` finished or the window
/// ran out.
fn interleave<F, S>(store: &Store, first: F, second: S) -> (Outcome, Outcome)
where
    F: FnOnce(&Store) -> Outcome + Send,
    S: FnOnce(&Store) -> Outcome + Send,
{
    let (read_tx, read_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let pause: Mutex<Option<(Sender<()>, Receiver<()>)>> = Mutex::new(Some((read_tx, done_rx)));
    let hook: ReadHook = Arc::new(move |row: Option<TicketRow>| {
        if let Some((read_tx, done_rx)) = pause.lock().unwrap().take() {
            read_tx.send(()).unwrap();
            let _ = done_rx.recv_timeout(INTERLEAVE_WINDOW);
        }
        row
    });
    let first_store = store.clone().with_read_hook(hook);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| first(&first_store));
        let second = scope.spawn(move || {
            read_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the first writer read the ticket");
            let outcome = second(store);
            let _ = done_tx.send(());
            outcome
        });
        (first.join().unwrap(), second.join().unwrap())
    })
}

/// A row of the ticket as it is now, to be handed out later as a stale read.
fn snapshot(store: &Store, id: &str) -> TicketRow {
    Connection::open(store.db_path())
        .unwrap()
        .query_row("SELECT * FROM tickets WHERE id = ?", [id], |row| {
            Ok(TicketRow::from_row(row))
        })
        .unwrap()
        .unwrap()
}

/// The store whose next transition reads `stale` instead of the current row.
fn with_stale_first_read(store: &Store, stale: TicketRow) -> Store {
    let stale = Mutex::new(Some(stale));
    store
        .clone()
        .with_read_hook(Arc::new(move |row: Option<TicketRow>| {
            stale.lock().unwrap().take().or(row)
        }))
}

fn assert_conflict(outcome: Outcome, code: &str) {
    assert_eq!(error(outcome), (409, code));
}

// --- Interleaved writers -----------------------------------------------------

#[test]
fn test_cancel_during_approve_is_not_overwritten() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        let (approved, canceled) = interleave(
            &store,
            |store| approve(store, &id),
            |store| cancel(store, &id),
        );
        // The approve read pending_approval first; the cancel is not lost.
        approved.unwrap();
        canceled.unwrap();
        assert_eq!(state(&store, &id), "canceled");
        assert!(claim(&store).is_none());
        let trail = transitions(&store, &id);
        assert_eq!(
            trail[trail.len() - 2..],
            [
                (
                    "ticket_approved".to_owned(),
                    Some("pending_approval".to_owned()),
                    Some("approved".to_owned())
                ),
                (
                    "ticket_canceled".to_owned(),
                    Some("approved".to_owned()),
                    Some("canceled".to_owned())
                ),
            ]
        );
    }
}

#[test]
fn test_cancel_during_runner_completion_is_reported() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        approve(&store, &id).unwrap();
        assert_eq!(claim(&store).unwrap()["id"], id.as_str());
        let (finished, canceled) = interleave(
            &store,
            |store| runner_finish(store, &id),
            |store| cancel(store, &id),
        );
        // The runner read running first and wins; the cancel then sees a
        // terminal ticket and is told so.
        assert_eq!(finished.unwrap()["state"], "succeeded");
        assert_conflict(canceled, "invalid_state");
        assert_eq!(state(&store, &id), "succeeded");
        assert!(!events(&store, &id).contains(&"ticket_canceled".to_owned()));
    }
}

#[test]
fn test_double_approve_has_one_winner() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        let (first, second) = interleave(
            &store,
            |store| approve(store, &id),
            |store| approve(store, &id),
        );
        first.unwrap();
        assert_conflict(second, "invalid_state");
        assert_eq!(
            events(&store, &id)
                .iter()
                .filter(|event| *event == "ticket_approved")
                .count(),
            1
        );
    }
}

#[test]
fn test_reject_during_approve_is_not_overwritten() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        let (approved, rejected) = interleave(
            &store,
            |store| approve(store, &id),
            |store| reject(store, &id),
        );
        approved.unwrap();
        assert_conflict(rejected, "invalid_state");
        assert_eq!(state(&store, &id), "approved");
    }
}

/// Claims never interleave: the claim holds the write lock from its first
/// read, so two concurrent claims hand the ticket to one runner.
#[test]
fn concurrent_claims_have_one_winner() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        approve(&store, &id).unwrap();
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| store.claim_ticket("runner-a", None, None).unwrap());
            let second = scope.spawn(|| store.claim_ticket("runner-b", None, None).unwrap());
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(
            usize::from(first.is_some()) + usize::from(second.is_some()),
            1
        );
        assert_eq!(
            events(&store, &id)
                .iter()
                .filter(|event| *event == "runner_claimed")
                .count(),
            1
        );
    }
}

// --- Compare-and-set on a stale read -------------------------------------------

#[test]
fn test_approve_with_stale_read_after_cancel_returns_state_changed() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        let stale = snapshot(&store, &id);
        cancel(&store, &id).unwrap();
        assert_conflict(
            approve(&with_stale_first_read(&store, stale), &id),
            "state_changed",
        );
        assert_eq!(state(&store, &id), "canceled");
        assert!(claim(&store).is_none());
        assert!(!events(&store, &id).contains(&"ticket_approved".to_owned()));
    }
}

#[test]
fn test_runner_completion_with_stale_read_after_cancel_returns_state_changed() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        approve(&store, &id).unwrap();
        assert!(claim(&store).is_some());
        let stale = snapshot(&store, &id);
        cancel(&store, &id).unwrap();
        assert_conflict(
            runner_finish(&with_stale_first_read(&store, stale), &id),
            "state_changed",
        );
        let ticket = store.get_ticket(&id).unwrap();
        assert_eq!(ticket["state"], "canceled");
        assert_eq!(ticket["result"], "canceled");
    }
}

#[test]
fn test_lifecycle_action_with_stale_read_returns_state_changed() {
    for _ in 0..repeat() {
        for action in ["reject", "cancel"] {
            let (_directory, store) = store();
            let id = create_ticket(&store);
            let stale = snapshot(&store, &id);
            approve(&store, &id).unwrap();
            let stale_store = with_stale_first_read(&store, stale);
            let outcome = if action == "reject" {
                reject(&stale_store, &id)
            } else {
                cancel(&stale_store, &id)
            };
            // The stale read saw pending_approval; the ticket is approved
            // now. Even where the action is valid from approved (cancel), it
            // must not commit against a state it did not read.
            assert_conflict(outcome, "state_changed");
            assert_eq!(state(&store, &id), "approved", "{action}");
        }
    }
}

#[test]
fn test_archive_with_stale_read_returns_state_changed() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        let stale = snapshot(&store, &id);
        approve(&store, &id).unwrap();
        assert_conflict(
            with_stale_first_read(&store, stale).archive_ticket(&id, APPROVER, None, None),
            "state_changed",
        );
        let ticket = store.get_ticket(&id).unwrap();
        assert_eq!(ticket["state"], "approved");
        assert!(ticket["archived_at"].is_null());
        // The approved ticket stays claimable.
        assert_eq!(claim(&store).unwrap()["id"], id.as_str());
    }
}

#[test]
fn test_unarchive_with_stale_read_returns_state_changed() {
    for _ in 0..repeat() {
        let (_directory, store) = store();
        let id = create_ticket(&store);
        store.archive_ticket(&id, APPROVER, None, None).unwrap();
        let stale = snapshot(&store, &id);
        store.unarchive_ticket(&id, APPROVER, None, None).unwrap();
        store
            .archive_ticket(&id, "other-approver", None, None)
            .unwrap();
        assert_conflict(
            with_stale_first_read(&store, stale).unarchive_ticket(&id, APPROVER, None, None),
            "state_changed",
        );
        assert_eq!(
            store.get_ticket(&id).unwrap()["archived_by"],
            "other-approver"
        );
    }
}
