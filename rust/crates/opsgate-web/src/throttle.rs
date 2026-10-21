//! The login throttle (`LoginThrottle`, PLAN.md 4.5.3): failed sign-ins per
//! client, in memory, on a monotonic clock, lost on restart.
//!
//! A client (its address, or `unknown`) is locked while it has at least
//! `limit` failures newer than `window_seconds`. A failure keeps the last
//! `limit` stamps; a successful sign-in resets the client. At most
//! `max_tracked_clients` clients are tracked: when a failure goes beyond
//! that, the clients without a recent failure are dropped first, then the
//! ones whose newest failure is oldest (ties in the order the clients were
//! first tracked, as Python's stable sort over its dictionary). Times are
//! seconds as `f64`, compared as Python compares its floats
//! (`fixtures/throttle.json`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// `LOGIN_FAILURE_LIMIT`.
pub const LOGIN_FAILURE_LIMIT: usize = 5;
/// `LOGIN_FAILURE_WINDOW_SECONDS` (15 minutes).
pub const LOGIN_FAILURE_WINDOW_SECONDS: f64 = 15.0 * 60.0;
/// `LOGIN_THROTTLE_MAX_TRACKED_CLIENTS`.
pub const LOGIN_THROTTLE_MAX_TRACKED_CLIENTS: usize = 10_000;

/// A monotonic clock in seconds (`time.monotonic`).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// One tracked client.
#[derive(Debug, Clone)]
struct Entry {
    /// When the client was (last) added to the dictionary: Python's
    /// insertion order, which decides ties when clients are dropped.
    order: u64,
    stamps: Vec<f64>,
}

#[derive(Debug, Default)]
struct Failures {
    entries: HashMap<String, Entry>,
    next_order: u64,
}

impl Failures {
    /// `_recent(key, now)`: the client's failures newer than the window;
    /// the client is dropped when none are left.
    fn recent(&mut self, key: &str, now: f64, window_seconds: f64) -> Vec<f64> {
        let cutoff = now - window_seconds;
        let Some(entry) = self.entries.get_mut(key) else {
            return Vec::new();
        };
        let recent: Vec<f64> = entry
            .stamps
            .iter()
            .copied()
            .filter(|stamp| *stamp > cutoff)
            .collect();
        if recent.is_empty() {
            self.entries.remove(key);
        } else {
            entry.stamps.clone_from(&recent);
        }
        recent
    }

    /// `self._failures[key] = stamps`: an existing client keeps its place.
    fn set(&mut self, key: &str, stamps: Vec<f64>) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.stamps = stamps;
            return;
        }
        let order = self.next_order;
        self.next_order += 1;
        self.entries.insert(key.to_owned(), Entry { order, stamps });
    }

    /// The keys in Python's dictionary order.
    fn ordered_keys(&self) -> Vec<String> {
        let mut keys: Vec<(&String, u64)> = self
            .entries
            .iter()
            .map(|(key, entry)| (key, entry.order))
            .collect();
        keys.sort_by_key(|(_, order)| *order);
        keys.into_iter().map(|(key, _)| key.clone()).collect()
    }
}

/// The per-client counter of failed sign-ins.
pub struct LoginThrottle {
    limit: usize,
    window_seconds: f64,
    max_tracked_clients: usize,
    clock: Clock,
    failures: Mutex<Failures>,
}

impl std::fmt::Debug for LoginThrottle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginThrottle")
            .field("limit", &self.limit)
            .field("window_seconds", &self.window_seconds)
            .field("max_tracked_clients", &self.max_tracked_clients)
            .finish_non_exhaustive()
    }
}

impl Default for LoginThrottle {
    /// The server's throttle: 5 failures in 15 minutes, 10 000 clients, the
    /// process's monotonic clock.
    fn default() -> Self {
        let origin = Instant::now();
        Self::new(
            LOGIN_FAILURE_LIMIT,
            LOGIN_FAILURE_WINDOW_SECONDS,
            LOGIN_THROTTLE_MAX_TRACKED_CLIENTS,
            Arc::new(move || origin.elapsed().as_secs_f64()),
        )
    }
}

impl LoginThrottle {
    /// `LoginThrottle(limit=…, window_seconds=…, max_tracked_clients=…,
    /// clock=…)`.
    pub fn new(
        limit: usize,
        window_seconds: f64,
        max_tracked_clients: usize,
        clock: Clock,
    ) -> Self {
        Self {
            limit,
            window_seconds,
            max_tracked_clients,
            clock,
            failures: Mutex::new(Failures::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Failures> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `is_locked(key)`.
    pub fn is_locked(&self, key: &str) -> bool {
        let mut failures = self.lock();
        failures
            .recent(key, (self.clock)(), self.window_seconds)
            .len()
            >= self.limit
    }

    /// `record_failure(key)`.
    pub fn record_failure(&self, key: &str) {
        let mut failures = self.lock();
        let now = (self.clock)();
        let mut recent = failures.recent(key, now, self.window_seconds);
        recent.push(now);
        // `recent[-limit:]` (all of them for a limit of 0, as in Python).
        if self.limit > 0 && recent.len() > self.limit {
            recent.drain(..recent.len() - self.limit);
        }
        failures.set(key, recent);
        if failures.entries.len() > self.max_tracked_clients {
            self.prune(&mut failures, now);
        }
    }

    /// `reset(key)`.
    pub fn reset(&self, key: &str) {
        self.lock().entries.remove(key);
    }

    /// `_prune(now)`: drop the clients without a recent failure, then, while
    /// too many are left, those whose newest failure is oldest.
    fn prune(&self, failures: &mut Failures, now: f64) {
        for key in failures.ordered_keys() {
            failures.recent(&key, now, self.window_seconds);
        }
        let overflow = failures
            .entries
            .len()
            .saturating_sub(self.max_tracked_clients);
        if overflow == 0 {
            return;
        }
        let mut by_age: Vec<(String, f64, u64)> = failures
            .entries
            .iter()
            .map(|(key, entry)| {
                let newest = entry.stamps.last().copied().unwrap_or(f64::NEG_INFINITY);
                (key.clone(), newest, entry.order)
            })
            .collect();
        // Python compares the floats with `<` (equal values tie, so the
        // insertion order decides).
        by_age.sort_by(|left, right| {
            left.1
                .partial_cmp(&right.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(left.2.cmp(&right.2))
        });
        for (key, _, _) in by_age.into_iter().take(overflow) {
            failures.entries.remove(&key);
        }
    }

    /// The tracked clients and their failure stamps in Python's dictionary
    /// order (`_failures`, for tests).
    pub fn tracked(&self) -> Vec<(String, Vec<f64>)> {
        let failures = self.lock();
        failures
            .ordered_keys()
            .into_iter()
            .map(|key| {
                let stamps = failures.entries[&key].stamps.clone();
                (key, stamps)
            })
            .collect()
    }
}
