//! The login throttle (`LoginThrottle`, PLAN.md 4.5.3): failed/pending sign-ins per
//! client, in memory, on a monotonic clock, lost on restart.
//!
//! Production admission reserves under the mutex before hashing and settles via
//! a guard. Pending checks expire after the failure window, survive sibling success,
//! and count with failures. A full client table denies new clients.
//! The legacy failure-counter helpers prune expired entries and evict the oldest
//! failures past the client limit (ties in insertion order, matching Python).
//! Times are seconds as `f64`, compared as Python compares its floats
//! (`fixtures/throttle.json`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// `LOGIN_FAILURE_LIMIT`.
pub const LOGIN_FAILURE_LIMIT: usize = 5;
/// `LOGIN_FAILURE_WINDOW_SECONDS` (15 minutes).
pub const LOGIN_FAILURE_WINDOW_SECONDS: f64 = 15.0 * 60.0;
/// `LOGIN_THROTTLE_MAX_TRACKED_CLIENTS`.
pub const LOGIN_THROTTLE_MAX_TRACKED_CLIENTS: usize = 10_000;
/// Maximum other clients examined by one production admission.
pub const LOGIN_THROTTLE_EXPIRY_CLIENT_BUDGET: usize = 16;

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
    #[cfg(test)]
    maintenance_visits: usize,
    pending: HashMap<String, HashMap<u64, f64>>,
    next_attempt: u64,
    entries: HashMap<String, Entry>,
    next_order: u64,
    // One removable round-robin position per active client. No stale queue nodes.
    tracked: HashMap<String, u64>,
    sweep: BTreeMap<u64, String>,
    next_sweep: u64,
}

impl Failures {
    fn sync_tracked(&mut self, key: &str) {
        if self.entries.contains_key(key) || self.pending.contains_key(key) {
            if !self.tracked.contains_key(key) {
                let order = self.next_sweep;
                self.next_sweep += 1;
                self.tracked.insert(key.to_owned(), order);
                self.sweep.insert(order, key.to_owned());
            }
        } else if let Some(order) = self.tracked.remove(key) {
            self.sweep.remove(&order);
        }
    }

    fn expire_client(&mut self, key: &str, now: f64, window_seconds: f64) {
        #[cfg(test)]
        {
            self.maintenance_visits += 1;
        }
        if let Some(attempts) = self.pending.get_mut(key) {
            attempts.retain(|_, stamp| *stamp > now - window_seconds);
            if attempts.is_empty() {
                self.pending.remove(key);
            }
        }
        self.recent(key, now, window_seconds);
        self.sync_tracked(key);
    }

    fn expire_incrementally(&mut self, now: f64, window_seconds: f64) {
        for _ in 0..LOGIN_THROTTLE_EXPIRY_CLIENT_BUDGET.min(self.tracked.len()) {
            let (order, key) = self
                .sweep
                .pop_first()
                .expect("tracked client has sweep entry");
            self.tracked.remove(&key);
            self.expire_client(&key, now, window_seconds);
            debug_assert!(!self.sweep.contains_key(&order));
        }
    }

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
        self.sync_tracked(key);
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
        self.sync_tracked(key);
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
#[derive(Clone)]
pub struct LoginThrottle {
    limit: usize,
    window_seconds: f64,
    max_tracked_clients: usize,
    clock: Clock,
    failures: Arc<Mutex<Failures>>,
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
            failures: Arc::new(Mutex::new(Failures::default())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Failures> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve capacity atomically before bcrypt. The guard releases on error/unwind.
    pub fn reserve(&self, key: &str) -> Option<Reservation> {
        let mut failures = self.lock();
        let now = (self.clock)();
        failures.expire_incrementally(now, self.window_seconds);
        failures.expire_client(key, now, self.window_seconds);
        let count = failures.recent(key, now, self.window_seconds).len()
            + failures.pending.get(key).map_or(0, HashMap::len);
        if count >= self.limit {
            return None;
        }
        if !failures.tracked.contains_key(key) && failures.tracked.len() >= self.max_tracked_clients
        {
            return None;
        }
        let attempt = failures.next_attempt;
        failures.next_attempt += 1;
        failures
            .pending
            .entry(key.to_owned())
            .or_default()
            .insert(attempt, now);
        failures.sync_tracked(key);
        Some(Reservation {
            throttle: self.clone(),
            key: key.to_owned(),
            attempt,
        })
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
        let mut failures = self.lock();
        failures.entries.remove(key);
        failures.sync_tracked(key);
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
            failures.sync_tracked(&key);
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

/// One admitted password check. Dropping it releases only its own reservation.
pub struct Reservation {
    throttle: LoginThrottle,
    key: String,
    attempt: u64,
}

impl Reservation {
    pub fn settle(self, success: bool) {
        self.finish(Some(success));
    }

    fn finish(&self, success: Option<bool>) {
        let mut failures = self.throttle.lock();
        let Some(attempts) = failures.pending.get_mut(&self.key) else {
            return;
        };
        let stamp = attempts.remove(&self.attempt);
        if attempts.is_empty() {
            failures.pending.remove(&self.key);
        }
        failures.sync_tracked(&self.key);
        let now = (self.throttle.clock)();
        if stamp.is_none_or(|stamp| stamp <= now - self.throttle.window_seconds) {
            return;
        }
        match success {
            Some(true) => {
                failures.entries.remove(&self.key);
            }
            Some(false) => {
                let mut recent = failures.recent(&self.key, now, self.throttle.window_seconds);
                recent.push(now);
                failures.set(&self.key, recent);
            }
            None => {}
        }
        failures.sync_tracked(&self.key);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.finish(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_expiry_preserves_target_and_bounds_storage() {
        let now = Arc::new(Mutex::new(0.0));
        let reading = now.clone();
        let throttle = LoginThrottle::new(1, 60.0, 64, Arc::new(move || *reading.lock().unwrap()));
        let mut slots: Vec<_> = (0..64)
            .map(|i| throttle.reserve(&format!("client-{i}")).unwrap())
            .collect();
        assert!(throttle.reserve("overflow").is_none());
        *now.lock().unwrap() = 60.0;
        let fresh = throttle.reserve("client-63").unwrap();
        fresh.settle(false);
        slots.pop().unwrap().settle(true);
        assert!(throttle.reserve("client-63").is_none());
        let new_client = throttle.reserve("new-client").unwrap();
        for _ in 0..4 {
            assert!(throttle.reserve("client-63").is_none());
        }
        assert_eq!(throttle.lock().tracked.len(), 2);
        assert_eq!(throttle.lock().sweep.len(), 2);
        *now.lock().unwrap() = 120.0;
        for i in 0..1000 {
            drop(throttle.reserve(&format!("churn-{i}")).unwrap());
        }
        let state = throttle.lock();
        assert!(state.tracked.is_empty());
        assert!(state.sweep.is_empty());
        assert!(state.entries.is_empty());
        assert!(state.pending.is_empty());
        drop(state);
        drop(new_client);
        drop(slots);
    }

    #[test]
    fn admission_key_visits_are_linear() {
        for clients in [1000, 2000, 4000] {
            let throttle = LoginThrottle::new(5, 900.0, 10_000, Arc::new(|| 0.0));
            let slots: Vec<_> = (0..clients)
                .map(|i| throttle.reserve(&format!("client-{i}")).unwrap())
                .collect();
            assert!(throttle.lock().maintenance_visits <= clients * 20);
            drop(slots);
        }
    }
}
