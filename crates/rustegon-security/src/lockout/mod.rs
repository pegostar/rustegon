// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Account lockout (FR-SEC-006, security.md §8): `max_failures` failed logins within `window`
//! lock the account for `lock`, doubling for each consecutive lockout up to `max_lock`.
//! In memory and per node (PD-048).
//!
//! Semantics, uniform with authentication failures (PD-048):
//! - Failures are tracked per **claimed** user name whether or not the user exists, so the
//!   lockout behaviour cannot be used to enumerate users.
//! - [`LockoutTracker::check`] runs **before** credentials are verified: a locked account gets
//!   `RGN-4007` whatever the presented credentials, so lock state is never a password oracle,
//!   and a correct password does not unlock it.
//! - A success clears the failure window and the escalation level; an administrator unlock
//!   ([`LockoutTracker::unlock`]) clears everything.
//! - The escalation level decays after `max_lock` without a new lockout, so idle entries can be
//!   forgotten and memory is bounded by `max_tracked`.
//!
//! Names are kept as BLAKE3 digests: memory per entry is fixed whatever an attacker sends as a
//! user name, and the table holds no plaintext names.

pub mod settings;

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Clock;

pub use self::settings::LockoutSettings;

/// BLAKE3 derive-key context of user-name digests.
const NAME_CONTEXT: &str = "rustegon 2026-11 lockout user name v1";

/// Lockout policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Master switch.
    pub enabled: bool,
    /// Failures within `window` that lock the account.
    pub max_failures: u32,
    /// Sliding window of counted failures.
    pub window: Duration,
    /// Duration of the first lockout.
    pub lock: Duration,
    /// Upper bound of the doubled lockout duration.
    pub max_lock: Duration,
    /// Maximum tracked names per node.
    pub max_tracked: usize,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        LockoutSettings::default().to_policy()
    }
}

/// Result of [`LockoutTracker::record_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    /// Counted; `remaining` more failures within the window lock the account.
    Counted {
        /// Failures left before lockout.
        remaining: u32,
    },
    /// This failure locked the account for `duration` (the caller audits
    /// [`crate::audit::AuditEventKind::AccountLocked`]).
    Locked {
        /// Lock duration.
        duration: Duration,
    },
    /// The account was already locked (the attempt should not have reached credential
    /// verification) or lockout is disabled.
    Ignored,
}

#[derive(Debug, Default)]
struct Entry {
    /// Monotonic instants of the failures inside the window, oldest first (≤ `max_failures`).
    failures: VecDeque<Duration>,
    /// End of the current lockout.
    locked_until: Option<Duration>,
    /// Consecutive lockouts without a success (escalation level).
    lock_count: u32,
    /// End of the last lockout, for decay of `lock_count`.
    last_lock_end: Duration,
}

impl Entry {
    fn is_locked(&self, now: Duration) -> bool {
        self.locked_until.is_some_and(|u| now < u)
    }

    /// Drops state that no longer matters at `now`; true if nothing is left (forgettable).
    fn expire(&mut self, now: Duration, policy: &LockoutPolicy) -> bool {
        if self.locked_until.is_some_and(|u| now >= u) {
            self.locked_until = None;
        }
        while self
            .failures
            .front()
            .is_some_and(|&f| now.saturating_sub(f) >= policy.window)
        {
            self.failures.pop_front();
        }
        if self.locked_until.is_none()
            && self.lock_count > 0
            && now.saturating_sub(self.last_lock_end) >= policy.max_lock
        {
            self.lock_count = 0;
        }
        self.locked_until.is_none() && self.failures.is_empty() && self.lock_count == 0
    }
}

/// Per-node lockout state.
pub struct LockoutTracker {
    clock: Arc<dyn Clock>,
    policy: LockoutPolicy,
    // One mutex over the table: operations are O(max_failures) without I/O or awaits, and a
    // failure must read-modify-write its entry atomically, or two concurrent failures could
    // both see `max_failures - 1` and neither lock.
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

impl fmt::Debug for LockoutTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockoutTracker")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// The `RGN-4007` error. It names neither the user nor the remaining time.
#[must_use]
pub fn account_locked() -> Error {
    Error::new(ErrorCode::AccountLocked, "account is temporarily locked")
}

fn digest(user: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(NAME_CONTEXT);
    h.update(user.as_bytes());
    *h.finalize().as_bytes()
}

impl LockoutTracker {
    /// A tracker with `policy`, reading time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, policy: LockoutPolicy) -> Self {
        Self {
            clock,
            policy,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        // Entries are updated field by field without panicking paths in between; a poisoned
        // lock can only come from a panic elsewhere and leaves every entry usable.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Refuses an authentication attempt for a locked `user`. Call before verifying
    /// credentials.
    ///
    /// # Errors
    /// [`ErrorCode::AccountLocked`].
    pub fn check(&self, user: &str) -> Result<(), Error> {
        if self.is_locked(user) {
            Err(account_locked())
        } else {
            Ok(())
        }
    }

    /// Whether `user` is locked now.
    #[must_use]
    pub fn is_locked(&self, user: &str) -> bool {
        if !self.policy.enabled {
            return false;
        }
        let now = self.clock.monotonic();
        self.lock_entries()
            .get(&digest(user))
            .is_some_and(|e| e.is_locked(now))
    }

    /// Records a failed authentication of `user`.
    pub fn record_failure(&self, user: &str) -> FailureOutcome {
        if !self.policy.enabled {
            return FailureOutcome::Ignored;
        }
        let now = self.clock.monotonic();
        let key = digest(user);
        let mut entries = self.lock_entries();
        if !entries.contains_key(&key) {
            make_room(&mut entries, now, &self.policy);
        }
        let e = entries.entry(key).or_default();
        e.expire(now, &self.policy);
        if e.is_locked(now) {
            return FailureOutcome::Ignored;
        }
        e.failures.push_back(now);
        let count = u32::try_from(e.failures.len()).unwrap_or(u32::MAX);
        if count < self.policy.max_failures {
            return FailureOutcome::Counted {
                remaining: self.policy.max_failures - count,
            };
        }
        // Lock: `lock · 2^(n-1)` for the n-th consecutive lockout, capped at `max_lock`.
        let doublings = e.lock_count.min(31);
        let duration = self
            .policy
            .lock
            .saturating_mul(1u32 << doublings)
            .min(self.policy.max_lock);
        e.lock_count = e.lock_count.saturating_add(1);
        let until = now.saturating_add(duration);
        e.locked_until = Some(until);
        e.last_lock_end = until;
        e.failures.clear();
        FailureOutcome::Locked { duration }
    }

    /// Records a successful authentication: clears failures and the escalation level.
    pub fn record_success(&self, user: &str) {
        let now = self.clock.monotonic();
        let mut entries = self.lock_entries();
        let key = digest(user);
        if let Some(e) = entries.get_mut(&key) {
            if e.is_locked(now) {
                // Unreachable through `check`; never let a success lift a lock.
                return;
            }
            entries.remove(&key);
        }
    }

    /// Administrator unlock; returns whether the account was locked.
    pub fn unlock(&self, user: &str) -> bool {
        let now = self.clock.monotonic();
        self.lock_entries()
            .remove(&digest(user))
            .is_some_and(|e| e.is_locked(now))
    }

    /// Number of tracked names.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.lock_entries().len()
    }
}

/// Ensures room for one more entry: forgets expired entries, then, if still at the cap,
/// unlocked entries with the oldest last failure, then the locks ending soonest. Evicting a
/// lock is the last resort (it unlocks early), preferred over refusing to track a new name,
/// which would exempt that name from lockout altogether.
fn make_room(entries: &mut HashMap<[u8; 32], Entry>, now: Duration, policy: &LockoutPolicy) {
    let cap = policy.max_tracked.max(1);
    if entries.len() < cap {
        return;
    }
    entries.retain(|_, e| !e.expire(now, policy));
    if entries.len() < cap {
        return;
    }
    // (locked, sort instant): unlocked entries sort first, by last failure; then locks by end.
    let victim = entries
        .iter()
        .min_by_key(|(_, e)| match e.locked_until {
            Some(u) if now < u => (true, u),
            _ => (false, e.failures.back().copied().unwrap_or_default()),
        })
        .map(|(k, _)| *k);
    if let Some(k) = victim {
        entries.remove(&k);
    }
}
