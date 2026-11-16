// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Rate limiting per user and per source IP (FR-SEC-005, security.md §8).
//!
//! Each (class, user) and (class, IP) pair has a token bucket of `burst` tokens refilled at
//! `count` per `per`. Buckets are implemented with GCRA (generic cell rate algorithm), which is
//! an exact token bucket stored as a single instant, the *theoretical arrival time* (TAT):
//! with emission interval `T = per / count` and tolerance `τ = T · burst`, a request at `now`
//! is admitted iff `max(TAT, now) + T − now ≤ τ`, and then `TAT := max(TAT, now) + T`.
//! Integer [`Duration`] arithmetic, no floating point, no refill timer.
//!
//! A bucket with `TAT ≤ now` is full, i.e. indistinguishable from an absent one, so evicting it
//! loses nothing: idle buckets are swept, and memory is bounded by `max_buckets`. When the cap
//! is reached with only active buckets (a flood of distinct IPs), the buckets closest to full
//! are dropped first (smallest TAT), the least lenient choice.
//!
//! Time comes from the monotonic [`Clock`] of `rustegon-sim-api`, so wall-clock jumps neither
//! refill nor drain buckets, and the simulator controls time.

pub mod settings;

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Clock;

pub use self::settings::RateLimitSettings;

/// Error detail carrying the retry delay of `RGN-4003` (`retry_after_ms` on the wire,
/// protocol.md §7).
pub const RETRY_AFTER_MS: &str = "retry_after_ms";

/// Sweep idle buckets every this many checks, so memory follows the active set even below
/// the cap.
const SWEEP_EVERY: u32 = 4096;

/// What is being limited (security.md §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitClass {
    /// Authentication attempts.
    Authentication,
    /// Session creation.
    SessionCreation,
    /// Any request.
    Request,
    /// Expensive administrative operations (backup, restore, key rotation, user management).
    AdminOp,
}

impl LimitClass {
    /// Name used in error details and settings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::SessionCreation => "session_creation",
            Self::Request => "request",
            Self::AdminOp => "admin_op",
        }
    }
}

impl fmt::Display for LimitClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rate: `count` requests per `per`, with up to `burst` at once. `count == 0` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Requests per period; 0 disables the limit.
    pub count: u32,
    /// Period.
    pub per: Duration,
    /// Bucket capacity (≥ 1 when limited).
    pub burst: u32,
}

impl Rate {
    /// No limit.
    pub const UNLIMITED: Self = Self {
        count: 0,
        per: Duration::from_secs(1),
        burst: 0,
    };

    /// `count` per minute with capacity `burst`.
    #[must_use]
    pub const fn per_minute(count: u32, burst: u32) -> Self {
        Self {
            count,
            per: Duration::from_secs(60),
            burst,
        }
    }

    /// `count` per second with capacity `burst`.
    #[must_use]
    pub const fn per_second(count: u32, burst: u32) -> Self {
        Self {
            count,
            per: Duration::from_secs(1),
            burst,
        }
    }

    fn is_limited(self) -> bool {
        self.count > 0 && !self.per.is_zero()
    }

    /// Emission interval `T` and tolerance `τ = T · max(burst, 1)`.
    fn gcra(self) -> (Duration, Duration) {
        let t = self.per / self.count;
        (t, t.saturating_mul(self.burst.max(1)))
    }
}

/// Per-user and per-IP rates of one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassLimits {
    /// Bucket per authenticated (or claimed) user name.
    pub per_user: Rate,
    /// Bucket per source IP.
    pub per_ip: Rate,
}

/// Limits of all classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Master switch.
    pub enabled: bool,
    /// Authentication attempts.
    pub authentication: ClassLimits,
    /// Session creation.
    pub session_creation: ClassLimits,
    /// Requests.
    pub request: ClassLimits,
    /// Expensive admin operations.
    pub admin_op: ClassLimits,
    /// Maximum number of buckets held in memory.
    pub max_buckets: usize,
}

impl RateLimitConfig {
    fn limits(&self, class: LimitClass) -> ClassLimits {
        match class {
            LimitClass::Authentication => self.authentication,
            LimitClass::SessionCreation => self.session_creation,
            LimitClass::Request => self.request,
            LimitClass::AdminOp => self.admin_op,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitSettings::default().to_config()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BucketKey {
    User(LimitClass, String),
    Ip(LimitClass, IpAddr),
}

struct Buckets {
    tat: HashMap<BucketKey, Duration>,
    checks_since_sweep: u32,
}

/// The node-local rate limiter.
pub struct RateLimiter {
    clock: Arc<dyn Clock>,
    config: RateLimitConfig,
    // One mutex over all buckets: a check is a few hash lookups and never awaits or does
    // I/O, and taking both of a request's buckets (user and IP) under the same lock makes the
    // admit-both-or-neither decision atomic.
    buckets: Mutex<Buckets>,
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The `RGN-4003` error for a rejected request.
#[must_use]
pub fn rate_limited(class: LimitClass, retry_after: Duration) -> Error {
    let ms = retry_after.as_nanos().div_ceil(1_000_000).max(1);
    let ms = u64::try_from(ms).unwrap_or(u64::MAX);
    Error::new(
        ErrorCode::RateLimited,
        format!("rate limit exceeded ({class}); retry after {ms} ms"),
    )
    .with_detail(RETRY_AFTER_MS, ms.to_string())
    .with_detail("limit", class.as_str())
}

impl RateLimiter {
    /// A limiter with `config`, reading time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, config: RateLimitConfig) -> Self {
        Self {
            clock,
            config,
            buckets: Mutex::new(Buckets {
                tat: HashMap::new(),
                checks_since_sweep: 0,
            }),
        }
    }

    /// Admits one request of `class` from `user` (if known) at `ip` (if known), consuming a
    /// token from each limited bucket, or consumes nothing and returns `RGN-4003` with the
    /// time after which a retry can succeed.
    ///
    /// # Errors
    /// [`ErrorCode::RateLimited`] with detail [`RETRY_AFTER_MS`].
    pub fn check(
        &self,
        class: LimitClass,
        user: Option<&str>,
        ip: Option<IpAddr>,
    ) -> Result<(), Error> {
        if !self.config.enabled {
            return Ok(());
        }
        let limits = self.config.limits(class);
        let mut wanted: Vec<(BucketKey, Rate)> = Vec::with_capacity(2);
        if let Some(u) = user.filter(|_| limits.per_user.is_limited()) {
            wanted.push((BucketKey::User(class, u.to_owned()), limits.per_user));
        }
        if let Some(ip) = ip.filter(|_| limits.per_ip.is_limited()) {
            wanted.push((BucketKey::Ip(class, ip), limits.per_ip));
        }
        if wanted.is_empty() {
            return Ok(());
        }
        let now = self.clock.monotonic();
        // Bucket state is a single `Duration` assignment, never left half-updated, so the data
        // behind a poisoned lock is still consistent.
        let mut b = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        b.checks_since_sweep += 1;
        if b.checks_since_sweep >= SWEEP_EVERY {
            b.checks_since_sweep = 0;
            b.tat.retain(|_, tat| *tat > now);
        }

        // Decide for every bucket first, commit only if all admit.
        let mut new_tats = Vec::with_capacity(wanted.len());
        let mut retry_after = Duration::ZERO;
        for (key, rate) in &wanted {
            let (t, tau) = rate.gcra();
            let tat = b.tat.get(key).copied().unwrap_or(now).max(now);
            let new_tat = tat.saturating_add(t);
            // `new_tat > now` because `tat ≥ now` and `t > 0`.
            let ahead = new_tat.saturating_sub(now);
            if ahead > tau {
                retry_after = retry_after.max(ahead.saturating_sub(tau));
            }
            new_tats.push(new_tat);
        }
        if !retry_after.is_zero() {
            return Err(rate_limited(class, retry_after));
        }
        for ((key, _), new_tat) in wanted.into_iter().zip(new_tats) {
            if !b.tat.contains_key(&key) {
                make_room(&mut b.tat, now, self.config.max_buckets);
            }
            b.tat.insert(key, new_tat);
        }
        Ok(())
    }

    /// Removes idle (full) buckets. Optional: checks sweep periodically on their own.
    pub fn sweep(&self) {
        let now = self.clock.monotonic();
        let mut b = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        b.tat.retain(|_, tat| *tat > now);
    }

    /// Number of buckets held.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .tat
            .len()
    }
}

/// Ensures room for one more bucket under `cap`: drops idle buckets, then, if still full, the
/// buckets closest to full until 90 % of the cap is used, so the O(n) selection is amortized
/// over the next 10 % of insertions.
fn make_room(tat: &mut HashMap<BucketKey, Duration>, now: Duration, cap: usize) {
    let cap = cap.max(1);
    if tat.len() < cap {
        return;
    }
    tat.retain(|_, t| *t > now);
    if tat.len() < cap {
        return;
    }
    let target = cap - cap / 10 - 1;
    let excess = tat.len() - target;
    let mut tats: Vec<Duration> = tat.values().copied().collect();
    let (_, threshold, _) = tats.select_nth_unstable(excess - 1);
    let threshold = *threshold;
    let mut to_remove = excess;
    // Remove up to `excess` buckets with TAT ≤ threshold (ties make the count inexact).
    tat.retain(|_, t| {
        if to_remove > 0 && *t <= threshold {
            to_remove -= 1;
            false
        } else {
            true
        }
    });
}
