// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Virtual clock of the single-threaded workloads.
//!
//! Every reading advances time by a small `tick`, so time is a deterministic function of the
//! sequence of calls (no OS time is ever read, ADR-029). Within one driver step, readings after
//! the first [`FREE_CALLS`] advance by the much larger `stall_tick` instead.
//!
//! Why: the workload drives every client from one OS thread. A transaction that waits for an
//! intent of another client's transaction can never be unblocked by that holder (it runs on the
//! same thread), so the only way out of such a wait is the liveness rule of
//! transaction-management.md §5.1 — the holder's heartbeat expires and the waiter aborts it.
//! An ordinary client action makes about a dozen readings (well below [`FREE_CALLS`]) and moves
//! time by microseconds; only a wait loop keeps reading, and then each reading moves time by
//! `stall_tick`, so the holder expires after a few iterations. `stall_tick` must stay below
//! `liveness_timeout / readings per wait iteration`: the waiter heartbeats on every iteration,
//! so it never expires itself, while the holder's idleness accumulates.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustegon_sim_api::{BoxFuture, Clock};

/// Readings per step at the base tick (an ordinary client action makes at most about 12).
pub const FREE_CALLS: u64 = 32;

/// Deterministic virtual clock (module docs). Monotonic and wall time are the same counter
/// (nanoseconds since the Unix epoch).
#[derive(Debug)]
pub struct SimClock {
    ns: AtomicU64,
    calls: AtomicU64,
    tick_ns: u64,
    stall_tick_ns: u64,
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl SimClock {
    /// A clock starting at `start` (since the Unix epoch) that advances `tick` per reading, and
    /// `stall_tick` per reading beyond [`FREE_CALLS`] in one step.
    #[must_use]
    pub fn new(start: Duration, tick: Duration, stall_tick: Duration) -> Self {
        Self {
            ns: AtomicU64::new(nanos(start)),
            calls: AtomicU64::new(0),
            tick_ns: nanos(tick).max(1),
            stall_tick_ns: nanos(stall_tick).max(1),
        }
    }

    /// Starts a new driver step: readings advance by the base tick again.
    pub fn begin_step(&self) {
        // SeqCst everywhere: the clock is read from one thread; the strongest ordering costs
        // nothing measurable and needs no argument.
        self.calls.store(0, Ordering::SeqCst);
    }

    /// Jumps forward by `d` (a pause or downtime nemesis).
    pub fn advance(&self, d: Duration) {
        self.ns.fetch_add(nanos(d), Ordering::SeqCst);
    }

    /// The current time without advancing it.
    #[must_use]
    pub fn peek(&self) -> Duration {
        Duration::from_nanos(self.ns.load(Ordering::SeqCst))
    }

    /// Advances by the tick in force and returns the new time.
    fn read(&self) -> Duration {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let step = if n < FREE_CALLS {
            self.tick_ns
        } else {
            self.stall_tick_ns
        };
        let now = self
            .ns
            .fetch_add(step, Ordering::SeqCst)
            .saturating_add(step);
        Duration::from_nanos(now)
    }
}

impl Clock for SimClock {
    fn monotonic(&self) -> Duration {
        self.read()
    }

    fn wall(&self) -> SystemTime {
        UNIX_EPOCH + self.read()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        // Virtual time: sleeping is jumping.
        self.advance(duration);
        Box::pin(std::future::ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_clock_readings_strictly_increase() {
        let c = SimClock::new(
            Duration::from_secs(10),
            Duration::from_micros(10),
            Duration::from_millis(10),
        );
        let mut last = c.peek();
        for _ in 0..200 {
            let now = c.monotonic();
            assert!(now > last);
            last = now;
        }
    }

    #[test]
    fn sim_clock_stalls_within_a_step_only() {
        let c = SimClock::new(
            Duration::ZERO,
            Duration::from_micros(10),
            Duration::from_millis(10),
        );
        for _ in 0..FREE_CALLS {
            c.monotonic();
        }
        assert_eq!(c.peek(), Duration::from_micros(10 * FREE_CALLS));
        let before = c.peek();
        c.monotonic();
        assert_eq!(c.peek().saturating_sub(before), Duration::from_millis(10));
        c.begin_step();
        let before = c.peek();
        c.monotonic();
        assert_eq!(c.peek().saturating_sub(before), Duration::from_micros(10));
    }
}
