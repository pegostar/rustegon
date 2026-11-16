// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Time source.

use std::time::{Duration, SystemTime};

use crate::BoxFuture;

/// Monotonic and wall-clock time plus timers.
pub trait Clock: Send + Sync + 'static {
    /// Monotonic time elapsed since this clock's origin; never goes backwards.
    fn monotonic(&self) -> Duration;

    /// Wall-clock time. May jump (NTP); use only for timestamps shown to humans or fed to the
    /// hybrid logical clock, never for measuring durations.
    fn wall(&self) -> SystemTime;

    /// Completes after `duration` of monotonic time.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// Production clock backed by the OS. `sleep` requires a Tokio runtime with the time driver.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: std::time::Instant,
}

// The production implementation is the one place allowed to read OS time (ADR-029).
#[allow(clippy::disallowed_methods)]
impl SystemClock {
    /// Creates a clock whose monotonic origin is "now".
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::disallowed_methods)]
impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_monotonic_never_decreases() {
        let clock = SystemClock::new();
        let mut last = clock.monotonic();
        for _ in 0..1000 {
            let now = clock.monotonic();
            assert!(now >= last);
            last = now;
        }
    }

    #[test]
    fn system_clock_wall_is_after_2025() {
        let since_epoch = SystemClock::new()
            .wall()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        assert!(since_epoch.as_secs() > 1_735_689_600); // 2025-01-01T00:00:00Z
    }

    #[tokio::test]
    async fn system_clock_sleep_waits_at_least_duration() {
        let clock = SystemClock::new();
        let start = clock.monotonic();
        clock.sleep(Duration::from_millis(20)).await;
        assert!(clock.monotonic().saturating_sub(start) >= Duration::from_millis(20));
    }
}
