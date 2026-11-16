// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared test helpers: a manually advanced clock.

#![allow(dead_code, clippy::unwrap_used)]

use std::{
    sync::Mutex,
    time::{Duration, SystemTime},
};

use rustegon_sim_api::{BoxFuture, Clock};

/// Wall time of monotonic zero: 2026-11-08T00:00:00Z.
pub const WALL_BASE_SECS: u64 = 20_765 * 86_400;

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct ManualClock(Mutex<Duration>);

impl ManualClock {
    /// Advances both monotonic and wall time.
    pub fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

impl Clock for ManualClock {
    fn monotonic(&self) -> Duration {
        *self.0.lock().unwrap()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(WALL_BASE_SECS) + self.monotonic()
    }

    fn sleep(&self, _duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}
