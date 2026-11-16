// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Node readiness for `GET /api/v1/health/ready` (FR-OPS-003, AC-OPS-003; PD-059).
//!
//! Liveness answers as long as the REST listener serves; readiness says whether the node
//! should receive traffic. It is `ready` only while the lifecycle is [`Lifecycle::Serving`]
//! *and* the store accepts writes: a node that is still starting (listeners not yet both
//! bound), draining for a graceful shutdown, or whose store was poisoned by a failed apply
//! answers 503, so a load balancer or orchestrator stops routing to it.
//!
//! The lifecycle starts at [`Lifecycle::Starting`]; the binary marks it serving once both
//! listeners are up and draining as the first step of a shutdown. Embedders that never mark it
//! keep a node that is live but never ready (fail closed).

use std::sync::atomic::{AtomicU8, Ordering};

use crate::services::Services;

/// Lifecycle phase of a node, as set by its binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Opening the store, binding listeners.
    Starting,
    /// Serving requests.
    Serving,
    /// Shutting down: listeners drain, no new traffic should arrive.
    Draining,
}

/// The lifecycle flag shared by the binary and the readiness probe.
#[derive(Debug, Default)]
pub struct Readiness(AtomicU8);

const STARTING: u8 = 0;
const SERVING: u8 = 1;
const DRAINING: u8 = 2;

impl Readiness {
    /// The current phase.
    #[must_use]
    pub fn lifecycle(&self) -> Lifecycle {
        // `Acquire`/`Release`: a probe that sees `Serving` also sees everything the binary did
        // before marking it (listeners bound).
        match self.0.load(Ordering::Acquire) {
            SERVING => Lifecycle::Serving,
            DRAINING => Lifecycle::Draining,
            _ => Lifecycle::Starting,
        }
    }

    /// Marks the node serving. Ignored once draining: a shutdown is never undone.
    pub fn mark_serving(&self) {
        let _ = self
            .0
            .compare_exchange(STARTING, SERVING, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Marks the node draining (first step of a graceful shutdown).
    pub fn mark_draining(&self) {
        self.0.store(DRAINING, Ordering::Release);
    }
}

/// What the readiness probe reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyStatus {
    /// Serving and the store is healthy: HTTP 200.
    Ready,
    /// Still starting: 503.
    Starting,
    /// Shutting down: 503.
    Draining,
    /// Serving, but the store refuses writes until reopened: 503.
    Unhealthy,
}

impl ReadyStatus {
    /// The `status` field of the probe's response.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Starting => "starting",
            Self::Draining => "draining",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// The readiness of the node behind `services` (module docs).
#[must_use]
pub fn status(services: &Services) -> ReadyStatus {
    match services.readiness().lifecycle() {
        Lifecycle::Starting => ReadyStatus::Starting,
        Lifecycle::Draining => ReadyStatus::Draining,
        Lifecycle::Serving => {
            if services.data().is_some_and(|d| !d.engine().is_healthy()) {
                ReadyStatus::Unhealthy
            } else {
                ReadyStatus::Ready
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_ops_003_lifecycle_never_leaves_draining() {
        let r = Readiness::default();
        assert_eq!(r.lifecycle(), Lifecycle::Starting);
        r.mark_serving();
        assert_eq!(r.lifecycle(), Lifecycle::Serving);
        r.mark_draining();
        r.mark_serving();
        assert_eq!(r.lifecycle(), Lifecycle::Draining);
    }
}
