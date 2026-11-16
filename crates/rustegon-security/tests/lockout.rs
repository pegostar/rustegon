// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Account lockout (FR-SEC-006, AC-SEC-006, TC-SEC-006): 10 failures in 5 min lock for 15 min,
//! doubling up to 24 h; admin unlock; expiry; `RGN-4007`; unknown users treated alike.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{sync::Arc, time::Duration};

use common::ManualClock;
use rustegon_common::ErrorCode;
use rustegon_security::lockout::{FailureOutcome, LockoutPolicy, LockoutTracker};

fn tracker(policy: LockoutPolicy) -> (Arc<ManualClock>, LockoutTracker) {
    let clock = Arc::new(ManualClock::default());
    (clock.clone(), LockoutTracker::new(clock, policy))
}

fn fail_n(t: &LockoutTracker, user: &str, n: u32) -> FailureOutcome {
    let mut last = FailureOutcome::Ignored;
    for _ in 0..n {
        last = t.record_failure(user);
    }
    last
}

#[test]
fn tc_sec_006_ten_failures_in_window_lock_for_15_min_then_expire() {
    let (clock, t) = tracker(LockoutPolicy::default());
    assert_eq!(
        fail_n(&t, "alice", 9),
        FailureOutcome::Counted { remaining: 1 }
    );
    t.check("alice").unwrap();
    assert_eq!(
        t.record_failure("alice"),
        FailureOutcome::Locked {
            duration: Duration::from_mins(15)
        }
    );
    let e = t.check("alice").unwrap_err();
    assert_eq!(e.code(), ErrorCode::AccountLocked);
    assert!(!e.message().contains("alice"));
    // Further failures while locked neither extend nor escalate.
    assert_eq!(t.record_failure("alice"), FailureOutcome::Ignored);
    clock.advance(Duration::from_secs(899));
    assert!(t.is_locked("alice"));
    clock.advance(Duration::from_secs(1));
    t.check("alice").unwrap();
    // Other users unaffected throughout.
    t.check("bob").unwrap();
}

#[test]
fn tc_sec_006_failures_outside_window_do_not_count() {
    let (clock, t) = tracker(LockoutPolicy::default());
    fail_n(&t, "alice", 9);
    clock.advance(Duration::from_mins(5));
    assert_eq!(
        t.record_failure("alice"),
        FailureOutcome::Counted { remaining: 9 }
    );
    // A sliding window: 9 failures spread so that never 10 fall within 5 minutes.
    for _ in 0..30 {
        clock.advance(Duration::from_secs(34));
        assert!(matches!(
            t.record_failure("alice"),
            FailureOutcome::Counted { .. }
        ));
    }
    assert!(!t.is_locked("alice"));
}

#[test]
fn tc_sec_006_lock_duration_doubles_up_to_24h_and_success_resets() {
    let (clock, t) = tracker(LockoutPolicy::default());
    let mut expected = Duration::from_mins(15);
    for _ in 0..10 {
        assert_eq!(
            fail_n(&t, "alice", 10),
            FailureOutcome::Locked { duration: expected }
        );
        clock.advance(expected);
        expected = (expected * 2).min(Duration::from_hours(24));
    }
    assert_eq!(expected, Duration::from_hours(24));
    // A success clears the escalation.
    t.record_success("alice");
    assert_eq!(
        fail_n(&t, "alice", 10),
        FailureOutcome::Locked {
            duration: Duration::from_mins(15)
        }
    );
    // A success never lifts an active lock.
    t.record_success("alice");
    assert!(t.is_locked("alice"));
}

#[test]
fn tc_sec_006_escalation_decays_after_max_lock_without_lockout() {
    let (clock, t) = tracker(LockoutPolicy::default());
    fail_n(&t, "alice", 10);
    clock.advance(Duration::from_mins(15));
    clock.advance(Duration::from_hours(24));
    assert_eq!(
        fail_n(&t, "alice", 10),
        FailureOutcome::Locked {
            duration: Duration::from_mins(15)
        }
    );
}

#[test]
fn tc_sec_006_admin_unlock() {
    let (_clock, t) = tracker(LockoutPolicy::default());
    fail_n(&t, "alice", 10);
    assert!(t.is_locked("alice"));
    assert!(t.unlock("alice"));
    t.check("alice").unwrap();
    assert!(!t.unlock("alice"));
    // Unlock also clears the escalation.
    assert_eq!(
        fail_n(&t, "alice", 10),
        FailureOutcome::Locked {
            duration: Duration::from_mins(15)
        }
    );
}

#[test]
fn tc_sec_006_unknown_users_locked_alike_and_memory_bounded() {
    let (clock, t) = tracker(LockoutPolicy {
        max_tracked: 1000,
        ..LockoutPolicy::default()
    });
    // The tracker does not know which users exist: any claimed name behaves the same.
    fail_n(&t, "no-such-user", 10);
    assert_eq!(
        t.check("no-such-user").unwrap_err().code(),
        ErrorCode::AccountLocked
    );
    for i in 0..5000 {
        t.record_failure(&format!("spray-{i}"));
        assert!(t.tracked() <= 1000);
    }
    // The locked entry is evicted only after every unlocked one.
    assert!(t.is_locked("no-such-user"));
    clock.advance(Duration::from_mins(5));
    t.record_failure("late");
    assert!(t.tracked() <= 1000);
}

#[test]
fn tc_sec_006_disabled_never_locks() {
    let (_clock, t) = tracker(LockoutPolicy {
        enabled: false,
        ..LockoutPolicy::default()
    });
    assert_eq!(fail_n(&t, "alice", 100), FailureOutcome::Ignored);
    t.check("alice").unwrap();
}
