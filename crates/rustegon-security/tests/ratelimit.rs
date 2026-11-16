// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Rate limiting (FR-SEC-005, AC-SEC-005, TC-SEC-005): default limits of security.md §8,
//! `RGN-4003` with `retry_after_ms`, per-user and per-IP buckets, bounded memory.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use common::ManualClock;
use rustegon_common::{Error, ErrorCode};
use rustegon_security::ratelimit::{
    ClassLimits, LimitClass, RETRY_AFTER_MS, Rate, RateLimitConfig, RateLimiter,
};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

fn retry_ms(e: &Error) -> u64 {
    assert_eq!(e.code(), ErrorCode::RateLimited);
    assert!(e.retryable());
    e.details()[RETRY_AFTER_MS].parse().unwrap()
}

fn limiter(config: RateLimitConfig) -> (Arc<ManualClock>, RateLimiter) {
    let clock = Arc::new(ManualClock::default());
    (clock.clone(), RateLimiter::new(clock, config))
}

#[test]
fn tc_sec_005_authentication_default_10_per_min_burst_20_per_ip() {
    let (clock, rl) = limiter(RateLimitConfig::default());
    for _ in 0..20 {
        rl.check(LimitClass::Authentication, Some("alice"), Some(ip(1)))
            .unwrap();
    }
    let e = rl
        .check(LimitClass::Authentication, Some("alice"), Some(ip(1)))
        .unwrap_err();
    // One token every 6 s.
    assert_eq!(retry_ms(&e), 6000);
    assert_eq!(e.details()["limit"], "authentication");
    // Another IP is independent; the user is not limited for authentication by default.
    rl.check(LimitClass::Authentication, Some("alice"), Some(ip(2)))
        .unwrap();
    clock.advance(Duration::from_millis(5999));
    let e = rl
        .check(LimitClass::Authentication, None, Some(ip(1)))
        .unwrap_err();
    assert_eq!(retry_ms(&e), 1);
    clock.advance(Duration::from_millis(1));
    rl.check(LimitClass::Authentication, None, Some(ip(1)))
        .unwrap();
    assert!(
        rl.check(LimitClass::Authentication, None, Some(ip(1)))
            .is_err()
    );
    // A full minute refills 10 tokens.
    clock.advance(Duration::from_mins(1));
    for _ in 0..10 {
        rl.check(LimitClass::Authentication, None, Some(ip(1)))
            .unwrap();
    }
    assert!(
        rl.check(LimitClass::Authentication, None, Some(ip(1)))
            .is_err()
    );
}

#[test]
fn tc_sec_005_requests_default_2000_per_sec_per_ip_unlimited_per_user() {
    let (clock, rl) = limiter(RateLimitConfig::default());
    for _ in 0..2000 {
        rl.check(LimitClass::Request, Some("bob"), Some(ip(1)))
            .unwrap();
    }
    let e = rl
        .check(LimitClass::Request, Some("bob"), Some(ip(1)))
        .unwrap_err();
    assert_eq!(retry_ms(&e), 1); // 0.5 ms rounded up
    // The user from another address is not limited.
    for _ in 0..5000 {
        if rl
            .check(LimitClass::Request, Some("bob"), Some(ip(2)))
            .is_err()
        {
            clock.advance(Duration::from_millis(1));
        }
    }
    rl.check(LimitClass::Request, Some("bob"), None).unwrap();
}

#[test]
fn tc_sec_005_user_and_ip_buckets_admit_both_or_neither() {
    let config = RateLimitConfig {
        admin_op: ClassLimits {
            per_user: Rate::per_minute(60, 2),
            per_ip: Rate::per_minute(60, 3),
        },
        ..RateLimitConfig::default()
    };
    let (_clock, rl) = limiter(config);
    rl.check(LimitClass::AdminOp, Some("u"), Some(ip(1)))
        .unwrap();
    rl.check(LimitClass::AdminOp, Some("u"), Some(ip(1)))
        .unwrap();
    // The user bucket is empty: refused, and the IP bucket must not be charged.
    assert!(
        rl.check(LimitClass::AdminOp, Some("u"), Some(ip(1)))
            .is_err()
    );
    rl.check(LimitClass::AdminOp, Some("v"), Some(ip(1)))
        .unwrap();
    assert!(
        rl.check(LimitClass::AdminOp, Some("w"), Some(ip(1)))
            .is_err()
    );
}

#[test]
fn tc_sec_005_disabled_and_unlimited_classes_never_refuse() {
    let (_clock, rl) = limiter(RateLimitConfig {
        enabled: false,
        ..RateLimitConfig::default()
    });
    for _ in 0..100 {
        rl.check(LimitClass::Authentication, None, Some(ip(1)))
            .unwrap();
    }
    assert_eq!(rl.bucket_count(), 0);
    let (_clock, rl) = limiter(RateLimitConfig {
        request: ClassLimits {
            per_user: Rate::UNLIMITED,
            per_ip: Rate::UNLIMITED,
        },
        ..RateLimitConfig::default()
    });
    for _ in 0..10_000 {
        rl.check(LimitClass::Request, Some("u"), Some(ip(1)))
            .unwrap();
    }
    assert_eq!(rl.bucket_count(), 0);
}

#[test]
fn tc_sec_005_memory_bounded_and_idle_buckets_evicted() {
    let (clock, rl) = limiter(RateLimitConfig {
        max_buckets: 1000,
        ..RateLimitConfig::default()
    });
    // A flood of distinct addresses never grows the table past the cap.
    for i in 0..5000u32 {
        let a = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        rl.check(LimitClass::Authentication, None, Some(a)).unwrap();
        assert!(rl.bucket_count() <= 1000);
    }
    // After a full refill every bucket is idle and swept.
    clock.advance(Duration::from_mins(10));
    rl.sweep();
    assert_eq!(rl.bucket_count(), 0);
    // A bucket under the cap keeps its state (no premature reset).
    for _ in 0..20 {
        rl.check(LimitClass::Authentication, None, Some(ip(9)))
            .unwrap();
    }
    assert!(
        rl.check(LimitClass::Authentication, None, Some(ip(9)))
            .is_err()
    );
}
