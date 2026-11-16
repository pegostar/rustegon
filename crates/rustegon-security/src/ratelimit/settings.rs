// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[rate_limit]` configuration section (security.md §8). A rate of 0 disables that bucket.

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

use super::{ClassLimits, Rate, RateLimitConfig};

/// Rate limiting settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSettings {
    /// Master switch.
    pub enabled: bool,
    /// Authentication attempts per minute per source IP.
    pub auth_per_ip_per_min: u32,
    /// Burst of authentication attempts per source IP.
    pub auth_per_ip_burst: u32,
    /// Authentication attempts per minute per claimed user (0: lockout covers users).
    pub auth_per_user_per_min: u32,
    /// Burst of authentication attempts per claimed user.
    pub auth_per_user_burst: u32,
    /// Sessions created per minute per user.
    pub session_per_user_per_min: u32,
    /// Burst of sessions created per user.
    pub session_per_user_burst: u32,
    /// Requests per second per source IP.
    pub request_per_ip_per_sec: u32,
    /// Burst of requests per source IP.
    pub request_per_ip_burst: u32,
    /// Requests per second per user (0: unlimited).
    pub request_per_user_per_sec: u32,
    /// Burst of requests per user.
    pub request_per_user_burst: u32,
    /// Expensive admin operations per minute per user.
    pub admin_per_user_per_min: u32,
    /// Burst of expensive admin operations per user.
    pub admin_per_user_burst: u32,
    /// Maximum buckets held in memory.
    pub max_buckets: u32,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        // security.md §8: authentication 10/min/IP burst 20; requests unlimited per user and
        // 2000/s per IP. Session creation and admin operations are PD-048 choices.
        Self {
            enabled: true,
            auth_per_ip_per_min: 10,
            auth_per_ip_burst: 20,
            auth_per_user_per_min: 0,
            auth_per_user_burst: 0,
            session_per_user_per_min: 30,
            session_per_user_burst: 30,
            request_per_ip_per_sec: 2000,
            request_per_ip_burst: 2000,
            request_per_user_per_sec: 0,
            request_per_user_burst: 0,
            admin_per_user_per_min: 60,
            admin_per_user_burst: 10,
            max_buckets: 100_000,
        }
    }
}

impl RateLimitSettings {
    /// The limiter configuration.
    #[must_use]
    pub fn to_config(&self) -> RateLimitConfig {
        RateLimitConfig {
            enabled: self.enabled,
            authentication: ClassLimits {
                per_user: Rate::per_minute(self.auth_per_user_per_min, self.auth_per_user_burst),
                per_ip: Rate::per_minute(self.auth_per_ip_per_min, self.auth_per_ip_burst),
            },
            session_creation: ClassLimits {
                per_user: Rate::per_minute(
                    self.session_per_user_per_min,
                    self.session_per_user_burst,
                ),
                per_ip: Rate::UNLIMITED,
            },
            request: ClassLimits {
                per_user: Rate::per_second(
                    self.request_per_user_per_sec,
                    self.request_per_user_burst,
                ),
                per_ip: Rate::per_second(self.request_per_ip_per_sec, self.request_per_ip_burst),
            },
            admin_op: ClassLimits {
                per_user: Rate::per_minute(self.admin_per_user_per_min, self.admin_per_user_burst),
                per_ip: Rate::UNLIMITED,
            },
            max_buckets: self.max_buckets as usize,
        }
    }

    fn pairs(&self) -> [(&'static str, u32, u32); 6] {
        [
            (
                "auth_per_ip",
                self.auth_per_ip_per_min,
                self.auth_per_ip_burst,
            ),
            (
                "auth_per_user",
                self.auth_per_user_per_min,
                self.auth_per_user_burst,
            ),
            (
                "session_per_user",
                self.session_per_user_per_min,
                self.session_per_user_burst,
            ),
            (
                "request_per_ip",
                self.request_per_ip_per_sec,
                self.request_per_ip_burst,
            ),
            (
                "request_per_user",
                self.request_per_user_per_sec,
                self.request_per_user_burst,
            ),
            (
                "admin_per_user",
                self.admin_per_user_per_min,
                self.admin_per_user_burst,
            ),
        ]
    }
}

const fn spec(name: &'static str, kind: Kind, doc: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        kind,
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc,
    }
}

/// Rates: 0 (off) up to 10 million per period.
const RATE: Kind = Kind::Integer {
    min: 0,
    max: 10_000_000,
};

impl Settings for RateLimitSettings {
    const SECTION: &'static str = "rate_limit";
    const FIELDS: &'static [FieldSpec] = &[
        spec("enabled", Kind::Bool, "Enable rate limiting."),
        spec(
            "auth_per_ip_per_min",
            RATE,
            "Authentication attempts per minute per source IP (0 = unlimited).",
        ),
        spec(
            "auth_per_ip_burst",
            RATE,
            "Burst of authentication attempts per source IP.",
        ),
        spec(
            "auth_per_user_per_min",
            RATE,
            "Authentication attempts per minute per claimed user (0 = unlimited).",
        ),
        spec(
            "auth_per_user_burst",
            RATE,
            "Burst of authentication attempts per claimed user.",
        ),
        spec(
            "session_per_user_per_min",
            RATE,
            "Sessions created per minute per user (0 = unlimited).",
        ),
        spec(
            "session_per_user_burst",
            RATE,
            "Burst of sessions created per user.",
        ),
        spec(
            "request_per_ip_per_sec",
            RATE,
            "Requests per second per source IP (0 = unlimited).",
        ),
        spec(
            "request_per_ip_burst",
            RATE,
            "Burst of requests per source IP.",
        ),
        spec(
            "request_per_user_per_sec",
            RATE,
            "Requests per second per user (0 = unlimited).",
        ),
        spec(
            "request_per_user_burst",
            RATE,
            "Burst of requests per user.",
        ),
        spec(
            "admin_per_user_per_min",
            RATE,
            "Expensive admin operations per minute per user (0 = unlimited).",
        ),
        spec(
            "admin_per_user_burst",
            RATE,
            "Burst of expensive admin operations per user.",
        ),
        spec(
            "max_buckets",
            Kind::Integer {
                min: 1_000,
                max: 10_000_000,
            },
            "Maximum rate-limit buckets held in memory per node.",
        ),
    ];

    fn validate(&self) -> Result<(), String> {
        for (name, rate, burst) in self.pairs() {
            if rate > 0 && burst == 0 {
                return Err(format!(
                    "{name}_burst must be at least 1 when {name} is limited"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn rate_limit_settings_defaults_and_validation() {
        let mut registry = Registry::new();
        registry.register::<RateLimitSettings>().unwrap();
        let s: RateLimitSettings = registry
            .load(&Sources::default())
            .unwrap()
            .section()
            .unwrap();
        assert_eq!(s, RateLimitSettings::default());
        let c = s.to_config();
        assert_eq!(c.authentication.per_ip, Rate::per_minute(10, 20));
        assert_eq!(c.request.per_ip, Rate::per_second(2000, 2000));
        assert_eq!(c.request.per_user.count, 0);
        let bad = Sources {
            flags: vec!["rate_limit.admin_per_user_burst=0".into()],
            ..Sources::default()
        };
        assert!(registry.load(&bad).is_err());
    }
}
