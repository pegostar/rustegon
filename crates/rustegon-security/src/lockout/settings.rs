// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[lockout]` configuration section (FR-SEC-006, security.md §8).

use std::time::Duration;

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

use super::LockoutPolicy;

const DAY: i64 = 86_400;

/// Lockout settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LockoutSettings {
    /// Master switch.
    pub enabled: bool,
    /// Failed logins within `window_secs` that lock the account.
    pub max_failures: u32,
    /// Window of counted failures, seconds.
    pub window_secs: u64,
    /// First lockout duration, seconds.
    pub lock_secs: u64,
    /// Maximum lockout duration after doubling, seconds.
    pub max_lock_secs: u64,
    /// Maximum user names tracked in memory per node.
    pub max_tracked: u32,
}

impl Default for LockoutSettings {
    fn default() -> Self {
        // FR-SEC-006 / security.md §8: 10 failures in 5 min → 15 min, doubling up to 24 h.
        Self {
            enabled: true,
            max_failures: 10,
            window_secs: 300,
            lock_secs: 900,
            max_lock_secs: 86_400,
            max_tracked: 100_000,
        }
    }
}

impl LockoutSettings {
    /// The tracker policy.
    #[must_use]
    pub fn to_policy(&self) -> LockoutPolicy {
        LockoutPolicy {
            enabled: self.enabled,
            max_failures: self.max_failures,
            window: Duration::from_secs(self.window_secs),
            lock: Duration::from_secs(self.lock_secs),
            max_lock: Duration::from_secs(self.max_lock_secs),
            max_tracked: self.max_tracked as usize,
        }
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

impl Settings for LockoutSettings {
    const SECTION: &'static str = "lockout";
    const FIELDS: &'static [FieldSpec] = &[
        spec("enabled", Kind::Bool, "Enable account lockout."),
        spec(
            "max_failures",
            Kind::Integer { min: 1, max: 1000 },
            "Failed logins within the window that lock the account.",
        ),
        spec(
            "window_secs",
            Kind::Integer { min: 1, max: DAY },
            "Window of counted failed logins, in seconds.",
        ),
        spec(
            "lock_secs",
            Kind::Integer { min: 1, max: DAY },
            "Duration of the first lockout, in seconds; doubles for each consecutive lockout.",
        ),
        spec(
            "max_lock_secs",
            Kind::Integer {
                min: 1,
                max: 7 * DAY,
            },
            "Maximum lockout duration after doubling, in seconds.",
        ),
        spec(
            "max_tracked",
            Kind::Integer {
                min: 1_000,
                max: 10_000_000,
            },
            "Maximum user names tracked for lockout in memory per node.",
        ),
    ];

    fn validate(&self) -> Result<(), String> {
        if self.max_lock_secs < self.lock_secs {
            return Err("max_lock_secs must be at least lock_secs".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn lockout_settings_defaults_and_validation() {
        let mut registry = Registry::new();
        registry.register::<LockoutSettings>().unwrap();
        let s: LockoutSettings = registry
            .load(&Sources::default())
            .unwrap()
            .section()
            .unwrap();
        assert_eq!(s, LockoutSettings::default());
        let p = s.to_policy();
        assert_eq!(p.window, Duration::from_mins(5));
        assert_eq!(p.lock, Duration::from_mins(15));
        assert_eq!(p.max_lock, Duration::from_hours(24));
        let bad = Sources {
            flags: vec!["lockout.max_lock_secs=60".into()],
            ..Sources::default()
        };
        assert!(registry.load(&bad).is_err());
    }
}
