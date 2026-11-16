// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[auth]` configuration section (implementation-rules.md §5, security.md §2 ⚙ values).

use std::time::Duration;

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

use crate::authn::scram::{DEFAULT_ITERATIONS, MAX_ITERATIONS, MIN_CONFIG_ITERATIONS};

/// GUI session idle timeout: 30 min (security.md §2.1).
pub const DEFAULT_GUI_IDLE_SECS: u64 = 30 * 60;
/// Driver session idle timeout: 12 h, refreshed by activity (security.md §2.1).
pub const DEFAULT_DRIVER_IDLE_SECS: u64 = 12 * 3600;
/// Absolute session lifetime: 24 h (security.md §2.1).
pub const DEFAULT_ABSOLUTE_SECS: u64 = 24 * 3600;
/// Shortest accepted timeout: 1 min (shorter would expire sessions between two requests).
const MIN_TIMEOUT_SECS: i64 = 60;
/// Longest accepted timeout: 30 days (a stolen token must not live forever).
const MAX_TIMEOUT_SECS: i64 = 30 * 86_400;

/// Authentication settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthnSettings {
    /// PBKDF2 iterations of new SCRAM credentials (existing ones keep theirs until the next
    /// password change).
    pub scram_iterations: u32,
    /// Idle timeout of GUI sessions, seconds.
    pub session_idle_timeout_gui_secs: u64,
    /// Idle timeout of driver/CLI sessions, seconds.
    pub session_idle_timeout_driver_secs: u64,
    /// Absolute session lifetime, seconds.
    pub session_absolute_timeout_secs: u64,
}

impl Default for AuthnSettings {
    fn default() -> Self {
        Self {
            scram_iterations: DEFAULT_ITERATIONS,
            session_idle_timeout_gui_secs: DEFAULT_GUI_IDLE_SECS,
            session_idle_timeout_driver_secs: DEFAULT_DRIVER_IDLE_SECS,
            session_absolute_timeout_secs: DEFAULT_ABSOLUTE_SECS,
        }
    }
}

impl AuthnSettings {
    /// Absolute session lifetime.
    #[must_use]
    pub const fn absolute_timeout(&self) -> Duration {
        Duration::from_secs(self.session_absolute_timeout_secs)
    }
}

const TIMEOUT: Kind = Kind::Integer {
    min: MIN_TIMEOUT_SECS,
    max: MAX_TIMEOUT_SECS,
};

impl Settings for AuthnSettings {
    const SECTION: &'static str = "auth";
    const FIELDS: &'static [FieldSpec] = &[
        FieldSpec {
            name: "scram_iterations",
            kind: Kind::Integer {
                min: MIN_CONFIG_ITERATIONS as i64,
                max: MAX_ITERATIONS as i64,
            },
            // Applies to credentials created after the change.
            mutability: Mutability::Dynamic,
            sensitivity: Sensitivity::Public,
            doc: "PBKDF2-HMAC-SHA256 iterations of new SCRAM-SHA-256 credentials.",
        },
        FieldSpec {
            name: "session_idle_timeout_gui_secs",
            kind: TIMEOUT,
            mutability: Mutability::Dynamic,
            sensitivity: Sensitivity::Public,
            doc: "Seconds of inactivity after which a GUI session expires.",
        },
        FieldSpec {
            name: "session_idle_timeout_driver_secs",
            kind: TIMEOUT,
            mutability: Mutability::Dynamic,
            sensitivity: Sensitivity::Public,
            doc: "Seconds of inactivity after which a driver or CLI session expires.",
        },
        FieldSpec {
            name: "session_absolute_timeout_secs",
            kind: TIMEOUT,
            mutability: Mutability::Dynamic,
            sensitivity: Sensitivity::Public,
            doc: "Seconds after creation at which any session expires regardless of activity.",
        },
    ];

    fn validate(&self) -> Result<(), String> {
        if self.session_idle_timeout_gui_secs > self.session_absolute_timeout_secs
            || self.session_idle_timeout_driver_secs > self.session_absolute_timeout_secs
        {
            return Err("auth: idle timeouts must not exceed the absolute session timeout".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn auth_settings_defaults_and_ranges() {
        let mut registry = Registry::new();
        registry.register::<AuthnSettings>().unwrap();
        let load = |flags: &[&str]| {
            registry.load(&Sources {
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
                ..Sources::default()
            })
        };
        let s: AuthnSettings = load(&[]).unwrap().section().unwrap();
        assert_eq!(s, AuthnSettings::default());
        assert_eq!(s.scram_iterations, 600_000);
        assert!(load(&["auth.scram_iterations=99999"]).is_err());
        assert!(load(&["auth.scram_iterations=100000"]).is_ok());
        assert!(load(&["auth.session_idle_timeout_gui_secs=90000"]).is_err());
        assert_eq!(s.absolute_timeout(), Duration::from_hours(24));
    }
}
