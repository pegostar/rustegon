// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! [`Redacted`] wrapper for secrets (coding-standards.md §3.6).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Text printed instead of a secret value.
pub const REDACTED: &str = "‹redacted›";

/// Wraps a secret so it cannot leak through `Debug`/`Display` (and therefore through logs,
/// error messages or panics). The value is reachable only through [`Redacted::expose`].
///
/// Serde is transparent so settings structs can hold secrets; configuration dumps redact secret
/// fields separately (see [`crate::settings::Config::dump_redacted`]).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wraps a secret.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the secret. Call sites are the audit points for secret usage.
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Serialize> Serialize for Redacted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Redacted<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_debug_and_display_hide_value() {
        let secret = Redacted::new(String::from("CANARY-s3cr3t"));
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(secret.to_string(), REDACTED);
        assert_eq!(format!("{:?}", Some(&secret)), format!("Some({REDACTED})"));
        assert_eq!(secret.expose(), "CANARY-s3cr3t");
    }
}
