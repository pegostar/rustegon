// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup identifiers and UTC timestamps (PD-064).
//!
//! A generated id is `<UTC yyyymmddThhmmssZ>-<8 hex digits>`, e.g. `20261109T101500Z-3fa85f64`:
//! the timestamp makes ids sort chronologically (lexicographic order = creation order to the
//! second), the random suffix keeps two backups started in the same second apart. Readers accept
//! any id of the [`BackupId::parse`] alphabet, so a later generator may change the form.

use std::{fmt, time::SystemTime};

use rustegon_sim_api::Rng;

use crate::error::{BackupError, Result};

/// Longest accepted backup id (bytes); generated ids are 25 bytes.
const MAX_ID_LEN: usize = 64;

/// Identifier of one backup, also its directory name under `backups/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackupId(String);

impl BackupId {
    /// A new id for a backup created at `at` (UTC timestamp + 32 random bits from `rng`).
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] when `at` is before the Unix epoch.
    pub fn generate(at: SystemTime, rng: &dyn Rng) -> Result<Self> {
        let utc = UtcTime::from_system_time(at)?;
        let mut suffix = [0u8; 4];
        rng.fill_bytes(&mut suffix);
        Ok(Self(format!("{}-{}", utc.compact(), hex(&suffix))))
    }

    /// Validates an id given by a user or found at a destination. Ids are used as a path
    /// component on every destination, so only `[A-Za-z0-9._-]` is accepted, without a leading
    /// dot (no `.`/`..`, no hidden names), at most 64 bytes.
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] when `id` is outside that alphabet.
    pub fn parse(id: &str) -> Result<Self> {
        let valid = !id.is_empty()
            && id.len() <= MAX_ID_LEN
            && !id.starts_with('.')
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(id.to_owned()))
        } else {
            Err(BackupError::InvalidArgument(format!(
                "invalid backup id {id:?}"
            )))
        }
    }

    /// The id as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex encoding.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A UTC calendar time with second precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UtcTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u64,
    minute: u64,
    second: u64,
}

/// Seconds per day.
const SECS_PER_DAY: u64 = 86_400;

impl UtcTime {
    pub(crate) fn from_system_time(at: SystemTime) -> Result<Self> {
        let secs = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| BackupError::InvalidArgument("time before the Unix epoch".into()))?
            .as_secs();
        let days = i64::try_from(secs / SECS_PER_DAY)
            .map_err(|_| BackupError::InvalidArgument("time out of range".into()))?;
        let (year, month, day) = civil_from_days(days);
        let rem = secs % SECS_PER_DAY;
        Ok(Self {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem % 3600 / 60,
            second: rem % 60,
        })
    }

    /// `yyyymmddThhmmssZ` (ISO 8601 basic format), used in ids.
    pub(crate) fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// `yyyy-mm-ddThh:mm:ssZ` (RFC 3339), used in the manifest.
    pub(crate) fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01, after H. Hinnant, "chrono-Compatible
/// Low-Level Date Algorithms", `civil_from_days`: shift the epoch to 0000-03-01 so the leap day is
/// the last day of the (March-based) year, then split into 400-year eras of 146 097 days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of March-based year, [0, 365]
    let mp = (5 * doy + 2) / 153; // March-based month, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // Both are small and positive by construction (1..=31, 1..=12).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    struct FixedRng;
    impl Rng for FixedRng {
        fn fill_bytes(&self, buf: &mut [u8]) {
            buf.fill(0xab);
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn utc_time_formats_known_dates() {
        let cases = [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (1_735_689_600, "2025-01-01T00:00:00Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
        ];
        for (secs, want) in cases {
            assert_eq!(UtcTime::from_system_time(at(secs)).unwrap().rfc3339(), want);
        }
    }

    #[test]
    fn backup_id_generate_is_timestamp_plus_suffix_and_parses() {
        let id = BackupId::generate(at(1_735_689_600 + 3_723), &FixedRng).unwrap();
        assert_eq!(id.as_str(), "20250101T010203Z-abababab");
        assert_eq!(BackupId::parse(id.as_str()).unwrap(), id);
        assert!(
            BackupId::generate(SystemTime::UNIX_EPOCH - Duration::from_secs(1), &FixedRng).is_err()
        );
    }

    #[test]
    fn backup_id_parse_rejects_path_tricks() {
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "c:", "a b"] {
            assert!(BackupId::parse(bad).is_err(), "{bad:?}");
        }
        assert!(BackupId::parse(&"x".repeat(65)).is_err());
        assert!(BackupId::parse("20261109T101500Z-3fa85f64").is_ok());
    }
}
