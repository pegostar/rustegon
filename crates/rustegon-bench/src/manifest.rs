// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Environment manifest stored next to every result (performance-benchmarks.md §2: hardware,
//! OS, commit, build, configuration).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Where and on what a result was measured.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    /// UTC date `YYYY-MM-DD` of the run.
    pub date: String,
    /// Environment label (`REF-1N` only on reference hardware).
    pub env: String,
    /// Commit measured.
    pub commit: String,
    /// Operating system and architecture.
    pub os: &'static str,
    /// CPU architecture.
    pub arch: &'static str,
    /// Logical CPUs available to the process.
    pub cpus: usize,
    /// Whether this was an optimised build (debug builds are not valid results).
    pub release_build: bool,
    /// Free-form notes (file system, disk, power plan).
    pub notes: String,
    /// Host description supplied by the runner (`--host-file`), `null` if absent.
    pub host: serde_json::Value,
}

impl Manifest {
    /// Collects the manifest; `now` is the wall clock (sim-api).
    #[must_use]
    pub fn collect(env: &str, commit: &str, notes: &str, now: SystemTime) -> Self {
        let days = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / 86_400);
        Self {
            date: civil_date(days),
            env: env.to_owned(),
            commit: commit.to_owned(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpus: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
            release_build: !cfg!(debug_assertions),
            notes: notes.to_owned(),
            host: serde_json::Value::Null,
        }
    }
}

/// `YYYY-MM-DD` of `days` since 1970-01-01 (Howard Hinnant, "chrono-compatible low-level date
/// algorithms", `civil_from_days`).
fn civil_date(days: u64) -> String {
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_matches_known_days() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_760), "2026-11-03");
    }
}
