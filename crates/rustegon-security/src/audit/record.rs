// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! **Audit record format 1** (*Provisional (PD-048)*; fixture
//! `crates/rustegon-security/tests/fixtures/formats/audit/1/`).
//!
//! One JSON object per line (`\n`-terminated, UTF-8), fields in this order:
//!
//! ```text
//! {"v":1,"seq":N,"ts":"2026-11-08T10:15:00.123Z","node":"n1","event":"login_failure",
//!  "user":"alice"|null,"roles":[..],"source_ip":"10.0.0.7"|null,"resource":..|null,
//!  "action":..|null,"outcome":"success"|"failure"|"denied","details":{"k":"v",..},
//!  "prev_hash":"<64 hex>"}
//! ```
//!
//! - `seq` starts at 1 and increases by exactly 1 per record across all files of a node.
//! - `prev_hash` is the BLAKE3 hash (derive-key mode, context [`HASH_CONTEXT`]) of the exact
//!   bytes of the previous line without its `\n`; the first record of a node has
//!   [`GENESIS_HASH`]. Hashing the raw bytes (not a re-serialization) means the verifier never
//!   depends on JSON canonicalization, and since every line contains its predecessor's hash,
//!   changing, removing or reordering any line breaks the hash of the line after it.
//! - Unknown fields are corruption: a new field means format 2 (implementation-rules.md §6).

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

/// Audit record format written by this crate.
pub const AUDIT_FORMAT: u32 = 1;

/// BLAKE3 derive-key context: separates audit-chain hashes from every other BLAKE3 use in the
/// system (session token hashes, checksums), so a value from one domain can never be presented
/// as a valid hash in another.
pub const HASH_CONTEXT: &str = "rustegon 2026-11 audit record v1";

/// `prev_hash` of the first record of a node.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One line of the audit file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Format version ([`AUDIT_FORMAT`]).
    pub v: u32,
    /// Per-node sequence number, from 1, without gaps.
    pub seq: u64,
    /// Wall-clock time, RFC 3339 UTC with milliseconds.
    pub ts: String,
    /// Node that wrote the record.
    pub node: String,
    /// Event kind ([`super::AuditEventKind::as_str`]).
    pub event: String,
    /// Acting (or claimed) user.
    pub user: Option<String>,
    /// Effective roles of the user.
    pub roles: Vec<String>,
    /// Client address.
    pub source_ip: Option<String>,
    /// Resource acted on.
    pub resource: Option<String>,
    /// Action.
    pub action: Option<String>,
    /// `success`, `failure` or `denied`.
    pub outcome: String,
    /// Event-specific details, secrets already redacted.
    pub details: BTreeMap<String, String>,
    /// Hash of the previous line (hex), or [`GENESIS_HASH`].
    pub prev_hash: String,
}

/// Chain hash of one line (without its `\n`), as lowercase hex.
#[must_use]
pub fn line_hash(line: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(HASH_CONTEXT);
    hasher.update(line);
    hasher.finalize().to_hex().to_string()
}

/// Formats a wall-clock time as RFC 3339 UTC with milliseconds (`1970-01-01T00:00:00.000Z`).
/// Times before the epoch (a badly set clock) are written as the epoch.
#[must_use]
pub fn format_ts(t: SystemTime) -> String {
    let since = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = since.as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar (Howard
/// Hinnant, "chrono-Compatible Low-Level Date Algorithms", `civil_from_days`, restricted to
/// non-negative day counts so all arithmetic stays unsigned).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_format_known_instants() {
        assert_eq!(
            format_ts(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(951_782_400_000 + 3_723_045);
        assert_eq!(format_ts(t), "2000-02-29T01:02:03.045Z");
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(20_765 * 86_400 + 86_399);
        assert_eq!(format_ts(t), "2026-11-08T23:59:59.000Z");
    }

    #[test]
    fn line_hash_is_domain_separated() {
        let h = line_hash(b"x");
        assert_eq!(h.len(), 64);
        assert_ne!(h, blake3::hash(b"x").to_hex().to_string());
    }
}
