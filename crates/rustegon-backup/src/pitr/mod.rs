// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Single-node point-in-time recovery (FR-BKP-002, FR-BKP-004, TC-BKP-004, AC-BKP-002;
//! PD-066 option (a), PD-088; backup-restore.md "Point-in-time recovery (M13a lane BF)").
//!
//! # Model
//! The single-voter Raft log is the store's WAL: every acknowledged commit is an entry of it.
//! Archiving every sealed log segment after the base backup therefore lets a restore roll the
//! backup's image forward: restore the image, propose the archived entries that follow its
//! applied index, then revert the store to the target timestamp T
//! (`EmbeddedDb::open_restored_with_replay`, `EmbeddedDb::revert_to`).
//!
//! Entries carry the evaluation timestamp of their batch, not a commit timestamp, and are not
//! monotone in log order (PD-066). Two rules decide where the replay may stop so that every
//! commit at or below T is replayed; the earlier one applies:
//! - **PD-066**: at the first entry with `ts > T + txn.max_duration` (a transaction that
//!   commits at or below T started at or below T and is aborted after `txn.max_duration`, so
//!   its commit entry was evaluated before `T + txn.max_duration`);
//! - **PD-088**: after the first segment whose *closed timestamp* is at or above T. Before each
//!   timed roll the archiver runs the write fence (`EmbeddedDb::close_timestamp`): when it
//!   returns, every transaction that can commit at or below the closed timestamp has committed
//!   and applied, so its entries are in the segments sealed by that roll. Without this rule the
//!   newest `txn.max_duration` of the archive could never be restored.
//!
//! # Archive layout (format 1)
//! ```text
//! <prefix>/pitr/<timeline>/index.json                    ArchiveIndex (below), rewritten atomically
//! <prefix>/pitr/<timeline>/segments/<id:020>.rlog        byte copy of a sealed log segment
//! <prefix>/pitr/<timeline>/segments/<id:020>.key.json    wrapped DEK of an encrypted (v2) segment
//! ```
//! A *timeline* is the log history of one store: 16 hex digits chosen when the archiver first
//! runs on it and kept in `<store>/pitr-archive.json`. A restored store has a new log (it
//! continues the image, then diverges at the restore), so it gets a new timeline; the backup
//! manifest records the timeline of its store (`Manifest::pitr`).

mod archiver;
mod restore;

use rustegon_common::{Error, ErrorCode};
use rustegon_mvcc::Timestamp;
use serde::{Deserialize, Serialize};

pub use archiver::{ArchiverConfig, PassOutcome, PitrArchiver, PitrMetrics, PreparedArchiver};
pub use restore::{PitrReport, StopRule, select_base};
pub(crate) use restore::{ReplayPlan, download, plan, replay};

use crate::{
    dest::{Destination, join_key},
    error::BackupError,
    manifest::HlcTimestamp,
};

/// Top-level directory of the archive at a destination.
pub const PITR_DIR: &str = "pitr";
/// Format version of `index.json` and the key sidecars.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;
/// The archive index of a timeline.
pub const INDEX_FILE: &str = "index.json";
/// Archiver state in the store directory (timeline, highest archived segment).
pub const STATE_FILE: &str = "pitr-archive.json";
/// Where a point-in-time restore keeps the downloaded segments (in the data directory).
pub const REPLAY_DIR: &str = "pitr-replay";
const SEGMENTS_DIR: &str = "segments";
/// Largest `index.json` accepted (about a million segments).
const MAX_INDEX_BYTES: u64 = 256 << 20;
/// Largest key sidecar accepted.
const MAX_SIDECAR_BYTES: u64 = 64 << 10;

/// One archived segment in `index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedSegment {
    /// Segment id (contiguous in a timeline's log).
    pub id: u64,
    /// Size of the copy in bytes.
    pub size: u64,
    /// BLAKE3 of the copy (64 hex digits).
    pub blake3: String,
    /// Format v2 segment: its wrapped DEK is in the `.key.json` sidecar.
    pub encrypted: bool,
    /// Lowest and highest log index of the store's range in the segment (`None`: no entry).
    pub first_index: Option<u64>,
    /// See `first_index`.
    pub last_index: Option<u64>,
    /// Lowest and highest evaluation timestamp of those entries.
    pub min_ts: Option<HlcTimestamp>,
    /// See `min_ts`.
    pub max_ts: Option<HlcTimestamp>,
    /// Closed timestamp of the roll that sealed it (module docs, PD-088), if one was taken.
    #[serde(default)]
    pub closed_ts: Option<HlcTimestamp>,
    /// When it was archived (RFC 3339 UTC).
    pub archived_at: String,
}

/// Segments that never reached the archive (`max_unarchived_bytes` exceeded, archiving
/// disabled for a while): a restore never replays across them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityBreak {
    /// First missing segment id.
    pub first_segment: u64,
    /// Last missing segment id.
    pub last_segment: u64,
    /// When the archiver gave them up (RFC 3339 UTC).
    pub detected_at: String,
    /// Why (`max_unarchived_bytes`, `segments_missing`).
    pub reason: String,
}

/// `index.json` of a timeline (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveIndex {
    /// [`ARCHIVE_FORMAT_VERSION`]; a newer one is `RGN-5007`, unknown fields are ignored.
    pub format_version: u32,
    /// The timeline (equal to the directory name).
    pub timeline: String,
    /// `txn.max_duration` of the source in milliseconds (the PD-066 replay margin).
    pub txn_max_duration_ms: u64,
    /// Archived segments by id.
    pub segments: Vec<ArchivedSegment>,
    /// Recorded continuity breaks.
    #[serde(default)]
    pub breaks: Vec<ContinuityBreak>,
}

/// The wrapped DEK sidecar of an encrypted segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeySidecar {
    format_version: u32,
    segment: u64,
    /// The KEK the DEK is wrapped under (the store's KEK).
    kek_id: String,
    /// The wrapped DEK (hex), as in the log's key registry.
    wrapped_dek: String,
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: u64,
}

fn corrupt(what: &str, reason: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::StorageCorruption, format!("{what}: {reason}"))
}

/// Parses a versioned archive JSON object (index or sidecar).
fn parse_versioned<T: for<'de> Deserialize<'de>>(what: &str, bytes: &[u8]) -> Result<T, Error> {
    let probe: VersionProbe = serde_json::from_slice(bytes).map_err(|e| corrupt(what, e))?;
    if probe.format_version > u64::from(ARCHIVE_FORMAT_VERSION) {
        return Err(BackupError::UnsupportedFormat {
            found: probe.format_version,
            supported: ARCHIVE_FORMAT_VERSION,
        }
        .into());
    }
    if probe.format_version == 0 {
        return Err(corrupt(what, "format_version 0 does not exist"));
    }
    serde_json::from_slice(bytes).map_err(|e| corrupt(what, e))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn to_json(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut out = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("archive JSON: {e}")))?;
    out.push(b'\n');
    Ok(out)
}

/// Whether `timeline` is a timeline id (16 lowercase hex digits).
#[must_use]
pub fn valid_timeline(timeline: &str) -> bool {
    timeline.len() == 16
        && timeline
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn timeline_prefix(timeline: &str) -> String {
    join_key(&[PITR_DIR, timeline])
}

fn index_key(timeline: &str) -> String {
    join_key(&[&timeline_prefix(timeline), INDEX_FILE])
}

fn segment_key(timeline: &str, id: u64) -> String {
    join_key(&[
        &timeline_prefix(timeline),
        SEGMENTS_DIR,
        &format!("{id:020}.rlog"),
    ])
}

fn sidecar_key(timeline: &str, id: u64) -> String {
    join_key(&[
        &timeline_prefix(timeline),
        SEGMENTS_DIR,
        &format!("{id:020}.key.json"),
    ])
}

/// Reads `index.json` of `timeline`; `None` when the timeline has no archive at `dest`.
///
/// # Errors
/// `RGN-3002` when the destination fails; `RGN-5002` for a malformed index or one naming
/// another timeline; `RGN-5007` for a newer format.
pub fn load_index(dest: &dyn Destination, timeline: &str) -> Result<Option<ArchiveIndex>, Error> {
    let bytes = match dest.get_bytes(&index_key(timeline), MAX_INDEX_BYTES) {
        Ok(b) => b,
        Err(BackupError::ObjectNotFound { .. }) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let what = format!("{} at {}", index_key(timeline), dest.describe());
    let index: ArchiveIndex = parse_versioned(&what, &bytes)?;
    if index.timeline != timeline {
        return Err(corrupt(&what, "names another timeline"));
    }
    Ok(Some(index))
}

const fn hlc(ts: Timestamp) -> HlcTimestamp {
    HlcTimestamp {
        wall: ts.wall,
        logical: ts.logical,
    }
}

const fn mvcc_ts(ts: HlcTimestamp) -> Timestamp {
    Timestamp::new(ts.wall, ts.logical)
}

/// Parses a restore target: RFC 3339 (`2026-11-10T09:30:00Z`, `2026-11-10T10:30:00.25+01:00`)
/// or an HLC timestamp `<wall ns>[.<logical>]` as printed by the CLI (`T=…`).
///
/// # Errors
/// `RGN-1001` for anything else.
pub fn parse_target_time(text: &str) -> Result<Timestamp, Error> {
    let bad = || {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{text:?} is not a point in time: use RFC 3339 (2026-11-10T09:30:00Z) or an \
                 HLC timestamp <wall ns>[.<logical>]"
            ),
        )
    };
    let text = text.trim();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let (wall, logical) = text.split_once('.').unwrap_or((text, "0"));
        let wall = wall.parse::<u64>().map_err(|_| bad())?;
        let logical = logical.parse::<u32>().map_err(|_| bad())?;
        return Ok(Timestamp::new(wall, logical));
    }
    parse_rfc3339_ns(text)
        .and_then(|ns| u64::try_from(ns).ok())
        .map(|wall| Timestamp::new(wall, 0))
        .ok_or_else(bad)
}

/// Nanoseconds since the Unix epoch of an RFC 3339 date-time, `None` if malformed.
fn parse_rfc3339_ns(text: &str) -> Option<i128> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let s = text.get(from..to)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 59 {
        return None;
    }
    let mut rest = &text[19..];
    let mut frac_ns: i128 = 0;
    if let Some(f) = rest.strip_prefix('.') {
        let digits = f.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        let value: i128 = f[..digits].parse().ok()?;
        frac_ns = value * 10_i128.pow(u32::try_from(9 - digits).ok()?);
        rest = &f[digits..];
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" => 0,
        _ => {
            let rb = rest.as_bytes();
            if rb.len() != 6 || !matches!(rb[0], b'+' | b'-') || rb[3] != b':' {
                return None;
            }
            let h: i64 = rest.get(1..3)?.parse().ok()?;
            let m: i64 = rest.get(4..6)?.parse().ok()?;
            if h > 23 || m > 59 {
                return None;
            }
            let sign = if rb[0] == b'-' { -1 } else { 1 };
            sign * (h * 3600 + m * 60)
        }
    };
    // Days from the civil date (H. Hinnant's algorithm), proleptic Gregorian calendar.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = ((days * 24 + hour) * 60 + minute) * 60 + second - offset_secs;
    Some(i128::from(secs) * 1_000_000_000 + frac_ns)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_bkp_002_target_times_parse_as_rfc3339_or_hlc() {
        let at = |t: &str| parse_target_time(t).unwrap();
        assert_eq!(at("1970-01-01T00:00:00Z"), Timestamp::new(0, 0));
        assert_eq!(
            at("2026-11-09T10:15:00Z"),
            Timestamp::new(1_794_219_300_000_000_000, 0)
        );
        assert_eq!(
            at("2026-11-09T11:15:00.5+01:00"),
            Timestamp::new(1_794_219_300_500_000_000, 0)
        );
        assert_eq!(
            at("1794219300000000000.7"),
            Timestamp::new(1_794_219_300_000_000_000, 7)
        );
        assert_eq!(at("42"), Timestamp::new(42, 0));
        for bad in [
            "",
            "yesterday",
            "2026-13-09T10:15:00Z",
            "2026-11-09T10:15:00",
            "2026-11-09T10:15:00.Z",
            "1969-12-31T23:59:59Z",
            "1.2.3",
        ] {
            assert!(parse_target_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fr_bkp_002_archive_keys_and_versions() {
        assert!(valid_timeline("0123456789abcdef"));
        assert!(!valid_timeline("0123456789ABCDEF"));
        assert!(!valid_timeline("abc"));
        assert_eq!(
            segment_key("0123456789abcdef", 7),
            "pitr/0123456789abcdef/segments/00000000000000000007.rlog"
        );
        crate::dest::validate_key(&sidecar_key("0123456789abcdef", 7)).unwrap();
        crate::dest::validate_key(&index_key("0123456789abcdef")).unwrap();
        let newer = br#"{"format_version": 2}"#;
        let err = parse_versioned::<ArchiveIndex>("x", newer).unwrap_err();
        assert_eq!(err.code(), ErrorCode::VersionIncompatible);
        let err = parse_versioned::<ArchiveIndex>("x", b"{").unwrap_err();
        assert_eq!(err.code(), ErrorCode::StorageCorruption);
    }
}
