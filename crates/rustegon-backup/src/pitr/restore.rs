// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Point-in-time restore (FR-BKP-002, PD-066, PD-088): choosing the base backup, planning the
//! replay, downloading the segments and replaying them into the restored store. Driven by
//! `crate::offline::restore_data_dir_to_time`, which adds the journal, the swap and the open.
//!
//! Every refusal happens in [`plan`], before anything is written: a target before the base
//! backup, a target past the archive's end (no stop rule reachable), a gap (missing segments,
//! a recorded continuity break, non-contiguous log indexes), a missing or wrong KEK
//! (`RGN-4006`). A corrupt segment is refused while downloading (BLAKE3 against the index,
//! `RGN-5002`), before the store is swapped in; a segment whose records are damaged in a way
//! the hash cannot see (it never is, the archiver validated it) fails the replay.

use std::{path::Path, sync::Arc};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{RANGE_ID, SegmentKey, read_segment},
};
use rustegon_mvcc::{ReplicaCommand, Timestamp};
use rustegon_sim_api::{FileSystem, OpenMode};
use rustegon_storage::encryption::{KekId, KekProvider, WrappedKey};

use super::{
    ArchivedSegment, KeySidecar, MAX_SIDECAR_BYTES, load_index, mvcc_ts, parse_versioned,
    segment_key, sidecar_key,
};
use crate::{
    dest::{Destination, hash_object},
    fsutil::{ensure_dir, io_err, sync_dir},
    manifest::Manifest,
    verify::{ListedBackup, list},
};

/// Which rule ended the replay (module docs of `pitr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRule {
    /// The image already covers T (a segment inside it is closed at or above T).
    Image,
    /// The first entry with `ts > T + txn.max_duration` (PD-066).
    MaxDuration,
    /// The end of the first segment closed at or above T (PD-088).
    ClosedTimestamp,
}

/// What a point-in-time restore replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PitrReport {
    /// The target T.
    pub target: Timestamp,
    /// The timeline replayed.
    pub timeline: String,
    /// Archived segments replayed.
    pub segments: usize,
    /// Log entries proposed (0 when a rerun found them applied).
    pub entries: u64,
    /// The rule that ended the replay.
    pub stop: StopRule,
}

/// The replay of one restore, fixed before anything is written.
#[derive(Debug, Clone)]
pub(crate) struct ReplayPlan {
    pub(crate) target: Timestamp,
    timeline: String,
    /// Entries at or below it are in the image.
    base_index: u64,
    /// `T + txn.max_duration` (PD-066).
    cutoff: Timestamp,
    segments: Vec<ArchivedSegment>,
    /// Wrapped DEKs of the encrypted segments, by id.
    keys: Vec<(u64, WrappedKey)>,
    stop: StopRule,
}

fn refuse(code: ErrorCode, message: String) -> Error {
    Error::new(code, message)
}

/// The newest complete backup at `dest` with a PITR timeline and `T_b <= target` (FR-BKP-002).
///
/// # Errors
/// `RGN-1030` when no such backup exists (the target is before the oldest one, or no backup
/// was taken with archiving on); destination errors.
pub fn select_base(dest: &dyn Destination, target: Timestamp) -> Result<Manifest, Error> {
    let mut oldest: Option<Timestamp> = None;
    let mut best: Option<Manifest> = None;
    for entry in list(dest)? {
        let ListedBackup::Complete(manifest) = entry else {
            continue;
        };
        if manifest.pitr.is_none() {
            continue;
        }
        let tb = mvcc_ts(manifest.consistency.timestamp);
        oldest = Some(oldest.map_or(tb, |o| o.min(tb)));
        if tb <= target
            && best
                .as_ref()
                .is_none_or(|b| mvcc_ts(b.consistency.timestamp) < tb)
        {
            best = Some(manifest);
        }
    }
    best.ok_or_else(|| match oldest {
        Some(o) => refuse(
            ErrorCode::NotFound,
            format!(
                "{target} is before the oldest PITR base backup at {} (T={o}): nothing to roll \
                 forward from",
                dest.describe()
            ),
        ),
        None => refuse(
            ErrorCode::NotFound,
            format!(
                "{} holds no complete backup taken with PITR archiving on",
                dest.describe()
            ),
        ),
    })
}

/// Plans the replay from `manifest`'s image to `target` (module docs; every refusal).
///
/// # Errors
/// `RGN-1001` for a target before the backup or a backup without timeline; `RGN-1030` when the
/// archive has no index for the timeline or does not reach the target; `RGN-5002` for a gap;
/// `RGN-4006` for a missing or wrong KEK; destination errors.
// One linear pass over the index whose refusals read top to bottom, in the documented order.
#[allow(clippy::too_many_lines)]
pub(crate) fn plan(
    archive: &dyn Destination,
    manifest: &Manifest,
    target: Timestamp,
    kek: Option<&Arc<dyn KekProvider>>,
) -> Result<ReplayPlan, Error> {
    let Some(link) = &manifest.pitr else {
        return Err(refuse(
            ErrorCode::InvalidArgument,
            format!(
                "backup {} was taken without PITR archiving: it can only be restored to its own \
                 T",
                manifest.backup_id
            ),
        ));
    };
    let tb = mvcc_ts(manifest.consistency.timestamp);
    if target < tb {
        return Err(refuse(
            ErrorCode::InvalidArgument,
            format!(
                "{target} is before backup {} (T={tb}); choose an older backup",
                manifest.backup_id
            ),
        ));
    }
    let index = load_index(archive, &link.timeline)?.ok_or_else(|| {
        refuse(
            ErrorCode::NotFound,
            format!(
                "{} holds no PITR archive of timeline {} (the timeline of backup {})",
                archive.describe(),
                link.timeline,
                manifest.backup_id
            ),
        )
    })?;
    let margin = index.txn_max_duration_ms.saturating_mul(1_000_000);
    let cutoff = Timestamp::new(target.wall.saturating_add(margin), target.logical);
    // The guard is the contiguity of segment ids and log indexes; recorded breaks
    // (`ContinuityBreak`) only explain a gap.
    let breaks: Vec<String> = index
        .breaks
        .iter()
        .map(|b| {
            format!(
                "segments {}..={} given up ({}, {})",
                b.first_segment, b.last_segment, b.reason, b.detected_at
            )
        })
        .collect();
    let gap = |what: String| {
        refuse(
            ErrorCode::StorageCorruption,
            format!(
                "PITR continuity gap in timeline {} at {}: {what}{}; the target cannot be \
                 reached from backup {} (take or choose a backup after the gap)",
                link.timeline,
                archive.describe(),
                if breaks.is_empty() {
                    String::new()
                } else {
                    format!(" (recorded: {})", breaks.join("; "))
                },
                manifest.backup_id
            ),
        )
    };
    let base_index = manifest.consistency.applied_index;
    let mut segments: Vec<ArchivedSegment> = index.segments.clone();
    segments.sort_by_key(|s| s.id);
    let mut chosen: Vec<ArchivedSegment> = Vec::new();
    let mut expected = base_index + 1;
    // The backup's own fence closed T_b: the image alone is the state at T_b.
    let mut stop = (target == tb).then_some(StopRule::Image);
    for seg in segments {
        if stop.is_some() {
            break;
        }
        let closed = seg.closed_ts.is_some_and(|c| mvcc_ts(c) >= target);
        let beyond_image = seg.last_index.is_some_and(|l| l >= expected);
        if chosen.is_empty() && !beyond_image {
            // Wholly inside the image (or without entries before the first needed one).
            if closed && seg.last_index.is_some_and(|l| l <= base_index) {
                stop = Some(StopRule::Image);
                break;
            }
            continue;
        }
        if let Some(prev) = chosen.last()
            && seg.id != prev.id + 1
        {
            return Err(gap(format!(
                "segments {}..{} are not archived",
                prev.id + 1,
                seg.id - 1
            )));
        }
        if let Some(first) = seg.first_index {
            let ok = if chosen.is_empty() {
                first <= expected
            } else {
                first == expected
            };
            if !ok {
                return Err(gap(format!(
                    "log entry {expected} is missing (segment {} starts at {first})",
                    seg.id
                )));
            }
        }
        if let Some(last) = seg.last_index {
            expected = expected.max(last + 1);
        }
        let past_cutoff = seg.max_ts.is_some_and(|m| mvcc_ts(m) > cutoff);
        chosen.push(seg);
        if past_cutoff {
            stop = Some(StopRule::MaxDuration);
            break;
        }
        if closed {
            stop = Some(StopRule::ClosedTimestamp);
            break;
        }
    }
    let Some(stop) = stop else {
        let latest = index
            .segments
            .iter()
            .filter_map(|s| s.closed_ts.map(mvcc_ts))
            .chain(index.segments.iter().filter_map(|s| {
                s.max_ts
                    .map(|m| Timestamp::new(m.wall.saturating_sub(margin), m.logical))
            }))
            .max();
        return Err(refuse(
            ErrorCode::NotFound,
            format!(
                "{target} is beyond the PITR archive of timeline {} at {}: the latest \
                 restorable time is {} (archived segments are sealed every \
                 backup.pitr.segment_interval_secs)",
                link.timeline,
                archive.describe(),
                latest.map_or_else(|| "none".to_owned(), |t| t.to_string())
            ),
        ));
    };
    let keys = load_keys(archive, &link.timeline, &chosen, kek)?;
    Ok(ReplayPlan {
        target,
        timeline: link.timeline.clone(),
        base_index,
        cutoff,
        segments: chosen,
        keys,
        stop,
    })
}

/// The wrapped DEKs of the encrypted planned segments, each checked against `kek` (`RGN-4006`
/// before anything is written).
fn load_keys(
    archive: &dyn Destination,
    timeline: &str,
    chosen: &[ArchivedSegment],
    kek: Option<&Arc<dyn KekProvider>>,
) -> Result<Vec<(u64, WrappedKey)>, Error> {
    let mut keys = Vec::new();
    for seg in chosen.iter().filter(|s| s.encrypted) {
        let what = sidecar_key(timeline, seg.id);
        let bytes = archive.get_bytes(&what, MAX_SIDECAR_BYTES)?;
        let sidecar: KeySidecar = parse_versioned(&what, &bytes)?;
        if sidecar.segment != seg.id {
            return Err(super::corrupt(&what, "names another segment"));
        }
        let Some(kek) = kek else {
            return Err(refuse(
                ErrorCode::KeyUnavailable,
                format!(
                    "archived log segment {} is encrypted under KEK {}; give the key file or \
                     variable of that KEK",
                    seg.id, sidecar.kek_id
                ),
            ));
        };
        if kek.key_id().as_str() != sidecar.kek_id {
            return Err(refuse(
                ErrorCode::KeyUnavailable,
                format!(
                    "archived log segment {} is encrypted under KEK {}, the given key is {}",
                    seg.id,
                    sidecar.kek_id,
                    kek.key_id()
                ),
            ));
        }
        let wrapped = WrappedKey {
            kek_id: KekId::new(sidecar.kek_id.clone()).map_err(Error::from)?,
            bytes: unhex(&sidecar.wrapped_dek)
                .ok_or_else(|| super::corrupt(&what, "malformed wrapped_dek"))?,
        };
        // A key with the right id but other material fails here, before anything is written.
        kek.unwrap(&wrapped).map_err(Error::from)?;
        keys.push((seg.id, wrapped));
    }
    Ok(keys)
}

fn local_segment(dir: &Path, id: u64) -> std::path::PathBuf {
    dir.join(format!("{id:020}.rlog"))
}

/// Downloads the planned segments into `dir`, each checked against its size and BLAKE3
/// (`RGN-5002`).
///
/// # Errors
/// `RGN-5002` for a corrupt or truncated copy; destination and I/O errors.
pub(crate) fn download(
    archive: &dyn Destination,
    plan: &ReplayPlan,
    fs: &dyn FileSystem,
    dir: &Path,
) -> Result<(), Error> {
    ensure_dir(fs, dir)?;
    for seg in &plan.segments {
        let key = segment_key(&plan.timeline, seg.id);
        let reader = archive.open(&key)?;
        let path = local_segment(dir, seg.id);
        let mut file = fs
            .open(&path, OpenMode::Truncate)
            .map_err(|e| io_err("create", &path, &e))?;
        let hash = hash_object(reader.as_ref(), |chunk| {
            file.append(chunk)
                .map_err(|e| crate::error::BackupError::local("write", &path, e))
        })?;
        if reader.size() != seg.size || hash != seg.blake3 {
            return Err(super::corrupt(
                &format!("{key} at {}", archive.describe()),
                format!(
                    "archived log segment does not match the index ({} bytes, blake3 {hash}; \
                     expected {} bytes, blake3 {})",
                    reader.size(),
                    seg.size,
                    seg.blake3
                ),
            ));
        }
        file.sync_data().map_err(|e| io_err("sync", &path, &e))?;
    }
    sync_dir(fs, dir)
}

/// Replays the downloaded segments into `db` (the store being restored), from the image's
/// applied index to the plan's stop rule. Deterministic, so a rerun stops at the same entry:
/// entries at or below the store's applied index are skipped (`EmbeddedDb::replay_entry`).
///
/// # Errors
/// `RGN-5002` for a damaged segment or a gap; `RGN-4006`; replica errors.
pub(crate) fn replay(
    db: &EmbeddedDb,
    fs: &dyn FileSystem,
    dir: &Path,
    plan: &ReplayPlan,
    kek: Option<&Arc<dyn KekProvider>>,
) -> Result<PitrReport, Error> {
    let mut entries = 0;
    'segments: for seg in &plan.segments {
        let key = match plan.keys.iter().find(|(id, _)| *id == seg.id) {
            Some((_, wrapped)) => Some(SegmentKey {
                kek: kek.cloned().ok_or_else(|| {
                    Error::new(ErrorCode::KeyUnavailable, "the archived log is encrypted")
                })?,
                wrapped: wrapped.clone(),
            }),
            None => None,
        };
        let reader = read_segment(fs, &local_segment(dir, seg.id), key.as_ref())?;
        if reader.segment_id() != seg.id {
            return Err(super::corrupt(
                &format!("archived log segment {}", seg.id),
                format!("its header names segment {}", reader.segment_id()),
            ));
        }
        for entry in reader {
            let entry = entry?;
            if entry.group != RANGE_ID || entry.index <= plan.base_index {
                continue;
            }
            if ReplicaCommand::decode(&entry.payload)?.ts > plan.cutoff {
                break 'segments;
            }
            if db.replay_entry(entry.index, &entry.payload)? {
                entries += 1;
            }
        }
    }
    tracing::info!(
        timeline = %plan.timeline,
        target = %plan.target,
        segments = plan.segments.len(),
        entries,
        "archived log replayed"
    );
    Ok(PitrReport {
        target: plan.target,
        timeline: plan.timeline.clone(),
        segments: plan.segments.len(),
        entries,
        stop: plan.stop,
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
