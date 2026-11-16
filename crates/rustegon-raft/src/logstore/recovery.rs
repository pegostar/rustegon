// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Log store recovery (storage-engine.md §9 "Open Raft log store: scan last segment, truncate
//! torn tail at last valid checksum"; replication.md §2).
//!
//! Every segment is replayed in id order through the live state machine. Rules, each protecting
//! acknowledged entries from being dropped silently:
//! - segment ids must be contiguous (deletion is oldest-first with a directory sync in between,
//!   so a gap means a lost segment);
//! - only the **last** segment may end in a torn write, classified by
//!   [`format::classify_invalid`]; any invalid record elsewhere, or a damaged record that cannot
//!   be a torn write, is corruption;
//! - every segment starts with a metadata snapshot record (it is written and synced with the
//!   header before anything else), which also replaces the state of all groups;
//! - at the end every group's entries must cover exactly its `[first_index, last_index]`.
//!
//! A torn last segment is repaired before the store accepts writes: if no record survived it is
//! removed (the batch that created it was never acknowledged), otherwise its valid prefix is
//! copied to `<name>.tmp`, synced and renamed over it. Without the repair the torn bytes would
//! sit in a segment that is no longer the last one after the next open, where they would be
//! (rightly) reported as corruption. Leftover `.tmp` files of an interrupted repair are deleted.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_sim_api::{File, FileSystem, OpenMode};
use rustegon_storage::{
    StorageError,
    encryption::{FileCipher, KeyManager, TAG_LEN},
};

use super::{
    RecoveryInfo, Segment,
    error::{LogStoreError, Result},
    format::{
        self, DecodedOp, HeaderCheck, RECORD_HEADER_LEN, SEGMENT_HEADER_LEN, check_segment_header,
        decode_body, parse_record_header, record_is_valid, segment_header,
    },
    group::{Change, GroupState, LiveCounts, Loc, apply_to},
    note_written, segment_path,
};

/// Chunk size for scanning and copying segment bytes.
const IO_CHUNK: usize = 1 << 20;
/// Suffix of a segment being rewritten by a torn-tail repair.
const TMP_SUFFIX: &str = ".tmp";

/// The recovered state handed to `LogStore::open`.
pub(super) struct Recovered {
    pub(super) segments: BTreeMap<u64, Segment>,
    pub(super) groups: BTreeMap<u64, GroupState>,
    pub(super) counts: LiveCounts,
    pub(super) info: RecoveryInfo,
    /// Id for the new active segment.
    pub(super) next_id: u64,
}

/// Segment id of a file name `<20 digits>.rlog`.
fn parse_segment_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".rlog")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// The cipher of a recovered segment, checking it against the key manager (module docs of
/// `logstore`, "Encryption"):
/// - an encrypted segment needs the store's keys and its DEK (else `RGN-4006`);
/// - in an encrypted log a plaintext segment is legitimate only if it has no DEK and is not
///   newer than the registry's plaintext admission (or the registry has no DEK at all: the
///   switch to encryption is starting now); anything else was not written by this store.
fn segment_cipher(
    keys: Option<&KeyManager>,
    id: u64,
    encrypted: bool,
) -> Result<Option<Arc<FileCipher>>> {
    match (keys, encrypted) {
        (None, false) => Ok(None),
        (None, true) => Err(StorageError::KeyUnavailable(format!(
            "raft log segment {id} is encrypted at rest but no key-encryption key is configured \
             (storage.encryption = none)"
        ))
        .into()),
        (Some(keys), true) => keys.file_cipher(id)?.map(Some).ok_or_else(|| {
            StorageError::KeyUnavailable(format!(
                "raft log segment {id} is encrypted but its DEK is not in the log's key registry"
            ))
            .into()
        }),
        (Some(keys), false) => {
            let registered = keys.file_numbers();
            let admitted = keys.admitted_plaintext_manifest().is_some_and(|a| id <= a);
            if registered.contains(&id) || !(registered.is_empty() || admitted) {
                return Err(LogStoreError::corruption(format!(
                    "plaintext raft log segment {id} in an encrypted log store (not written by \
                     this store before encryption was enabled)"
                )));
            }
            Ok(None)
        }
    }
}

/// Replays the log in `dir` (created if missing), resolving segment ciphers through `keys`
/// when the store is encrypted.
pub(super) fn recover(
    fs: &dyn FileSystem,
    dir: &Path,
    keys: Option<&KeyManager>,
) -> Result<Recovered> {
    fs.create_dir_all(dir)?;
    let mut ids = Vec::new();
    for path in fs.read_dir(dir)? {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(TMP_SUFFIX) && parse_segment_name(&name[..name.len() - 4]).is_some() {
            // An interrupted repair: the original segment is still in place.
            fs.remove_file(&path)?;
        } else if let Some(id) = parse_segment_name(name) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    if let Some(pair) = ids.windows(2).find(|w| w[1] != w[0] + 1) {
        return Err(LogStoreError::corruption(format!(
            "raft log segments {pair:?} are not consecutive: a segment is missing"
        )));
    }
    let mut state = Replay::default();
    let mut segments = BTreeMap::new();
    let mut next_id = ids.last().map_or(1, |&id| id + 1);
    for (i, &id) in ids.iter().enumerate() {
        let last = i + 1 == ids.len();
        let path = segment_path(dir, id);
        let file = fs.open(&path, OpenMode::Read)?;
        let scan = state.scan(id, file.as_ref(), last)?;
        // A segment removed below as a torn creation needs no key (it holds no payload).
        let cipher = if scan.torn && scan.records == 0 {
            None
        } else {
            segment_cipher(keys, id, scan.encrypted)?
        };
        let written = state.written.remove(&id).unwrap_or_default();
        if !scan.torn {
            segments.insert(
                id,
                Segment {
                    file,
                    size: scan.valid_end,
                    cipher,
                    written,
                },
            );
            continue;
        }
        state.info.torn_tail = true;
        drop(file);
        if scan.records == 0 {
            // Header or first record torn: the segment was being created and never received an
            // acknowledged batch. Its id is reused for the new active segment.
            fs.remove_file(&path)?;
            fs.sync_dir(dir)?;
            next_id = id;
        } else {
            rewrite_prefix(fs, dir, &path, scan.valid_end)?;
            let file = fs.open(&path, OpenMode::Read)?;
            segments.insert(
                id,
                Segment {
                    file,
                    size: scan.valid_end,
                    cipher,
                    written,
                },
            );
        }
    }
    for (group, g) in &state.groups {
        g.verify_complete().map_err(|e| {
            LogStoreError::corruption(format!(
                "group {group}: {e}; entries of an acknowledged batch are missing"
            ))
        })?;
    }
    sync_recovered(fs, dir, &segments)?;
    let mut info = state.info;
    info.segments = segments.len();
    info.groups = state.groups.len();
    Ok(Recovered {
        segments,
        groups: state.groups,
        counts: state.counts,
        info,
        next_id,
    })
}

/// Makes every recovered segment durable before the store accepts writes (NFR-REL-003).
///
/// Why: what recovery reads may live only in the OS cache. After a failed `sync_data` (EIO) the
/// store is poisoned, but if the *process* restarts without a power loss the unsynced tail is
/// still readable and is accepted here as valid. `open` then starts a new segment, so that tail
/// is no longer in the last segment; a later power cut would tear it there and the next open
/// would (rightly) report corruption or a gap in acknowledged entries. Syncing at open turns the
/// accepted tail into durable data, as PostgreSQL syncs its data directory when crash recovery
/// starts. All segments are synced, not only the last one, so no reasoning about which segment
/// could hold unsynced bytes is needed (a rollover may have failed after a failed sync); syncing
/// an already durable file is cheap. Found by the M2 T10 fault workload (`--io-restart`).
/// A write handle is opened because Windows `FlushFileBuffers` needs `GENERIC_WRITE`; nothing is
/// appended through it.
fn sync_recovered(
    fs: &dyn FileSystem,
    dir: &Path,
    segments: &BTreeMap<u64, Segment>,
) -> Result<()> {
    for &id in segments.keys() {
        let file = fs.open(&segment_path(dir, id), OpenMode::Append)?;
        file.sync_data()?;
    }
    fs.sync_dir(dir)?;
    Ok(())
}

/// Copies `path[..len]` to `path.tmp`, syncs it, renames it over `path` and syncs the directory.
fn rewrite_prefix(fs: &dyn FileSystem, dir: &Path, path: &Path, len: u64) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(TMP_SUFFIX);
    let tmp = PathBuf::from(tmp);
    let src = fs.open(path, OpenMode::Read)?;
    let mut dst = fs.open(&tmp, OpenMode::CreateNew)?;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut pos = 0u64;
    while pos < len {
        let n = usize::try_from(len - pos).map_or(IO_CHUNK, |r| r.min(IO_CHUNK));
        src.read_exact_at(&mut buf[..n], pos)?;
        dst.append(&buf[..n])?;
        pos += n as u64;
    }
    // Data first, then the rename, then the directory: the repaired segment replaces the torn one
    // atomically, and a crash in between leaves the torn original (repaired again next open).
    dst.sync_data()?;
    drop(dst);
    drop(src);
    fs.rename(&tmp, path)?;
    fs.sync_dir(dir)?;
    Ok(())
}

/// Result of scanning one segment.
struct Scan {
    /// End of the last valid record.
    valid_end: u64,
    /// Valid records.
    records: u64,
    /// Whether a torn tail follows `valid_end`.
    torn: bool,
    /// Whether the segment is encrypted (format v2).
    encrypted: bool,
}

#[derive(Default)]
struct Replay {
    groups: BTreeMap<u64, GroupState>,
    counts: LiveCounts,
    info: RecoveryInfo,
    buf: Vec<u8>,
    /// Per segment, the index range of each group's entry records (`Segment::written`).
    written: BTreeMap<u64, BTreeMap<u64, (u64, u64)>>,
}

impl Replay {
    /// Replays segment `id`.
    fn scan(&mut self, id: u64, file: &dyn File, last: bool) -> Result<Scan> {
        let size = file.size()?;
        let mut head = [0u8; SEGMENT_HEADER_LEN];
        let head_len =
            usize::try_from(size).map_or(SEGMENT_HEADER_LEN, |s| s.min(SEGMENT_HEADER_LEN));
        file.read_exact_at(&mut head[..head_len], 0)?;
        let encrypted = match check_segment_header(&head[..head_len], id) {
            HeaderCheck::Valid { encrypted } => encrypted,
            HeaderCheck::Unsupported(version) => {
                return Err(LogStoreError::UnsupportedVersion {
                    segment: id,
                    version,
                });
            }
            HeaderCheck::Invalid => {
                if last && header_is_torn(file, size, id, &head[..head_len])? {
                    return Ok(Scan {
                        valid_end: 0,
                        records: 0,
                        torn: true,
                        encrypted: false,
                    });
                }
                return Err(LogStoreError::corruption(format!(
                    "raft log segment {id} has an invalid header"
                )));
            }
        };
        let mut pos = SEGMENT_HEADER_LEN as u64;
        let mut records = 0u64;
        while pos < size {
            if self.read_record(file, pos, size)? {
                let rec_len = self.buf.len() as u64;
                self.replay_record(id, pos, records == 0, encrypted)?;
                pos += rec_len;
                records += 1;
                continue;
            }
            if last && tail_is_torn(file, pos, size)? {
                return Ok(Scan {
                    valid_end: pos,
                    records,
                    torn: true,
                    encrypted,
                });
            }
            return Err(LogStoreError::corruption(format!(
                "raft log segment {id}: invalid record at offset {pos}{}",
                if last {
                    " that is not a torn final write"
                } else {
                    " in a segment that is not the last one"
                }
            )));
        }
        if records == 0 {
            if last {
                // Header complete but the snapshot record never landed: still a torn creation.
                return Ok(Scan {
                    valid_end: pos,
                    records,
                    torn: true,
                    encrypted,
                });
            }
            return Err(LogStoreError::corruption(format!(
                "raft log segment {id} holds no record"
            )));
        }
        Ok(Scan {
            valid_end: pos,
            records,
            torn: false,
            encrypted,
        })
    }

    /// Reads the record at `pos` into `self.buf`; `false` if it is not a complete valid record.
    fn read_record(&mut self, file: &dyn File, pos: u64, size: u64) -> Result<bool> {
        let rest = size - pos;
        if rest < RECORD_HEADER_LEN as u64 {
            return Ok(false);
        }
        let mut header = [0u8; RECORD_HEADER_LEN];
        file.read_exact_at(&mut header, pos)?;
        let Some(body_len) = parse_record_header(&header) else {
            return Ok(false);
        };
        let rec_len = RECORD_HEADER_LEN + body_len + 1;
        if rec_len as u64 > rest {
            return Ok(false);
        }
        self.buf.resize(rec_len, 0);
        file.read_exact_at(&mut self.buf, pos)?;
        Ok(record_is_valid(&self.buf))
    }

    /// Applies the valid record in `self.buf`, found at `pos` of segment `id`.
    fn replay_record(&mut self, id: u64, pos: u64, first: bool, encrypted: bool) -> Result<()> {
        let at = |e: String| LogStoreError::corruption(format!("segment {id} offset {pos}: {e}"));
        let body = &self.buf[RECORD_HEADER_LEN..self.buf.len() - 1];
        let ops = decode_body(body).map_err(at)?;
        if first {
            // The segment-head snapshot is the complete state: groups it does not mention were
            // removed before the segment started.
            if !ops
                .iter()
                .all(|op| matches!(op, DecodedOp::SetState { .. }))
            {
                return Err(at("first record is not a metadata snapshot".to_owned()));
            }
            let mentioned: Vec<u64> = ops
                .iter()
                .filter_map(|op| match op {
                    DecodedOp::SetState { group, .. } => Some(*group),
                    _ => None,
                })
                .collect();
            let stale: Vec<u64> = self
                .groups
                .keys()
                .copied()
                .filter(|g| !mentioned.contains(g))
                .collect();
            for g in stale {
                apply_to(&mut self.groups, &mut self.counts, g, None).map_err(at)?;
            }
        }
        let body_start = pos + RECORD_HEADER_LEN as u64;
        for op in ops {
            let (group, change) = match op {
                DecodedOp::Entry {
                    group,
                    index,
                    payload_len,
                    ..
                } if encrypted && (payload_len as usize) < TAG_LEN => {
                    return Err(at(format!(
                        "group {group} entry {index}: encrypted payload of {payload_len} bytes \
                         is shorter than its tag"
                    )));
                }
                DecodedOp::Entry {
                    group,
                    index,
                    term,
                    payload_offset,
                    payload_len,
                } => {
                    note_written(self.written.entry(id).or_default(), group, index);
                    (
                        group,
                        Some(Change::Entry {
                            index,
                            loc: Loc {
                                segment: id,
                                offset: body_start + payload_offset as u64,
                                len: payload_len,
                                term,
                            },
                        }),
                    )
                }
                DecodedOp::HardState { group, hs } => (group, Some(Change::HardState(hs))),
                DecodedOp::Truncate {
                    group,
                    last_index,
                    last_term,
                } => (
                    group,
                    Some(Change::Truncate {
                        last_index,
                        last_term,
                    }),
                ),
                DecodedOp::Purge {
                    group,
                    first_index,
                    boundary_term,
                } => (
                    group,
                    Some(Change::Purge {
                        first_index,
                        boundary_term,
                    }),
                ),
                DecodedOp::SetState { group, meta } => (group, Some(Change::SetState(meta))),
                DecodedOp::RemoveGroup { group } => (group, None),
            };
            apply_to(&mut self.groups, &mut self.counts, group, change).map_err(at)?;
        }
        Ok(())
    }
}

/// Whether every byte of `file` from `from` to `size` is zero.
fn zeros_from(file: &dyn File, from: u64, size: u64) -> Result<bool> {
    let mut buf =
        vec![0u8; IO_CHUNK.min(usize::try_from(size.saturating_sub(from)).unwrap_or(IO_CHUNK))];
    let mut pos = from;
    while pos < size {
        let n = usize::try_from(size - pos).map_or(buf.len(), |r| r.min(buf.len()));
        file.read_exact_at(&mut buf[..n], pos)?;
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        pos += n as u64;
    }
    Ok(true)
}

/// Whether the invalid record at `pos` (through EOF) is a torn final write.
fn tail_is_torn(file: &dyn File, pos: u64, size: u64) -> Result<bool> {
    let rest = size - pos;
    let mut header = [0u8; RECORD_HEADER_LEN];
    let header = if rest >= RECORD_HEADER_LEN as u64 {
        file.read_exact_at(&mut header, pos)?;
        Some(header)
    } else {
        None
    };
    // The closures cannot return errors; remember the first one and report it afterwards, so an
    // I/O failure is never mistaken for corruption or for a torn tail.
    let failure: RefCell<Option<LogStoreError>> = RefCell::new(None);
    let torn = format::classify_invalid(
        rest,
        header.as_ref(),
        |p| {
            let mut b = [0u8; 1];
            match file.read_exact_at(&mut b, pos + p) {
                Ok(()) => Some(b[0]),
                Err(e) => {
                    failure.borrow_mut().get_or_insert(e.into());
                    None
                }
            }
        },
        |p| match zeros_from(file, pos + p, size) {
            Ok(z) => z,
            Err(e) => {
                failure.borrow_mut().get_or_insert(e);
                false
            }
        },
    );
    match failure.into_inner() {
        Some(e) => Err(e),
        None => Ok(torn),
    }
}

/// Whether an invalid segment header is a torn creation: the file holds a prefix of the header
/// segment `id` should have, followed by nothing or zeros only.
fn header_is_torn(file: &dyn File, size: u64, id: u64, head: &[u8]) -> Result<bool> {
    // Either format may have been being written (plaintext or encrypted store); the longer
    // common prefix decides, since the two headers differ only from the version field on.
    let common = [false, true]
        .into_iter()
        .map(|encrypted| {
            let expected = segment_header(id, encrypted);
            head.iter()
                .zip(expected.iter())
                .take_while(|(a, b)| a == b)
                .count()
        })
        .max()
        .unwrap_or(0);
    zeros_from(file, common as u64, size)
}

#[cfg(test)]
mod tests {
    use super::parse_segment_name;

    #[test]
    fn segment_names_parse_strictly() {
        assert_eq!(parse_segment_name("00000000000000000042.rlog"), Some(42));
        assert_eq!(parse_segment_name("42.rlog"), None);
        assert_eq!(parse_segment_name("0000000000000000004x.rlog"), None);
        assert_eq!(parse_segment_name("00000000000000000042.rlog.tmp"), None);
        assert_eq!(parse_segment_name("99999999999999999999.rlog"), None);
    }
}
