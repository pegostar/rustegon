// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! File sink of the audit log: one chain per node, split into segment files
//! `audit-<first seq, 20 digits>.jsonl` in the audit directory.
//!
//! - **Rotation** is lazy: a new segment is created by the write of its first record, when the
//!   active segment would exceed `max_file_size`. A crash between creating and writing leaves
//!   an empty newest segment, which recovery removes.
//! - **Retention** (`max_files`, 0 = keep all) removes the oldest segments only after the new
//!   segment's first record is durable, so the newest sealed segment, which holds the chain
//!   tail, always exists while the active one is empty.
//! - **Recovery** ([`AuditLog::open`]) reads the newest segment, drops a torn tail (bytes after
//!   the last `\n`: an append that was never synced, hence never acknowledged), checks the
//!   remaining lines and continues the chain from the last record. Complete lines that do not
//!   parse are not torn writes but corruption or tampering: open fails rather than destroy
//!   evidence.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rustegon_sim_api::{Clock, File, FileSystem, OpenMode};

use super::{
    AuditError, ChainFault,
    event::AuditEvent,
    io_err,
    record::{AUDIT_FORMAT, AuditRecord, GENESIS_HASH, format_ts, line_hash},
};

const PREFIX: &str = "audit-";
const SUFFIX: &str = ".jsonl";
const TMP_SUFFIX: &str = ".jsonl.tmp";

/// Static configuration of an [`AuditLog`].
#[derive(Debug, Clone)]
pub struct AuditLogConfig {
    /// Directory of the segment files (created if missing).
    pub dir: PathBuf,
    /// Node name written in every record.
    pub node: String,
    /// Size in bytes at which a new segment is started.
    pub max_file_size: u64,
    /// Number of segments kept; 0 keeps all.
    pub max_files: u32,
}

/// File name of the segment whose first record has `first_seq`.
#[must_use]
pub fn segment_name(first_seq: u64) -> String {
    format!("{PREFIX}{first_seq:020}{SUFFIX}")
}

/// First sequence number encoded in a segment file name.
pub(crate) fn parse_segment_name(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let digits = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Segments of `dir` sorted by first sequence number.
pub(crate) fn list_segments(
    fs: &dyn FileSystem,
    dir: &Path,
) -> Result<Vec<(u64, PathBuf)>, AuditError> {
    let mut out: Vec<(u64, PathBuf)> = fs
        .read_dir(dir)
        .map_err(io_err(dir))?
        .into_iter()
        .filter_map(|p| parse_segment_name(&p).map(|s| (s, p)))
        .collect();
    out.sort_unstable_by_key(|(s, _)| *s);
    Ok(out)
}

/// Whole content of a file.
pub(crate) fn read_all(fs: &dyn FileSystem, path: &Path) -> Result<Vec<u8>, AuditError> {
    let file = fs.open(path, OpenMode::Read).map_err(io_err(path))?;
    let size = file.size().map_err(io_err(path))?;
    let len = usize::try_from(size).map_err(|_| AuditError::Io {
        path: path.to_owned(),
        source: std::io::Error::other("file too large"),
    })?;
    let mut buf = vec![0; len];
    file.read_exact_at(&mut buf, 0).map_err(io_err(path))?;
    Ok(buf)
}

/// Splits `bytes` into its complete (`\n`-terminated) prefix and the torn tail length.
pub(crate) fn complete_prefix(bytes: &[u8]) -> (&[u8], usize) {
    let cut = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    (&bytes[..cut], bytes.len() - cut)
}

/// Checks the complete lines of one segment: each is a format-1 record, `seq` increases by one
/// from `first_seq`, and each `prev_hash` is the hash of the line before. The first line's
/// `prev_hash` is checked against `first_prev` when known. Returns `(last seq, last line hash)`
/// or `None` for an empty segment.
pub(crate) fn check_lines(
    path: &Path,
    lines: &[u8],
    first_seq: u64,
    first_prev: Option<&str>,
) -> Result<Option<(u64, String)>, AuditError> {
    let corrupt = |line: usize, fault: ChainFault| AuditError::Corrupt {
        path: path.to_owned(),
        line,
        fault,
    };
    let mut expected_seq = first_seq;
    let mut prev: Option<String> = first_prev.map(str::to_owned);
    let mut last = None;
    // `lines` is a complete prefix: empty or ending in '\n'.
    let body = lines.strip_suffix(b"\n").unwrap_or(lines);
    if body.is_empty() {
        return Ok(None);
    }
    for (i, line) in body.split(|&b| b == b'\n').enumerate() {
        let n = i + 1;
        let rec: AuditRecord = serde_json::from_slice(line)
            .map_err(|e| corrupt(n, ChainFault::Malformed(e.to_string())))?;
        if rec.v != AUDIT_FORMAT {
            return Err(corrupt(
                n,
                ChainFault::Malformed(format!("unsupported format {}", rec.v)),
            ));
        }
        if rec.seq != expected_seq {
            let fault = if i == 0 {
                ChainFault::NameMismatch
            } else {
                ChainFault::SeqMismatch {
                    expected: expected_seq,
                    found: rec.seq,
                }
            };
            return Err(corrupt(n, fault));
        }
        if prev.as_deref().is_some_and(|p| p != rec.prev_hash) {
            return Err(corrupt(n, ChainFault::HashMismatch));
        }
        let h = line_hash(line);
        last = Some((rec.seq, h.clone()));
        prev = Some(h);
        expected_seq = rec.seq.saturating_add(1);
    }
    Ok(last)
}

struct Active {
    file: Box<dyn File>,
    size: u64,
}

struct State {
    active: Option<Active>,
    segments: Vec<(u64, PathBuf)>,
    next_seq: u64,
    prev_hash: String,
    failed: bool,
}

/// The per-node audit file sink.
pub struct AuditLog {
    fs: Arc<dyn FileSystem>,
    clock: Arc<dyn Clock>,
    cfg: AuditLogConfig,
    // One mutex serializes sequence assignment, hashing and the append: file order, `seq`
    // order and chain order are then the same by construction, which is what the verifier
    // checks. It is held across blocking file I/O, which is fine because callers run on the
    // blocking I/O pool and nothing awaits while holding it (module docs).
    state: Mutex<State>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens (or creates) the audit log in `cfg.dir`, recovering the chain tail.
    ///
    /// # Errors
    /// I/O errors; [`AuditError::Corrupt`] if a complete line of the newest segment is not a
    /// valid continuation of the chain or the chain tail is missing.
    pub fn open(
        fs: Arc<dyn FileSystem>,
        clock: Arc<dyn Clock>,
        cfg: AuditLogConfig,
    ) -> Result<Self, AuditError> {
        let dir = cfg.dir.clone();
        fs.create_dir_all(&dir).map_err(io_err(&dir))?;
        // A leftover temp file is a copy of a valid prefix whose rename did not happen; the
        // original segment still exists, so the copy is discarded.
        for p in fs.read_dir(&dir).map_err(io_err(&dir))? {
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(TMP_SUFFIX))
            {
                fs.remove_file(&p).map_err(io_err(&p))?;
            }
        }
        let mut segments = list_segments(fs.as_ref(), &dir)?;
        let mut removed_empty: Option<u64> = None;
        let mut tail: Option<(u64, String)> = None;
        while let Some((first_seq, path)) = segments.last().cloned() {
            let bytes = read_all(fs.as_ref(), &path)?;
            let (prefix, torn) = complete_prefix(&bytes);
            if prefix.is_empty() {
                // Created by a rotation whose first record never became durable.
                fs.remove_file(&path).map_err(io_err(&path))?;
                fs.sync_dir(&dir).map_err(io_err(&dir))?;
                segments.pop();
                removed_empty = Some(first_seq);
                continue;
            }
            if torn > 0 {
                rewrite_prefix(fs.as_ref(), &dir, &path, prefix)?;
            }
            tail = check_lines(&path, prefix, first_seq, None)?;
            break;
        }
        let (next_seq, prev_hash) = if let Some((seq, hash)) = tail {
            (seq.saturating_add(1), hash)
        } else {
            if removed_empty.is_some_and(|s| s != 1) {
                return Err(AuditError::Corrupt {
                    path: dir,
                    line: 0,
                    fault: ChainFault::Malformed(
                        "chain tail lost: no segment precedes the empty newest one".into(),
                    ),
                });
            }
            (1, GENESIS_HASH.to_owned())
        };
        let active = match segments.last() {
            Some((_, path)) => {
                let file = fs.open(path, OpenMode::Append).map_err(io_err(path))?;
                let size = file.size().map_err(io_err(path))?;
                Some(Active { file, size })
            }
            None => None,
        };
        Ok(Self {
            fs,
            clock,
            cfg,
            state: Mutex::new(State {
                active,
                segments,
                next_seq,
                prev_hash,
                failed: false,
            }),
        })
    }

    /// Sequence number the next record will get.
    ///
    /// # Errors
    /// [`AuditError::Failed`] if a writer panicked.
    pub fn next_seq(&self) -> Result<u64, AuditError> {
        Ok(self.state.lock().map_err(|_| AuditError::Failed)?.next_seq)
    }

    /// Hash of the last record (the chain head), for anchoring outside the node.
    ///
    /// # Errors
    /// [`AuditError::Failed`] if a writer panicked.
    pub fn head_hash(&self) -> Result<String, AuditError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AuditError::Failed)?
            .prev_hash
            .clone())
    }

    /// Appends one event and makes it durable before returning its sequence number, so an
    /// operation acknowledged after auditing is never missing from the log.
    ///
    /// # Errors
    /// I/O errors (the log then refuses further records, see [`AuditError::Failed`]).
    pub fn record(&self, event: &AuditEvent) -> Result<u64, AuditError> {
        // A poisoned mutex means a writer panicked mid-append: the file state is unknown.
        let mut st = self.state.lock().map_err(|_| AuditError::Failed)?;
        if st.failed {
            return Err(AuditError::Failed);
        }
        let seq = st.next_seq;
        let rec = AuditRecord {
            v: AUDIT_FORMAT,
            seq,
            ts: format_ts(self.clock.wall()),
            node: self.cfg.node.clone(),
            event: event.kind.as_str().to_owned(),
            user: event.user.clone(),
            roles: event.roles.clone(),
            source_ip: event.source_ip.map(|ip| ip.to_string()),
            resource: event.resource.clone(),
            action: event.action.clone(),
            outcome: event.outcome.as_str().to_owned(),
            details: event.redacted_details(),
            prev_hash: st.prev_hash.clone(),
        };
        let line = serde_json::to_string(&rec).map_err(|e| AuditError::Io {
            path: self.cfg.dir.clone(),
            source: std::io::Error::other(e),
        })?;
        let hash = line_hash(line.as_bytes());
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        let len = bytes.len() as u64;

        let result = self.append(&mut st, seq, &bytes, len);
        if result.is_err() {
            st.failed = true;
        }
        result?;
        st.next_seq = seq.saturating_add(1);
        st.prev_hash = hash;
        self.apply_retention(&mut st);
        Ok(seq)
    }

    fn append(&self, st: &mut State, seq: u64, bytes: &[u8], len: u64) -> Result<(), AuditError> {
        let rotate = match &st.active {
            None => true,
            Some(a) => a.size > 0 && a.size.saturating_add(len) > self.cfg.max_file_size,
        };
        let dir = &self.cfg.dir;
        if rotate {
            let path = dir.join(segment_name(seq));
            let file = self
                .fs
                .open(&path, OpenMode::CreateNew)
                .map_err(io_err(&path))?;
            st.active = Some(Active { file, size: 0 });
            st.segments.push((seq, path));
        }
        let path = st
            .segments
            .last()
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        let active = st.active.as_mut().ok_or(AuditError::Failed)?;
        active.file.append(bytes).map_err(io_err(&path))?;
        active.file.sync_data().map_err(io_err(&path))?;
        active.size = active.size.saturating_add(len);
        if rotate {
            // The new name must be durable before older segments may be removed.
            self.fs.sync_dir(dir).map_err(io_err(dir))?;
        }
        Ok(())
    }

    /// Removes the oldest segments beyond `max_files`. Runs only after the newest record is
    /// durable; a failed removal leaves the segment listed and is retried at the next record
    /// (the record itself is already safe, so it is not reported as failed).
    fn apply_retention(&self, st: &mut State) {
        let keep = self.cfg.max_files as usize;
        if keep == 0 {
            return;
        }
        let mut removed = false;
        while st.segments.len() > keep {
            let path = st.segments[0].1.clone();
            if self.fs.remove_file(&path).is_err() {
                break;
            }
            st.segments.remove(0);
            removed = true;
        }
        if removed {
            // Best effort: a removal that is not durable reappears after a crash and is removed
            // again by the next rotation.
            let _ = self.fs.sync_dir(&self.cfg.dir);
        }
    }
}

/// Replaces `path` by its first `prefix.len()` bytes via a synced temp file and an atomic
/// rename (the file system API has no truncate).
fn rewrite_prefix(
    fs: &dyn FileSystem,
    dir: &Path,
    path: &Path,
    prefix: &[u8],
) -> Result<(), AuditError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = fs.open(&tmp, OpenMode::Truncate).map_err(io_err(&tmp))?;
    f.append(prefix).map_err(io_err(&tmp))?;
    f.sync_data().map_err(io_err(&tmp))?;
    drop(f);
    fs.rename(&tmp, path).map_err(io_err(path))?;
    fs.sync_dir(dir).map_err(io_err(dir))
}
