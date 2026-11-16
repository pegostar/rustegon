// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read path: point lookups and user-key iterators over memtables + SSTs at a snapshot
//! (storage-engine.md §1, §3, §8).
//!
//! A [`ReadView`] pins one consistent set of sources: memtables (newest first), and a `Version`
//! (whose `Arc` keeps its SSTs from being deleted, `version/set.rs`). For one user key, sources
//! are strictly ordered by age — memtables are newer than L0, L0 files are ordered newest first
//! and hold disjoint seqno ranges, and every L(n) entry is newer than the L(n+1) entries of the
//! same key — so a lookup can stop at the first source that resolves the key.
//!
//! Resolution of one key at snapshot `s`: take its versions with seqno <= `s`, newest first;
//! merge operands accumulate until a `Put` (merged into it) or a tombstone / the end (merged onto
//! nothing, `merge::full_merge`); a tombstone without operands means "absent". A merged counter
//! outside `i64` is reported as `RGN-1009` here, never during compaction (§8).

use std::sync::Arc;

use bytes::Bytes;

use crate::{
    error::{Result, StorageError},
    iter::{InternalIterator, MergingIterator},
    key::{InternalKey, MAX_SEQNO, ParsedKey, SeqNo, ValueKind, compare_internal, seek_key},
    memtable::Memtable,
    merge::full_merge,
    range_del::{FragmentedTombstones, RangeTombstone},
    sst::SstIterator,
    table_cache::TableCache,
    version::{FileMeta, NUM_LEVELS, Version},
};

/// A consistent set of sources to read from.
#[derive(Clone)]
pub struct ReadView {
    memtables: Vec<Arc<Memtable>>,
    version: Arc<Version>,
    tables: Arc<TableCache>,
}

impl ReadView {
    /// A view over `memtables` (active first, then immutable ones newest first) and `version`.
    #[must_use]
    pub fn new(
        memtables: Vec<Arc<Memtable>>,
        version: Arc<Version>,
        tables: Arc<TableCache>,
    ) -> Self {
        Self {
            memtables,
            version,
            tables,
        }
    }

    /// The value of `user_key` visible at `snapshot`, merge operands resolved.
    ///
    /// # Errors
    /// [`StorageError::CounterOverflow`] (`RGN-1009`) for a merged value outside `i64`;
    /// corruption and I/O errors.
    pub fn get(&self, user_key: &[u8], snapshot: SeqNo) -> Result<Option<Bytes>> {
        let mut resolver = Resolver::default();
        for memtable in &self.memtables {
            resolver.cover(covering(&memtable.range_tombstones(), user_key, snapshot));
            if let Some(Resolved(done)) =
                feed(&mut memtable.cursor(), user_key, snapshot, &mut resolver)?
            {
                return Ok(done);
            }
        }
        let contains =
            |f: &FileMeta| f.smallest.user_key() <= user_key && f.largest.user_key() >= user_key;
        for file in self.version.files(0).iter().filter(|f| contains(f)) {
            if let Some(Resolved(done)) = self.feed_file(file, user_key, snapshot, &mut resolver)? {
                return Ok(done);
            }
        }
        for level in 1..NUM_LEVELS {
            // L1+ files are sorted and user-key-disjoint: at most one can hold the key.
            let files = self.version.files(level);
            let at = files.partition_point(|f| f.largest.user_key() < user_key);
            if let Some(file) = files.get(at).filter(|f| contains(f))
                && let Some(Resolved(done)) =
                    self.feed_file(file, user_key, snapshot, &mut resolver)?
            {
                return Ok(done);
            }
        }
        resolver.finish()
    }

    /// A user-key iterator at `snapshot`; position it with a seek method.
    ///
    /// # Errors
    /// I/O and corruption errors opening the SSTs.
    pub fn iterator(&self, snapshot: SeqNo) -> Result<DbIterator> {
        let mut children: Vec<Box<dyn InternalIterator>> = Vec::new();
        let mut tombstones: Vec<RangeTombstone> = Vec::new();
        for memtable in &self.memtables {
            children.push(Box::new(memtable.cursor()));
            tombstones.extend(memtable.range_tombstones());
        }
        // shortcut: every live SST is opened to collect its tombstones (the table cache keeps
        // them); a per-level tombstone index in the version would avoid opening untouched
        // L1+ files. Revisit with BM-STO scan benchmarks.
        for (_, file) in self.version.all_files() {
            tombstones.extend_from_slice(self.tables.get(file.number)?.range_tombstones());
        }
        for file in self.version.files(0) {
            children.push(Box::new(self.tables.get(file.number)?.new_iterator()));
        }
        for level in 1..NUM_LEVELS {
            let files = self.version.files(level);
            if !files.is_empty() {
                children.push(Box::new(LevelIterator::new(
                    files.to_vec(),
                    Arc::clone(&self.tables),
                )));
            }
        }
        Ok(DbIterator {
            inner: MergingIterator::new(children),
            tombstones: FragmentedTombstones::new(&tombstones, snapshot),
            snapshot,
            forward: true,
            current: None,
            _view: self.clone(),
        })
    }

    fn feed_file(
        &self,
        file: &FileMeta,
        user_key: &[u8],
        snapshot: SeqNo,
        resolver: &mut Resolver,
    ) -> Result<Option<Resolved>> {
        let reader = self.tables.get(file.number)?;
        // Tombstones apply whatever the point filter says.
        resolver.cover(covering(reader.range_tombstones(), user_key, snapshot));
        if !reader.may_contain_key(user_key) {
            return Ok(None);
        }
        feed(&mut reader.new_iterator(), user_key, snapshot, resolver)
    }
}

/// Feeds the versions of `user_key` visible at `snapshot` from `it` into `resolver`; returns the
/// result once resolved (`None`: the key continues in older sources).
fn feed(
    it: &mut dyn InternalIterator,
    user_key: &[u8],
    snapshot: SeqNo,
    resolver: &mut Resolver,
) -> Result<Option<Resolved>> {
    // The first entry at or after this key is the newest version with seqno <= snapshot.
    it.seek(&seek_key(user_key, snapshot))?;
    while it.valid() {
        let parsed = parse(it.key())?;
        if parsed.user_key != user_key {
            break;
        }
        if let Some(done) = resolver.push(parsed.seqno, parsed.kind, it.value())? {
            return Ok(Some(done));
        }
        it.next()?;
    }
    Ok(None)
}

/// Largest seqno <= `snapshot` of a tombstone in `tombstones` covering `user_key`.
fn covering(tombstones: &[RangeTombstone], user_key: &[u8], snapshot: SeqNo) -> Option<SeqNo> {
    tombstones
        .iter()
        .filter(|t| {
            t.seqno <= snapshot && t.start.as_slice() <= user_key && user_key < t.end.as_slice()
        })
        .map(|t| t.seqno)
        .max()
}

fn parse(key: &[u8]) -> Result<ParsedKey<'_>> {
    ParsedKey::parse(key).map_err(|e| StorageError::corruption(format!("internal key: {e}")))
}

/// Final result of resolving one key: its value, or `None` when it is absent/deleted.
struct Resolved(Option<Bytes>);

/// Accumulates one key's versions, newest first (module docs).
#[derive(Default)]
struct Resolver {
    operands: Vec<Bytes>,
    /// Largest seqno of a visible range tombstone covering the key: versions below it are
    /// deleted (`range_del.rs`).
    cutoff: SeqNo,
}

impl Resolver {
    fn with_cutoff(cutoff: Option<SeqNo>) -> Self {
        Self {
            operands: Vec::new(),
            cutoff: cutoff.unwrap_or(0),
        }
    }

    /// Raises the cutoff with tombstones found in an older source.
    fn cover(&mut self, seqno: Option<SeqNo>) {
        self.cutoff = self.cutoff.max(seqno.unwrap_or(0));
    }

    /// Adds the next older version; `Some(result)` once the key is resolved.
    fn push(&mut self, seqno: SeqNo, kind: ValueKind, value: Bytes) -> Result<Option<Resolved>> {
        // A version older than a covering range tombstone reads like a point tombstone.
        let kind = if seqno < self.cutoff {
            ValueKind::Delete
        } else {
            kind
        };
        let operands = self.operands.iter().map(Bytes::as_ref);
        Ok(Some(Resolved(match kind {
            ValueKind::Merge => {
                self.operands.push(value);
                return Ok(None);
            }
            ValueKind::Put if self.operands.is_empty() => Some(value),
            ValueKind::Put => Some(full_merge(Some(&value), operands)?.into()),
            ValueKind::Delete | ValueKind::SingleDelete if self.operands.is_empty() => None,
            ValueKind::Delete | ValueKind::SingleDelete => Some(full_merge(None, operands)?.into()),
            ValueKind::RangeDelete => {
                return Err(StorageError::corruption(
                    "range tombstone among point entries",
                ));
            }
        })))
    }

    /// Result when no older version exists.
    fn finish(self) -> Result<Option<Bytes>> {
        if self.operands.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            full_merge(None, self.operands.iter().map(Bytes::as_ref))?.into(),
        ))
    }
}

/// Concatenates the sorted, disjoint files of one L1+ level, opening them lazily.
struct LevelIterator {
    files: Vec<Arc<FileMeta>>,
    tables: Arc<TableCache>,
    index: usize,
    current: Option<SstIterator>,
}

impl LevelIterator {
    fn new(files: Vec<Arc<FileMeta>>, tables: Arc<TableCache>) -> Self {
        Self {
            files,
            tables,
            index: 0,
            current: None,
        }
    }

    fn open(&mut self, index: usize) -> Result<&mut SstIterator> {
        self.current = None;
        self.index = index;
        let number = self.files[index].number;
        Ok(self.current.insert(self.tables.get(number)?.new_iterator()))
    }

    fn skip_forward(&mut self) -> Result<()> {
        while self.current.as_ref().is_some_and(|c| !c.valid()) {
            if self.index + 1 >= self.files.len() {
                self.current = None;
                return Ok(());
            }
            self.open(self.index + 1)?.seek_to_first()?;
        }
        Ok(())
    }

    fn skip_backward(&mut self) -> Result<()> {
        while self.current.as_ref().is_some_and(|c| !c.valid()) {
            if self.index == 0 {
                self.current = None;
                return Ok(());
            }
            self.open(self.index - 1)?.seek_to_last()?;
        }
        Ok(())
    }
}

impl InternalIterator for LevelIterator {
    fn valid(&self) -> bool {
        self.current.as_ref().is_some_and(SstIterator::valid)
    }

    fn key(&self) -> &[u8] {
        self.current.as_ref().map_or(&[], SstIterator::key)
    }

    fn value(&self) -> Bytes {
        self.current
            .as_ref()
            .map_or_else(Bytes::new, SstIterator::value)
    }

    fn seek_to_first(&mut self) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }
        self.open(0)?.seek_to_first()?;
        self.skip_forward()
    }

    fn seek(&mut self, target: &[u8]) -> Result<()> {
        let at = self
            .files
            .partition_point(|f| compare_internal(f.largest.as_bytes(), target).is_lt());
        if at >= self.files.len() {
            self.current = None;
            return Ok(());
        }
        self.open(at)?.seek(target)?;
        self.skip_forward()
    }

    fn next(&mut self) -> Result<()> {
        if let Some(c) = &mut self.current {
            c.next()?;
        }
        self.skip_forward()
    }

    fn seek_to_last(&mut self) -> Result<()> {
        let Some(last) = self.files.len().checked_sub(1) else {
            return Ok(());
        };
        self.open(last)?.seek_to_last()?;
        self.skip_backward()
    }

    fn prev(&mut self) -> Result<()> {
        if let Some(c) = &mut self.current {
            c.prev()?;
        }
        self.skip_backward()
    }
}

/// Iterator over user keys and their resolved values at a snapshot, in either direction.
///
/// Positioning invariant: after a forward step the inner iterator is on the first entry of the
/// next user key (all versions of the current key consumed); after a backward step it is on the
/// last entry of the previous user key. A direction change therefore re-seeks the inner iterator
/// around the current user key.
pub struct DbIterator {
    inner: MergingIterator,
    /// Range tombstones of every source visible at `snapshot`.
    tombstones: FragmentedTombstones,
    snapshot: SeqNo,
    forward: bool,
    current: Option<(Vec<u8>, Bytes)>,
    /// Pins the memtables and the version (and so the SST files) for the iterator's lifetime.
    _view: ReadView,
}

impl DbIterator {
    /// Whether the iterator is positioned on a key.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.current.is_some()
    }

    /// Current user key (empty unless valid).
    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.current.as_ref().map_or(&[], |(k, _)| k)
    }

    /// Current resolved value (empty unless valid).
    #[must_use]
    pub fn value(&self) -> Bytes {
        self.current
            .as_ref()
            .map_or_else(Bytes::new, |(_, v)| v.clone())
    }

    /// Positions at the first visible key.
    ///
    /// # Errors
    /// Corruption, I/O and `RGN-1009` merge errors; the iterator is then invalid.
    pub fn seek_to_first(&mut self) -> Result<()> {
        let r = self
            .inner
            .seek_to_first()
            .and_then(|()| self.find_forward());
        self.guard(r)
    }

    /// Positions at the first visible key >= `user_key`.
    ///
    /// # Errors
    /// As [`Self::seek_to_first`].
    pub fn seek(&mut self, user_key: &[u8]) -> Result<()> {
        let target = seek_key(user_key, self.snapshot);
        let r = self.inner.seek(&target).and_then(|()| self.find_forward());
        self.guard(r)
    }

    /// Positions at the last visible key.
    ///
    /// # Errors
    /// As [`Self::seek_to_first`].
    pub fn seek_to_last(&mut self) -> Result<()> {
        let r = self
            .inner
            .seek_to_last()
            .and_then(|()| self.find_backward());
        self.guard(r)
    }

    /// Positions at the last visible key <= `user_key`.
    ///
    /// # Errors
    /// As [`Self::seek_to_first`].
    pub fn seek_for_prev(&mut self, user_key: &[u8]) -> Result<()> {
        let target = last_internal_key(user_key);
        let r = self
            .inner
            .seek_for_prev(target.as_bytes())
            .and_then(|()| self.find_backward());
        self.guard(r)
    }

    /// Advances to the next visible key; no-op when invalid.
    ///
    /// # Errors
    /// As [`Self::seek_to_first`].
    // Not `Iterator::next`: advancing is fallible and keys are borrowed (lending cursor).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<()> {
        let Some((user_key, _)) = &self.current else {
            return Ok(());
        };
        let r = if self.forward {
            self.find_forward()
        } else {
            // Inner is on the previous key's entries: skip past every version of `user_key`.
            let user_key = user_key.clone();
            self.inner
                .seek(last_internal_key(&user_key).as_bytes())
                .and_then(|()| {
                    if self.inner.valid() && parse(self.inner.key())?.user_key == user_key {
                        self.inner.next()?;
                    }
                    self.find_forward()
                })
        };
        self.guard(r)
    }

    /// Steps to the previous visible key; no-op when invalid.
    ///
    /// # Errors
    /// As [`Self::seek_to_first`].
    pub fn prev(&mut self) -> Result<()> {
        let Some((user_key, _)) = &self.current else {
            return Ok(());
        };
        let r = if self.forward {
            // Inner is past `user_key`: put it on the last entry before its newest version.
            let first = seek_key(user_key, MAX_SEQNO);
            self.inner
                .seek(&first)
                .and_then(|()| {
                    if self.inner.valid() {
                        self.inner.prev()
                    } else {
                        self.inner.seek_to_last()
                    }
                })
                .and_then(|()| self.find_backward())
        } else {
            self.find_backward()
        };
        self.guard(r)
    }

    fn guard(&mut self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.current = None;
        }
        result
    }

    /// From the first entry of some user key, finds the next key with a visible value.
    fn find_forward(&mut self) -> Result<()> {
        self.forward = true;
        loop {
            if !self.inner.valid() {
                self.current = None;
                return Ok(());
            }
            let user_key = parse(self.inner.key())?.user_key.to_vec();
            let mut resolver = Resolver::with_cutoff(self.tombstones.max_covering(&user_key));
            let mut outcome = None;
            while self.inner.valid() {
                let parsed = parse(self.inner.key())?;
                if parsed.user_key != user_key.as_slice() {
                    break;
                }
                if outcome.is_none() && parsed.seqno <= self.snapshot {
                    outcome = resolver.push(parsed.seqno, parsed.kind, self.inner.value())?;
                }
                self.inner.next()?;
            }
            let value = match outcome {
                Some(Resolved(value)) => value,
                None => resolver.finish()?,
            };
            if let Some(value) = value {
                self.current = Some((user_key, value));
                return Ok(());
            }
        }
    }

    /// From the last entry of some user key, finds the previous key with a visible value.
    fn find_backward(&mut self) -> Result<()> {
        self.forward = false;
        loop {
            if !self.inner.valid() {
                self.current = None;
                return Ok(());
            }
            let user_key = parse(self.inner.key())?.user_key.to_vec();
            // Versions arrive oldest first; collect the visible ones, then resolve newest first.
            let mut versions = Vec::new();
            while self.inner.valid() {
                let parsed = parse(self.inner.key())?;
                if parsed.user_key != user_key.as_slice() {
                    break;
                }
                if parsed.seqno <= self.snapshot {
                    versions.push((parsed.seqno, parsed.kind, self.inner.value()));
                }
                self.inner.prev()?;
            }
            let mut resolver = Resolver::with_cutoff(self.tombstones.max_covering(&user_key));
            let mut outcome = None;
            for (seqno, kind, value) in versions.into_iter().rev() {
                outcome = resolver.push(seqno, kind, value)?;
                if outcome.is_some() {
                    break;
                }
            }
            let value = match outcome {
                Some(Resolved(value)) => value,
                None => resolver.finish()?,
            };
            if let Some(value) = value {
                self.current = Some((user_key, value));
                return Ok(());
            }
        }
    }
}

/// The last internal key of `user_key` in internal order (seqno 0, lowest kind).
fn last_internal_key(user_key: &[u8]) -> InternalKey {
    InternalKey::new(user_key, 0, ValueKind::Delete)
}
