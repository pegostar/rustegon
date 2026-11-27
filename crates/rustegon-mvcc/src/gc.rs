// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC garbage collection (transaction-management.md §3 "GC", storage-engine.md §3
//! "compaction filters", §11): the GC threshold, the compaction filter that physically drops
//! shadowed versions, and the explicit GC batch.
//!
//! **Visibility invariant.** For every read timestamp `ts >= threshold`, GC never changes what
//! a read returns. A version `v` of key *K* with `v.ts <= threshold` is garbage iff a *newer*
//! version `v'` of *K* with `v'.ts <= threshold` that is a base (full value or tombstone) stays
//! in the store: every reader at `ts >= threshold` then stops at `v'` (or a newer one) before
//! reaching `v`. Merge operands are not bases: the versions below them are still needed.
//!
//! - **Compaction filter** ([`MvccGcFilter`]): within one sub-job the storage engine calls the
//!   filter in key order, and a key's versions come newest first, so the filter remembers per
//!   logical key whether it already *kept* a base `<= threshold`; every older version it is
//!   consulted on is then removed. Only versions the filter itself kept count, so versions of
//!   *K* in other levels, other sub-jobs or protected by snapshots (never shown to the filter)
//!   only make it keep more. The newest base `<= threshold` is always kept by the filter, even a
//!   tombstone: whether anything older survives elsewhere (another level, a snapshot-protected
//!   entry, the other side of a subcompaction boundary) is unknowable to it.
//! - **GC batch** ([`gc_batch`]): the leaseholder's GC request (storage-engine.md §11) — point
//!   deletes, applied atomically through a write batch (a Raft command in the cluster), of every
//!   version below the newest base `<= threshold`, and of that base too when it is a tombstone
//!   (then nothing older remains). The filter and the bottommost compaction then drop the
//!   deleted entries physically.
//!
//! **Threshold ordering.** The threshold only moves forward ([`GcThreshold::advance`]) and is
//! advanced *before* any GC batch or compaction uses the new value. A read checks the threshold
//! *after* pinning its engine view (`MvccReader`): everything removed from that view was removed
//! under a threshold `<=` the one checked, so a read that passes the check is unaffected.
//!
//! Assumptions: no version at `ts <= threshold` is written after the threshold passed `ts`
//! (writers check it, `MvccWriter`); range deletes over MVCC keys cover whole logical keys
//! (range removal, index drop). Keys of the range-local keyspace (`0x01 …`) and meta slots
//! (intents, transaction records) are never touched. The threshold itself is part of the
//! range's replicated state (M3); here it is an in-memory cell.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use rustegon_storage::{
    EngineOptions, LsmEngine, WriteBatch,
    compaction::{CompactionFilter, FilterDecision},
};

use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
    key::{LOCAL_PREFIX, MvccKey, MvccPrefixExtractor},
    value::VersionValue,
};

/// The GC threshold of a store (or range): reads below it fail with `RGN-2007`.
///
/// **Pins** (protected timestamps, backup-restore.md §2; PD-067): [`GcThreshold::pin`] protects
/// every version visible at a timestamp for as long as the returned [`GcPin`] lives. The
/// threshold never advances past the oldest pinned timestamp, so a long reader at a fixed
/// timestamp (the logical dump's scan at T, which outlives `txn.max_duration`) keeps passing
/// its threshold check and sees every version it needs. Pinning and advancing are decided
/// under the same mutex, so a pin either wins (the threshold stops below it) or fails because
/// the threshold had already passed it — never both.
#[derive(Debug, Default)]
pub struct GcThreshold {
    state: Mutex<ThresholdState>,
}

/// The threshold and the live pins (timestamp → number of pins at it).
#[derive(Debug, Default)]
struct ThresholdState {
    ts: Timestamp,
    pins: std::collections::BTreeMap<Timestamp, usize>,
}

impl GcThreshold {
    /// A threshold starting at `ts`.
    #[must_use]
    pub fn new(ts: Timestamp) -> Self {
        Self {
            state: Mutex::new(ThresholdState {
                ts,
                pins: std::collections::BTreeMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ThresholdState> {
        // Every update completes before the guard is released: poison carries no information.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current threshold.
    #[must_use]
    pub fn get(&self) -> Timestamp {
        self.lock().ts
    }

    /// Moves the threshold forward to `ts` (never backward), but never past the oldest pinned
    /// timestamp; returns the resulting threshold, which the caller must use for its GC work.
    pub fn advance(&self, ts: Timestamp) -> Timestamp {
        let mut st = self.lock();
        let target = match st.pins.keys().next() {
            Some(&oldest) => ts.min(oldest),
            None => ts,
        };
        if target > st.ts {
            st.ts = target;
        }
        st.ts
    }

    /// Pins `ts` (struct docs): until the returned guard is dropped the threshold stays
    /// `<= ts`, so reads at `ts` keep working and GC keeps every version they can see.
    ///
    /// # Errors
    /// [`MvccError::BelowGcThreshold`] (`RGN-2007`) when the threshold is already above `ts`:
    /// versions a read at `ts` needs may be gone.
    pub fn pin(self: &Arc<Self>, ts: Timestamp) -> Result<GcPin> {
        let mut st = self.lock();
        if ts < st.ts {
            return Err(MvccError::BelowGcThreshold {
                ts,
                threshold: st.ts,
            });
        }
        *st.pins.entry(ts).or_default() += 1;
        Ok(GcPin {
            threshold: Arc::clone(self),
            ts,
        })
    }

    /// The oldest pinned timestamp, if any pin is held.
    #[must_use]
    pub fn oldest_pin(&self) -> Option<Timestamp> {
        self.lock().pins.keys().next().copied()
    }

    fn unpin(&self, ts: Timestamp) {
        let mut st = self.lock();
        if let Some(n) = st.pins.get_mut(&ts) {
            *n -= 1;
            if *n == 0 {
                st.pins.remove(&ts);
            }
        }
    }

    /// Checks that an operation at `ts` may run: `ts >= threshold`.
    ///
    /// # Errors
    /// [`MvccError::BelowGcThreshold`] (`RGN-2007`) otherwise.
    pub fn check(&self, ts: Timestamp) -> Result<()> {
        let threshold = self.get();
        if ts < threshold {
            return Err(MvccError::BelowGcThreshold { ts, threshold });
        }
        Ok(())
    }
}

/// A pin of the GC threshold at one timestamp ([`GcThreshold::pin`]); released on drop.
#[derive(Debug)]
pub struct GcPin {
    threshold: Arc<GcThreshold>,
    ts: Timestamp,
}

impl GcPin {
    /// The pinned timestamp.
    #[must_use]
    pub fn ts(&self) -> Timestamp {
        self.ts
    }
}

impl Drop for GcPin {
    fn drop(&mut self) {
        self.threshold.unpin(self.ts);
    }
}

/// Per-sub-job state of the filter: the logical key being filtered and whether a base
/// `<= cutoff` of it was already kept.
#[derive(Debug, Default)]
struct FilterState {
    key: Vec<u8>,
    shadowed: bool,
}

/// The MVCC GC compaction filter (module docs). Install it with [`mvcc_engine_options`].
pub struct MvccGcFilter {
    threshold: Arc<GcThreshold>,
    /// Threshold captured when a sub-job's instance was created (`None`: read on every call).
    cutoff: Option<Timestamp>,
    /// Only one sub-job uses an instance; the mutex just satisfies `Sync` (never contended).
    state: Mutex<FilterState>,
}

impl fmt::Debug for MvccGcFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MvccGcFilter")
            .field("threshold", &self.threshold.get())
            .field("cutoff", &self.cutoff)
            .finish_non_exhaustive()
    }
}

impl MvccGcFilter {
    /// A filter dropping versions shadowed below `threshold`.
    #[must_use]
    pub fn new(threshold: Arc<GcThreshold>) -> Self {
        Self {
            threshold,
            cutoff: None,
            state: Mutex::new(FilterState::default()),
        }
    }

    fn decide(&self, user_key: &[u8], value: &[u8]) -> FilterDecision {
        if user_key.first() == Some(&LOCAL_PREFIX) {
            return FilterDecision::Keep;
        }
        // Meta slots and anything that is not an MVCC version are never garbage.
        let Ok(MvccKey::Version(key, ts)) = MvccKey::decode(user_key) else {
            return FilterDecision::Keep;
        };
        let cutoff = self.cutoff.unwrap_or_else(|| self.threshold.get());
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.key != key {
            state.key.clear();
            state.key.extend_from_slice(key);
            state.shadowed = false;
        }
        if ts > cutoff {
            return FilterDecision::Keep;
        }
        if state.shadowed {
            return FilterDecision::Remove;
        }
        // An undecodable value is kept and does not shadow anything: never drop on a guess.
        if VersionValue::decode(value).is_ok_and(|v| v.is_base()) {
            state.shadowed = true;
        }
        FilterDecision::Keep
    }
}

impl CompactionFilter for MvccGcFilter {
    fn filter(&self, _level: usize, user_key: &[u8], value: &[u8]) -> FilterDecision {
        self.decide(user_key, value)
    }

    fn for_subcompaction(&self) -> Option<Box<dyn CompactionFilter>> {
        Some(Box::new(Self {
            threshold: Arc::clone(&self.threshold),
            cutoff: Some(self.threshold.get()),
            state: Mutex::new(FilterState::default()),
        }))
    }
}

/// `base` with the MVCC prefix extractor: SST filters on logical keys, so a read of any entry
/// of a key tests the filter of that key (storage-engine.md §4, ADR-039). Use it for every
/// engine holding MVCC data.
#[must_use]
pub fn mvcc_filter_options(mut base: EngineOptions) -> EngineOptions {
    let extractor = Arc::new(MvccPrefixExtractor);
    base.reader.prefix_extractor = extractor.clone();
    base.compaction.writer.prefix_extractor = extractor;
    base
}

/// [`mvcc_filter_options`] and the GC compaction filter.
#[must_use]
pub fn mvcc_engine_options(base: EngineOptions, threshold: Arc<GcThreshold>) -> EngineOptions {
    let mut base = mvcc_filter_options(base);
    base.compaction_filter = Some(Arc::new(MvccGcFilter::new(threshold)));
    base
}

/// The explicit GC request for the logical keys in `[start, end)` (module docs): a batch of
/// point deletes of every version below the newest base `<= threshold.get()`, plus that base
/// when it is a tombstone. Apply it with `LsmEngine::write` (through Raft in the cluster).
/// Advance the threshold before calling. Returns the batch (empty when there is no garbage).
///
/// # Errors
/// Storage errors; [`MvccError::Corruption`] for a non-MVCC key in the span.
pub fn gc_batch(
    engine: &LsmEngine,
    threshold: &GcThreshold,
    start: &[u8],
    end: &[u8],
) -> Result<WriteBatch> {
    gc_batch_limited(engine, threshold, start, end, usize::MAX).map(|(batch, _)| batch)
}

/// [`gc_batch`] bounded to about `max_ops` deletes: the batch stops at a logical-key boundary
/// once it holds at least `max_ops` operations and returns where to continue (`Some(key)`: call
/// again with `start = key`; `None`: the span is done). A key's deletes are never split across
/// batches, so every batch is a valid GC request on its own.
///
/// # Errors
/// As [`gc_batch`].
pub fn gc_batch_limited(
    engine: &LsmEngine,
    threshold: &GcThreshold,
    start: &[u8],
    end: &[u8],
    max_ops: usize,
) -> Result<(WriteBatch, Option<Vec<u8>>)> {
    let cutoff = threshold.get();
    let mut batch = WriteBatch::new();
    let mut iter = engine.iterator(None)?;
    iter.seek(start)?;
    // Per logical key (versions come newest first): `collecting` turns on at the newest base
    // <= cutoff; every older version is then garbage.
    let mut current: Vec<u8> = Vec::new();
    let mut collecting = false;
    let mut started = false;
    while iter.valid() {
        let raw = iter.key().to_vec();
        let decoded = MvccKey::decode(&raw)?;
        let key = decoded.logical();
        if key >= end {
            break;
        }
        if !started || key != current.as_slice() {
            if batch.len() >= max_ops {
                // The meta key sorts before every entry of `key` (key.rs ordering argument).
                return Ok((batch, Some(crate::key::meta_key(key))));
            }
            current.clear();
            current.extend_from_slice(key);
            collecting = false;
            started = true;
        }
        if let MvccKey::Version(_, ts) = decoded {
            if collecting {
                batch.delete(&raw);
            } else if ts <= cutoff {
                match VersionValue::decode(&iter.value())? {
                    VersionValue::Tombstone => {
                        batch.delete(&raw);
                        collecting = true;
                    }
                    VersionValue::Value(_) => collecting = true,
                    VersionValue::MergeOperand(_) => {}
                }
            }
        }
        iter.next()?;
    }
    Ok((batch, None))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::key::{meta_key, version_key};

    fn value(v: &[u8]) -> Vec<u8> {
        VersionValue::Value(Bytes::copy_from_slice(v)).encode()
    }

    #[test]
    fn tc_bkp_013_pins_hold_the_threshold_and_release_on_drop() {
        let t = Arc::new(GcThreshold::new(Timestamp::new(10, 0)));
        // A pin below the threshold cannot be granted: those versions may be gone already.
        assert!(matches!(
            t.pin(Timestamp::new(9, 0)),
            Err(MvccError::BelowGcThreshold { .. })
        ));
        let a = t.pin(Timestamp::new(15, 0)).unwrap();
        let b = t.pin(Timestamp::new(15, 0)).unwrap();
        let c = t.pin(Timestamp::new(30, 0)).unwrap();
        assert_eq!(t.oldest_pin(), Some(Timestamp::new(15, 0)));
        assert_eq!(t.advance(Timestamp::new(50, 0)), Timestamp::new(15, 0));
        assert!(t.check(a.ts()).is_ok());
        drop(a);
        // Still pinned at 15 by `b`.
        assert_eq!(t.advance(Timestamp::new(50, 0)), Timestamp::new(15, 0));
        drop(b);
        assert_eq!(t.advance(Timestamp::new(50, 0)), Timestamp::new(30, 0));
        drop(c);
        assert_eq!(t.oldest_pin(), None);
        assert_eq!(t.advance(Timestamp::new(50, 0)), Timestamp::new(50, 0));
    }

    #[test]
    fn threshold_only_moves_forward() {
        let t = GcThreshold::new(Timestamp::new(10, 0));
        assert_eq!(t.advance(Timestamp::new(5, 0)), Timestamp::new(10, 0));
        assert_eq!(t.advance(Timestamp::new(20, 1)), Timestamp::new(20, 1));
        assert!(t.check(Timestamp::new(20, 0)).is_err());
        assert!(t.check(Timestamp::new(20, 1)).is_ok());
    }

    #[test]
    fn filter_keeps_newest_base_below_threshold_and_drops_older() {
        let f = MvccGcFilter::new(Arc::new(GcThreshold::new(Timestamp::new(10, 0))));
        let f = f.for_subcompaction().unwrap();
        let ts = |w| Timestamp::new(w, 0);
        let merge = VersionValue::MergeOperand(Bytes::from_static(b"op")).encode();
        let tomb = VersionValue::Tombstone.encode();
        let cases = [
            (meta_key(b"a"), value(b"intent"), FilterDecision::Keep),
            (version_key(b"a", ts(12)), value(b"x"), FilterDecision::Keep),
            (
                version_key(b"a", ts(9)),
                merge.clone(),
                FilterDecision::Keep,
            ),
            (
                version_key(b"a", ts(8)),
                value(b"base"),
                FilterDecision::Keep,
            ),
            (
                version_key(b"a", ts(7)),
                value(b"old"),
                FilterDecision::Remove,
            ),
            (
                version_key(b"a", ts(6)),
                tomb.clone(),
                FilterDecision::Remove,
            ),
            // Next logical key starts fresh; its newest base is a tombstone: kept.
            (version_key(b"b", ts(5)), tomb, FilterDecision::Keep),
            (
                version_key(b"b", ts(4)),
                value(b"old"),
                FilterDecision::Remove,
            ),
            // Local keys are never touched.
            (vec![0x01, b'r', 0x0D], merge, FilterDecision::Keep),
        ];
        for (key, val, expect) in cases {
            assert_eq!(f.filter(1, &key, &val), expect, "{key:?}");
        }
    }

    #[test]
    fn filter_keeps_undecodable_values() {
        let f = MvccGcFilter::new(Arc::new(GcThreshold::new(Timestamp::new(10, 0))));
        let k1 = version_key(b"a", Timestamp::new(5, 0));
        let k2 = version_key(b"a", Timestamp::new(4, 0));
        assert_eq!(f.filter(1, &k1, b"\xFF"), FilterDecision::Keep);
        assert_eq!(f.filter(1, &k2, &value(b"x")), FilterDecision::Keep);
    }
}
