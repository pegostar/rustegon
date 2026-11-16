// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC value encodings v1 (transaction-management.md §3 "Value encodings v1"): committed
//! versions, intents (`TxnMeta` + provisional value + per-sequence history) and transaction
//! records. Every encoding starts with a format version byte (implementation-rules.md §6);
//! integers are fixed-width big endian and variable-length fields carry a `u32 BE` length, so
//! every value has exactly one encoding. Decoders validate everything and never panic on
//! malformed input (they return [`MvccError::Corruption`]).

use bytes::Bytes;

use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
};

/// Format version of every value encoding in this module.
pub const FORMAT_VERSION: u8 = 1;

/// A transaction id (UUID bytes).
pub type TxnId = [u8; 16];

const TAG_VALUE: u8 = 1;
const TAG_TOMBSTONE: u8 = 2;
const TAG_MERGE: u8 = 3;

/// The content of one MVCC version (committed, or provisional in an intent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionValue {
    /// A full value (e.g. an `RDoc`).
    Value(Bytes),
    /// A deletion: the key reads as absent at this version.
    Tombstone,
    /// A merge operand (`rustegon_storage::merge` encoding) applied on top of the older
    /// versions (storage-engine.md §8).
    MergeOperand(Bytes),
}

impl VersionValue {
    /// `version(1) ‖ tag(1) ‖ payload`; tags 1 value, 2 tombstone (no payload), 3 merge operand.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, payload): (u8, &[u8]) = match self {
            Self::Value(v) => (TAG_VALUE, v),
            Self::Tombstone => (TAG_TOMBSTONE, &[]),
            Self::MergeOperand(v) => (TAG_MERGE, v),
        };
        let mut out = Vec::with_capacity(2 + payload.len());
        out.push(FORMAT_VERSION);
        out.push(tag);
        out.extend_from_slice(payload);
        out
    }

    /// Decodes [`VersionValue::encode`] output.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] on an unknown version or tag, or a tombstone with a payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [version, tag, payload @ ..] = bytes else {
            return Err(MvccError::corruption("version value shorter than 2 bytes"));
        };
        check_version(*version, "version value")?;
        match *tag {
            TAG_VALUE => Ok(Self::Value(Bytes::copy_from_slice(payload))),
            TAG_TOMBSTONE if payload.is_empty() => Ok(Self::Tombstone),
            TAG_TOMBSTONE => Err(MvccError::corruption("tombstone with payload")),
            TAG_MERGE => Ok(Self::MergeOperand(Bytes::copy_from_slice(payload))),
            t => Err(MvccError::corruption(format!(
                "unknown version value tag {t}"
            ))),
        }
    }

    /// Whether the version is a base for merging (a full value or a tombstone).
    #[must_use]
    pub fn is_base(&self) -> bool {
        !matches!(self, Self::MergeOperand(_))
    }
}

/// An inclusive range of sequence numbers rolled back by `ROLLBACK TO SAVEPOINT` (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeqRange {
    /// First ignored sequence number.
    pub start: u32,
    /// Last ignored sequence number (inclusive).
    pub end: u32,
}

impl SeqRange {
    /// Whether `seq` lies in the range.
    #[must_use]
    pub fn contains(&self, seq: u32) -> bool {
        self.start <= seq && seq <= self.end
    }
}

/// Whether `seq` is rolled back by any of `ranges`.
#[must_use]
pub fn is_ignored(ranges: &[SeqRange], seq: u32) -> bool {
    ranges.iter().any(|r| r.contains(seq))
}

/// Metadata of a write intent (§3): which transaction wrote it, at which epoch, timestamp and
/// sequence number, and where its transaction record lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnMeta {
    /// Writing transaction.
    pub txn_id: TxnId,
    /// Restart epoch of the transaction when it wrote the intent.
    pub epoch: u32,
    /// Provisional commit timestamp of the intent.
    pub write_ts: Timestamp,
    /// Sequence number of the write within the transaction.
    pub seq: u32,
    /// Anchor key: the transaction record is at `txn_record_key(anchor_key, txn_id)`.
    pub anchor_key: Vec<u8>,
    /// Sequence ranges rolled back by savepoints, sorted and disjoint.
    pub ignored_seq_ranges: Vec<SeqRange>,
}

impl TxnMeta {
    /// `version ‖ txn_id(16) ‖ epoch u32 ‖ write_ts(12) ‖ seq u32 ‖ anchor (u32 len ‖ bytes) ‖
    /// count u32 ‖ count × (start u32, end u32)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(46 + self.anchor_key.len());
        w.u8(FORMAT_VERSION);
        w.raw(&self.txn_id);
        w.u32(self.epoch);
        w.ts(self.write_ts);
        w.u32(self.seq);
        w.bytes(&self.anchor_key);
        w.len(self.ignored_seq_ranges.len());
        for r in &self.ignored_seq_ranges {
            w.u32(r.start);
            w.u32(r.end);
        }
        w.0
    }

    /// Decodes [`TxnMeta::encode`] output.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] on truncation, trailing bytes, an unknown version or unsorted /
    /// overlapping / inverted ignored ranges.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "TxnMeta");
        check_version(r.u8()?, "TxnMeta")?;
        let meta = Self {
            txn_id: r.array()?,
            epoch: r.u32()?,
            write_ts: r.ts()?,
            seq: r.u32()?,
            anchor_key: r.bytes()?.to_vec(),
            ignored_seq_ranges: decode_ranges(&mut r)?,
        };
        r.finish()?;
        Ok(meta)
    }
}

fn decode_ranges(r: &mut Reader<'_>) -> Result<Vec<SeqRange>> {
    let n = r.count(8)?;
    let mut ranges = Vec::with_capacity(n);
    for _ in 0..n {
        let range = SeqRange {
            start: r.u32()?,
            end: r.u32()?,
        };
        if range.start > range.end
            || ranges
                .last()
                .is_some_and(|p: &SeqRange| p.end >= range.start)
        {
            return Err(MvccError::corruption(
                "ignored sequence ranges not sorted and disjoint",
            ));
        }
        ranges.push(range);
    }
    Ok(ranges)
}

/// The value stored in the meta slot of a key holding a write intent: the intent's metadata,
/// its provisional value (written at `meta.seq`) and the transaction's earlier provisional
/// values of the key (`history`, ascending sequence numbers, all `< meta.seq`), kept so that a
/// rollback to a savepoint can expose the value an earlier sequence number wrote (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentValue {
    /// Intent metadata.
    pub meta: TxnMeta,
    /// Provisional value written at `meta.seq`.
    pub value: VersionValue,
    /// Earlier provisional values `(seq, value)` of the same transaction epoch.
    pub history: Vec<(u32, VersionValue)>,
}

impl IntentValue {
    /// `version ‖ TxnMeta (u32 len ‖ bytes) ‖ value (u32 len ‖ VersionValue) ‖ count u32 ‖
    /// count × (seq u32 ‖ u32 len ‖ VersionValue)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.u8(FORMAT_VERSION);
        w.bytes(&self.meta.encode());
        w.bytes(&self.value.encode());
        w.len(self.history.len());
        for (seq, value) in &self.history {
            w.u32(*seq);
            w.bytes(&value.encode());
        }
        w.0
    }

    /// Decodes [`IntentValue::encode`] output.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] on malformed input, including history sequence numbers that
    /// are not ascending or not below `meta.seq`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "intent");
        check_version(r.u8()?, "intent")?;
        let meta = TxnMeta::decode(r.bytes()?)?;
        let value = VersionValue::decode(r.bytes()?)?;
        let n = r.count(10)?;
        let mut history: Vec<(u32, VersionValue)> = Vec::with_capacity(n);
        for _ in 0..n {
            let seq = r.u32()?;
            if seq >= meta.seq || history.last().is_some_and(|(p, _)| *p >= seq) {
                return Err(MvccError::corruption(
                    "intent history sequence numbers out of order",
                ));
            }
            history.push((seq, VersionValue::decode(r.bytes()?)?));
        }
        r.finish()?;
        Ok(Self {
            meta,
            value,
            history,
        })
    }

    /// The newest provisional value with a sequence number `<= max_seq` that is not rolled back
    /// by `ignored`; `None` if every candidate is.
    #[must_use]
    pub fn visible(&self, max_seq: u32, ignored: &[SeqRange]) -> Option<(u32, &VersionValue)> {
        std::iter::once((self.meta.seq, &self.value))
            .chain(self.history.iter().rev().map(|(s, v)| (*s, v)))
            .find(|(seq, _)| *seq <= max_seq && !is_ignored(ignored, *seq))
    }
}

/// An intent found by a reader or writer, reported for resolution (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Logical key of the intent.
    pub key: Vec<u8>,
    /// Its metadata (transaction, timestamp, record location).
    pub meta: TxnMeta,
}

/// Status of a transaction record (§3, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnStatus {
    /// Running.
    Pending,
    /// Parallel commit in progress: committed iff all in-flight writes succeeded (§6).
    Staging,
    /// Committed (explicitly).
    Committed,
    /// Aborted.
    Aborted,
}

impl TxnStatus {
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Staging => 2,
            Self::Committed => 3,
            Self::Aborted => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Staging),
            3 => Ok(Self::Committed),
            4 => Ok(Self::Aborted),
            c => Err(MvccError::corruption(format!(
                "unknown transaction status {c}"
            ))),
        }
    }
}

/// A write whose replication the coordinator has not yet proven (parallel commit, §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightWrite {
    /// Logical key written.
    pub key: Vec<u8>,
    /// Sequence number of the write.
    pub seq: u32,
}

/// A key span `[start, end)` holding intents of the transaction; an empty `end` means the
/// single key `start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// First key.
    pub start: Vec<u8>,
    /// Exclusive end, or empty for a point span.
    pub end: Vec<u8>,
}

/// The transaction record (§3), stored in the meta slot of `txn_record_key(anchor, txn_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnRecord {
    /// Current status.
    pub status: TxnStatus,
    /// Provisional (or final) commit timestamp.
    pub write_ts: Timestamp,
    /// Read timestamp.
    pub read_ts: Timestamp,
    /// Priority (§5.3).
    pub priority: u32,
    /// Last heartbeat of the coordinator (§9 liveness).
    pub heartbeat_ts: Timestamp,
    /// Writes not yet proven replicated (STAGING).
    pub in_flight_writes: Vec<InFlightWrite>,
    /// Spans holding the transaction's intents, for resolution and record GC (§7).
    pub lock_spans: Vec<Span>,
}

impl TxnRecord {
    /// `version ‖ status u8 (1 PENDING, 2 STAGING, 3 COMMITTED, 4 ABORTED) ‖ write_ts(12) ‖
    /// read_ts(12) ‖ priority u32 ‖ heartbeat_ts(12) ‖ count u32 ‖ count × (key (u32 len ‖ bytes)
    /// ‖ seq u32) ‖ count u32 ‖ count × (start (u32 len ‖ bytes) ‖ end (u32 len ‖ bytes))`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.u8(FORMAT_VERSION);
        w.u8(self.status.code());
        w.ts(self.write_ts);
        w.ts(self.read_ts);
        w.u32(self.priority);
        w.ts(self.heartbeat_ts);
        w.len(self.in_flight_writes.len());
        for f in &self.in_flight_writes {
            w.bytes(&f.key);
            w.u32(f.seq);
        }
        w.len(self.lock_spans.len());
        for s in &self.lock_spans {
            w.bytes(&s.start);
            w.bytes(&s.end);
        }
        w.0
    }

    /// Decodes [`TxnRecord::encode`] output.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] on malformed input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "TxnRecord");
        check_version(r.u8()?, "TxnRecord")?;
        let status = TxnStatus::from_code(r.u8()?)?;
        let write_ts = r.ts()?;
        let read_ts = r.ts()?;
        let priority = r.u32()?;
        let heartbeat_ts = r.ts()?;
        let n = r.count(8)?;
        let mut in_flight_writes = Vec::with_capacity(n);
        for _ in 0..n {
            in_flight_writes.push(InFlightWrite {
                key: r.bytes()?.to_vec(),
                seq: r.u32()?,
            });
        }
        let n = r.count(8)?;
        let mut lock_spans = Vec::with_capacity(n);
        for _ in 0..n {
            lock_spans.push(Span {
                start: r.bytes()?.to_vec(),
                end: r.bytes()?.to_vec(),
            });
        }
        r.finish()?;
        Ok(Self {
            status,
            write_ts,
            read_ts,
            priority,
            heartbeat_ts,
            in_flight_writes,
            lock_spans,
        })
    }
}

fn check_version(version: u8, what: &str) -> Result<()> {
    if version == FORMAT_VERSION {
        Ok(())
    } else {
        Err(MvccError::corruption(format!(
            "{what}: unknown format version {version}"
        )))
    }
}

/// Big-endian encoder.
struct Writer(Vec<u8>);

impl Writer {
    fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn ts(&mut self, ts: Timestamp) {
        self.0.extend_from_slice(&ts.to_be_bytes());
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    /// A length or count as `u32 BE`. Values are bounded far below 4 GiB by the transaction
    /// limits (§9: 64 MiB per transaction), so saturation never happens in practice; a
    /// saturated length would make the decoder reject the value rather than misread it.
    fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.raw(b);
    }
}

/// Bounds-checked big-endian decoder over a borrowed buffer.
struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(MvccError::corruption(format!("{}: truncated", self.what)));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn ts(&mut self) -> Result<Timestamp> {
        Ok(Timestamp::from_be_bytes(self.array()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// A count of items each at least `min_item` bytes long; rejects counts the remaining input
    /// cannot hold, so a corrupt count never triggers a huge allocation.
    fn count(&mut self, min_item: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_item) > self.buf.len() {
            return Err(MvccError::corruption(format!(
                "{}: count {n} too large",
                self.what
            )));
        }
        Ok(n)
    }

    fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(MvccError::corruption(format!(
                "{}: trailing bytes",
                self.what
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> TxnMeta {
        TxnMeta {
            txn_id: [3; 16],
            epoch: 2,
            write_ts: Timestamp::new(100, 7),
            seq: 9,
            anchor_key: b"anchor".to_vec(),
            ignored_seq_ranges: vec![SeqRange { start: 2, end: 3 }, SeqRange { start: 5, end: 5 }],
        }
    }

    #[test]
    fn version_value_round_trip() {
        for v in [
            VersionValue::Value(Bytes::from_static(b"doc")),
            VersionValue::Value(Bytes::new()),
            VersionValue::Tombstone,
            VersionValue::MergeOperand(Bytes::from_static(b"\x01\x01\x02")),
        ] {
            assert_eq!(VersionValue::decode(&v.encode()).unwrap(), v);
        }
    }

    #[test]
    fn intent_visible_respects_seq_and_ignored_ranges() {
        let intent = IntentValue {
            meta: meta(),
            value: VersionValue::Value(Bytes::from_static(b"s9")),
            history: vec![
                (1, VersionValue::Value(Bytes::from_static(b"s1"))),
                (4, VersionValue::Tombstone),
            ],
        };
        assert_eq!(IntentValue::decode(&intent.encode()).unwrap(), intent);
        assert_eq!(intent.visible(9, &[]).map(|v| v.0), Some(9));
        assert_eq!(intent.visible(8, &[]).map(|v| v.0), Some(4));
        let ignored = [SeqRange { start: 4, end: 9 }];
        assert_eq!(intent.visible(9, &ignored).map(|v| v.0), Some(1));
        assert_eq!(intent.visible(0, &[]), None);
    }

    #[test]
    fn decoders_reject_bad_ranges_and_history() {
        let mut m = meta();
        m.ignored_seq_ranges = vec![SeqRange { start: 3, end: 2 }];
        assert!(TxnMeta::decode(&m.encode()).is_err());
        m.ignored_seq_ranges = vec![SeqRange { start: 1, end: 3 }, SeqRange { start: 3, end: 4 }];
        assert!(TxnMeta::decode(&m.encode()).is_err());
        let intent = IntentValue {
            meta: meta(),
            value: VersionValue::Tombstone,
            history: vec![(9, VersionValue::Tombstone)],
        };
        assert!(IntentValue::decode(&intent.encode()).is_err());
    }
}
