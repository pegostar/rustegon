// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Merge operators for counters and FTS statistics (storage-engine.md §8, data-model.md §10).
//!
//! A `Merge(k, operand)` write records a delta instead of a full value, so increments never need a
//! read-modify-write (and therefore never conflict on the value). The value of a key at a read
//! timestamp is the newest base value (`Put`) or nothing (tombstone / absent) combined with every
//! operand newer than it. Two entry points serve the engine:
//!
//! - [`full_merge`]: at read and when compaction reaches the base value (or the bottom level);
//!   produces the value, failing with [`StorageError::CounterOverflow`] (`RGN-1009`) when a sum
//!   leaves the `i64` range.
//! - [`partial_merge`]: during compaction, collapses a run of adjacent operands into one operand
//!   whose full merge is indistinguishable from the run's.
//!
//! Sums accumulate in `i128` (data-model.md §10) so transient excursions past `i64` that later
//! deltas bring back into range are not errors; only the final value is range-checked.
//!
//! Base values use the same encoding as operands (a base is just "the sum so far"), so compaction
//! can write a full-merge result back as a `Put` without a second format.

use crate::coding::{Reader, put_varint};
use crate::error::{Result, StorageError};

/// Encoding version byte, first byte of every operand/value (implementation-rules.md §6).
const FORMAT_VERSION: u8 = 1;
/// Type tag of [`MergeOperand::CounterDelta`].
const TAG_COUNTER_DELTA: u8 = 1;
/// Type tag of [`MergeOperand::TermStats`].
const TAG_TERM_STATS: u8 = 2;

/// A merge operand, or (with the same shape) a merged base value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOperand {
    /// Document counter increment (data-model.md §10); negative deltas decrement.
    CounterDelta(i64),
    /// Full-text term statistics delta: document frequency and summed term frequency.
    TermStats {
        /// Change in the number of documents containing the term.
        df_delta: i64,
        /// Change in the sum of term frequencies over all documents.
        tf_sum_delta: i64,
    },
}

impl MergeOperand {
    /// Encodes as `version ‖ tag ‖ zigzag varint fields`: 3–22 bytes, small deltas stay small.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.push(FORMAT_VERSION);
        match *self {
            Self::CounterDelta(d) => {
                buf.push(TAG_COUNTER_DELTA);
                put_varint(&mut buf, zigzag(d));
            }
            Self::TermStats {
                df_delta,
                tf_sum_delta,
            } => {
                buf.push(TAG_TERM_STATS);
                put_varint(&mut buf, zigzag(df_delta));
                put_varint(&mut buf, zigzag(tf_sum_delta));
            }
        }
        buf
    }

    /// Decodes an operand or base value; never panics.
    ///
    /// The encoding is canonical: over-long varints are rejected, so every accepted byte string is
    /// exactly `decode(x).encode()` and equal values always have equal bytes (compaction output
    /// and checksums never depend on which writer produced an operand).
    ///
    /// # Errors
    /// [`StorageError::Corruption`] (`RGN-5002`) on unknown version/tag, truncation, non-minimal
    /// varints or trailing bytes. A key whose base `Put` is not a merge value at all (e.g. a
    /// document written under a key that later receives operands) lands here too: the storage
    /// layer cannot tell such a usage error from damage, and the document layer (M2) prevents
    /// it by only emitting operands for counter fields (storage-engine.md §8).
    pub fn decode(input: &[u8]) -> Result<Self> {
        let bad = |what: &str| StorageError::corruption(format!("merge operand: {what}"));
        let mut r = Reader::new(input);
        let version = r.u8().ok_or_else(|| bad("empty"))?;
        if version != FORMAT_VERSION {
            return Err(bad(&format!("unsupported version {version}")));
        }
        let field = |r: &mut Reader<'_>| {
            r.canonical_varint()
                .map(unzigzag)
                .ok_or_else(|| bad("truncated or non-minimal varint"))
        };
        let op = match r.u8().ok_or_else(|| bad("missing tag"))? {
            TAG_COUNTER_DELTA => Self::CounterDelta(field(&mut r)?),
            TAG_TERM_STATS => Self::TermStats {
                df_delta: field(&mut r)?,
                tf_sum_delta: field(&mut r)?,
            },
            tag => return Err(bad(&format!("unknown tag {tag}"))),
        };
        if !r.is_empty() {
            return Err(bad("trailing bytes"));
        }
        Ok(op)
    }
}

/// Running `i128` sum of operands of one type.
#[derive(Clone, Copy)]
enum Acc {
    Counter(i128),
    TermStats(i128, i128),
}

impl Acc {
    fn zero_like(op: MergeOperand) -> Self {
        match op {
            MergeOperand::CounterDelta(_) => Self::Counter(0),
            MergeOperand::TermStats { .. } => Self::TermStats(0, 0),
        }
    }

    /// Adds `op`; mixing operand types is corruption (one key holds one kind of merge value).
    fn add(self, op: MergeOperand) -> Result<Self> {
        // i128 overflow needs ~2^64 maximal operands, impossible in practice; still checked so the
        // failure is an error, not a wrap.
        let ovf = || StorageError::CounterOverflow;
        match (self, op) {
            (Self::Counter(s), MergeOperand::CounterDelta(d)) => {
                Ok(Self::Counter(s.checked_add(d.into()).ok_or_else(ovf)?))
            }
            (
                Self::TermStats(df, tf),
                MergeOperand::TermStats {
                    df_delta,
                    tf_sum_delta,
                },
            ) => Ok(Self::TermStats(
                df.checked_add(df_delta.into()).ok_or_else(ovf)?,
                tf.checked_add(tf_sum_delta.into()).ok_or_else(ovf)?,
            )),
            _ => Err(StorageError::corruption(
                "merge operand type differs from the key's other operands",
            )),
        }
    }

    /// Narrows to `i64`; `None` if any component is out of range.
    fn to_operand(self) -> Option<MergeOperand> {
        match self {
            Self::Counter(s) => i64::try_from(s).ok().map(MergeOperand::CounterDelta),
            Self::TermStats(df, tf) => Some(MergeOperand::TermStats {
                df_delta: i64::try_from(df).ok()?,
                tf_sum_delta: i64::try_from(tf).ok()?,
            }),
        }
    }
}

/// Sums encoded operands (any order: addition is commutative); `None` for an empty run.
fn sum<'a>(
    start: Option<Acc>,
    operands: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<Acc>> {
    let mut acc = start;
    for raw in operands {
        let op = MergeOperand::decode(raw)?;
        acc = Some(acc.unwrap_or_else(|| Acc::zero_like(op)).add(op)?);
    }
    Ok(acc)
}

/// Full merge: `base` is the encoded newest `Put` below the operands, or `None` when the operands
/// sit on a tombstone or on nothing (the sum restarts at zero). `operands` are encoded operands in
/// internal-key iterator order (newest first). Returns the encoded value.
///
/// # Compaction
/// `CounterOverflow` is a property of the *current* total, not of the data: a newer operand may
/// bring the `i128` sum back into range. A compaction that gets this error must therefore keep
/// the base and operands unmerged (as written) and must not fail the job; only the read path
/// reports the error to the client (`RGN-1009`). [`partial_merge`] returns `Ok(None)` for every
/// run whose sum leaves `i64`, so the "keep the operands" fallback is always available.
///
/// # Errors
/// [`StorageError::CounterOverflow`] if the result leaves `i64` (`RGN-1009` at read; compaction
/// keeps the operands instead, see above);
/// [`StorageError::Corruption`] on undecodable or type-mixed input, including a base that is not
/// a merge value (`RGN-5002`);
/// [`StorageError::InvalidArgument`] if there is neither a base nor an operand.
pub fn full_merge<'a>(
    base: Option<&[u8]>,
    operands: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>> {
    let start = base
        .map(|b| {
            let v = MergeOperand::decode(b)?;
            Acc::zero_like(v).add(v)
        })
        .transpose()?;
    let acc = sum(start, operands)?
        .ok_or_else(|| StorageError::InvalidArgument("full merge of nothing".into()))?;
    let value = acc.to_operand().ok_or(StorageError::CounterOverflow)?;
    Ok(value.encode())
}

/// Partial merge of adjacent operands (newest first) into one operand, for compaction.
///
/// Returns `Ok(None)` when the run's sum does not fit an `i64` operand: compaction then keeps the
/// operands as they are, because a later operand may bring the total back into range and the full
/// merge (which sums in `i128`) must see the same result either way.
///
/// # Compaction
/// Never returns `CounterOverflow` for an `i64`-range overflow (only for the unreachable `i128`
/// one): `None` is the signal to keep the run as is. Together with the [`full_merge`] contract
/// this means an overflowing counter never wedges a compaction job.
///
/// # Errors
/// [`StorageError::Corruption`] on undecodable or type-mixed input;
/// [`StorageError::InvalidArgument`] for an empty run.
pub fn partial_merge<'a>(operands: impl IntoIterator<Item = &'a [u8]>) -> Result<Option<Vec<u8>>> {
    let acc = sum(None, operands)?
        .ok_or_else(|| StorageError::InvalidArgument("partial merge of no operands".into()))?;
    Ok(acc.to_operand().map(|op| op.encode()))
}

/// Maps signed to unsigned so small magnitudes of either sign encode in few varint bytes.
fn zigzag(v: i64) -> u64 {
    // Bit reinterpretation intended (standard zigzag).
    #[allow(clippy::cast_sign_loss)]
    let r = ((v << 1) ^ (v >> 63)) as u64;
    r
}

fn unzigzag(v: u64) -> i64 {
    #[allow(clippy::cast_possible_wrap)]
    let r = ((v >> 1) as i64) ^ -((v & 1) as i64);
    r
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn counter(d: i64) -> Vec<u8> {
        MergeOperand::CounterDelta(d).encode()
    }

    fn decode_counter(v: &[u8]) -> i64 {
        match MergeOperand::decode(v) {
            Ok(MergeOperand::CounterDelta(d)) => d,
            other => panic!("not a counter: {other:?}"),
        }
    }

    fn arb_operand() -> impl Strategy<Value = MergeOperand> {
        prop_oneof![
            any::<i64>().prop_map(MergeOperand::CounterDelta),
            (any::<i64>(), any::<i64>()).prop_map(|(df_delta, tf_sum_delta)| {
                MergeOperand::TermStats {
                    df_delta,
                    tf_sum_delta,
                }
            }),
        ]
    }

    /// Mix of small and extreme deltas so both in-range and overflowing sums occur.
    fn arb_delta() -> impl Strategy<Value = i64> {
        prop_oneof![-1000i64..1000, Just(i64::MAX), Just(i64::MIN), any::<i64>()]
    }

    fn ts(df_delta: i64, tf_sum_delta: i64) -> Vec<u8> {
        MergeOperand::TermStats {
            df_delta,
            tf_sum_delta,
        }
        .encode()
    }

    /// Sequential model: apply operands oldest first to the base in i128, then range-check.
    fn model(base: Option<i64>, oldest_first: &[i64]) -> Option<i64> {
        let total: i128 = i128::from(base.unwrap_or(0))
            + oldest_first.iter().map(|&d| i128::from(d)).sum::<i128>();
        i64::try_from(total).ok()
    }

    /// [`model`] per `TermStats` field; the value exists only if both fields fit.
    fn ts_model(base: Option<(i64, i64)>, oldest_first: &[(i64, i64)]) -> Option<MergeOperand> {
        let (df, tf): (Vec<i64>, Vec<i64>) = oldest_first.iter().copied().unzip();
        Some(MergeOperand::TermStats {
            df_delta: model(base.map(|b| b.0), &df)?,
            tf_sum_delta: model(base.map(|b| b.1), &tf)?,
        })
    }

    /// Byte-level damage applied to a valid encoding.
    #[derive(Debug, Clone)]
    enum Mutation {
        Truncate(prop::sample::Index),
        FlipBit(prop::sample::Index, u8),
        Append(Vec<u8>),
    }

    fn arb_mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            any::<prop::sample::Index>().prop_map(Mutation::Truncate),
            (any::<prop::sample::Index>(), 0u8..8).prop_map(|(i, b)| Mutation::FlipBit(i, b)),
            proptest::collection::vec(any::<u8>(), 1..4).prop_map(Mutation::Append),
        ]
    }

    /// Shared body of the partial-merge proptests: partially merging `ops[i..j]` (falling back to
    /// keeping the run when it declines) must not change the full merge.
    fn check_partial_merge_preserves_full_merge(
        base: Option<&[u8]>,
        ops: &[Vec<u8>],
        i: usize,
        j: usize,
    ) -> std::result::Result<(), TestCaseError> {
        let whole = full_merge(base, ops.iter().map(Vec::as_slice));
        let mut compacted = ops[..i].to_vec();
        match partial_merge(ops[i..j].iter().map(Vec::as_slice))? {
            Some(merged) => compacted.push(merged),
            None => compacted.extend_from_slice(&ops[i..j]),
        }
        compacted.extend_from_slice(&ops[j..]);
        let split = full_merge(base, compacted.iter().map(Vec::as_slice));
        match (whole, split) {
            (Ok(x), Ok(y)) => prop_assert_eq!(x, y),
            (Err(StorageError::CounterOverflow), Err(StorageError::CounterOverflow)) => {}
            (x, y) => prop_assert!(false, "diverged: {x:?} vs {y:?}"),
        }
        Ok(())
    }

    /// Two sample indices into `len` items as a non-empty half-open run `i..j`.
    fn run(len: usize, a: prop::sample::Index, b: prop::sample::Index) -> (usize, usize) {
        let (x, y) = (a.index(len), b.index(len));
        (x.min(y), x.max(y) + 1)
    }

    proptest! {
        #[test]
        fn operand_round_trips(op in arb_operand()) {
            prop_assert_eq!(MergeOperand::decode(&op.encode()).ok(), Some(op));
        }

        #[test]
        fn decode_of_mutated_encoding_is_canonical_or_corruption(
            op in arb_operand(),
            mutation in arb_mutation(),
        ) {
            let mut bytes = op.encode();
            match mutation {
                Mutation::Truncate(i) => bytes.truncate(i.index(bytes.len())),
                Mutation::FlipBit(i, bit) => {
                    let i = i.index(bytes.len());
                    bytes[i] ^= 1 << bit;
                }
                Mutation::Append(tail) => bytes.extend_from_slice(&tail),
            }
            match MergeOperand::decode(&bytes) {
                // Canonical encoding: an accepted input is exactly the encoding of its value,
                // which in turn decodes to the same value.
                Ok(got) => {
                    prop_assert_eq!(got.encode(), bytes.clone());
                    prop_assert_eq!(MergeOperand::decode(&got.encode()).ok(), Some(got));
                }
                Err(e) => prop_assert!(e.is_corruption(), "{e:?}"),
            }
        }

        #[test]
        fn decode_of_random_bytes_is_canonical_or_corruption(
            bytes in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            match MergeOperand::decode(&bytes) {
                Ok(op) => prop_assert_eq!(op.encode(), bytes),
                Err(e) => prop_assert!(e.is_corruption(), "{e:?}"),
            }
        }

        #[test]
        fn term_stats_full_merge_equals_sequential_model(
            base in proptest::option::of((arb_delta(), arb_delta())),
            oldest_first in proptest::collection::vec((arb_delta(), arb_delta()), 1..16),
        ) {
            let base_enc = base.map(|(df, tf)| ts(df, tf));
            let ops: Vec<Vec<u8>> = oldest_first.iter().rev().map(|&(df, tf)| ts(df, tf)).collect();
            let got = full_merge(base_enc.as_deref(), ops.iter().map(Vec::as_slice));
            match ts_model(base, &oldest_first) {
                Some(want) => prop_assert_eq!(MergeOperand::decode(&got?)?, want),
                None => prop_assert!(matches!(got, Err(StorageError::CounterOverflow))),
            }
        }

        #[test]
        fn term_stats_partial_merge_of_any_adjacent_run_preserves_full_merge(
            base in proptest::option::of((arb_delta(), arb_delta())),
            newest_first in proptest::collection::vec((arb_delta(), arb_delta()), 1..16),
            a in any::<prop::sample::Index>(),
            b in any::<prop::sample::Index>(),
        ) {
            let (i, j) = run(newest_first.len(), a, b);
            let base_enc = base.map(|(df, tf)| ts(df, tf));
            let ops: Vec<Vec<u8>> = newest_first.iter().map(|&(df, tf)| ts(df, tf)).collect();
            check_partial_merge_preserves_full_merge(base_enc.as_deref(), &ops, i, j)?;
        }

        #[test]
        fn full_merge_equals_sequential_model(
            base in proptest::option::of(arb_delta()),
            oldest_first in proptest::collection::vec(arb_delta(), 1..16),
        ) {
            let base_enc = base.map(counter);
            let ops: Vec<Vec<u8>> = oldest_first.iter().rev().map(|&d| counter(d)).collect();
            let got = full_merge(base_enc.as_deref(), ops.iter().map(Vec::as_slice));
            match model(base, &oldest_first) {
                Some(want) => prop_assert_eq!(decode_counter(&got?), want),
                None => prop_assert!(matches!(got, Err(StorageError::CounterOverflow))),
            }
        }

        #[test]
        fn partial_merge_of_any_adjacent_run_preserves_full_merge(
            base in proptest::option::of(arb_delta()),
            newest_first in proptest::collection::vec(arb_delta(), 1..16),
            a in any::<prop::sample::Index>(),
            b in any::<prop::sample::Index>(),
        ) {
            let (i, j) = run(newest_first.len(), a, b);
            let base_enc = base.map(counter);
            let ops: Vec<Vec<u8>> = newest_first.iter().map(|&d| counter(d)).collect();
            check_partial_merge_preserves_full_merge(base_enc.as_deref(), &ops, i, j)?;
        }
    }

    /// Compaction contract (storage-engine.md §8): for an overflowing run `full_merge` errors and
    /// `partial_merge` declines, so compaction can keep the operands; once a newer operand brings
    /// the total back into range, the kept operands full-merge to the exact value.
    #[test]
    fn overflowing_run_full_merge_errors_and_partial_merge_declines() -> Result<()> {
        type Enc = fn(i64) -> Vec<u8>;
        let encoders: [(&str, Enc); 3] = [
            ("counter", counter),
            ("term stats df", |d| ts(d, 0)),
            ("term stats tf_sum", |d| ts(0, d)),
        ];
        for (name, enc) in encoders {
            // Newest first: total is i64::MAX + 1.
            let ops = [enc(1), enc(i64::MAX)];
            let slices = || ops.iter().map(Vec::as_slice);
            assert!(
                matches!(
                    full_merge(None, slices()),
                    Err(StorageError::CounterOverflow)
                ),
                "{name}"
            );
            assert!(
                matches!(
                    full_merge(Some(&enc(0)), slices()),
                    Err(StorageError::CounterOverflow)
                ),
                "{name}"
            );
            assert_eq!(partial_merge(slices())?, None, "{name}");

            // A later operand brings the total back: kept operands + it merge exactly.
            let back = [enc(-2), enc(1), enc(i64::MAX)];
            let v = full_merge(None, back.iter().map(Vec::as_slice))?;
            assert_eq!(
                MergeOperand::decode(&v)?,
                MergeOperand::decode(&enc(i64::MAX - 1))?
            );
        }
        Ok(())
    }

    #[test]
    fn term_stats_tf_sum_overflow_with_df_in_range_declines_partial_merge() -> Result<()> {
        let ops = [ts(1, 1), ts(1, i64::MAX)];
        assert_eq!(partial_merge(ops.iter().map(Vec::as_slice))?, None);
        assert!(matches!(
            full_merge(None, ops.iter().map(Vec::as_slice)),
            Err(StorageError::CounterOverflow)
        ));
        // Same df with tf_sum in range does merge, so `None` above is due to tf_sum alone.
        let ok = [ts(1, 1), ts(1, i64::MAX - 1)];
        assert_eq!(
            partial_merge(ok.iter().map(Vec::as_slice))?,
            Some(ts(2, i64::MAX))
        );
        Ok(())
    }

    #[test]
    fn non_minimal_varint_is_corruption() {
        // CounterDelta(0) is `[1, 1, 0]`; `0x80 0x00` is an over-long zero.
        assert_eq!(counter(0), [FORMAT_VERSION, TAG_COUNTER_DELTA, 0]);
        let over_long: &[u8] = &[FORMAT_VERSION, TAG_COUNTER_DELTA, 0x80, 0x00];
        assert!(MergeOperand::decode(over_long).is_err_and(|e| e.is_corruption()));
        // TermStats{df: 1, tf_sum: 0} with df written as the over-long `0x82 0x00`.
        assert_eq!(ts(1, 0), [FORMAT_VERSION, TAG_TERM_STATS, 2, 0]);
        let ts_over_long: &[u8] = &[FORMAT_VERSION, TAG_TERM_STATS, 0x82, 0x00, 0];
        assert!(MergeOperand::decode(ts_over_long).is_err_and(|e| e.is_corruption()));
    }

    /// A base `Put` that is not a merge value (here: arbitrary document bytes) is storage
    /// corruption, `RGN-5002` (storage-engine.md §8: the storage layer cannot tell a usage error).
    #[test]
    fn non_merge_base_value_maps_to_rgn_5002() {
        use rustegon_common::{Error, ErrorCode};
        let document = br#"{"name":"x"}"#;
        let err = match full_merge(Some(document), [counter(1).as_slice()]) {
            Err(e) => e,
            Ok(v) => panic!("non-merge base accepted: {v:?}"),
        };
        assert!(err.is_corruption(), "{err:?}");
        assert_eq!(Error::from(err).code(), ErrorCode::StorageCorruption);
    }

    #[test]
    fn tombstone_base_restarts_from_zero() -> Result<()> {
        let ops = [counter(3), counter(4)];
        let on_tombstone = full_merge(None, ops.iter().map(Vec::as_slice))?;
        let on_base = full_merge(Some(&counter(100)), ops.iter().map(Vec::as_slice))?;
        assert_eq!(decode_counter(&on_tombstone), 7);
        assert_eq!(decode_counter(&on_base), 107);
        Ok(())
    }

    #[test]
    fn base_without_operands_is_the_base() -> Result<()> {
        let v = full_merge(Some(&counter(-5)), std::iter::empty())?;
        assert_eq!(decode_counter(&v), -5);
        Ok(())
    }

    #[test]
    fn overflow_is_counter_overflow_and_maps_to_rgn_1009() {
        let ops = [counter(i64::MAX), counter(1)];
        let err = full_merge(None, ops.iter().map(Vec::as_slice));
        assert!(matches!(err, Err(StorageError::CounterOverflow)));
        let ops = [counter(i64::MIN), counter(-1)];
        let err = full_merge(None, ops.iter().map(Vec::as_slice));
        assert!(matches!(err, Err(StorageError::CounterOverflow)));
    }

    #[test]
    fn transient_overflow_is_not_an_error() -> Result<()> {
        let ops = [counter(i64::MIN), counter(i64::MAX), counter(i64::MAX)];
        // Run of the two MAXes cannot become one operand; full merge is still exact.
        assert_eq!(partial_merge(ops[1..].iter().map(Vec::as_slice))?, None);
        assert_eq!(
            decode_counter(&full_merge(None, ops.iter().map(Vec::as_slice))?),
            i64::MAX - 1
        );
        Ok(())
    }

    #[test]
    fn term_stats_sum_per_field_and_overflow_per_field() -> Result<()> {
        let ops = [ts(1, 5), ts(-1, -2), ts(2, 7)];
        let v = full_merge(Some(&ts(10, 100)), ops.iter().map(Vec::as_slice))?;
        assert_eq!(
            MergeOperand::decode(&v)?,
            MergeOperand::TermStats {
                df_delta: 12,
                tf_sum_delta: 110
            }
        );
        let ops = [ts(0, i64::MAX), ts(0, 1)];
        assert!(matches!(
            full_merge(None, ops.iter().map(Vec::as_slice)),
            Err(StorageError::CounterOverflow)
        ));
        Ok(())
    }

    #[test]
    fn mixed_types_and_garbage_are_corruption() {
        let ts = MergeOperand::TermStats {
            df_delta: 1,
            tf_sum_delta: 1,
        }
        .encode();
        let mixed = [counter(1), ts];
        assert!(
            full_merge(None, mixed.iter().map(Vec::as_slice)).is_err_and(|e| e.is_corruption())
        );

        let mut trailing = counter(1);
        trailing.push(0);
        let cases: [&[u8]; 6] = [&[], &[2, 1, 0], &[1], &[1, 9, 0], &[1, 1, 0x80], &trailing];
        for bytes in cases {
            assert!(
                MergeOperand::decode(bytes).is_err_and(|e| e.is_corruption()),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn empty_input_is_invalid_argument() {
        assert!(matches!(
            full_merge(None, std::iter::empty()),
            Err(StorageError::InvalidArgument(_))
        ));
        assert!(matches!(
            partial_merge(std::iter::empty()),
            Err(StorageError::InvalidArgument(_))
        ));
    }

    #[test]
    fn small_deltas_encode_compactly() {
        assert_eq!(counter(1), [FORMAT_VERSION, TAG_COUNTER_DELTA, 2]);
        assert_eq!(counter(-1), [FORMAT_VERSION, TAG_COUNTER_DELTA, 1]);
    }
}
