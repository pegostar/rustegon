// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Statistics of one collection (query-engine.md §2 "Statistics"; layout *Provisional (PD
//! pending)*, query-engine.md §2.1).
//!
//! Row-level counters (`row_count`, `total_bytes`, per-field null / missing / array rows, the
//! NDV sketch, array lengths) are computed over **every** document; the value distribution
//! (MCV list, histogram) over the sampled documents, as fractions of the sampled rows, so it
//! applies to the whole collection without rescaling.
//!
//! Array-valued fields follow the multikey rule of indexing.md §3.1: a row contributes each
//! distinct element once (fractions are "rows containing the value"), so for such fields the
//! MCV and histogram fractions may add up to more than the non-null fraction.

use super::{histogram::Histogram, hll::HyperLogLog, to_f64};

/// Relative change of a statistic above which cached plans are invalidated (query-engine.md
/// §8: "statistics change > 20 %").
pub const STATS_CHANGE_THRESHOLD: f64 = 0.20;

/// Inclusive upper bounds of the array-length distribution buckets (stats format 1):
/// `0, 1, 2, 3, 4, 5–8, 9–16, 17–64, 65–256, > 256`.
pub const ARRAY_LENGTH_BOUNDS: [u64; 10] = [0, 1, 2, 3, 4, 8, 16, 64, 256, u64::MAX];

/// A most-common value.
#[derive(Debug, Clone, PartialEq)]
pub struct McvEntry {
    /// Key-encoded value.
    pub value: Vec<u8>,
    /// Fraction of rows containing it.
    pub fraction: f64,
}

/// Statistics of one field path.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldStats {
    /// Field path (dot notation, data-model.md §2.2).
    pub path: String,
    /// Whether some index covers the path (collected unconditionally) rather than discovered
    /// in the documents.
    pub indexed: bool,
    /// Rows where some extracted value is `null`.
    pub rows_null: u64,
    /// Rows where the path is missing.
    pub rows_missing: u64,
    /// Rows where the path reached an array (multikey rows).
    pub rows_array: u64,
    /// Distinct non-null values (`HyperLogLog` estimate over all rows).
    pub ndv: u64,
    /// The NDV sketch (kept so that per-range statistics can be merged).
    pub hll: HyperLogLog,
    /// Most-common values, by descending fraction (at most 20 by default).
    pub mcv: Vec<McvEntry>,
    /// Equi-depth histogram of the non-null values not in `mcv`.
    pub histogram: Histogram,
    /// Number of arrays per length bucket ([`ARRAY_LENGTH_BOUNDS`]).
    pub array_lengths: [u64; ARRAY_LENGTH_BOUNDS.len()],
}

impl FieldStats {
    /// An empty entry for `path`.
    #[must_use]
    pub fn new(path: impl Into<String>, indexed: bool) -> Self {
        Self {
            path: path.into(),
            indexed,
            rows_null: 0,
            rows_missing: 0,
            rows_array: 0,
            ndv: 0,
            hll: HyperLogLog::new(),
            mcv: Vec::new(),
            histogram: Histogram::default(),
            array_lengths: [0; ARRAY_LENGTH_BOUNDS.len()],
        }
    }

    /// Fraction of MCV-covered rows.
    #[must_use]
    pub fn mcv_fraction(&self) -> f64 {
        self.mcv.iter().map(|m| m.fraction).sum()
    }

    /// Average array length, `None` when no array was seen.
    #[must_use]
    pub fn avg_array_length(&self) -> Option<f64> {
        let arrays: u64 = self.array_lengths.iter().sum();
        if arrays == 0 {
            return None;
        }
        // Bucket midpoints; the open last bucket counts as 512.
        let mut lower = 0u64;
        let mut total = 0.0;
        for (count, upper) in self.array_lengths.iter().zip(ARRAY_LENGTH_BOUNDS) {
            let mid = if upper == u64::MAX {
                512.0
            } else {
                f64::midpoint(to_f64(lower), to_f64(upper))
            };
            total += mid * to_f64(*count);
            lower = upper.saturating_add(1);
        }
        Some(total / to_f64(arrays))
    }
}

/// Bucket index of an array of `len` elements in [`ARRAY_LENGTH_BOUNDS`].
#[must_use]
pub fn array_length_bucket(len: u64) -> usize {
    ARRAY_LENGTH_BOUNDS
        .iter()
        .position(|b| len <= *b)
        .unwrap_or(ARRAY_LENGTH_BOUNDS.len() - 1)
}

/// Size of one index at collection time (FR-IDX-004 "size"; indexing.md §1 `stats`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexSize {
    /// Index id.
    pub index_id: u32,
    /// Number of entries.
    pub entries: u64,
    /// Bytes of keys plus values (logical, without MVCC overhead).
    pub bytes: u64,
}

/// Statistics of one collection (module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct CollectionStats {
    /// Database id.
    pub database_id: u32,
    /// Collection id.
    pub collection_id: u32,
    /// Documents.
    pub row_count: u64,
    /// Sum of the encoded document sizes.
    pub total_bytes: u64,
    /// Documents the value distributions were computed from (`row_count` for a full scan).
    pub sample_rows: u64,
    /// Collection time, ms since the epoch (`datetime`).
    pub collected_at_ms: i64,
    /// Per-field statistics, in collection order (indexed paths first).
    pub fields: Vec<FieldStats>,
    /// Index sizes (filled by the job that scans the index spans).
    pub indexes: Vec<IndexSize>,
}

impl CollectionStats {
    /// Average encoded document size in bytes (0 for an empty collection).
    #[must_use]
    pub fn avg_doc_size(&self) -> f64 {
        if self.row_count == 0 {
            0.0
        } else {
            to_f64(self.total_bytes) / to_f64(self.row_count)
        }
    }

    /// The statistics of `path`, if collected.
    #[must_use]
    pub fn field(&self, path: &str) -> Option<&FieldStats> {
        self.fields.iter().find(|f| f.path == path)
    }
}

/// Relative change from `old` to `new` (`|new − old| / max(old, 1)`).
fn relative_change(old: u64, new: u64) -> f64 {
    to_f64(old.abs_diff(new)) / to_f64(old.max(1))
}

/// Whether statistics changed enough to invalidate cached plans (query-engine.md §8):
/// row count or the NDV of a field present in both changed by more than `threshold`
/// (relative), a null/missing fraction moved by more than `threshold` (absolute), or the set of
/// collected fields differs. *Provisional (PD pending)*: the spec names "> 20 %" without the
/// statistic it applies to.
#[must_use]
pub fn significant_change(old: &CollectionStats, new: &CollectionStats, threshold: f64) -> bool {
    if relative_change(old.row_count, new.row_count) > threshold {
        return true;
    }
    if old.fields.len() != new.fields.len() {
        return true;
    }
    let frac = |n: u64, rows: u64| to_f64(n) / to_f64(rows.max(1));
    for f in &old.fields {
        let Some(g) = new.field(&f.path) else {
            return true;
        };
        let null_old = frac(f.rows_null + f.rows_missing, old.row_count);
        let null_new = frac(g.rows_null + g.rows_missing, new.row_count);
        if relative_change(f.ndv, g.ndv) > threshold || (null_old - null_new).abs() > threshold {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(rows: u64, ndv: u64) -> CollectionStats {
        let mut f = FieldStats::new("a", true);
        f.ndv = ndv;
        CollectionStats {
            database_id: 1,
            collection_id: 2,
            row_count: rows,
            total_bytes: rows * 10,
            sample_rows: rows,
            collected_at_ms: 0,
            fields: vec![f],
            indexes: vec![],
        }
    }

    #[test]
    fn change_signal_threshold() {
        let base = stats(1000, 100);
        assert!(!significant_change(
            &base,
            &stats(1200, 100),
            STATS_CHANGE_THRESHOLD
        ));
        assert!(significant_change(
            &base,
            &stats(1201, 100),
            STATS_CHANGE_THRESHOLD
        ));
        assert!(significant_change(
            &base,
            &stats(799, 100),
            STATS_CHANGE_THRESHOLD
        ));
        assert!(significant_change(
            &base,
            &stats(1000, 121),
            STATS_CHANGE_THRESHOLD
        ));
        let mut other = stats(1000, 100);
        other.fields[0].path = "b".into();
        assert!(significant_change(&base, &other, STATS_CHANGE_THRESHOLD));
        let mut nulls = stats(1000, 100);
        nulls.fields[0].rows_missing = 300;
        assert!(significant_change(&base, &nulls, STATS_CHANGE_THRESHOLD));
    }

    #[test]
    fn array_buckets() {
        assert_eq!(array_length_bucket(0), 0);
        assert_eq!(array_length_bucket(4), 4);
        assert_eq!(array_length_bucket(5), 5);
        assert_eq!(array_length_bucket(1000), 9);
        let mut f = FieldStats::new("a", false);
        assert_eq!(f.avg_array_length(), None);
        f.array_lengths[2] = 2;
        assert_eq!(f.avg_array_length(), Some(2.0));
    }
}
