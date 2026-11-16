// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The per-document accumulator of the statistics job (query-engine.md §2 "stats job").
//!
//! The job driver reads every document of a collection inside one read-only transaction (one
//! snapshot) and feeds them to [`StatsCollector::add_document`]:
//! - row-level counters and the NDV sketches see **every** document (cheap, exact counts);
//! - the value distributions (MCV, histogram) come from a reservoir sample of documents
//!   (Vitter's algorithm R, seeded, so a run is reproducible), or from all documents when
//!   [`StatsConfig::sample_size`] is `None` (full scan).
//!
//! Fields collected: every indexed path given at construction, plus top-level fields discovered
//! in the documents (the "sampled unindexed fields" of §2), up to
//! [`StatsConfig::max_unindexed_fields`]; the server-maintained `_rev`, `_createdAt`,
//! `_updatedAt` are skipped. A field discovered at row `n` was missing from the `n` earlier rows
//! (otherwise it would have been discovered there), so its missing count starts at `n`.
//!
//! Value extraction follows the index rule (indexing.md §3.1, PD-032), so statistics describe
//! what an index on the path contains: an object segment selects the field, a numeric segment
//! on an array selects the element, any other segment fans out over the array's object
//! elements, a terminal array yields its distinct elements (an empty array is the value `[]`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rustegon_doc::{
    Document, Value,
    keyenc::{Direction, encode_element},
    path::FieldPath,
};

use super::{
    histogram::Histogram,
    model::{CollectionStats, FieldStats, McvEntry, array_length_bucket},
    to_f64, to_u64,
};

/// Server-maintained fields that carry no selectivity information worth collecting.
const SKIPPED_FIELDS: [&str; 3] = ["_rev", "_createdAt", "_updatedAt"];

/// Settings of a statistics run (`query.stats.*`; *Provisional (PD pending)*, query-engine.md
/// §2.1). Static per run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsConfig {
    /// Documents kept for the value distributions; `None` = all (full scan). Default 30 000
    /// (enough for a 64-bucket histogram within ~1 % per bucket); range 64..=10 000 000.
    pub sample_size: Option<usize>,
    /// Histogram buckets (query-engine.md §2: 64). Range 1..=1024.
    pub histogram_buckets: usize,
    /// MCV list length (query-engine.md §2: 20). Range 0..=1000.
    pub mcv_size: usize,
    /// Unindexed top-level fields discovered per collection. Default 32; range 0..=1024.
    pub max_unindexed_fields: usize,
    /// Seed of the reservoir sampler (reproducible runs; ADR-029).
    pub seed: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            sample_size: Some(30_000),
            histogram_buckets: 64,
            mcv_size: 20,
            max_unindexed_fields: 32,
            seed: 0x5EED_57A7,
        }
    }
}

impl StatsConfig {
    /// Checks the documented ranges.
    ///
    /// # Errors
    /// A message naming the setting out of range.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(n) = self.sample_size
            && !(64..=10_000_000).contains(&n)
        {
            return Err(format!("query.stats.sample_size {n} outside 64..=10000000"));
        }
        if !(1..=1024).contains(&self.histogram_buckets) {
            return Err("query.stats.histogram_buckets outside 1..=1024".into());
        }
        if self.mcv_size > 1000 || self.max_unindexed_fields > 1024 {
            return Err("query.stats.mcv_size or max_unindexed_fields out of range".into());
        }
        Ok(())
    }
}

/// `SplitMix64`: a tiny seeded generator, enough for reservoir slot choice (no new dependency).
#[derive(Debug, Clone)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`); the modulo bias (< n / 2^64) is negligible here.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// One collected field while the job runs.
#[derive(Debug)]
struct Tracked {
    path: FieldPath,
    stats: FieldStats,
}

/// The values one document holds at a path.
#[derive(Debug, Default)]
struct Extracted<'a> {
    values: Vec<&'a Value>,
    array_lengths: Vec<usize>,
}

/// Accumulates statistics of one collection (module docs).
#[derive(Debug)]
pub struct StatsCollector {
    config: StatsConfig,
    database_id: u32,
    collection_id: u32,
    fields: Vec<Tracked>,
    by_name: HashMap<String, usize>,
    unindexed: usize,
    rows: u64,
    bytes: u64,
    /// Sampled rows: per tracked field index, the distinct non-null encoded values.
    reservoir: Vec<BTreeMap<usize, Vec<Vec<u8>>>>,
    rng: SplitMix64,
}

impl StatsCollector {
    /// A collector for `collection_id`, always collecting `indexed_paths` (dot notation;
    /// invalid paths and wildcard paths are skipped: no single field to describe).
    #[must_use]
    pub fn new(
        config: StatsConfig,
        database_id: u32,
        collection_id: u32,
        indexed_paths: &[String],
    ) -> Self {
        let rng = SplitMix64(config.seed);
        let mut c = Self {
            config,
            database_id,
            collection_id,
            fields: Vec::new(),
            by_name: HashMap::new(),
            unindexed: 0,
            rows: 0,
            bytes: 0,
            reservoir: Vec::new(),
            rng,
        };
        for p in indexed_paths {
            if p.ends_with("**") || c.by_name.contains_key(p) {
                continue;
            }
            if let Ok(path) = FieldPath::parse(p) {
                c.track(p, path, true);
            }
        }
        c
    }

    fn track(&mut self, name: &str, path: FieldPath, indexed: bool) -> usize {
        let idx = self.fields.len();
        let mut stats = FieldStats::new(name, indexed);
        // Discovered now: missing from every earlier row (module docs).
        stats.rows_missing = self.rows;
        self.fields.push(Tracked { path, stats });
        self.by_name.insert(name.to_owned(), idx);
        idx
    }

    /// Adds one document of `encoded_len` bytes (its `RDoc` size).
    pub fn add_document(&mut self, doc: &Document, encoded_len: usize) {
        self.discover(doc);
        self.rows += 1;
        self.bytes += encoded_len as u64;
        let slot = self.reservoir_slot();
        let mut sampled = BTreeMap::new();
        for (idx, t) in self.fields.iter_mut().enumerate() {
            let mut ex = Extracted::default();
            extract(doc, t.path.segments(), &mut ex);
            let s = &mut t.stats;
            if ex.values.is_empty() {
                s.rows_missing += 1;
                continue;
            }
            if !ex.array_lengths.is_empty() {
                s.rows_array += 1;
                for len in &ex.array_lengths {
                    s.array_lengths[array_length_bucket(*len as u64)] += 1;
                }
            }
            let mut distinct = BTreeSet::new();
            let mut null = false;
            for v in &ex.values {
                if matches!(v, Value::Null) {
                    null = true;
                    continue;
                }
                let mut out = Vec::new();
                // `counter` is the only non-encodable value and never stored: skip it.
                if encode_element(&mut out, Some(v), Direction::Ascending).is_ok() {
                    distinct.insert(out);
                }
            }
            if null {
                s.rows_null += 1;
            }
            for v in &distinct {
                s.hll.add(v);
            }
            if slot.is_some() && !distinct.is_empty() {
                sampled.insert(idx, distinct.into_iter().collect());
            }
        }
        match slot {
            Some(i) if i < self.reservoir.len() => self.reservoir[i] = sampled,
            Some(_) => self.reservoir.push(sampled),
            None => {}
        }
    }

    /// Starts tracking new top-level fields of `doc`, up to the configured limit.
    fn discover(&mut self, doc: &Document) {
        if self.unindexed >= self.config.max_unindexed_fields {
            return;
        }
        for (name, _) in doc.iter() {
            if self.unindexed >= self.config.max_unindexed_fields {
                break;
            }
            if SKIPPED_FIELDS.contains(&name) || self.by_name.contains_key(name) {
                continue;
            }
            self.track(name, FieldPath::field(name), false);
            self.unindexed += 1;
        }
    }

    /// Algorithm R: the slot the current row takes (`len` = append), or `None` if not sampled.
    /// Called after `rows` counts the current row.
    fn reservoir_slot(&mut self) -> Option<usize> {
        let len = self.reservoir.len();
        match self.config.sample_size {
            None => Some(len),
            Some(k) if len < k => Some(len),
            Some(k) => {
                let j = usize::try_from(self.rng.below(self.rows)).unwrap_or(usize::MAX);
                (j < k).then_some(j)
            }
        }
    }

    /// Rows added so far.
    #[must_use]
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// Finishes the run: computes NDV, MCV lists and histograms.
    #[must_use]
    pub fn finish(self, collected_at_ms: i64) -> CollectionStats {
        let sample_rows = self.reservoir.len() as u64;
        let mut counts: Vec<BTreeMap<Vec<u8>, u64>> = vec![BTreeMap::new(); self.fields.len()];
        for row in self.reservoir {
            for (idx, values) in row {
                if let Some(c) = counts.get_mut(idx) {
                    for v in values {
                        *c.entry(v).or_insert(0) += 1;
                    }
                }
            }
        }
        let fields = self
            .fields
            .into_iter()
            .zip(counts)
            .map(|(t, c)| {
                let mut s = t.stats;
                s.ndv = to_u64(s.hll.estimate());
                distribution(&mut s, c, sample_rows, &self.config);
                s
            })
            .collect();
        CollectionStats {
            database_id: self.database_id,
            collection_id: self.collection_id,
            row_count: self.rows,
            total_bytes: self.bytes,
            sample_rows,
            collected_at_ms,
            fields,
            indexes: Vec::new(),
        }
    }
}

/// Splits the sampled value counts into the MCV list and the histogram of the rest.
///
/// MCV rule (PostgreSQL-like, *Provisional*): when the sample has at most `mcv_size` distinct
/// values all of them are MCVs (the distribution is then exact); otherwise the most frequent
/// values seen at least twice and more than 1.25 × the average count, up to `mcv_size`.
fn distribution(
    s: &mut FieldStats,
    counts: BTreeMap<Vec<u8>, u64>,
    sample_rows: u64,
    config: &StatsConfig,
) {
    if counts.is_empty() || sample_rows == 0 {
        return;
    }
    let rows = to_f64(sample_rows);
    let total: u64 = counts.values().sum();
    let avg = to_f64(total) / to_f64(counts.len() as u64);
    let mut by_count: Vec<(&Vec<u8>, u64)> = counts.iter().map(|(v, c)| (v, *c)).collect();
    // Most frequent first; ties by value for determinism.
    by_count.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let all = counts.len() <= config.mcv_size;
    let mcv: BTreeSet<Vec<u8>> = by_count
        .iter()
        .take(config.mcv_size)
        .filter(|(_, c)| all || (*c >= 2 && to_f64(*c) > 1.25 * avg))
        .map(|(v, _)| (*v).clone())
        .collect();
    s.mcv = by_count
        .iter()
        .filter(|(v, _)| mcv.contains(*v))
        .map(|(v, c)| McvEntry {
            value: (*v).clone(),
            fraction: to_f64(*c) / rows,
        })
        .collect();
    let rest: Vec<(Vec<u8>, u64)> = counts
        .into_iter()
        .filter(|(v, _)| !mcv.contains(v))
        .collect();
    s.histogram = Histogram::build(&rest, sample_rows, config.histogram_buckets);
}

/// Collects the values at `segs` below `doc` (module docs; indexing.md §3.1).
fn extract<'a>(doc: &'a Document, segs: &[rustegon_doc::path::Segment], out: &mut Extracted<'a>) {
    let Some((first, rest)) = segs.split_first() else {
        return;
    };
    if let Some(v) = doc.get(&first.name) {
        extract_value(v, rest, out);
    }
}

fn extract_value<'a>(v: &'a Value, segs: &[rustegon_doc::path::Segment], out: &mut Extracted<'a>) {
    let Some((seg, rest)) = segs.split_first() else {
        match v {
            Value::Array(items) => {
                out.array_lengths.push(items.len());
                if items.is_empty() {
                    out.values.push(v);
                } else {
                    out.values.extend(items.iter());
                }
            }
            _ => out.values.push(v),
        }
        return;
    };
    match v {
        Value::Object(d) => {
            if let Some(child) = d.get(&seg.name) {
                extract_value(child, rest, out);
            }
        }
        Value::Array(items) => {
            if let Some(i) = seg.index {
                if let Some(child) = items.get(i) {
                    extract_value(child, rest, out);
                }
            } else {
                // Fan-out over object elements: the path reached an array (multikey row).
                out.array_lengths.push(items.len());
                for item in items {
                    if let Value::Object(d) = item
                        && let Some(child) = d.get(&seg.name)
                    {
                        extract_value(child, rest, out);
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn doc(fields: Vec<(&str, Value)>) -> Document {
        Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect())
            .unwrap()
    }

    #[test]
    fn extraction_follows_index_rules() {
        let inner = |x: i64| Value::Object(doc(vec![("b", Value::Int64(x))]));
        let d = doc(vec![
            ("a", Value::Array(vec![inner(1), inner(2), Value::Int64(9)])),
            ("e", Value::Array(vec![])),
            ("n", Value::Array(vec![Value::Int64(5), Value::Int64(5)])),
        ]);
        let get = |p: &str| {
            let mut ex = Extracted::default();
            extract(&d, FieldPath::parse(p).unwrap().segments(), &mut ex);
            (ex.values.len(), ex.array_lengths)
        };
        assert_eq!(get("a.b"), (2, vec![3]));
        assert_eq!(get("a.0.b"), (1, vec![]));
        assert_eq!(get("e"), (1, vec![0]));
        assert_eq!(get("n"), (2, vec![2]));
        assert_eq!(get("zz"), (0, vec![]));
    }

    #[test]
    fn discovery_backfills_missing_and_skips_system_fields() {
        let mut c = StatsCollector::new(StatsConfig::default(), 1, 2, &["x".to_owned()]);
        c.add_document(
            &doc(vec![("x", Value::Int64(1)), ("_rev", Value::Null)]),
            10,
        );
        c.add_document(&doc(vec![("x", Value::Null), ("y", Value::Int64(2))]), 20);
        c.add_document(&doc(vec![("y", Value::Array(vec![]))]), 30);
        let s = c.finish(0);
        assert_eq!((s.row_count, s.total_bytes, s.sample_rows), (3, 60, 3));
        assert!(s.field("_rev").is_none());
        let x = s.field("x").unwrap();
        assert!(x.indexed);
        assert_eq!((x.rows_null, x.rows_missing, x.ndv), (1, 1, 1));
        let y = s.field("y").unwrap();
        assert!(!y.indexed);
        assert_eq!((y.rows_missing, y.rows_array, y.ndv), (1, 1, 2));
        assert_eq!(y.array_lengths[0], 1);
        // Few distinct values: all are MCVs, exact fractions of the 3 rows.
        assert_eq!(y.mcv.len(), 2);
        assert!(y.histogram.is_empty());
    }

    #[test]
    fn reservoir_is_bounded_and_seeded() {
        let config = StatsConfig {
            sample_size: Some(100),
            ..StatsConfig::default()
        };
        let run = || {
            let mut c = StatsCollector::new(config.clone(), 1, 2, &[]);
            for i in 0..10_000 {
                c.add_document(&doc(vec![("v", Value::Int64(i))]), 8);
            }
            c.finish(0)
        };
        let (a, b) = (run(), run());
        assert_eq!(a.sample_rows, 100);
        assert_eq!(a, b);
        assert_eq!(a.row_count, 10_000);
    }

    #[test]
    fn config_ranges() {
        assert!(StatsConfig::default().validate().is_ok());
        let bad = StatsConfig {
            sample_size: Some(1),
            ..StatsConfig::default()
        };
        assert!(bad.validate().is_err());
        let bad = StatsConfig {
            histogram_buckets: 0,
            ..StatsConfig::default()
        };
        assert!(bad.validate().is_err());
    }
}
