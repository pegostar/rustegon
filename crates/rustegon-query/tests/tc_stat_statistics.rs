// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Statistics and the v1 cardinality model (query-engine.md §2–§3; *Provisional (PD pending)*
//! test ids TC-STAT-001…005, proposed in the M3 wave 2 lane G report):
//! - TC-STAT-001 `HyperLogLog` error within 3σ (σ = 1.04/√m) on seeded data;
//! - TC-STAT-002 MCV and histogram accuracy on a skewed (Zipf) distribution, full and sampled;
//! - TC-STAT-003 conjunction damping math through the public estimator;
//! - TC-STAT-004 estimator vs true counts on generated documents.
//!
//! Measured errors are printed to stderr (`cargo nextest run --no-capture`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names
)]

use std::ops::Bound;

use rustegon_doc::{
    Document, Value,
    keyenc::{Direction, encode_element},
};
use rustegon_query::stats::{
    CollectionStats, HyperLogLog, Predicate, StatsCollector, StatsConfig, damped_and,
    estimate_rows, selectivity,
};

/// `SplitMix64`, the test's own seeded generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Zipf(s) over ranks `1..=n` by inverse CDF.
struct Zipf(Vec<f64>);

impl Zipf {
    fn new(n: usize, s: f64) -> Self {
        let mut cdf = Vec::with_capacity(n);
        let mut acc = 0.0;
        for k in 1..=n {
            acc += 1.0 / (k as f64).powf(s);
            cdf.push(acc);
        }
        for c in &mut cdf {
            *c /= acc;
        }
        Self(cdf)
    }

    fn sample(&self, rng: &mut Rng) -> i64 {
        let u = rng.unit();
        (self.0.partition_point(|c| *c < u) + 1) as i64
    }
}

fn enc(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_element(&mut out, Some(v), Direction::Ascending).unwrap();
    out
}

fn doc(fields: Vec<(&str, Value)>) -> Document {
    Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()).unwrap()
}

// ---------------------------------------------------------------------------------------------

#[test]
fn tc_stat_001_hll_error_within_theoretical_bound() {
    let sigma = HyperLogLog::standard_error();
    let mut worst: f64 = 0.0;
    let mut sum_abs = 0.0;
    let mut runs = 0.0;
    for n in [
        10u64, 100, 1_000, 5_000, 10_000, 20_000, 50_000, 100_000, 1_000_000,
    ] {
        for seed in 0..3u64 {
            let mut h = HyperLogLog::new();
            let base = seed.wrapping_mul(0x1_0000_0000);
            for i in 0..n {
                h.add(&enc(&Value::Int64((base + i) as i64)));
                // Duplicates must not count.
                if i % 7 == 0 {
                    h.add(&enc(&Value::Float64((base + i) as f64)));
                }
            }
            let err = (h.estimate() - n as f64).abs() / n as f64;
            eprintln!("TC-STAT-001 n={n} seed={seed} relative error={err:.5}");
            assert!(err <= 3.0 * sigma, "n={n} seed={seed}: error {err} > 3σ");
            worst = worst.max(err);
            sum_abs += err;
            runs += 1.0;
        }
    }
    let mean = sum_abs / runs;
    eprintln!("TC-STAT-001 σ={sigma:.5} worst={worst:.5} mean={mean:.5}");
    assert!(mean <= 1.5 * sigma, "mean error {mean} above 1.5σ");
    // Merging the sketches of two halves equals the sketch of the whole.
    let (mut a, mut b, mut all) = (HyperLogLog::new(), HyperLogLog::new(), HyperLogLog::new());
    for i in 0..20_000i64 {
        let k = enc(&Value::Int64(i));
        if i % 2 == 0 {
            a.add(&k);
        } else {
            b.add(&k);
        }
        all.add(&k);
    }
    a.merge(&b);
    assert_eq!(a, all);
}

/// 100 000 rows, `z` Zipf(1.1) over 1 000 ranks.
fn zipf_stats(sample_size: Option<usize>) -> (CollectionStats, Vec<i64>) {
    let zipf = Zipf::new(1000, 1.1);
    let mut rng = Rng(42);
    let config = StatsConfig {
        sample_size,
        ..StatsConfig::default()
    };
    let mut c = StatsCollector::new(config, 1, 2, &["z".to_owned()]);
    let mut values = Vec::with_capacity(100_000);
    for _ in 0..100_000 {
        let z = zipf.sample(&mut rng);
        values.push(z);
        c.add_document(&doc(vec![("z", Value::Int64(z))]), 16);
    }
    (c.finish(0), values)
}

#[test]
fn tc_stat_002_mcv_and_histogram_on_skewed_data() {
    for (label, sample, mcv_tol, range_tol) in [
        ("full", None, 1e-9, 0.01),
        ("sample-30000", Some(30_000), 0.01, 0.02),
    ] {
        let (stats, values) = zipf_stats(sample);
        let f = stats.field("z").unwrap();
        let n = values.len() as f64;
        // NDV: the HLL over every row, not the sample.
        let true_ndv = {
            let mut v = values.clone();
            v.sort_unstable();
            v.dedup();
            v.len() as f64
        };
        let ndv_err = (f.ndv as f64 - true_ndv).abs() / true_ndv;
        assert!(
            ndv_err <= 3.0 * HyperLogLog::standard_error(),
            "{label}: ndv {ndv_err}"
        );
        // MCV: the heaviest ranks, with their true frequencies.
        assert_eq!(f.mcv.len(), 20, "{label}");
        assert_eq!(f.mcv[0].value, enc(&Value::Int64(1)), "{label}");
        let mut worst_mcv: f64 = 0.0;
        for m in &f.mcv {
            let truth = values
                .iter()
                .filter(|v| enc(&Value::Int64(**v)) == m.value)
                .count() as f64
                / n;
            worst_mcv = worst_mcv.max((m.fraction - truth).abs());
        }
        assert!(worst_mcv <= mcv_tol, "{label}: MCV error {worst_mcv}");
        // Histogram buckets: equi-depth over the non-MCV mass.
        let h = &f.histogram;
        assert_eq!(h.buckets.len(), 64, "{label}");
        let depth = h.total_fraction() / 64.0;
        let worst_depth = h
            .buckets
            .iter()
            .map(|b| (b.fraction - depth).abs() / depth)
            .fold(0.0, f64::max);
        // Integer-valued data: a bucket boundary cannot split a value, so a bucket may exceed
        // the target by up to one value's mass.
        assert!(
            worst_depth <= 1.0,
            "{label}: bucket depth deviation {worst_depth}"
        );
        // Ranges vs truth.
        let mut rng = Rng(7);
        let mut worst_range: f64 = 0.0;
        for _ in 0..200 {
            let a = rng.below(1000) as i64 + 1;
            let b = rng.below(1000) as i64 + 1;
            let (lo, hi) = (a.min(b), a.max(b));
            let truth = values.iter().filter(|v| **v >= lo && **v < hi).count() as f64 / n;
            let est = selectivity(
                &stats,
                &Predicate::Range {
                    path: "z".into(),
                    lower: Bound::Included(Value::Int64(lo)),
                    upper: Bound::Excluded(Value::Int64(hi)),
                },
            );
            worst_range = worst_range.max((est - truth).abs());
        }
        eprintln!(
            "TC-STAT-002 {label}: ndv error={ndv_err:.5} worst MCV abs error={worst_mcv:.5} \
             worst bucket depth deviation={worst_depth:.3} worst range abs error={worst_range:.5}"
        );
        assert!(
            worst_range <= range_tol,
            "{label}: range error {worst_range}"
        );
    }
}

#[test]
fn tc_stat_003_conjunction_damping_and_disjunction() {
    // s sorted ascending: 0.01, 0.1, 0.5 → 0.01 × 0.1^½ × 0.5^¼.
    let expected = 0.01 * 0.1f64.sqrt() * 0.5f64.powf(0.25);
    assert!((damped_and(vec![0.5, 0.01, 0.1]) - expected).abs() < 1e-15);
    // Through the estimator: three fields with exact single-value fractions.
    let mut c = StatsCollector::new(
        StatsConfig {
            sample_size: None,
            ..StatsConfig::default()
        },
        1,
        2,
        &[],
    );
    for i in 0..1000i64 {
        c.add_document(
            &doc(vec![
                ("a", Value::Bool(i % 100 == 0)),
                ("b", Value::Bool(i % 10 == 0)),
                ("c", Value::Bool(i % 2 == 0)),
            ]),
            10,
        );
    }
    let stats = c.finish(0);
    let eq = |p: &str| Predicate::Eq {
        path: p.into(),
        value: Value::Bool(true),
    };
    let and = Predicate::And(vec![eq("c"), eq("a"), eq("b")]);
    assert!((selectivity(&stats, &and) - expected).abs() < 1e-12);
    let or = Predicate::Or(vec![eq("a"), eq("b")]);
    assert!((selectivity(&stats, &or) - (1.0 - 0.99 * 0.9)).abs() < 1e-12);
}

/// Generated documents: `u` uniform over 1000 values, `z` Zipf(1.2) over 500, `s` one of 8
/// strings, `n` 30 % null / 10 % missing / else 0..50, `tags` arrays of 0–5 of 20 tags.
fn generated(rows: usize, seed: u64) -> Vec<Document> {
    let mut rng = Rng(seed);
    let zipf = Zipf::new(500, 1.2);
    let names = ["ant", "bee", "cat", "dog", "eel", "fox", "gnu", "hen"];
    (0..rows)
        .map(|i| {
            let mut fields = vec![
                ("_id", Value::Int64(i as i64)),
                ("u", Value::Int64(rng.below(1000) as i64)),
                ("z", Value::Int64(zipf.sample(&mut rng))),
                ("s", Value::String(names[rng.below(8) as usize].into())),
            ];
            let r = rng.below(100);
            if r < 30 {
                fields.push(("n", Value::Null));
            } else if r >= 40 {
                fields.push(("n", Value::Int64(rng.below(50) as i64)));
            }
            let len = rng.below(6);
            let tags = (0..len)
                .map(|_| Value::String(format!("t{}", rng.below(20))))
                .collect();
            fields.push(("tags", Value::Array(tags)));
            doc(fields)
        })
        .collect()
}

/// Reference evaluation of a predicate on one document (values compared by key encoding,
/// arrays match when an element matches, like the estimator's multikey rule).
fn matches(d: &Document, p: &Predicate) -> bool {
    let vals = |path: &str| -> Option<Vec<Value>> {
        d.get(path).map(|v| match v {
            Value::Array(items) if !items.is_empty() => items.clone(),
            other => vec![other.clone()],
        })
    };
    let inside = |k: &[u8], lo: &Bound<Value>, hi: &Bound<Value>| {
        (match lo {
            Bound::Unbounded => true,
            Bound::Included(x) => k >= enc(x).as_slice(),
            Bound::Excluded(x) => k > enc(x).as_slice(),
        }) && (match hi {
            Bound::Unbounded => true,
            Bound::Included(x) => k <= enc(x).as_slice(),
            Bound::Excluded(x) => k < enc(x).as_slice(),
        })
    };
    match p {
        Predicate::Eq { path, value } => {
            vals(path).is_some_and(|vs| vs.iter().any(|v| enc(v) == enc(value)))
        }
        Predicate::In { path, values } => values.iter().any(|v| {
            matches(
                d,
                &Predicate::Eq {
                    path: path.clone(),
                    value: v.clone(),
                },
            )
        }),
        Predicate::Range { path, lower, upper } => vals(path).is_some_and(|vs| {
            vs.iter()
                .any(|v| !matches!(v, Value::Null) && inside(&enc(v), lower, upper))
        }),
        Predicate::IsNull { path } => vals(path).is_none_or(|vs| vs.contains(&Value::Null)),
        Predicate::IsMissing { path } => d.get(path).is_none(),
        Predicate::And(ps) => ps.iter().all(|p| matches(d, p)),
        Predicate::Or(ps) => ps.iter().any(|p| matches(d, p)),
        Predicate::Not(p) => !matches(d, p),
        Predicate::Other => true,
    }
}

#[test]
fn tc_stat_004_estimator_vs_true_counts() {
    let docs = generated(50_000, 99);
    let mut c = StatsCollector::new(
        StatsConfig::default(),
        1,
        2,
        &["u".to_owned(), "tags".to_owned()],
    );
    for d in &docs {
        c.add_document(d, 64);
    }
    let stats = c.finish(0);
    let n = docs.len() as f64;
    let int = Value::Int64;
    let s = |v: &str| Value::String(v.into());
    let range = |p: &str, lo: i64, hi: i64| Predicate::Range {
        path: p.into(),
        lower: Bound::Included(int(lo)),
        upper: Bound::Excluded(int(hi)),
    };
    let eq = |p: &str, v: Value| Predicate::Eq {
        path: p.into(),
        value: v,
    };
    // (label, predicate, tolerance as a fraction of the collection)
    let cases: Vec<(&str, Predicate, f64)> = vec![
        ("u = 17", eq("u", int(17)), 0.002),
        ("u = 999", eq("u", int(999)), 0.002),
        (
            "u IN (1,2,3,2.0)",
            Predicate::In {
                path: "u".into(),
                values: vec![int(1), int(2), int(3), Value::Float64(2.0)],
            },
            0.003,
        ),
        ("u in [100,350)", range("u", 100, 350), 0.02),
        ("u in [0,10)", range("u", 0, 10), 0.01),
        ("z = 1", eq("z", int(1)), 0.01),
        ("z = 2", eq("z", int(2)), 0.01),
        ("z = 300", eq("z", int(300)), 0.002),
        ("z in [10,500)", range("z", 10, 500), 0.02),
        ("s = 'cat'", eq("s", s("cat")), 0.01),
        ("s = 'zzz'", eq("s", s("zzz")), 0.002),
        ("n IS NULL", Predicate::IsNull { path: "n".into() }, 1e-9),
        (
            "n IS MISSING",
            Predicate::IsMissing { path: "n".into() },
            1e-9,
        ),
        ("n = null", eq("n", Value::Null), 1e-9),
        ("n in [0,25)", range("n", 0, 25), 0.02),
        ("tags = 't3'", eq("tags", s("t3")), 0.01),
        (
            "u<500 AND s='cat'",
            Predicate::And(vec![range("u", 0, 500), eq("s", s("cat"))]),
            0.05,
        ),
        (
            "s='ant' OR s='bee'",
            Predicate::Or(vec![eq("s", s("ant")), eq("s", s("bee"))]),
            0.03,
        ),
        (
            "NOT n IS NULL",
            Predicate::Not(Box::new(Predicate::IsNull { path: "n".into() })),
            1e-9,
        ),
    ];
    let mut worst: f64 = 0.0;
    for (label, p, tol) in &cases {
        let truth = docs.iter().filter(|d| matches(d, p)).count() as f64;
        let est = estimate_rows(&stats, p);
        let err = (est - truth).abs() / n;
        eprintln!("TC-STAT-004 {label}: true={truth} estimated={est:.1} abs error/rows={err:.5}");
        assert!(
            err <= *tol,
            "{label}: estimated {est}, true {truth}, error {err} > {tol}"
        );
        worst = worst.max(err);
    }
    eprintln!("TC-STAT-004 worst abs error/rows={worst:.5}");
    assert!((stats.avg_doc_size() - 64.0).abs() < 1e-9);
}
