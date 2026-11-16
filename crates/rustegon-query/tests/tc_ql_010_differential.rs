// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-010: the differential-testing harness (query-engine.md §11, AC-QL-002) exercised on the
//! reference interpreter: TLP and `NoREC` self-consistency over ≥ 10 000 generated queries, the
//! differential oracle (reference against itself, including collection state after writes) and
//! planted bugs that the oracles must catch.
//!
//! Budget knobs: `RGQL_DIFF_SEED`, `RGQL_DIFF_CASES`, `RGQL_DIFF_SECONDS` (see
//! `rustegon_query::testkit::runner`). A failure prints the seed and the statement text.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use rustegon_common::Error;
use rustegon_doc::Document;
use rustegon_query::{
    ast::{Expr, IsTest, Select, Statement},
    testkit::{
        Output, Params, QueryEngine, Reference,
        datagen::GenConfig,
        oracle::plant_le_bug,
        runner::{Budget, Stats, run_differential, run_self_oracles},
    },
};

/// Cases of the default self-oracle run: enough for ≥ 10 000 TLP checks (about 4.5 per case).
const SELF_ORACLE_CASES: u64 = 3_000;

fn report(name: &str, stats: &Stats) {
    println!("{name}: {stats:?}");
}

#[test]
fn tc_ql_010_reference_tlp_norec_self_consistency() {
    let budget = Budget::from_env(SELF_ORACLE_CASES);
    let mut engine = Reference::new();
    let config = GenConfig {
        time_dependent: true,
        ..GenConfig::default()
    };
    let stats = run_self_oracles(&budget, &config, &mut engine).unwrap_or_else(|m| panic!("{m}"));
    report("self-oracles", &stats);
    if budget.max_cases >= SELF_ORACLE_CASES && budget.seconds.is_none() {
        assert!(stats.tlp >= 10_000, "only {} TLP checks", stats.tlp);
        assert!(stats.norec >= 10_000, "only {} NoREC checks", stats.norec);
    }
}

#[test]
fn tc_ql_010_reference_against_itself_differential() {
    let budget = Budget::from_env(500);
    let config = GenConfig {
        time_dependent: true,
        ..GenConfig::default()
    };
    let (mut a, mut b) = (Reference::new(), Reference::new());
    let stats =
        run_differential(&budget, &config, &mut a, &mut b).unwrap_or_else(|m| panic!("{m}"));
    report("differential", &stats);
    // The generator must mostly produce statements that run, not errors or unsupported ones.
    // (Unsupported: decimal128 division/rounding, outside the reference scope.)
    assert!(stats.agreed > 3 * stats.same_error, "{stats:?}");
    assert!(stats.unsupported * 100 < stats.statements, "{stats:?}");
}

/// An engine wrapper that rewrites statements before running them: a planted bug.
struct Mutant {
    inner: Reference,
    mutate: fn(&Statement) -> Option<Output>,
    rewrite: fn(&Statement) -> Statement,
}

impl QueryEngine for Mutant {
    #[allow(clippy::unnecessary_literal_bound)] // The trait serves non-literal names too.
    fn name(&self) -> &str {
        "mutant"
    }
    fn reset(&mut self) -> Result<(), Error> {
        self.inner.reset()
    }
    fn load(&mut self, collection: &str, docs: &[Document]) -> Result<(), Error> {
        QueryEngine::load(&mut self.inner, collection, docs)
    }
    fn run(&mut self, stmt: &Statement, params: &Params) -> Result<Output, Error> {
        if let Some(out) = (self.mutate)(stmt) {
            return Ok(out);
        }
        self.inner.run(&(self.rewrite)(stmt), params)
    }
    fn scan(&mut self, collection: &str) -> Result<Vec<Document>, Error> {
        self.inner.scan(collection)
    }
}

fn no_shortcut(_: &Statement) -> Option<Output> {
    None
}

fn identity(s: &Statement) -> Statement {
    s.clone()
}

/// Planted bug 1: `<=` evaluated as `<` in `WHERE` and `SELECT VALUE`. The mutation is a
/// function of the predicate, so the TLP partitions and both `NoREC` forms stay consistent with
/// each other: only the differential oracle can see it.
fn le_as_lt(s: &Statement) -> Statement {
    let mut s = s.clone();
    let filter = match &mut s {
        Statement::Query(q) => {
            if let Some(Select::Value { expr }) = &mut q.select {
                *expr = plant_le_bug(expr);
            }
            q.filter.as_mut()
        }
        Statement::Update(u) => u.filter.as_mut(),
        Statement::Delete(d) => d.filter.as_mut(),
        _ => None,
    };
    if let Some(f) = filter {
        *f = plant_le_bug(f);
    }
    s
}

/// Planted bug 2: `WHERE <p> IS NULL` on a predicate returns no rows (an "optimisation" that
/// forgets three-valued logic). TLP must notice the missing unknown partition.
fn drop_unknown_partition(s: &Statement) -> Option<Output> {
    match s {
        Statement::Query(q)
            if matches!(
                &q.filter,
                Some(Expr::Is { test: IsTest::Null, negated: false, expr }) if !matches!(**expr, Expr::Path { .. })
            ) =>
        {
            Some(Output::default())
        }
        _ => None,
    }
}

#[test]
fn tc_ql_010_planted_bug_caught_by_differential() {
    let mut reference = Reference::new();
    let mut mutant = Mutant {
        inner: Reference::new(),
        mutate: no_shortcut,
        rewrite: le_as_lt,
    };
    let result = run_differential(
        &Budget::cases(500),
        &GenConfig::default(),
        &mut reference,
        &mut mutant,
    );
    let mismatch = result.expect_err("the <= → < mutant must be detected");
    println!("detected as expected:\n{mismatch}");
    assert_eq!(mismatch.oracle, "differential");
    assert!(mismatch.text.contains("<="), "{mismatch}");
}

#[test]
fn tc_ql_010_planted_bug_caught_by_tlp() {
    let mut mutant = Mutant {
        inner: Reference::new(),
        mutate: drop_unknown_partition,
        rewrite: identity,
    };
    let result = run_self_oracles(&Budget::cases(500), &GenConfig::default(), &mut mutant);
    let mismatch = result.expect_err("the dropped IS NULL partition must be detected");
    println!("detected as expected:\n{mismatch}");
    assert_eq!(mismatch.oracle, "tlp");
}

/// Regression (seed 6840335469013531742): a write unsupported on one side only (the reference
/// has no `floor` on `decimal128`) is skipped, not reported as a collection-state mismatch,
/// although the other side applied it.
#[test]
fn tc_ql_010_unsupported_write_skips_state_comparison() {
    use rustegon_doc::Value;
    use rustegon_query::{
        parse_statement,
        testkit::oracle::{Verdict, differential},
    };
    let mut doc = Document::new();
    doc.insert("_id".to_owned(), Value::Int64(1));
    let (mut a, mut b) = (Reference::new(), Reference::new());
    for e in [&mut a, &mut b] {
        QueryEngine::load(e, "t", std::slice::from_ref(&doc)).unwrap();
    }
    // Only `b` applies the update; `a` reports the decimal `floor` as unsupported.
    b.run(
        &parse_statement("UPDATE t SET x = 1 WHERE _id = 1").unwrap(),
        &Params::new(),
    )
    .unwrap();
    let stmt = parse_statement("UPDATE t SET x = floor(1.5m) WHERE _id = 1").unwrap();
    let verdict = differential(&mut a, &mut b, &stmt, &Params::new()).unwrap();
    assert_eq!(verdict, Verdict::Unsupported);
}
