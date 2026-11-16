// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! AC-DRV-003 cross-driver report (conformance README §6): compares the
//! `conformance-results.json` files written by the driver runners test by test and checks the
//! `r1` coverage of `model.yaml`.
//!
//! The files come from `RGN_DRIVER_RESULTS`, a comma-separated list of paths; the first one is
//! the reference (`scripts/ci-local.sh` passes .NET, then Java on JDK 21 and JDK 25). Without
//! the variable the test only prints how to run it, so the plain Rust gate needs no driver
//! toolchain. For every pair (reference, other):
//! - both list every test id of the suite, with the same status;
//! - for a test both passed, `observations` and `outcome` are identical once re-serialised as
//!   compact JSON with sorted keys (whitespace and string escaping are encoding details of the
//!   writers, not observations);
//! - no test failed.
//!
//! Coverage: an `r1` operation is covered when a test that `covers` it passed in every file;
//! AC-DRV-003 needs all of them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod drivers_support;

use std::collections::{BTreeMap, BTreeSet};

use drivers_support::{conformance_dir, load_yaml};
use serde_json::Value as Json;

/// Environment variable naming the results files (comma-separated, reference first).
const RESULTS_ENV: &str = "RGN_DRIVER_RESULTS";

const CATEGORIES: &[&str] = &[
    "crud", "query", "cursor", "bulk", "txn", "errors", "schema", "auth", "client",
];

/// One runner's file: label (driver + path) and results by test id.
struct Run {
    label: String,
    results: BTreeMap<String, Json>,
}

fn load_run(path: &str) -> Run {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let doc: Json = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let driver = doc["driver"].as_str().unwrap_or("?");
    let mut results = BTreeMap::new();
    for r in doc["results"]
        .as_array()
        .unwrap_or_else(|| panic!("{path}: results"))
    {
        let id = r["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{path}: id"))
            .to_owned();
        assert!(
            results.insert(id.clone(), r.clone()).is_none(),
            "{path}: duplicate {id}"
        );
    }
    Run {
        label: format!(
            "{driver} ({})",
            std::path::Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
        ),
        results,
    }
}

/// Test id → `covers` of every test file of the suite.
fn suite_tests() -> BTreeMap<String, Vec<String>> {
    let mut tests = BTreeMap::new();
    for category in CATEGORIES {
        let mut files: Vec<_> = std::fs::read_dir(conformance_dir().join(category))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        files.sort();
        for file in files {
            for t in load_yaml(&file)["tests"].as_array().unwrap() {
                let covers = t["covers"]
                    .as_array()
                    .map(|c| c.iter().map(|x| x.as_str().unwrap().to_owned()).collect())
                    .unwrap_or_default();
                tests.insert(t["id"].as_str().unwrap().to_owned(), covers);
            }
        }
    }
    tests
}

fn r1_operations() -> BTreeSet<String> {
    load_yaml(&conformance_dir().join("model.yaml"))["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|op| op["status"] == "r1")
        .map(|op| op["id"].as_str().unwrap().to_owned())
        .collect()
}

fn status(r: &Json) -> &str {
    r["status"].as_str().unwrap_or("?")
}

/// Compact JSON with sorted keys (`serde_json::Map` is ordered by key without `preserve_order`;
/// with it the writers' order, which README §6 already requires to be sorted, is kept).
fn canonical(v: &Json) -> String {
    serde_json::to_string(v).unwrap()
}

/// Differences between the reference and another run, one line each.
fn compare(reference: &Run, other: &Run, suite: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut diffs = Vec::new();
    for id in suite.keys() {
        let (Some(a), Some(b)) = (reference.results.get(id), other.results.get(id)) else {
            diffs.push(format!(
                "{id}: missing in {}",
                if reference.results.contains_key(id) {
                    &other.label
                } else {
                    &reference.label
                }
            ));
            continue;
        };
        if status(a) != status(b) {
            diffs.push(format!("{id}: status {} vs {}", status(a), status(b)));
            continue;
        }
        if status(a) != "passed" {
            continue;
        }
        for field in ["observations", "outcome"] {
            let (x, y) = (canonical(&a[field]), canonical(&b[field]));
            if x != y {
                diffs.push(format!("{id}: {field} differ\n    {x}\n    {y}"));
            }
        }
    }
    for id in other.results.keys() {
        if !suite.contains_key(id) {
            diffs.push(format!("{id}: not a test of the suite ({})", other.label));
        }
    }
    diffs
}

#[test]
fn ac_drv_003_driver_results_are_identical_and_cover_every_r1_operation() {
    let Ok(paths) = std::env::var(RESULTS_ENV) else {
        println!(
            "{RESULTS_ENV} not set: nothing to compare (set it to the runners' conformance-results \
             files, comma-separated, reference first; scripts/ci-local.sh does)"
        );
        return;
    };
    let runs: Vec<Run> = paths
        .split(',')
        .filter(|p| !p.is_empty())
        .map(load_run)
        .collect();
    assert!(runs.len() >= 2, "{RESULTS_ENV}: at least two files");
    let suite = suite_tests();
    let mut problems = Vec::new();

    for run in &runs {
        let count = |s: &str| run.results.values().filter(|r| status(r) == s).count();
        println!(
            "{}: {} passed, {} failed, {} skipped",
            run.label,
            count("passed"),
            count("failed"),
            count("skipped")
        );
        for (id, r) in &run.results {
            if status(r) == "failed" {
                problems.push(format!("{id}: failed in {}: {}", run.label, r["reason"]));
            }
        }
    }

    let reference = &runs[0];
    for other in &runs[1..] {
        let diffs = compare(reference, other, &suite);
        let identical = suite.len() - diffs.iter().filter(|d| !d.contains("not a test")).count();
        println!(
            "{} vs {}: {identical} of {} tests identical, {} differences",
            reference.label,
            other.label,
            suite.len(),
            diffs.len()
        );
        problems.extend(diffs);
    }

    // Coverage: covered when a covering test passed in every run.
    let r1 = r1_operations();
    let covered: BTreeSet<&String> = suite
        .iter()
        .filter(|(id, _)| {
            runs.iter()
                .all(|r| r.results.get(*id).is_some_and(|x| status(x) == "passed"))
        })
        .flat_map(|(_, covers)| covers)
        .collect();
    let uncovered: Vec<&String> = r1.iter().filter(|op| !covered.contains(op)).collect();
    println!(
        "r1 coverage: {} of {} operations covered by a test passed on every run",
        r1.len() - uncovered.len(),
        r1.len()
    );
    for op in uncovered {
        problems.push(format!("{op}: no covering test passed on every run"));
    }

    assert!(
        problems.is_empty(),
        "AC-DRV-003 not met:\n{}",
        problems.join("\n")
    );
}
