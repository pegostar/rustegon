// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SCH-002: the selected JSON-Schema-Test-Suite subset (FR-SCH-002, AC-SCH-002).
//!
//! The files under `tests/fixtures/json-schema-test-suite/draft2020-12/` are vendored verbatim
//! from <https://github.com/json-schema-org/JSON-Schema-Test-Suite> (MIT, see the `LICENSE`
//! next to them; revision in `SOURCE.txt`). The subset is one file per keyword of data-model.md
//! §5 plus `boolean_schema.json` (2020-12 boolean schemas): 22 files. Nothing is fetched at test
//! time.
//!
//! Every test case of these files must pass (100 %), except:
//! - the groups in [`UNSUPPORTED_GROUPS`], whose schema uses a keyword outside the subset
//!   (`patternProperties`, `prefixItems`, …). They are not skipped silently: the test asserts
//!   that their schema is **rejected** at compile time, which is the specified behaviour for
//!   unsupported keywords;
//! - the cases in [`DEVIATIONS`], where data-model.md §5 deliberately differs from JSON Schema;
//!   the test asserts that the Rustegon result is the documented opposite.
//!
//! Instances are converted with the document JSON parser (data-model.md §2), exactly as a
//! client document would be.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use rustegon_catalog::{CatalogError, Validator};
use rustegon_doc::json::parse_value;
use serde_json::Value as Json;

/// The selected files (data-model.md §5 keyword list + boolean schemas).
const FILES: [&str; 22] = [
    "type",
    "required",
    "properties",
    "additionalProperties",
    "enum",
    "const",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "boolean_schema",
];

/// (file, group description, unsupported keyword) — schemas that must fail to compile.
const UNSUPPORTED_GROUPS: &[(&str, &str, &str)] = &[
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "patternProperties",
    ),
    (
        "additionalProperties",
        "non-ASCII pattern with additionalProperties",
        "patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties with propertyNames",
        "propertyNames",
    ),
    (
        "additionalProperties",
        "dependentSchemas with additionalProperties",
        "dependentSchemas",
    ),
    ("items", "items and subitems", "$defs"),
    (
        "items",
        "prefixItems with no additional items allowed",
        "prefixItems",
    ),
    (
        "items",
        "items does not look in applicators, valid case",
        "prefixItems",
    ),
    (
        "items",
        "prefixItems validation adjusts the starting index for items",
        "prefixItems",
    ),
    ("items", "items with heterogeneous array", "prefixItems"),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "prefixItems",
    ),
    ("allOf", "allOf combined with anyOf, oneOf", "multipleOf"),
    (
        "not",
        "collect annotations inside a 'not', even if collection is disabled",
        "unevaluatedProperties",
    ),
];

/// (file, group, test, reason) — cases whose expected `valid` is inverted by data-model.md §5.
const DEVIATIONS: &[(&str, &str, &str, &str)] = &[(
    "type",
    "integer type matches integers",
    "a float with zero fractional part is an integer",
    "data-model.md §5: `integer` = int64; `1.0` parses as float64 (§2)",
)];

/// Exact counts of the vendored subset (guards against silent changes of the fixtures or the
/// exclusion lists).
const EXPECTED_TOTAL: usize = 546;
const EXPECTED_UNSUPPORTED: usize = 74;

fn suite_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/json-schema-test-suite/draft2020-12")
}

fn wrap(schema: &Json) -> String {
    format!("{{\"$jsonSchema\":{schema}}}")
}

#[derive(Default)]
struct Tally {
    total: usize,
    passed: usize,
    unsupported: usize,
    deviations: usize,
    failures: Vec<String>,
}

fn run_group(file: &str, group: &Json, tally: &mut Tally) {
    let desc = group["description"].as_str().unwrap();
    let tests = group["tests"].as_array().unwrap();
    tally.total += tests.len();
    let compiled = Validator::compile(&wrap(&group["schema"]));
    if let Some((_, _, kw)) = UNSUPPORTED_GROUPS
        .iter()
        .find(|(f, g, _)| *f == file && *g == desc)
    {
        match compiled {
            Err(CatalogError::InvalidArgument(m)) if m.contains(kw) => {
                tally.unsupported += tests.len();
            }
            other => tally.failures.push(format!(
                "{file} / {desc}: expected rejection of `{kw}`, got {other:?}"
            )),
        }
        return;
    }
    let validator = match compiled {
        Ok(v) => v,
        Err(e) => {
            tally
                .failures
                .push(format!("{file} / {desc}: schema does not compile: {e}"));
            return;
        }
    };
    for t in tests {
        let tdesc = t["description"].as_str().unwrap();
        let expected = t["valid"].as_bool().unwrap();
        let instance = match parse_value(&t["data"].to_string()) {
            Ok(v) => v,
            Err(e) => {
                tally.failures.push(format!(
                    "{file} / {desc} / {tdesc}: instance not representable: {e}"
                ));
                continue;
            }
        };
        let report = validator.validate(&instance);
        let actual = report.is_valid();
        assert_eq!(
            actual,
            validator.is_valid(&instance),
            "{file} / {desc} / {tdesc}: probe and report disagree"
        );
        if !actual {
            // FR-SCH-003: every failure names a pointer and a keyword.
            let first = report.errors.first().expect("invalid report has an error");
            assert!(first.path.is_empty() || first.path.starts_with('/'));
            assert_ne!(first.keyword, "");
        }
        let deviation = DEVIATIONS
            .iter()
            .any(|(f, g, d, _)| *f == file && *g == desc && *d == tdesc);
        if deviation {
            if actual == expected {
                tally.failures.push(format!(
                    "{file} / {desc} / {tdesc}: listed deviation no longer deviates"
                ));
            } else {
                tally.deviations += 1;
            }
        } else if actual == expected {
            tally.passed += 1;
        } else {
            tally.failures.push(format!(
                "{file} / {desc} / {tdesc}: expected valid={expected}, got {actual} ({:?})",
                report.errors.first()
            ));
        }
    }
}

#[test]
fn tc_sch_002_json_schema_test_suite_subset_passes() {
    let mut tally = Tally::default();
    let mut seen_groups = 0usize;
    for file in FILES {
        let path = suite_dir().join(format!("{file}.json"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let groups: Json = serde_json::from_str(&text).unwrap();
        for group in groups.as_array().unwrap() {
            let desc = group["description"].as_str().unwrap();
            if UNSUPPORTED_GROUPS
                .iter()
                .any(|(f, g, _)| *f == file && *g == desc)
            {
                seen_groups += 1;
            }
            run_group(file, group, &mut tally);
        }
    }
    assert!(
        tally.failures.is_empty(),
        "{} failures:\n{}",
        tally.failures.len(),
        tally.failures.join("\n")
    );
    // Every exclusion must still match a group / case of the fixtures (no stale entries).
    assert_eq!(seen_groups, UNSUPPORTED_GROUPS.len());
    assert_eq!(tally.deviations, DEVIATIONS.len());
    assert_eq!(tally.total, EXPECTED_TOTAL);
    assert_eq!(tally.unsupported, EXPECTED_UNSUPPORTED);
    // 100 % of the selected subset (AC-SCH-002).
    assert_eq!(
        tally.passed,
        EXPECTED_TOTAL - EXPECTED_UNSUPPORTED - DEVIATIONS.len()
    );
}
