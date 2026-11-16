// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures (implementation-rules.md §6; formats freeze at M2 exit, DEC-018):
//! `RDoc` v1 (data-model.md §4) and key encoding v1 (§3.1).
//!
//! - `rdoc/1/<case>.rdoc` + `<case>.json`: the canonical `RDoc` bytes of a fixed document and its
//!   canonical JSON. Compatibility: every committed `.rdoc` must decode to its `.json`, forever.
//!   Stability: the current encoder must reproduce every v1 file byte for byte; a failure means
//!   the format changed and needs a version bump plus new fixtures, not a regeneration.
//! - `keyenc/1/vectors.txt`: golden vectors `<hex> <asc|desc> <canonical JSON | missing>`, listed
//!   in ascending §2.1 order (the test also checks the order).
//!
//! Generate missing fixtures (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-doc --test formats`.

// Test code: casts and short names in reference implementations are deliberate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]

use std::{
    cmp::Ordering,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use rustegon_doc::{
    Document, Value,
    compare::compare,
    json::{JsonMode, parse_document, parse_value, to_json, value_to_json},
    keyenc::{Direction, encode_key},
    rdoc::{decode, encode},
};

fn fixtures(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats")
        .join(rel)
}

fn write_mode() -> bool {
    std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The fixed `RDoc` v1 cases.
fn rdoc_cases() -> Vec<(&'static str, Document)> {
    let p = |s: &str| parse_document(s).unwrap();
    let mut counter = Document::new();
    counter.insert("_id", Value::Int64(1));
    counter.insert("views", Value::Counter(42));
    counter.insert("neg", Value::Counter(-3));
    let many: String = format!(
        "{{{}}}",
        (0..40)
            .map(|i| format!("\"f{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    vec![
        (
            "all_types",
            p(concat!(
                r#"{"_id":{"$oid":"65a1b2c3d4e5f60718293a4b"},"null":null,"t":true,"f":false,"#,
                r#""i":-42,"big":{"$int64":"9223372036854775807"},"x":1.5,"#,
                r#""nan":{"$float":"NaN"},"inf":{"$float":"-Infinity"},"#,
                r#""dec":{"$decimal":"12.50"},"s":"héllo","#,
                r#""bin":{"$binary":{"base64":"AQID","subType":"00"}},"#,
                r#""ubin":{"$binary":{"base64":"ASNFZ4mrze8BI0VniavN7w==","subType":"04"}},"#,
                r#""dt":{"$date":"2026-01-01T00:00:00.000Z"},"ts":{"$ts":"1767225600000.7"},"#,
                r#""u":{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"},"#,
                r#""arr":[1,"two",3.0],"obj":{"k":"v"},"vec":{"$vector":[0.5,-1.0,3.25]},"#,
                r#""min":{"$minKey":1},"max":{"$maxKey":1}}"#
            )),
        ),
        (
            "nested",
            p(r#"{"a":{"b":{"c":[[],{},[{"d":[1,[2,[3]]]}]]}},"e":[{"x":1},{"y":[{}]}],"z":{}}"#),
        ),
        (
            "strings",
            p(&format!(
                r#"{{"empty":"","nul":"a\u0000b","esc":"\"\\\n\t\u0001","uni":"日本語😀","long":"{}","a.b c":"dotted name"}}"#,
                "x".repeat(300)
            )),
        ),
        (
            "numbers",
            p(concat!(
                r#"{"zero":0,"negzero":-0.0,"one":1,"m1":-1,"i64min":{"$int64":"-9223372036854775808"},"#,
                r#""safe":9007199254740992,"unsafe":{"$int64":"9007199254740993"},"#,
                r#""sub":5e-324,"fmax":1.7976931348623157e308,"tenth":0.1,"#,
                r#""dmin":{"$decimal":"1E-6176"},"dmax":{"$decimal":"9.999999999999999999999999999999999E+6144"},"#,
                r#""dneg0":{"$decimal":"-0"},"dinf":{"$decimal":"Infinity"},"dnan":{"$decimal":"NaN"},"#,
                r#""dt_min":{"$date":"-292275055-05-16T16:47:04.192Z"}}"#
            )),
        ),
        ("counter", counter),
        ("many_fields", p(&many)),
        ("empty", Document::new()),
    ]
}

#[test]
fn rdoc_v1_fixtures_stable_and_readable() {
    let dir = fixtures("rdoc/1");
    if write_mode() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, doc) in rdoc_cases() {
        let bytes = encode(&doc).unwrap();
        let json = to_json(&doc, JsonMode::Canonical);
        let (rdoc_path, json_path) = (
            dir.join(format!("{name}.rdoc")),
            dir.join(format!("{name}.json")),
        );
        if write_mode() && !rdoc_path.exists() {
            std::fs::write(&rdoc_path, &bytes).unwrap();
            std::fs::write(&json_path, &json).unwrap();
        }
        let committed = std::fs::read(&rdoc_path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
                rdoc_path.display()
            )
        });
        assert_eq!(bytes, committed, "{name}: RDoc v1 encoder output changed");
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            json,
            "{name}: canonical JSON changed"
        );
    }
    // Compatibility: every committed v1 file decodes to its JSON.
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rdoc") {
            let doc = decode(&std::fs::read(&path).unwrap()).unwrap();
            let json = std::fs::read_to_string(path.with_extension("json")).unwrap();
            assert_eq!(
                to_json(&doc, JsonMode::Canonical),
                json,
                "{}",
                path.display()
            );
            seen += 1;
        }
    }
    assert!(seen >= rdoc_cases().len());
}

/// Golden key vectors in ascending §2.1 order (`None` = missing).
fn key_cases() -> Vec<(Direction, Option<Value>)> {
    let asc: Vec<Option<Value>> = std::iter::once(Some(r#"{"$minKey":1}"#))
        .chain(std::iter::once(None))
        .chain(
            [
                "null",
                r#"{"$float":"NaN"}"#,
                r#"{"$float":"-Infinity"}"#,
                r#"{"$decimal":"-1E+6144"}"#,
                "-1.7976931348623157e308",
                r#"{"$int64":"-9223372036854775808"}"#,
                "-123",
                "-1",
                "-0.5",
                r#"{"$decimal":"-1E-6176"}"#,
                "0",
                "5e-324",
                "0.1",
                "1",
                "1.5",
                "123",
                r#"{"$int64":"9223372036854775807"}"#,
                r#"{"$decimal":"12345678901234567890123456789012.34"}"#,
                "1e300",
                r#"{"$float":"Infinity"}"#,
                r#""""#,
                r#""a""#,
                r#""a\u0000""#,
                r#""ab""#,
                r#""é""#,
                "{}",
                r#"{"a":1}"#,
                r#"{"a":1,"b":null}"#,
                r#"{"b":0}"#,
                "[]",
                "[1]",
                r#"[1,"x"]"#,
                "[2]",
                r#"{"$binary":{"base64":"","subType":"00"}}"#,
                r#"{"$binary":{"base64":"AQ==","subType":"00"}}"#,
                r#"{"$binary":{"base64":"AQ==","subType":"80"}}"#,
                r#"{"$oid":"65a1b2c3d4e5f60718293a4b"}"#,
                r#"{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"}"#,
                "false",
                "true",
                r#"{"$date":"1969-12-31T23:59:59.999Z"}"#,
                r#"{"$date":"1970-01-01T00:00:00.000Z"}"#,
                r#"{"$ts":"1.0"}"#,
                r#"{"$ts":"1.1"}"#,
                r#"{"$vector":[]}"#,
                r#"{"$vector":[-1.0]}"#,
                r#"{"$vector":[0.5]}"#,
                r#"{"$vector":[0.5,0.25]}"#,
            ]
            .into_iter()
            .map(Some),
        )
        .chain(std::iter::once(Some(r#"{"$maxKey":1}"#)))
        .map(|j| j.map(|j| parse_value(j).unwrap()))
        .collect();
    let mut cases: Vec<(Direction, Option<Value>)> = asc
        .iter()
        .cloned()
        .map(|v| (Direction::Ascending, v))
        .collect();
    for j in ["1", "-1", r#""a""#, "[1]", r#"{"a":1}"#] {
        cases.push((Direction::Descending, Some(parse_value(j).unwrap())));
    }
    cases.push((Direction::Descending, None));
    cases
}

fn key_line(dir: Direction, v: Option<&Value>) -> String {
    let key = encode_key(&[(v, dir)]).unwrap();
    let d = if dir == Direction::Ascending {
        "asc"
    } else {
        "desc"
    };
    let text = v.map_or_else(
        || "missing".to_owned(),
        |v| value_to_json(v, JsonMode::Canonical),
    );
    format!("{} {d} {text}", hex(&key))
}

#[test]
fn keyenc_v1_golden_vectors() {
    let path = fixtures("keyenc/1/vectors.txt");
    let cases = key_cases();
    let expected: String = cases
        .iter()
        .map(|(d, v)| key_line(*d, v.as_ref()) + "\n")
        .collect();
    if write_mode() && !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &expected).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            path.display()
        )
    });
    for (got, want) in expected.lines().zip(committed.lines()) {
        assert_eq!(got, want, "key encoding v1 changed");
    }
    assert_eq!(expected.lines().count(), committed.lines().count());

    // The ascending vectors are strictly increasing, in bytes and in the §2.1 order.
    let asc: Vec<&(Direction, Option<Value>)> = cases
        .iter()
        .filter(|(d, _)| *d == Direction::Ascending)
        .collect();
    for w in asc.windows(2) {
        let (a, b) = (w[0].1.as_ref(), w[1].1.as_ref());
        let (ka, kb) = (
            encode_key(&[(a, Direction::Ascending)]).unwrap(),
            encode_key(&[(b, Direction::Ascending)]).unwrap(),
        );
        assert!(ka < kb, "{a:?} < {b:?}");
        assert_eq!(compare(a, b), Ordering::Less, "{a:?} < {b:?}");
    }
}
