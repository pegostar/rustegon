// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Helpers shared by the driver export and conformance tests of this crate (M11, PD-075):
//! paths of `drivers/conformance/`, YAML loading as JSON values, and the golden-file check
//! (`RGN_FIXTURES_BLESS=1` rewrites, otherwise a stale file fails the test).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use serde_json::{Map, Number, Value as Json};
use yaml_rust2::{Yaml, YamlLoader};

/// Environment variable that turns a golden check into a rewrite (same as `golden_api.rs`).
pub const BLESS_ENV: &str = "RGN_FIXTURES_BLESS";

/// The repository root.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `drivers/conformance/`.
pub fn conformance_dir() -> PathBuf {
    repo_root().join("drivers/conformance")
}

fn blessing() -> bool {
    std::env::var(BLESS_ENV).is_ok_and(|v| v == "1")
}

/// Compares `content` with the checked-in file at `path` (line endings normalised, since a
/// checkout may convert them); with `RGN_FIXTURES_BLESS=1` writes the file instead.
pub fn check_or_bless(path: &Path, content: &str, command: &str) {
    if blessing() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e} (generate with {BLESS_ENV}=1 {command})",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    if committed != content {
        let line = committed
            .lines()
            .zip(content.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "length".to_owned(), |i| format!("line {}", i + 1));
        panic!(
            "{} is stale (first difference: {line}); re-bless with {BLESS_ENV}=1 {command} and review the diff",
            path.display()
        );
    }
}

/// Parses one YAML document (YAML 1.2 core schema subset used by the suite) into JSON.
pub fn yaml_to_json(text: &str, what: &str) -> Json {
    let docs =
        YamlLoader::load_from_str(text).unwrap_or_else(|e| panic!("{what}: invalid YAML: {e}"));
    assert_eq!(docs.len(), 1, "{what}: expected exactly one YAML document");
    convert(&docs[0], what)
}

/// Loads a YAML file as JSON.
pub fn load_yaml(path: &Path) -> Json {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    yaml_to_json(&text, &path.display().to_string())
}

fn convert(y: &Yaml, what: &str) -> Json {
    match y {
        Yaml::Null => Json::Null,
        Yaml::Boolean(b) => Json::Bool(*b),
        Yaml::Integer(i) => Json::Number(Number::from(*i)),
        Yaml::Real(s) => {
            let f: f64 = s.parse().unwrap_or_else(|_| {
                panic!("{what}: YAML float `{s}` is not a finite JSON number (use {{$float: …}})")
            });
            Json::Number(
                Number::from_f64(f).unwrap_or_else(|| panic!("{what}: non-finite float `{s}`")),
            )
        }
        Yaml::String(s) => Json::String(s.clone()),
        Yaml::Array(items) => Json::Array(items.iter().map(|i| convert(i, what)).collect()),
        Yaml::Hash(h) => {
            let mut map = Map::new();
            for (k, v) in h {
                let key = match k {
                    Yaml::String(s) => s.clone(),
                    Yaml::Integer(i) => i.to_string(),
                    other => panic!("{what}: unsupported mapping key {other:?}"),
                };
                assert!(
                    map.insert(key.clone(), convert(v, what)).is_none(),
                    "{what}: duplicate key `{key}`"
                );
            }
            Json::Object(map)
        }
        other => panic!(
            "{what}: unsupported YAML node {other:?} (aliases and tags are not used by the suite)"
        ),
    }
}
