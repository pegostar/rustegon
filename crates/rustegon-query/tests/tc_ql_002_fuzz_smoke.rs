// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! AC-QL-002 stable smoke test: the exact checks of the cargo-fuzz targets
//! (`tests/common/fuzz_check.rs`) on stable Rust, so CI catches regressions without nightly.
//!
//! - every committed crash reproducer under `fuzz/regressions/<target>/` is replayed through its
//!   target's check (a fixed crash stays fixed);
//! - the golden corpora (text inputs and recorded structured JSON) are replayed and
//!   byte-mutated through every target;
//! - arbitrary bytes go through every target.
//!
//! All of it runs on a 2 MiB stack (the Rust/tokio default) in the test profile. Case count:
//! `RGQL_FUZZ_CASES` (default 2000 per property). The real campaign is `fuzz/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{fs, path::PathBuf, sync::OnceLock};

use common::fuzz_check;
use proptest::{collection::vec, prelude::*, test_runner::Config};

const DEFAULT_CASES: u32 = 2000;
const STACK: usize = 2 * 1024 * 1024;

type Check = fn(&[u8]);

/// The fuzz targets (`fuzz/Cargo.toml` `[[bin]]` names) and their checks.
const TARGETS: &[(&str, Check)] = &[
    ("parse_statement", fuzz_check::statement),
    ("parse_script", fuzz_check::script),
    ("roundtrip", fuzz_check::round_trip),
    ("ast_json", fuzz_check::ast_json),
];

fn cases() -> u32 {
    std::env::var("RGQL_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// Golden inputs (RGQL text) and recorded structured JSON, as fuzzing seeds (loaded once).
fn seeds() -> &'static [Vec<u8>] {
    static SEEDS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    SEEDS.get_or_init(load_seeds)
}

fn load_seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for file in ["grammar.rgql", "errors.rgql", "error_positions.rgql"] {
        for case in common::golden::load(file) {
            out.push(case.input.into_bytes());
            for (title, body) in case.sections {
                if title == "json" {
                    out.push(body.into_bytes());
                }
            }
        }
    }
    out
}

#[test]
fn tc_ql_002_fuzz_regressions_stay_fixed() {
    on_small_stack(|| {
        let mut replayed = 0;
        for &(target, check) in TARGETS {
            let dir = fuzz_dir().join("regressions").join(target);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_file() {
                    check(&fs::read(&path).unwrap());
                    replayed += 1;
                }
            }
        }
        eprintln!("replayed {replayed} fuzz regression inputs");
    });
}

#[test]
fn tc_ql_002_fuzz_seed_corpus_passes_every_target() {
    on_small_stack(|| {
        let seeds = seeds();
        assert!(seeds.len() > 200, "golden seed corpus too small");
        for seed in seeds {
            for &(_, check) in TARGETS {
                check(seed);
            }
        }
        // With `RGQL_FUZZ_SEED_DIR=<dir>` the seeds are also written there, one file each, to
        // seed a cargo-fuzz corpus (`fuzz/README.md`).
        if let Some(dir) = std::env::var_os("RGQL_FUZZ_SEED_DIR") {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir).unwrap();
            for (i, seed) in seeds.iter().enumerate() {
                fs::write(dir.join(format!("golden-{i:04}")), seed).unwrap();
            }
        }
    });
}

fn mutate(seed: &[u8], edits: &[(prop::sample::Index, u8, u8)]) -> Vec<u8> {
    let mut data = seed.to_vec();
    for (at, kind, byte) in edits {
        let i = at.index(data.len() + 1);
        match kind % 4 {
            0 if i < data.len() => data[i] = *byte,
            1 => data.insert(i, *byte),
            2 if i < data.len() => {
                data.remove(i);
            }
            _ => {
                // Duplicate a short slice: nesting and repetition.
                let j = (i + 8).min(data.len());
                let dup = data[i..j].to_vec();
                data.splice(i..i, dup);
            }
        }
    }
    data
}

proptest! {
    #![proptest_config(Config { cases: cases(), ..Config::default() })]

    #[test]
    fn tc_ql_002_fuzz_arbitrary_bytes(data in vec(any::<u8>(), 0..256)) {
        on_small_stack(move || {
            for &(_, check) in TARGETS {
                check(&data);
            }
        });
    }

    #[test]
    fn tc_ql_002_fuzz_mutated_seeds(
        pick in any::<prop::sample::Index>(),
        edits in vec((any::<prop::sample::Index>(), any::<u8>(), any::<u8>()), 1..6),
    ) {
        on_small_stack(move || {
            let seeds = seeds();
            let data = mutate(&seeds[pick.index(seeds.len())], &edits);
            for &(_, check) in TARGETS {
                check(&data);
            }
        });
    }
}
