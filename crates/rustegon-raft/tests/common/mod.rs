// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared test support: an in-memory reference model of the log store, a generator of
//! operations valid against it, and a full-state comparison.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeMap, path::Path, sync::Arc};

use rustegon_raft::{HardState, LogBatch, LogStore, LogStoreError, LogStoreOptions};
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_storage::encryption::{FileKekProvider, KekProvider, KeyManager, SecretKey};

/// Directory of the log store in the simulated file system.
pub const DIR: &str = "/store/raft-log";

/// Directory of the log store's DEK registry when encrypted (as `rustegon-engine` lays it out).
pub const KEYS_DIR: &str = "/store/keys/raft-log";

/// Opens the store in [`DIR`] with `segment_size`.
pub fn open(fs: &Arc<SimFileSystem>, segment_size: u64) -> Result<LogStore, LogStoreError> {
    LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size,
            encryption: None,
            archive_floor: None,
        },
    )
}

/// The fixed test KEK (never a real key).
pub fn test_kek() -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([0x5A; 32])))
}

/// The log's key manager in [`KEYS_DIR`] under `kek` (opened, or created on first use);
/// `seed` drives DEK generation.
pub fn keys(
    fs: &Arc<SimFileSystem>,
    kek: Arc<dyn KekProvider>,
    seed: u64,
) -> Result<Arc<KeyManager>, LogStoreError> {
    Ok(Arc::new(KeyManager::open_or_create(
        fs.clone(),
        Path::new(KEYS_DIR),
        kek,
        Arc::new(SimRng::new(seed)),
    )?))
}

/// Opens the store in [`DIR`] encrypted at rest under [`test_kek`] (FR-EAR-001, PD-057).
pub fn open_encrypted(
    fs: &Arc<SimFileSystem>,
    segment_size: u64,
) -> Result<LogStore, LogStoreError> {
    let encryption = Some(keys(fs, test_kek(), 7)?);
    LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size,
            encryption,
            archive_floor: None,
        },
    )
}

/// One logical operation (mirrors `LogBatch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Append {
        group: u64,
        index: u64,
        term: u64,
        payload: Vec<u8>,
    },
    HardState {
        group: u64,
        hs: HardState,
    },
    Truncate {
        group: u64,
        from: u64,
    },
    Purge {
        group: u64,
        up_to: u64,
    },
    Install {
        group: u64,
        index: u64,
        term: u64,
    },
    Remove {
        group: u64,
    },
}

/// Reference state of one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelGroup {
    pub first: u64,
    pub last: u64,
    pub last_term: u64,
    pub boundary_term: u64,
    pub hs: HardState,
    pub entries: BTreeMap<u64, (u64, Vec<u8>)>,
}

impl Default for ModelGroup {
    fn default() -> Self {
        Self {
            first: 1,
            last: 0,
            last_term: 0,
            boundary_term: 0,
            hs: HardState::default(),
            entries: BTreeMap::new(),
        }
    }
}

impl ModelGroup {
    pub fn term(&self, index: u64) -> Option<u64> {
        if index + 1 == self.first {
            return Some(self.boundary_term);
        }
        self.entries.get(&index).map(|e| e.0)
    }
}

/// Reference model of the whole store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Model {
    pub groups: BTreeMap<u64, ModelGroup>,
}

impl Model {
    pub fn group(&self, g: u64) -> ModelGroup {
        self.groups.get(&g).cloned().unwrap_or_default()
    }

    /// Applies one op; `Err` if the store must reject it.
    fn apply(&mut self, op: &Op) -> Result<(), ()> {
        match op {
            Op::Remove { group } => {
                self.groups.remove(group);
                return Ok(());
            }
            Op::Append {
                group,
                index,
                term,
                payload,
            } => {
                let g = self.groups.entry(*group).or_default();
                if *index < g.first || *index > g.last + 1 || *term < g.term(index - 1).ok_or(())? {
                    return Err(());
                }
                g.entries.retain(|&i, _| i < *index);
                g.entries.insert(*index, (*term, payload.clone()));
                g.last = *index;
                g.last_term = *term;
            }
            Op::HardState { group, hs } => self.groups.entry(*group).or_default().hs = *hs,
            Op::Truncate { group, from } => {
                let g = self.groups.entry(*group).or_default();
                if *from > g.last {
                    return Ok(());
                }
                if *from < g.first {
                    return Err(());
                }
                g.last_term = g.term(from - 1).ok_or(())?;
                g.last = from - 1;
                g.entries.retain(|&i, _| i < *from);
            }
            Op::Purge { group, up_to } => {
                let g = self.groups.entry(*group).or_default();
                if *up_to < g.first {
                    return Ok(());
                }
                if *up_to > g.last {
                    return Err(());
                }
                g.boundary_term = g.term(*up_to).ok_or(())?;
                g.first = up_to + 1;
                g.entries.retain(|&i, _| i > *up_to);
            }
            Op::Install { group, index, term } => {
                let g = self.groups.entry(*group).or_default();
                g.entries.clear();
                g.first = index + 1;
                g.last = *index;
                g.last_term = *term;
                g.boundary_term = *term;
            }
        }
        Ok(())
    }

    /// The model after `ops` as one atomic batch, or `None` if the store must reject it.
    pub fn after(&self, ops: &[Op]) -> Option<Model> {
        let mut next = self.clone();
        for op in ops {
            next.apply(op).ok()?;
        }
        Some(next)
    }
}

/// The `LogBatch` for `ops`.
pub fn batch(ops: &[Op]) -> LogBatch {
    let mut b = LogBatch::new();
    for op in ops {
        match op {
            Op::Append {
                group,
                index,
                term,
                payload,
            } => b.append(*group, *index, *term, payload.clone()),
            Op::HardState { group, hs } => b.set_hard_state(*group, *hs),
            Op::Truncate { group, from } => b.truncate_suffix(*group, *from),
            Op::Purge { group, up_to } => b.purge(*group, *up_to),
            Op::Install { group, index, term } => b.install_snapshot(*group, *index, *term),
            Op::Remove { group } => b.remove_group(*group),
        };
    }
    b
}

/// Payload of entry `index` written with `salt`: variable length, recognisable bytes.
pub fn payload(group: u64, index: u64, salt: u64) -> Vec<u8> {
    let len = usize::try_from((index * 7 + salt) % 48).unwrap();
    (0..len)
        .map(|i| u8::try_from((group * 31 + index * 17 + salt + i as u64) % 251).unwrap())
        .collect()
}

/// Number of groups the generators use.
pub const GROUPS: u64 = 4;

/// Turns raw random numbers into one op, valid against `m` (which already includes the
/// batch's earlier ops) unless `kind` selects the deliberately invalid variant (9).
#[allow(clippy::many_single_char_names)] // Raw random inputs have no better names.
pub fn gen_op(m: &Model, kind: u8, g: u64, a: u64, b: u64) -> Op {
    let group = g % GROUPS;
    let s = m.group(group);
    let span = s.last + 1 - s.first; // number of stored entries
    match kind % 10 {
        0..=3 => {
            let index = if a.is_multiple_of(5) && span > 0 {
                s.first + a % span
            } else {
                s.last + 1
            };
            let base = s.term(index - 1).unwrap();
            Op::Append {
                group,
                index,
                term: base + b % 2,
                payload: payload(group, index, b),
            }
        }
        4 => Op::HardState {
            group,
            hs: HardState {
                term: b % 10,
                vote: a % 3,
                commit: a % 50,
            },
        },
        5 => Op::Truncate {
            group,
            from: s.first + a % (span + 1),
        },
        6 => Op::Purge {
            group,
            up_to: s.first - 1 + a % (span + 1),
        },
        7 => Op::Install {
            group,
            index: s.last + a % 5,
            term: s.last_term + b % 2,
        },
        8 => Op::Remove { group },
        _ => Op::Append {
            group,
            index: s.last + 2,
            term: s.last_term,
            payload: vec![1],
        },
    }
}

/// Asserts that `store` holds exactly `model`.
pub fn assert_matches(store: &LogStore, model: &Model, ctx: &str) {
    if let Some(d) = diff(store, model) {
        panic!("{ctx}: {d}");
    }
}

/// The first difference between `store` and `model`, or `None` if the store holds exactly the
/// model's state.
pub fn diff(store: &LogStore, model: &Model) -> Option<String> {
    let mut ids: Vec<u64> = store.groups().collect();
    ids.extend(model.groups.keys());
    ids.sort_unstable();
    ids.dedup();
    for g in ids {
        let m = model.group(g);
        let got = (
            store.first_index(g),
            store.last_index(g),
            store.last_term(g),
            store.hard_state(g),
        );
        let want = (m.first, m.last, m.last_term, m.hs);
        if got != want {
            return Some(format!("group {g} metadata {got:?}, want {want:?}"));
        }
        match store.term(g, m.first - 1) {
            Ok(t) if t == m.boundary_term => {}
            other => return Some(format!("group {g} boundary term {other:?}")),
        }
        let entries = match store.entries(g, m.first, m.last + 1) {
            Ok(e) => e,
            Err(e) => return Some(format!("group {g} entries: {e}")),
        };
        let want: Vec<(u64, u64, Vec<u8>)> = m
            .entries
            .iter()
            .map(|(&i, (t, p))| (i, *t, p.clone()))
            .collect();
        let got: Vec<(u64, u64, Vec<u8>)> = entries
            .into_iter()
            .map(|e| (e.index, e.term, e.payload))
            .collect();
        if got != want {
            return Some(format!("group {g} entries {got:?}, want {want:?}"));
        }
        if store.entries(g, m.last + 1, m.last + 2).is_ok() {
            return Some(format!("group {g} read past the end"));
        }
        if m.first > 1 && store.entries(g, m.first - 1, m.first).is_ok() {
            return Some(format!("group {g} read of a purged entry"));
        }
    }
    None
}

/// splitmix64: reproducible workload randomness.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A workload step.
#[derive(Debug, Clone)]
pub enum Step {
    Batch(Vec<Op>),
    Reopen,
}

/// A reproducible valid workload of `steps` steps, built against the model as it evolves.
pub fn workload(seed: u64, steps: usize) -> Vec<Step> {
    let mut rng = Rng(seed);
    let mut model = Model::default();
    let mut out = Vec::new();
    while out.len() < steps {
        if rng.next().is_multiple_of(12) {
            out.push(Step::Reopen);
            continue;
        }
        let n = 1 + rng.next() % 4;
        let mut ops = Vec::new();
        let mut m = model.clone();
        for _ in 0..n {
            // Skew towards appends; never the invalid kind 9.
            let kind = u8::try_from(rng.next() % 9).unwrap();
            let op = gen_op(&m, kind, rng.next(), rng.next(), rng.next());
            m = m
                .after(std::slice::from_ref(&op))
                .expect("generated op is valid");
            ops.push(op);
        }
        model = m;
        out.push(Step::Batch(ops));
    }
    out
}
