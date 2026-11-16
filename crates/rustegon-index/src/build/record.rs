// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The persisted job record of one online index build: **index build record format 1**
//! (*Provisional (PD pending)*, database-engine.md §2.3 "checkpoint … stored in the job record";
//! fixture `crates/rustegon-index/tests/fixtures/formats/index_build/1/`).
//!
//! ```text
//! key    0x02 'b' collection_id(u32 BE) index_id(u32 BE)
//! value  { build_format: 1, type: "index_build", database_id, collection_id, index_id,
//!          phase: "build"|"cleanup", cursor?: binary, docs_scanned, entries_written,
//!          error?: string }
//! ```
//! - `cursor`: the full storage key of the last document processed by the backfill (phase
//!   `build`) or of the last index entry deleted (phase `cleanup`); absent before the first
//!   batch of the phase. A batch writes it in the same transaction as its entries, so a crash
//!   resumes exactly after the last committed batch.
//! - `error`: the message of the failure that turned the build into a cleanup (RGN-1022 …).
//!
//! The record lives in the system namespace under its own sub-namespace byte `'b'` (the catalog
//! owns `'d'`, `'n'`, `'s'`, `'i'`), instead of in the index descriptor: a per-batch checkpoint
//! in the descriptor would bump the collection descriptor version on every batch (every index
//! descriptor change does, database-engine.md §2.5) and make every concurrent writer conflict
//! with every batch. The `/sys/jobs` records of `rustegon-jobs` (database-engine.md §7) replace
//! it when that crate exists. Decoding is strict (an unknown field is corruption: a new field
//! means format 2, implementation-rules.md §6).

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, keyspace::NS_SYSTEM, rdoc, value::BINARY_GENERIC};

/// Sub-namespace byte of index build records.
pub const SUB_INDEX_BUILD: u8 = b'b';
/// Index build record format written by this crate.
pub const BUILD_FORMAT: i64 = 1;

const F_FORMAT: &str = "build_format";
const F_TYPE: &str = "type";
const F_DATABASE_ID: &str = "database_id";
const F_COLLECTION_ID: &str = "collection_id";
const F_INDEX_ID: &str = "index_id";
const F_PHASE: &str = "phase";
const F_CURSOR: &str = "cursor";
const F_DOCS: &str = "docs_scanned";
const F_ENTRIES: &str = "entries_written";
const F_ERROR: &str = "error";
const TYPE_BUILD: &str = "index_build";
const FIELDS: &[&str] = &[
    F_FORMAT,
    F_TYPE,
    F_DATABASE_ID,
    F_COLLECTION_ID,
    F_INDEX_ID,
    F_PHASE,
    F_CURSOR,
    F_DOCS,
    F_ENTRIES,
    F_ERROR,
];

/// Phase of the job (the build state proper is the index descriptor's state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPhase {
    /// Walking the index through its build states.
    Build,
    /// The index is `Dropping` (failed or cancelled build): its span is being deleted.
    Cleanup,
}

/// One index build record (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRecord {
    /// Owning database.
    pub database_id: u32,
    /// Owning collection.
    pub collection_id: u32,
    /// The index being built.
    pub index_id: u32,
    /// Phase.
    pub phase: JobPhase,
    /// Resume checkpoint (module docs).
    pub cursor: Option<Vec<u8>>,
    /// Documents processed by the backfill so far.
    pub docs_scanned: u64,
    /// Index entries written by the backfill so far (idempotent re-writes included).
    pub entries_written: u64,
    /// Why the build is being cleaned up, if it failed.
    pub error: Option<String>,
}

impl BuildRecord {
    /// A fresh record of a build that has not started its backfill.
    #[must_use]
    pub fn new(database_id: u32, collection_id: u32, index_id: u32) -> Self {
        Self {
            database_id,
            collection_id,
            index_id,
            phase: JobPhase::Build,
            cursor: None,
            docs_scanned: 0,
            entries_written: 0,
            error: None,
        }
    }

    /// The record's key.
    #[must_use]
    pub fn key(&self) -> Vec<u8> {
        build_record_key(self.collection_id, self.index_id)
    }
}

/// Key of the build record of index `index_id` of collection `collection_id`.
#[must_use]
pub fn build_record_key(collection_id: u32, index_id: u32) -> Vec<u8> {
    let mut k = build_record_prefix();
    k.extend_from_slice(&collection_id.to_be_bytes());
    k.extend_from_slice(&index_id.to_be_bytes());
    k
}

/// Prefix of every build record (the recovery scan).
#[must_use]
pub fn build_record_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_INDEX_BUILD]
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::StorageCorruption,
        format!("index build record: {}", msg.into()),
    )
}

fn count(v: u64) -> Value {
    // Counters cannot reach i64::MAX documents; saturate rather than fail a batch.
    Value::Int64(i64::try_from(v).unwrap_or(i64::MAX))
}

/// Encodes a record into its canonical `RDoc` bytes.
///
/// # Errors
/// Document codec errors (none for valid records).
pub fn encode_build_record(r: &BuildRecord) -> Result<Vec<u8>, Error> {
    let mut doc = Document::new();
    doc.insert(F_FORMAT, Value::Int64(BUILD_FORMAT));
    doc.insert(F_TYPE, Value::String(TYPE_BUILD.into()));
    doc.insert(F_DATABASE_ID, Value::Int64(i64::from(r.database_id)));
    doc.insert(F_COLLECTION_ID, Value::Int64(i64::from(r.collection_id)));
    doc.insert(F_INDEX_ID, Value::Int64(i64::from(r.index_id)));
    let phase = match r.phase {
        JobPhase::Build => "build",
        JobPhase::Cleanup => "cleanup",
    };
    doc.insert(F_PHASE, Value::String(phase.into()));
    if let Some(c) = &r.cursor {
        doc.insert(
            F_CURSOR,
            Value::Binary {
                subtype: BINARY_GENERIC,
                data: c.clone(),
            },
        );
    }
    doc.insert(F_DOCS, count(r.docs_scanned));
    doc.insert(F_ENTRIES, count(r.entries_written));
    if let Some(e) = &r.error {
        doc.insert(F_ERROR, Value::String(e.clone()));
    }
    Ok(rdoc::encode(&doc)?)
}

fn id(doc: &Document, name: &str) -> Result<u32, Error> {
    match doc.get(name) {
        Some(Value::Int64(v)) => {
            u32::try_from(*v).map_err(|_| corrupt(format!("{name} not a u32")))
        }
        _ => Err(corrupt(format!("{name} missing or not an int64"))),
    }
}

fn counter(doc: &Document, name: &str) -> Result<u64, Error> {
    match doc.get(name) {
        Some(Value::Int64(v)) => u64::try_from(*v).map_err(|_| corrupt(format!("{name} < 0"))),
        _ => Err(corrupt(format!("{name} missing or not an int64"))),
    }
}

/// Decodes a record written by [`encode_build_record`].
///
/// # Errors
/// `RGN-5002 StorageCorruption` for anything else (unknown fields, wrong types, unsupported
/// `build_format`).
pub fn decode_build_record(bytes: &[u8]) -> Result<BuildRecord, Error> {
    let doc = rdoc::decode(bytes).map_err(|e| corrupt(e.to_string()))?;
    match doc.get(F_FORMAT) {
        Some(Value::Int64(BUILD_FORMAT)) => {}
        Some(Value::Int64(v)) => return Err(corrupt(format!("unsupported build_format {v}"))),
        _ => return Err(corrupt("missing build_format")),
    }
    if let Some((name, _)) = doc.iter().find(|(n, _)| !FIELDS.contains(n)) {
        return Err(corrupt(format!("unknown field {name:?}")));
    }
    if doc.get(F_TYPE) != Some(&Value::String(TYPE_BUILD.into())) {
        return Err(corrupt("type is not \"index_build\""));
    }
    let phase = match doc.get(F_PHASE) {
        Some(Value::String(p)) if p == "build" => JobPhase::Build,
        Some(Value::String(p)) if p == "cleanup" => JobPhase::Cleanup,
        _ => return Err(corrupt("phase is not \"build\" or \"cleanup\"")),
    };
    let cursor = match doc.get(F_CURSOR) {
        None => None,
        Some(Value::Binary {
            subtype: BINARY_GENERIC,
            data,
        }) => Some(data.clone()),
        Some(_) => return Err(corrupt("cursor is not generic binary")),
    };
    let error = match doc.get(F_ERROR) {
        None => None,
        Some(Value::String(e)) => Some(e.clone()),
        Some(_) => return Err(corrupt("error is not a string")),
    };
    Ok(BuildRecord {
        database_id: id(&doc, F_DATABASE_ID)?,
        collection_id: id(&doc, F_COLLECTION_ID)?,
        index_id: id(&doc, F_INDEX_ID)?,
        phase,
        cursor,
        docs_scanned: counter(&doc, F_DOCS)?,
        entries_written: counter(&doc, F_ENTRIES)?,
        error,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sample() -> BuildRecord {
        BuildRecord {
            database_id: 100,
            collection_id: 101,
            index_id: 102,
            phase: JobPhase::Cleanup,
            cursor: Some(vec![3, 0, 0, 0, 0, 100]),
            docs_scanned: 7,
            entries_written: 9,
            error: Some("duplicate".into()),
        }
    }

    #[test]
    fn round_trip_and_key_layout() {
        for r in [sample(), BuildRecord::new(1, 2, 3)] {
            let bytes = encode_build_record(&r).unwrap();
            assert_eq!(decode_build_record(&bytes).unwrap(), r);
        }
        assert_eq!(
            build_record_key(0x0102_0304, 7),
            vec![NS_SYSTEM, b'b', 1, 2, 3, 4, 0, 0, 0, 7]
        );
        assert!(sample().key().starts_with(&build_record_prefix()));
    }

    #[test]
    fn strict_decoding() {
        let base = rdoc::decode(&encode_build_record(&sample()).unwrap()).unwrap();
        let bad: Vec<(&str, Value)> = vec![
            ("extra", Value::Null),
            (F_FORMAT, Value::Int64(2)),
            (F_PHASE, Value::String("running".into())),
            (F_TYPE, Value::String("index".into())),
            (F_INDEX_ID, Value::Int64(-1)),
            (F_DOCS, Value::Int64(-1)),
            (F_CURSOR, Value::String("k".into())),
            (F_ERROR, Value::Int64(1)),
        ];
        for (name, v) in bad {
            let mut d = base.clone();
            d.insert(name, v);
            let err = decode_build_record(&rdoc::encode(&d).unwrap()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::StorageCorruption, "{name}");
        }
        assert!(decode_build_record(b"junk").is_err());
    }
}
