// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Logical dump and restore of a single node (M13a lane BG; FR-BKP-007, PD-067, PD-084,
//! PD-085; backup-restore.md "Logical dump format v1").
//!
//! [`dump`] and [`logical_restore`] are what a [`super::BackupBackend`] delegates its `dump` and
//! `logical_restore` operations to: they speak the service's [`DumpSink`] / [`DumpSource`] and
//! the engine's backup primitives (lane BD), and own the **dump format v1**.
//!
//! # Why here
//! The sink/source traits and the chunk types live in `rustegon-server` (`services::backup`),
//! and this crate already depends on `rustegon-engine`, `rustegon-catalog`, `rustegon-doc`
//! (extended JSON) and `rustegon-backup` (key rules, `HlcTimestamp`). Implementing the format in
//! `rustegon-backup` would add the `rustegon-backup -> rustegon-engine` edge plus a second set of
//! sink/source traits and an adapter, for no gain: the format is only ever produced and consumed
//! by the server.
//!
//! # Format v1 (PD-067, PD-084)
//! ```text
//! <db>.database.json              database options
//! <db>/<coll>.metadata.json       collection options, validator, shard key, index definitions
//! <db>/<coll>.ndjson              one document per line, canonical extended JSON
//! dump.json                       format version, T, per-file BLAKE3, per-collection count + checksum
//! ```
//! Every file is streamed in byte order of its path, contiguously; `dump.json` comes last (it
//! describes the others). Two collections of one database whose names differ only by ASCII case
//! would be the same file on a case-insensitive file system: the second and later of such a
//! group go to `<db>/case-<k>/<coll>.*` (PD-085). A restore never derives names from paths: the
//! metadata file carries the database and collection names.
//!
//! The collection checksum (`checksum`) is order-independent: the sum modulo 2^256 of the
//! BLAKE3 hashes (read as little-endian integers) of each document's canonical JSON **without
//! `_rev`** (a revision names a write of the source store; the restore regenerates it). It
//! equals for the source at T and for the restored collection, whatever their key order.
//!
//! # Dump
//! One [`PinnedSnapshot`] for the whole dump: T is closed (no transaction can commit at or below
//! it any more) and protected from GC, every collection is read at T with committed-only reads
//! ([`EmbeddedDb::scan_at`]), so the dump is consistent across collections, never blocks writers
//! and is not bounded by `txn.max_duration`. Users, roles and every other security record live in
//! the system keyspace, which the dump never reads; databases starting with `_` and collections
//! starting with `system.` are skipped as well.
//!
//! # Restore
//! Streaming, in the order of PD-067: for each collection, create it **without** validator
//! (an existing target is refused with `RGN-1031` unless `drop_existing`, which drops it at that
//! point) → bulk load ([`EmbeddedDb::import_documents`]: keeps `_id`, `_createdAt`, `_updatedAt`,
//! regenerates `_rev`, skips validators) → once `dump.json` arrived and every file, count and
//! checksum matched → set the validator → build the indexes. Per-file hashes are computed while
//! the bytes stream, so nothing is buffered beyond one import batch.
//!
//! **A failed restore is undone, a replaced collection is not restored (PD-084):** on any error
//! (malformed or corrupt stream, checksum mismatch, cancellation, engine error) every collection
//! and database this restore created is dropped again (best effort; failures to clean up are
//! logged and reported in `details.cleanup`). Collections replaced through `drop_existing` were
//! dropped when their metadata arrived and stay dropped: `--drop` means "replace", take a
//! snapshot first if the old contents matter.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use rustegon_backup::{HlcTimestamp, validate_key};
use rustegon_catalog::{
    CollectionDescriptor, CollectionKind, CollectionOptions, CollectionSpec, DatabaseOptions,
    IndexDescriptor, IndexField, IndexOrder, IndexOrigin, IndexScope, IndexSpec, ShardKey,
    ShardStrategy, ValidationAction, ValidationLevel,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document,
    json::{JsonMode, parse_document, to_json},
};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{FenceOptions, ImportOptions, PinnedSnapshot, ScanOptions},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::backup::{
    DUMP_CHUNK_BYTES, DumpChunk, DumpScope, DumpSink, DumpSource, DumpSummary,
    LogicalRestoreOptions, LogicalRestoreSummary, MAX_DUMP_CHUNK_BYTES, RestoredCollection,
};
use crate::CancelToken;

/// Version of the logical dump format written by [`dump`]; [`logical_restore`] reads it and
/// refuses newer ones with `RGN-5007`.
pub const DUMP_FORMAT_VERSION: u32 = 1;
/// The `format` field of `dump.json`.
pub const DUMP_FORMAT_NAME: &str = "rustegon-dump";
/// Name of the dump's own manifest, the last file of a dump.
pub const DUMP_MANIFEST: &str = "dump.json";
/// Suffix of a database file (`<db>.database.json`, top level).
pub const DATABASE_SUFFIX: &str = ".database.json";
/// Suffix of a collection metadata file.
pub const METADATA_SUFFIX: &str = ".metadata.json";
/// Suffix of a collection data file.
pub const DATA_SUFFIX: &str = ".ndjson";
/// Largest JSON file (manifest, metadata) a restore accepts: guards the buffer of an untrusted
/// stream. A manifest of 64 MiB lists far more collections than a node holds.
const MAX_JSON_FILE_BYTES: usize = 64 << 20;
/// Longest document line a restore accepts. A document is at most 16 MiB of `RDoc`; its JSON can
/// be larger (escapes, wrappers), so the line bound is four times that.
const MAX_LINE_BYTES: usize = 64 << 20;

// ---------------------------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------------------------

/// Whether the operation is still wanted, checked between files and batches. Implemented by the
/// service's [`CancelToken`]; tests use their own.
pub trait CancelCheck {
    /// `Ok` while the operation should go on.
    ///
    /// # Errors
    /// `RGN-5005` (cancelled) or `RGN-5006` (deadline).
    fn check(&self) -> Result<(), Error>;
}

impl CancelCheck for CancelToken {
    fn check(&self) -> Result<(), Error> {
        CancelToken::check(self)
    }
}

// ---------------------------------------------------------------------------------------------
// Persisted format v1
// ---------------------------------------------------------------------------------------------

/// `dump.json` (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpManifest {
    /// Always [`DUMP_FORMAT_NAME`].
    pub format: String,
    /// [`DUMP_FORMAT_VERSION`]; read first, a newer one is `RGN-5007`.
    pub format_version: u32,
    /// The snapshot timestamp T every collection was read at.
    pub timestamp: HlcTimestamp,
    /// The dumped databases, in name order.
    pub databases: Vec<DumpedDatabase>,
    /// Every other file of the dump, in path order.
    pub files: Vec<DumpedFile>,
}

/// One database of a [`DumpManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpedDatabase {
    /// Database name.
    pub name: String,
    /// Its database file (`<db>.database.json`).
    pub file: String,
    /// Its dumped collections, in name order.
    pub collections: Vec<DumpedCollection>,
}

/// One collection of a [`DumpManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpedCollection {
    /// Collection name.
    pub name: String,
    /// Its metadata file.
    pub metadata: String,
    /// Its data file.
    pub data: String,
    /// Number of documents (= lines of the data file).
    pub documents: u64,
    /// Order-independent equality checksum without `_rev` (module docs), 64 hex digits.
    pub checksum: String,
}

/// One file of a [`DumpManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpedFile {
    /// Relative path (a destination key).
    pub path: String,
    /// Size in bytes.
    pub bytes: u64,
    /// BLAKE3 of the content, 64 lowercase hex digits.
    pub blake3: String,
}

impl DumpManifest {
    /// Parses and checks `dump.json`: version first (newer → `RGN-5007`), then structure.
    ///
    /// # Errors
    /// `RGN-5007` for a newer format, `RGN-5002` for anything else that is wrong.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let manifest: Self = parse_versioned(DUMP_MANIFEST, bytes)?;
        if manifest.format != DUMP_FORMAT_NAME {
            return Err(corrupt(
                DUMP_MANIFEST,
                format!("format {:?} is not {DUMP_FORMAT_NAME}", manifest.format),
            ));
        }
        let mut seen = BTreeSet::new();
        for f in &manifest.files {
            validate_key(&f.path).map_err(|e| corrupt(DUMP_MANIFEST, e.to_string()))?;
            if f.path == DUMP_MANIFEST || !seen.insert(f.path.as_str()) {
                return Err(corrupt(
                    DUMP_MANIFEST,
                    format!("file {:?} listed twice", f.path),
                ));
            }
        }
        Ok(manifest)
    }
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: u64,
}

/// `<db>.database.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DatabaseFile {
    format_version: u32,
    database: String,
    options: DatabaseOptionsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DatabaseOptionsV1 {
    implicit_collection_creation: bool,
}

/// `<db>/<coll>.metadata.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetadataFile {
    format_version: u32,
    database: String,
    collection: String,
    kind: KindV1,
    shard_key: ShardKeyV1,
    options: CollectionOptionsV1,
    indexes: Vec<IndexV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum KindV1 {
    Document,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShardKeyV1 {
    strategy: StrategyV1,
    fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StrategyV1 {
    Hashed,
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CollectionOptionsV1 {
    /// The validator as stored: JSON text, verbatim.
    validator: Option<String>,
    validation_level: LevelV1,
    validation_action: ActionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LevelV1 {
    Off,
    Strict,
    Moderate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionV1 {
    Error,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexV1 {
    name: String,
    fields: Vec<IndexFieldV1>,
    unique: bool,
    sparse: bool,
    partial: Option<String>,
    hidden: bool,
    scope: ScopeV1,
    origin: OriginV1,
    include: Vec<String>,
    created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexFieldV1 {
    path: String,
    order: OrderV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OrderV1 {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ScopeV1 {
    Global,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OriginV1 {
    Manual,
    Auto,
}

impl MetadataFile {
    fn new(database: &str, coll: &CollectionDescriptor, indexes: &[IndexDescriptor]) -> Self {
        let o = &coll.options;
        Self {
            format_version: DUMP_FORMAT_VERSION,
            database: database.to_owned(),
            collection: coll.name.clone(),
            kind: KindV1::Document,
            shard_key: ShardKeyV1 {
                strategy: match coll.shard_key.strategy {
                    ShardStrategy::Hashed => StrategyV1::Hashed,
                    ShardStrategy::Range => StrategyV1::Range,
                },
                fields: coll.shard_key.fields.clone(),
            },
            options: CollectionOptionsV1 {
                validator: o.validator.clone(),
                validation_level: match o.validation_level {
                    ValidationLevel::Off => LevelV1::Off,
                    ValidationLevel::Strict => LevelV1::Strict,
                    ValidationLevel::Moderate => LevelV1::Moderate,
                },
                validation_action: match o.validation_action {
                    ValidationAction::Error => ActionV1::Error,
                    ValidationAction::Warn => ActionV1::Warn,
                },
            },
            indexes: indexes.iter().map(IndexV1::from_descriptor).collect(),
        }
    }

    fn shard_key(&self) -> ShardKey {
        ShardKey {
            strategy: match self.shard_key.strategy {
                StrategyV1::Hashed => ShardStrategy::Hashed,
                StrategyV1::Range => ShardStrategy::Range,
            },
            fields: self.shard_key.fields.clone(),
        }
    }

    fn options(&self) -> CollectionOptions {
        let o = &self.options;
        CollectionOptions {
            validator: o.validator.clone(),
            validation_level: match o.validation_level {
                LevelV1::Off => ValidationLevel::Off,
                LevelV1::Strict => ValidationLevel::Strict,
                LevelV1::Moderate => ValidationLevel::Moderate,
            },
            validation_action: match o.validation_action {
                ActionV1::Error => ValidationAction::Error,
                ActionV1::Warn => ValidationAction::Warn,
            },
        }
    }
}

impl IndexV1 {
    fn from_descriptor(d: &IndexDescriptor) -> Self {
        Self {
            name: d.name.clone(),
            fields: d
                .fields
                .iter()
                .map(|f| IndexFieldV1 {
                    path: f.path.clone(),
                    order: match f.order {
                        IndexOrder::Asc => OrderV1::Asc,
                        IndexOrder::Desc => OrderV1::Desc,
                    },
                })
                .collect(),
            unique: d.unique,
            sparse: d.sparse,
            partial: d.partial.clone(),
            hidden: d.hidden,
            scope: match d.scope {
                IndexScope::Global => ScopeV1::Global,
                IndexScope::Local => ScopeV1::Local,
            },
            origin: match d.origin {
                IndexOrigin::Manual => OriginV1::Manual,
                IndexOrigin::Auto => OriginV1::Auto,
            },
            include: d.include.clone(),
            created_at_ms: d.created_at_ms,
        }
    }

    fn spec(&self) -> IndexSpec {
        IndexSpec {
            name: self.name.clone(),
            fields: self
                .fields
                .iter()
                .map(|f| IndexField {
                    path: f.path.clone(),
                    order: match f.order {
                        OrderV1::Asc => IndexOrder::Asc,
                        OrderV1::Desc => IndexOrder::Desc,
                    },
                })
                .collect(),
            unique: self.unique,
            sparse: self.sparse,
            partial: self.partial.clone(),
            hidden: self.hidden,
            scope: match self.scope {
                ScopeV1::Global => IndexScope::Global,
                ScopeV1::Local => IndexScope::Local,
            },
            origin: match self.origin {
                OriginV1::Manual => IndexOrigin::Manual,
                OriginV1::Auto => IndexOrigin::Auto,
            },
            include: self.include.clone(),
            created_at_ms: self.created_at_ms,
        }
    }
}

/// Parses a versioned JSON file of the dump: the version first, so a newer file fails with
/// `RGN-5007` even when its structure changed.
fn parse_versioned<T: DeserializeOwned>(path: &str, bytes: &[u8]) -> Result<T, Error> {
    let probe: VersionProbe =
        serde_json::from_slice(bytes).map_err(|e| corrupt(path, format!("unreadable: {e}")))?;
    if probe.format_version > u64::from(DUMP_FORMAT_VERSION) {
        return Err(Error::new(
            ErrorCode::VersionIncompatible,
            format!(
                "{path} has dump format version {}, this server reads up to {DUMP_FORMAT_VERSION}",
                probe.format_version
            ),
        )
        .with_detail("file", path)
        .with_detail("found", probe.format_version.to_string())
        .with_detail("supported", DUMP_FORMAT_VERSION.to_string()));
    }
    if probe.format_version == 0 {
        return Err(corrupt(path, "format_version 0 does not exist"));
    }
    serde_json::from_slice(bytes).map_err(|e| corrupt(path, format!("invalid: {e}")))
}

fn to_json_file<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("dump serialisation: {e}")))?;
    out.push(b'\n');
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Equality checksum
// ---------------------------------------------------------------------------------------------

/// Order-independent multiset checksum (module docs): the sum modulo 2^256 of 256-bit values.
/// Addition, unlike XOR, does not cancel a document present twice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Sum256([u64; 4]);

impl Sum256 {
    fn add(&mut self, hash: &[u8; 32]) {
        let mut carry = false;
        for (i, limb) in self.0.iter_mut().enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(&hash[i * 8..i * 8 + 8]);
            let (s1, c1) = limb.overflowing_add(u64::from_le_bytes(word));
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *limb = s2;
            carry = c1 || c2;
        }
    }

    /// 64 hex digits of the 32-byte little-endian representation.
    fn to_hex(self) -> String {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

/// The checksum contribution of one document: BLAKE3 of its canonical JSON without `_rev`.
fn document_hash(doc: &Document) -> [u8; 32] {
    let text = if doc.get("_rev").is_some() {
        let mut d = doc.clone();
        d.remove("_rev");
        to_json(&d, JsonMode::Canonical)
    } else {
        to_json(doc, JsonMode::Canonical)
    };
    *blake3::hash(text.as_bytes()).as_bytes()
}

// ---------------------------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------------------------

/// Tuning of [`dump_with`].
#[derive(Debug, Clone)]
pub struct DumpOptions {
    /// Bytes per chunk (clamped to 1..=[`MAX_DUMP_CHUNK_BYTES`]).
    pub chunk_bytes: usize,
    /// Batches of the snapshot scans.
    pub scan: ScanOptions,
    /// The write fence that closes T. The service's cancel token cannot drive the engine's
    /// cancel handle, so the fence is bounded by its timeout (default 120 s) only.
    pub fence: FenceOptions,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            chunk_bytes: DUMP_CHUNK_BYTES,
            scan: ScanOptions::default(),
            fence: FenceOptions::default(),
        }
    }
}

/// The logical dump of `scope` (module docs; PD-067): `sink.started(T)`, then every file in path
/// order, `dump.json` last. Empty scope lists mean every database.
///
/// # Errors
/// `RGN-1030` for a database or collection of `scope` that does not exist at T; `RGN-5007` for
/// a collection kind format v1 cannot hold; the fence's errors (`RGN-5006`); `RGN-5005` when
/// `cancel` fires or the sink's client went away; storage errors.
pub fn dump(
    db: &Arc<EmbeddedDb>,
    scope: &DumpScope,
    sink: &mut dyn DumpSink,
    cancel: &dyn CancelCheck,
) -> Result<DumpSummary, Error> {
    dump_with(db, scope, sink, cancel, &DumpOptions::default())
}

/// [`dump`] with explicit [`DumpOptions`].
///
/// # Errors
/// As [`dump`].
pub fn dump_with(
    db: &Arc<EmbeddedDb>,
    scope: &DumpScope,
    sink: &mut dyn DumpSink,
    cancel: &dyn CancelCheck,
    options: &DumpOptions,
) -> Result<DumpSummary, Error> {
    cancel.check()?;
    // One snapshot for the whole dump: every collection at the same T, and its versions pinned
    // against GC until the last file is written (PD-067).
    let snapshot = Arc::new(db.pin_snapshot(&options.fence)?);
    let plan = plan_dump(db, &snapshot, scope)?;
    let ts = snapshot.ts();
    let timestamp = HlcTimestamp {
        wall: ts.wall,
        logical: ts.logical,
    };
    sink.started(timestamp)?;

    let chunk_bytes = options.chunk_bytes.clamp(1, MAX_DUMP_CHUNK_BYTES);
    let mut files = Vec::new();
    let mut stats: BTreeMap<(usize, usize), (u64, Sum256)> = BTreeMap::new();
    for (path, file) in plan.files() {
        cancel.check()?;
        let mut out = FileOut::new(&mut *sink, path, chunk_bytes);
        match file {
            PlannedFile::Database(i) => {
                let d = &plan.databases[i];
                out.write(&to_json_file(&DatabaseFile {
                    format_version: DUMP_FORMAT_VERSION,
                    database: d.name.clone(),
                    options: DatabaseOptionsV1 {
                        implicit_collection_creation: d.options.implicit_collection_creation,
                    },
                })?)?;
            }
            PlannedFile::Metadata(i, j) => {
                let d = &plan.databases[i];
                let c = &d.collections[j];
                out.write(&to_json_file(&MetadataFile::new(
                    &d.name,
                    &c.descriptor,
                    &c.indexes,
                ))?)?;
            }
            PlannedFile::Data(i, j) => {
                let d = &plan.databases[i];
                let c = &d.collections[j];
                let mut scan = db.scan_at(&snapshot, &d.name, &c.descriptor.name, options.scan)?;
                let mut count = 0u64;
                let mut sum = Sum256::default();
                while let Some(batch) = scan.next_batch()? {
                    cancel.check()?;
                    for doc in &batch {
                        let mut line = to_json(doc, JsonMode::Canonical);
                        line.push('\n');
                        out.write(line.as_bytes())?;
                        sum.add(&document_hash(doc));
                        count += 1;
                    }
                }
                stats.insert((i, j), (count, sum));
            }
        }
        files.push(out.finish()?);
    }

    let mut summary = DumpSummary::default();
    let databases = plan
        .databases
        .iter()
        .enumerate()
        .map(|(i, d)| DumpedDatabase {
            name: d.name.clone(),
            file: database_file(&d.name),
            collections: d
                .collections
                .iter()
                .enumerate()
                .map(|(j, c)| {
                    let (documents, sum) = stats.get(&(i, j)).copied().unwrap_or_default();
                    summary.collections += 1;
                    summary.documents += documents;
                    DumpedCollection {
                        name: c.descriptor.name.clone(),
                        metadata: format!("{}{METADATA_SUFFIX}", c.stem),
                        data: format!("{}{DATA_SUFFIX}", c.stem),
                        documents,
                        checksum: sum.to_hex(),
                    }
                })
                .collect(),
        })
        .collect();
    let manifest = DumpManifest {
        format: DUMP_FORMAT_NAME.to_owned(),
        format_version: DUMP_FORMAT_VERSION,
        timestamp,
        databases,
        files,
    };
    cancel.check()?;
    let mut out = FileOut::new(sink, DUMP_MANIFEST.to_owned(), chunk_bytes);
    out.write(&to_json_file(&manifest)?)?;
    out.finish()?;
    Ok(summary)
}

fn database_file(db: &str) -> String {
    format!("{db}{DATABASE_SUFFIX}")
}

/// What one dump writes, resolved at T.
struct DumpPlan {
    databases: Vec<PlannedDatabase>,
}

struct PlannedDatabase {
    name: String,
    options: DatabaseOptions,
    collections: Vec<PlannedCollection>,
}

struct PlannedCollection {
    descriptor: CollectionDescriptor,
    indexes: Vec<IndexDescriptor>,
    /// Path without suffix: `<db>/<coll>` or `<db>/case-<k>/<coll>` (PD-085).
    stem: String,
}

#[derive(Clone, Copy)]
enum PlannedFile {
    Database(usize),
    Metadata(usize, usize),
    Data(usize, usize),
}

impl DumpPlan {
    /// Every file but `dump.json`, in path (byte) order: the order of a directory listing, so a
    /// dump directory sent back by `rustegon restore` arrives exactly as it was dumped.
    fn files(&self) -> Vec<(String, PlannedFile)> {
        let mut files = BTreeMap::new();
        for (i, d) in self.databases.iter().enumerate() {
            files.insert(database_file(&d.name), PlannedFile::Database(i));
            for (j, c) in d.collections.iter().enumerate() {
                files.insert(
                    format!("{}{METADATA_SUFFIX}", c.stem),
                    PlannedFile::Metadata(i, j),
                );
                files.insert(format!("{}{DATA_SUFFIX}", c.stem), PlannedFile::Data(i, j));
            }
        }
        files.into_iter().collect()
    }
}

/// Which collections of one database the scope selects.
enum Selection {
    All,
    Some(BTreeSet<String>),
}

fn missing(kind: &str, name: &str) -> Error {
    Error::new(ErrorCode::NotFound, format!("{kind} {name} not found")).with_detail("kind", kind)
}

/// Whether a name is a system object the dump never exports (module docs).
fn is_system_database(name: &str) -> bool {
    name.starts_with('_')
}

fn is_system_collection(name: &str) -> bool {
    name.starts_with("system.")
}

fn plan_dump(
    db: &EmbeddedDb,
    snapshot: &PinnedSnapshot,
    scope: &DumpScope,
) -> Result<DumpPlan, Error> {
    let all: BTreeMap<String, DatabaseOptions> = db
        .databases_at(snapshot)?
        .into_iter()
        .filter(|d| !is_system_database(&d.name))
        .map(|d| (d.name, d.options))
        .collect();
    let mut selected: BTreeMap<String, Selection> = BTreeMap::new();
    if scope.databases.is_empty() && scope.collections.is_empty() {
        for name in all.keys() {
            selected.insert(name.clone(), Selection::All);
        }
    }
    for name in &scope.databases {
        if !all.contains_key(name) {
            return Err(missing("database", name));
        }
        selected.insert(name.clone(), Selection::All);
    }
    for (d, c) in &scope.collections {
        if !all.contains_key(d) {
            return Err(missing("database", d));
        }
        match selected
            .entry(d.clone())
            .or_insert_with(|| Selection::Some(BTreeSet::new()))
        {
            Selection::All => {}
            Selection::Some(set) => {
                set.insert(c.clone());
            }
        }
    }

    let mut databases = Vec::new();
    for (name, selection) in selected {
        let options = all.get(&name).cloned().unwrap_or_default();
        let mut collections: Vec<CollectionDescriptor> = db
            .collections_at(snapshot, &name)?
            .into_iter()
            .filter(|c| !is_system_collection(&c.name))
            .collect();
        if let Selection::Some(wanted) = &selection {
            for c in wanted {
                if !collections.iter().any(|d| &d.name == c) {
                    return Err(missing("collection", &format!("{name}.{c}")));
                }
            }
            collections.retain(|d| wanted.contains(&d.name));
        }
        let stems = collection_stems(&name, collections.iter().map(|c| c.name.as_str()));
        let mut planned = Vec::with_capacity(collections.len());
        for (descriptor, stem) in collections.into_iter().zip(stems) {
            if descriptor.kind != CollectionKind::Document {
                return Err(Error::new(
                    ErrorCode::VersionIncompatible,
                    format!(
                        "collection {name}.{} is not a document collection; dump format \
                         {DUMP_FORMAT_VERSION} holds document collections only",
                        descriptor.name
                    ),
                ));
            }
            let indexes = db.indexes_at(snapshot, &name, &descriptor.name)?;
            planned.push(PlannedCollection {
                descriptor,
                indexes,
                stem,
            });
        }
        databases.push(PlannedDatabase {
            name,
            options,
            collections: planned,
        });
    }
    Ok(DumpPlan { databases })
}

/// File stems of the collections of `db`, in the given (name) order: `<db>/<coll>`, except that
/// the k-th later collection whose name equals an earlier one ignoring ASCII case goes to
/// `<db>/case-<k>/<coll>` (PD-085), so no two files collide on a case-insensitive file system.
/// Collection names never contain `/`, so a `case-<k>` directory never meets a collection file.
fn collection_stems<'a>(db: &str, names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    names
        .map(|name| {
            let n = seen.entry(name.to_ascii_lowercase()).or_insert(0);
            let stem = if *n == 0 {
                format!("{db}/{name}")
            } else {
                format!("{db}/case-{n}/{name}")
            };
            *n += 1;
            stem
        })
        .collect()
}

/// One file being written to the sink: buffered into chunks of `chunk_bytes`, hashed while it
/// streams.
struct FileOut<'s> {
    sink: &'s mut dyn DumpSink,
    path: String,
    buf: Vec<u8>,
    hasher: blake3::Hasher,
    bytes: u64,
    chunk_bytes: usize,
}

impl<'s> FileOut<'s> {
    fn new(sink: &'s mut dyn DumpSink, path: String, chunk_bytes: usize) -> Self {
        Self {
            sink,
            path,
            buf: Vec::new(),
            hasher: blake3::Hasher::new(),
            bytes: 0,
            chunk_bytes,
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher.update(data);
        self.bytes += data.len() as u64;
        self.buf.extend_from_slice(data);
        // Strictly more than one chunk buffered: the last chunk of a file always carries data
        // (unless the file is empty), so no file ends with an empty extra message.
        while self.buf.len() > self.chunk_bytes {
            let rest = self.buf.split_off(self.chunk_bytes);
            let full = std::mem::replace(&mut self.buf, rest);
            self.sink.chunk(DumpChunk {
                path: self.path.clone(),
                data: full,
                end_of_file: false,
            })?;
        }
        Ok(())
    }

    fn finish(self) -> Result<DumpedFile, Error> {
        let Self {
            sink,
            path,
            buf,
            hasher,
            bytes,
            ..
        } = self;
        sink.chunk(DumpChunk {
            path: path.clone(),
            data: buf,
            end_of_file: true,
        })?;
        Ok(DumpedFile {
            path,
            bytes,
            blake3: hasher.finalize().to_hex().to_string(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------------------------

/// A logical restore from `source` into `db` (module docs; PD-067, PD-084).
///
/// # Errors
/// `RGN-1001` for a malformed stream (bad or unknown path, files out of order or interleaved,
/// truncated file or stream, missing `dump.json`, data after it, malformed document);
/// `RGN-5002` for a file or collection whose size, hash, count or checksum does not match
/// `dump.json`, or a corrupt JSON file; `RGN-5007` for a newer dump format; `RGN-1031` for an
/// existing target collection without `drop_existing`; `RGN-1030` for a scope naming something
/// the dump does not hold; `RGN-5005` when cancelled; engine errors (`RGN-1005` duplicate `_id`,
/// `RGN-1022` unique index violation, …). Every error undoes what the restore created.
pub fn logical_restore(
    db: &Arc<EmbeddedDb>,
    options: &LogicalRestoreOptions,
    source: &mut dyn DumpSource,
    cancel: &dyn CancelCheck,
) -> Result<LogicalRestoreSummary, Error> {
    logical_restore_with(db, options, source, cancel, &ImportOptions::default())
}

/// [`logical_restore`] with explicit import transaction bounds.
///
/// # Errors
/// As [`logical_restore`].
pub fn logical_restore_with(
    db: &Arc<EmbeddedDb>,
    options: &LogicalRestoreOptions,
    source: &mut dyn DumpSource,
    cancel: &dyn CancelCheck,
    import: &ImportOptions,
) -> Result<LogicalRestoreSummary, Error> {
    let mut restorer = Restorer {
        db,
        options,
        import: *import,
        cancel,
        last_path: None,
        open: None,
        received: BTreeMap::new(),
        manifest: None,
        databases: BTreeMap::new(),
        collections: BTreeMap::new(),
        created_databases: Vec::new(),
        created_collections: Vec::new(),
    };
    match restorer.run(source) {
        Ok(summary) => Ok(summary),
        Err(e) => Err(restorer.undo(e)),
    }
}

/// What kind of dump file a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileKind {
    Manifest,
    Database(String),
    Metadata(String),
    Data(String),
}

fn classify(path: &str) -> Result<FileKind, Error> {
    if path == DUMP_MANIFEST {
        return Ok(FileKind::Manifest);
    }
    if !path.contains('/')
        && let Some(db) = path.strip_suffix(DATABASE_SUFFIX)
        && !db.is_empty()
    {
        return Ok(FileKind::Database(db.to_owned()));
    }
    if path.contains('/') {
        if let Some(stem) = path.strip_suffix(METADATA_SUFFIX) {
            return Ok(FileKind::Metadata(stem.to_owned()));
        }
        if let Some(stem) = path.strip_suffix(DATA_SUFFIX) {
            return Ok(FileKind::Data(stem.to_owned()));
        }
    }
    Err(malformed(path, format!("{path} is not a file of a dump")))
}

fn malformed(path: &str, msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
        .with_detail("field", "chunk")
        .with_detail("file", path)
}

fn corrupt(path: &str, msg: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::StorageCorruption,
        format!("dump file {path}: {}", msg.into()),
    )
    .with_detail("file", path)
}

/// The body of a file being received.
enum Body {
    /// A JSON file, kept until it is complete.
    Json(Vec<u8>),
    /// A data file: the unfinished last line and the documents not yet imported.
    Lines {
        pending: Vec<u8>,
        batch: Vec<Document>,
        batch_bytes: usize,
        line: u64,
    },
}

struct IncomingFile {
    path: String,
    kind: FileKind,
    hasher: blake3::Hasher,
    bytes: u64,
    body: Body,
}

/// A collection whose metadata arrived.
struct CollectionState {
    meta: MetadataFile,
    in_scope: bool,
    data_seen: bool,
    documents: u64,
    checksum: Sum256,
    imported: u64,
}

struct Restorer<'a> {
    db: &'a Arc<EmbeddedDb>,
    options: &'a LogicalRestoreOptions,
    import: ImportOptions,
    cancel: &'a dyn CancelCheck,
    /// The last file started (path order check; `dump.json` excluded).
    last_path: Option<String>,
    open: Option<IncomingFile>,
    /// Completed files: size and BLAKE3.
    received: BTreeMap<String, (u64, String)>,
    manifest: Option<DumpManifest>,
    databases: BTreeMap<String, DatabaseFile>,
    /// By file stem.
    collections: BTreeMap<String, CollectionState>,
    created_databases: Vec<String>,
    created_collections: Vec<(String, String)>,
}

impl Restorer<'_> {
    fn run(&mut self, source: &mut dyn DumpSource) -> Result<LogicalRestoreSummary, Error> {
        self.cancel.check()?;
        while let Some(chunk) = source.next_chunk()? {
            self.cancel.check()?;
            self.chunk(&chunk)?;
        }
        if let Some(open) = &self.open {
            return Err(malformed(
                &open.path,
                format!("the stream ended inside file {}", open.path),
            ));
        }
        let Some(manifest) = self.manifest.take() else {
            return Err(malformed(
                DUMP_MANIFEST,
                format!("the stream ended without {DUMP_MANIFEST}: the dump is incomplete"),
            ));
        };
        let order = self.verify(&manifest)?;
        self.finalize(&manifest, &order)
    }

    fn chunk(&mut self, chunk: &DumpChunk) -> Result<(), Error> {
        let path = chunk.path.as_str();
        if self.manifest.is_some() {
            return Err(malformed(
                path,
                format!("file {path} after {DUMP_MANIFEST}, which must be the last file"),
            ));
        }
        validate_key(path).map_err(|e| malformed(path, e.to_string()))?;
        if chunk.data.len() > MAX_DUMP_CHUNK_BYTES {
            return Err(malformed(
                path,
                format!("a chunk carries at most {MAX_DUMP_CHUNK_BYTES} bytes"),
            ));
        }
        match &self.open {
            Some(open) if open.path != path => {
                return Err(malformed(
                    path,
                    format!("file {path} started before file {} was complete", open.path),
                ));
            }
            Some(_) => {}
            None => self.start_file(path)?,
        }
        let Some(open) = self.open.as_mut() else {
            return Err(Error::new(ErrorCode::Internal, "no open dump file"));
        };
        open.hasher.update(&chunk.data);
        open.bytes += chunk.data.len() as u64;
        if let Body::Json(buf) = &mut open.body {
            if buf.len() + chunk.data.len() > MAX_JSON_FILE_BYTES {
                return Err(malformed(
                    path,
                    format!("{path} is larger than {MAX_JSON_FILE_BYTES} bytes"),
                ));
            }
            buf.extend_from_slice(&chunk.data);
        } else {
            self.lines(&chunk.data)?;
        }
        if chunk.end_of_file {
            self.end_file()?;
        }
        Ok(())
    }

    fn start_file(&mut self, path: &str) -> Result<(), Error> {
        if self.received.contains_key(path) {
            return Err(malformed(path, format!("file {path} was already complete")));
        }
        let kind = classify(path)?;
        if kind != FileKind::Manifest {
            // Path order (module docs): it also guarantees that a database file precedes the
            // directory of its collections and a metadata file precedes its data file.
            if let Some(last) = &self.last_path
                && last.as_str() >= path
            {
                return Err(malformed(
                    path,
                    format!("file {path} arrived after {last}: files must come in path order"),
                ));
            }
            self.last_path = Some(path.to_owned());
        }
        let body = match &kind {
            FileKind::Data(stem) => {
                let Some(state) = self.collections.get(stem) else {
                    return Err(malformed(
                        path,
                        format!("file {path} arrived before {stem}{METADATA_SUFFIX}"),
                    ));
                };
                if state.data_seen {
                    return Err(malformed(path, format!("second data file for {stem}")));
                }
                Body::Lines {
                    pending: Vec::new(),
                    batch: Vec::new(),
                    batch_bytes: 0,
                    line: 0,
                }
            }
            _ => Body::Json(Vec::new()),
        };
        self.open = Some(IncomingFile {
            path: path.to_owned(),
            kind,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            body,
        });
        Ok(())
    }

    /// Splits `data` into document lines (the open file is a data file).
    fn lines(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut start = 0;
        while let Some(pos) = data[start..].iter().position(|&b| b == b'\n') {
            let end = start + pos;
            let line = {
                let Some(IncomingFile {
                    body: Body::Lines { pending, .. },
                    ..
                }) = self.open.as_mut()
                else {
                    return Err(Error::new(ErrorCode::Internal, "no open data file"));
                };
                if pending.is_empty() {
                    data[start..end].to_vec()
                } else {
                    pending.extend_from_slice(&data[start..end]);
                    std::mem::take(pending)
                }
            };
            self.document_line(&line)?;
            start = end + 1;
        }
        let Some(IncomingFile {
            path,
            body: Body::Lines { pending, .. },
            ..
        }) = self.open.as_mut()
        else {
            return Err(Error::new(ErrorCode::Internal, "no open data file"));
        };
        pending.extend_from_slice(&data[start..]);
        if pending.len() > MAX_LINE_BYTES {
            return Err(malformed(
                path,
                format!("{path}: a line is longer than {MAX_LINE_BYTES} bytes"),
            ));
        }
        Ok(())
    }

    /// One complete line of the open data file: parse, count, checksum, import in batches.
    fn document_line(&mut self, line: &[u8]) -> Result<(), Error> {
        let flush = {
            let Some(IncomingFile {
                path,
                kind: FileKind::Data(stem),
                body:
                    Body::Lines {
                        batch,
                        batch_bytes,
                        line: number,
                        ..
                    },
                ..
            }) = self.open.as_mut()
            else {
                return Err(Error::new(ErrorCode::Internal, "no open data file"));
            };
            *number += 1;
            let number = *number;
            let path = path.as_str();
            let at = |e: Error| {
                e.with_detail("file", path)
                    .with_detail("line", number.to_string())
            };
            let text = std::str::from_utf8(line)
                .map_err(|_| at(malformed(path, format!("{path}: a line is not UTF-8"))))?;
            let doc = parse_document(text).map_err(|e| at(Error::from(e)))?;
            let Some(state) = self.collections.get_mut(stem.as_str()) else {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "data file without metadata",
                ));
            };
            state.documents += 1;
            state.checksum.add(&document_hash(&doc));
            if !state.in_scope {
                return Ok(());
            }
            *batch_bytes += line.len();
            batch.push(doc);
            batch.len() >= self.import.batch_docs.max(1) || *batch_bytes >= self.import.batch_bytes
        };
        if flush {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Imports the buffered documents of the open data file.
    fn flush_batch(&mut self) -> Result<(), Error> {
        let Some(IncomingFile {
            kind: FileKind::Data(stem),
            body: Body::Lines {
                batch, batch_bytes, ..
            },
            ..
        }) = self.open.as_mut()
        else {
            return Err(Error::new(ErrorCode::Internal, "no open data file"));
        };
        if batch.is_empty() {
            return Ok(());
        }
        self.cancel.check()?;
        let docs = std::mem::take(batch);
        *batch_bytes = 0;
        let Some(state) = self.collections.get_mut(stem.as_str()) else {
            return Err(Error::new(
                ErrorCode::Internal,
                "data file without metadata",
            ));
        };
        let outcome = self.db.import_documents(
            &state.meta.database,
            &state.meta.collection,
            docs,
            &self.import,
        )?;
        state.imported += outcome.documents;
        Ok(())
    }

    fn end_file(&mut self) -> Result<(), Error> {
        if matches!(
            self.open,
            Some(IncomingFile {
                body: Body::Lines { .. },
                ..
            })
        ) {
            if let Some(IncomingFile {
                path,
                body: Body::Lines { pending, .. },
                ..
            }) = &self.open
                && !pending.is_empty()
            {
                return Err(malformed(
                    path,
                    format!("{path} ends inside a line: the file is truncated"),
                ));
            }
            self.flush_batch()?;
        }
        let Some(file) = self.open.take() else {
            return Err(Error::new(ErrorCode::Internal, "no open dump file"));
        };
        let hash = file.hasher.finalize().to_hex().to_string();
        self.received.insert(file.path.clone(), (file.bytes, hash));
        match (file.kind, file.body) {
            (FileKind::Manifest, Body::Json(bytes)) => {
                self.manifest = Some(DumpManifest::parse(&bytes)?);
            }
            (FileKind::Database(name), Body::Json(bytes)) => {
                let parsed: DatabaseFile = parse_versioned(&file.path, &bytes)?;
                if parsed.database != name {
                    return Err(corrupt(
                        &file.path,
                        format!("names database {:?}", parsed.database),
                    ));
                }
                if self.whole_database_in_scope(&name) {
                    self.databases.insert(name.clone(), parsed);
                    self.ensure_database(&name)?;
                } else {
                    self.databases.insert(name, parsed);
                }
            }
            (FileKind::Metadata(stem), Body::Json(bytes)) => {
                let meta: MetadataFile = parse_versioned(&file.path, &bytes)?;
                self.collection_metadata(&file.path, stem, meta)?;
            }
            (FileKind::Data(stem), _) => {
                if let Some(state) = self.collections.get_mut(&stem) {
                    state.data_seen = true;
                }
            }
            _ => return Err(Error::new(ErrorCode::Internal, "dump file body mismatch")),
        }
        Ok(())
    }

    fn whole_database_in_scope(&self, db: &str) -> bool {
        let s = &self.options.scope;
        (s.databases.is_empty() && s.collections.is_empty()) || s.databases.iter().any(|d| d == db)
    }

    fn collection_in_scope(&self, db: &str, coll: &str) -> bool {
        self.whole_database_in_scope(db)
            || self
                .options
                .scope
                .collections
                .iter()
                .any(|(d, c)| d == db && c == coll)
    }

    /// Creates `name` from its dumped options unless it exists.
    fn ensure_database(&mut self, name: &str) -> Result<(), Error> {
        if self.db.database(name)?.is_some() {
            return Ok(());
        }
        let Some(file) = self.databases.get(name) else {
            return Err(Error::new(ErrorCode::Internal, "database file missing"));
        };
        let options = DatabaseOptions {
            implicit_collection_creation: file.options.implicit_collection_creation,
        };
        self.db.create_database(name, &options)?;
        self.created_databases.push(name.to_owned());
        Ok(())
    }

    /// A complete metadata file: check it, and for a collection in scope create the target
    /// without validator (PD-067).
    fn collection_metadata(
        &mut self,
        path: &str,
        stem: String,
        meta: MetadataFile,
    ) -> Result<(), Error> {
        let in_dir = stem
            .split_once('/')
            .is_some_and(|(db, _)| db == meta.database);
        if !in_dir {
            return Err(corrupt(
                path,
                format!("describes {}.{}", meta.database, meta.collection),
            ));
        }
        if !self.databases.contains_key(&meta.database) {
            return Err(malformed(
                path,
                format!(
                    "{path} arrived before {}: files must come in path order",
                    database_file(&meta.database)
                ),
            ));
        }
        let in_scope = self.collection_in_scope(&meta.database, &meta.collection);
        if in_scope {
            self.cancel.check()?;
            self.ensure_database(&meta.database)?;
            let (database, name) = (meta.database.as_str(), meta.collection.as_str());
            if self.db.collection(database, name)?.is_some() && !self.options.drop_existing {
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "collection {database}.{name} exists; restore with --drop to replace it"
                    ),
                )
                .with_detail("kind", "collection"));
            }
            let spec = CollectionSpec {
                name: name.to_owned(),
                kind: CollectionKind::Document,
                shard_key: meta.shard_key(),
                // Without validator: the dump holds what the source accepted (PD-067).
                options: CollectionOptions::default(),
            };
            self.db
                .prepare_import_target(database, &spec, self.options.drop_existing)?;
            self.created_collections
                .push((database.to_owned(), name.to_owned()));
        }
        self.collections.insert(
            stem,
            CollectionState {
                meta,
                in_scope,
                data_seen: false,
                documents: 0,
                checksum: Sum256::default(),
                imported: 0,
            },
        );
        Ok(())
    }

    /// Every file listed in `dump.json` arrived with its size and hash, and nothing else did.
    fn verify_files(&self, manifest: &DumpManifest) -> Result<(), Error> {
        let mut listed = BTreeSet::new();
        for f in &manifest.files {
            listed.insert(f.path.as_str());
            match self.received.get(&f.path) {
                None => {
                    return Err(corrupt(
                        &f.path,
                        format!("listed in {DUMP_MANIFEST} but missing from the stream"),
                    ));
                }
                Some((bytes, hash)) => {
                    if *bytes != f.bytes {
                        return Err(corrupt(
                            &f.path,
                            format!("{bytes} bytes received, {} expected", f.bytes),
                        ));
                    }
                    if *hash != f.blake3 {
                        return Err(corrupt(&f.path, "BLAKE3 mismatch".to_owned()));
                    }
                }
            }
        }
        for path in self.received.keys() {
            if path != DUMP_MANIFEST && !listed.contains(path.as_str()) {
                return Err(corrupt(
                    path,
                    format!("received but not listed in {DUMP_MANIFEST}"),
                ));
            }
        }
        Ok(())
    }

    /// Checks every received file, collection and the scope against `dump.json`; returns the
    /// stems of the collections in manifest order.
    fn verify(&self, manifest: &DumpManifest) -> Result<Vec<String>, Error> {
        self.verify_files(manifest)?;
        let mut order = Vec::new();
        let mut described = BTreeSet::new();
        for d in &manifest.databases {
            if d.file != database_file(&d.name) || !self.databases.contains_key(&d.name) {
                return Err(corrupt(
                    DUMP_MANIFEST,
                    format!("database {} has no database file", d.name),
                ));
            }
            for c in &d.collections {
                let stem = c
                    .metadata
                    .strip_suffix(METADATA_SUFFIX)
                    .filter(|s| c.data.strip_suffix(DATA_SUFFIX) == Some(*s))
                    .ok_or_else(|| {
                        corrupt(
                            DUMP_MANIFEST,
                            format!("collection {}.{}: inconsistent file names", d.name, c.name),
                        )
                    })?;
                let Some(state) = self.collections.get(stem) else {
                    return Err(corrupt(&c.metadata, "missing from the stream".to_owned()));
                };
                if !state.data_seen {
                    return Err(corrupt(&c.data, "missing from the stream".to_owned()));
                }
                if state.meta.database != d.name || state.meta.collection != c.name {
                    return Err(corrupt(
                        &c.metadata,
                        format!("does not describe {}.{}", d.name, c.name),
                    ));
                }
                if state.documents != c.documents {
                    return Err(corrupt(
                        &c.data,
                        format!(
                            "{} documents received, {} expected",
                            state.documents, c.documents
                        ),
                    ));
                }
                if state.checksum.to_hex() != c.checksum {
                    return Err(corrupt(&c.data, "collection checksum mismatch".to_owned()));
                }
                described.insert(stem.to_owned());
                order.push(stem.to_owned());
            }
        }
        if let Some(stem) = self.collections.keys().find(|s| !described.contains(*s)) {
            return Err(corrupt(
                &format!("{stem}{METADATA_SUFFIX}"),
                format!("received but not listed in {DUMP_MANIFEST}"),
            ));
        }
        // A scope naming something the dump does not hold is the caller's mistake (RGN-1030),
        // detected only now because the dump's content is known only from its manifest.
        let has_db = |name: &str| manifest.databases.iter().any(|d| d.name == name);
        for name in &self.options.scope.databases {
            if !has_db(name) {
                return Err(missing("database", name));
            }
        }
        for (d, c) in &self.options.scope.collections {
            let found = manifest
                .databases
                .iter()
                .any(|x| x.name == *d && x.collections.iter().any(|y| y.name == *c));
            if !found {
                return Err(missing("collection", &format!("{d}.{c}")));
            }
        }
        Ok(order)
    }

    /// After verification: validators, then indexes (PD-067), per collection in scope.
    fn finalize(
        &mut self,
        manifest: &DumpManifest,
        order: &[String],
    ) -> Result<LogicalRestoreSummary, Error> {
        let mut collections = Vec::new();
        for stem in order {
            let Some(state) = self.collections.get(stem) else {
                continue;
            };
            if !state.in_scope {
                continue;
            }
            self.cancel.check()?;
            let (database, name) = (&state.meta.database, &state.meta.collection);
            let options = state.meta.options();
            if options != CollectionOptions::default() {
                self.db.set_collection_options(database, name, &options)?;
            }
            let mut indexes = 0u32;
            for index in &state.meta.indexes {
                self.cancel.check()?;
                self.db.create_index(database, name, &index.spec())?;
                indexes += 1;
            }
            collections.push(RestoredCollection {
                database: database.clone(),
                collection: name.clone(),
                documents: state.imported,
                indexes,
            });
        }
        Ok(LogicalRestoreSummary {
            source_timestamp: manifest.timestamp,
            collections,
        })
    }

    /// Drops what this restore created (module docs, PD-084) and returns `error` with the
    /// outcome of the cleanup in `details.cleanup`.
    fn undo(&mut self, error: Error) -> Error {
        let mut clean = true;
        for (database, collection) in self.created_collections.drain(..).rev() {
            if let Err(e) = self.db.drop_collection(&database, &collection) {
                clean = false;
                tracing::warn!(
                    database = %database,
                    collection = %collection,
                    error = %e,
                    "logical restore: could not drop a partially restored collection"
                );
            }
        }
        for database in self.created_databases.drain(..).rev() {
            if let Err(e) = self.db.drop_database(&database) {
                clean = false;
                tracing::warn!(
                    database = %database,
                    error = %e,
                    "logical restore: could not drop a database it created"
                );
            }
        }
        error.with_detail("cleanup", if clean { "done" } else { "incomplete" })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_bkp_007_checksum_is_order_independent_and_counts_duplicates() {
        let ha = *blake3::hash(b"a").as_bytes();
        let hb = *blake3::hash(b"b").as_bytes();
        let mut ab = Sum256::default();
        ab.add(&ha);
        ab.add(&hb);
        let mut ba = Sum256::default();
        ba.add(&hb);
        ba.add(&ha);
        assert_eq!(ab, ba);
        let mut twice = Sum256::default();
        twice.add(&ha);
        twice.add(&ha);
        assert_ne!(twice, Sum256::default(), "a duplicate does not cancel out");
        // Carries propagate across limbs and wrap modulo 2^256.
        let mut wrap = Sum256::default();
        wrap.add(&[0xff; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        wrap.add(&one);
        assert_eq!(wrap, Sum256::default());
        assert_eq!(Sum256::default().to_hex(), "0".repeat(64));
    }

    #[test]
    fn fr_bkp_007_paths_classify_into_dump_files() {
        assert_eq!(classify("dump.json").unwrap(), FileKind::Manifest);
        assert_eq!(
            classify("shop.database.json").unwrap(),
            FileKind::Database("shop".into())
        );
        assert_eq!(
            classify("shop/a.b.metadata.json").unwrap(),
            FileKind::Metadata("shop/a.b".into())
        );
        assert_eq!(
            classify("shop/case-1/A.ndjson").unwrap(),
            FileKind::Data("shop/case-1/A".into())
        );
        for bad in [
            "shop/x.json",
            "other.json",
            ".database.json",
            "a/b.database",
        ] {
            assert_eq!(
                classify(bad).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "{bad}"
            );
        }
    }

    #[test]
    fn fr_bkp_007_case_colliding_collections_get_distinct_stems() {
        let stems = collection_stems("db", ["A", "Items", "a", "items", "iTems"].into_iter());
        assert_eq!(
            stems,
            [
                "db/A",
                "db/Items",
                "db/case-1/a",
                "db/case-1/items",
                "db/case-2/iTems"
            ]
        );
        let lower: BTreeSet<String> = stems.iter().map(|s| s.to_ascii_lowercase()).collect();
        assert_eq!(lower.len(), stems.len());
    }

    #[test]
    fn fr_bkp_007_newer_dump_files_are_rgn_5007() {
        let e = DumpManifest::parse(br#"{"format_version": 2, "anything": true}"#).unwrap_err();
        assert_eq!(e.code(), ErrorCode::VersionIncompatible);
        let e = DumpManifest::parse(b"not json").unwrap_err();
        assert_eq!(e.code(), ErrorCode::StorageCorruption);
        let e = DumpManifest::parse(br#"{"format_version": 0}"#).unwrap_err();
        assert_eq!(e.code(), ErrorCode::StorageCorruption);
    }
}
