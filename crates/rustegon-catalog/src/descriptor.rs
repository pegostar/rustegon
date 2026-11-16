// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Database and collection descriptors (database-engine.md §1–§2, data-model.md §1, §5).
//!
//! A descriptor is the authoritative metadata of one object. Every change produces a new
//! descriptor with `version + 1`; caches and (from M6) schema leases are keyed by that version.
//! The persisted form is a canonical `RDoc` (see [`crate::codec`]).

use rustegon_doc::keyspace::ShardHash;

/// Version of a freshly created descriptor.
pub const FIRST_VERSION: u64 = 1;
/// The `_id` field, default shard key of document collections (FR-SHD-002).
pub const ID_FIELD: &str = "_id";

/// Lifecycle state of a database or collection descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorState {
    /// Visible and usable.
    Public,
    /// Dropped: the name is released, the id is never reused, and the data span waits for GC.
    Dropping,
}

/// Collection kind (data-model.md §1). Only `Document` is used before M8/M9; the other kinds
/// are representable so that the descriptor format does not change when they arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionKind {
    /// Documents keyed by `_id` (created explicitly or implicitly on first write).
    Document,
    /// Wide-column table (explicit `CREATE TABLE` only).
    Table,
    /// Time-series collection (explicit `CREATE TIMESERIES` only).
    Timeseries,
}

/// How documents are distributed over ranges (FR-SHD-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardStrategy {
    /// Hash of the shard key prefixes the document key (`hash16`, data-model.md §3.2).
    Hashed,
    /// Documents are ordered by the shard key itself.
    Range,
}

/// Shard key: strategy and the field paths it is computed from. Immutable after creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardKey {
    /// Hashed or range.
    pub strategy: ShardStrategy,
    /// Field paths (dot notation), at least one.
    pub fields: Vec<String>,
}

impl Default for ShardKey {
    /// `hashed(_id)`, the default of document collections (data-model.md §3.2).
    fn default() -> Self {
        Self {
            strategy: ShardStrategy::Hashed,
            fields: vec![ID_FIELD.to_owned()],
        }
    }
}

impl ShardKey {
    /// Whether document keys of this collection carry `hash16` (data-model.md §3.2).
    #[must_use]
    pub fn shard_hash(&self) -> ShardHash {
        match self.strategy {
            ShardStrategy::Hashed => ShardHash::Hashed,
            ShardStrategy::Range => ShardHash::Unhashed,
        }
    }
}

/// `validationLevel` (data-model.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationLevel {
    /// No validation.
    Off,
    /// All inserts and updates are validated.
    #[default]
    Strict,
    /// Updates of already-invalid documents are not validated.
    Moderate,
}

/// `validationAction` (data-model.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationAction {
    /// Reject the write with `RGN-1006`.
    #[default]
    Error,
    /// Accept the write and return a warning.
    Warn,
}

/// Collection options stored in the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CollectionOptions {
    /// The validator definition as JSON text (e.g. `{"$jsonSchema":{…}}`), stored verbatim and
    /// evaluated from M3. It is kept as text because stored `RDoc` field names cannot start with
    /// `$` (data-model.md §2.2) while JSON Schema keywords do (database-engine.md §2.5).
    pub validator: Option<String>,
    /// When the validator applies.
    pub validation_level: ValidationLevel,
    /// What a failed validation does.
    pub validation_action: ValidationAction,
}

/// Database options stored in the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseOptions {
    /// `implicitCollectionCreation`: whether the first write to a missing collection creates it
    /// (FR-SCH-001; default `true`, feature-analysis F03). When false the write fails with
    /// `RGN-1030`.
    pub implicit_collection_creation: bool,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            implicit_collection_creation: true,
        }
    }
}

/// Descriptor of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseDescriptor {
    /// Cluster-unique id, never reused.
    pub id: u32,
    /// Name (system-overview.md §9 rules).
    pub name: String,
    /// Descriptor version, +1 on every change.
    pub version: u64,
    /// Lifecycle state.
    pub state: DescriptorState,
    /// Options.
    pub options: DatabaseOptions,
}

/// Descriptor of a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionDescriptor {
    /// Cluster-unique id, never reused.
    pub id: u32,
    /// Id of the owning database.
    pub database_id: u32,
    /// Name, unique within the database (system-overview.md §9 rules).
    pub name: String,
    /// Kind (data-model.md §1).
    pub kind: CollectionKind,
    /// Descriptor version, +1 on every change.
    pub version: u64,
    /// Lifecycle state.
    pub state: DescriptorState,
    /// Shard key, immutable.
    pub shard_key: ShardKey,
    /// Options (validator).
    pub options: CollectionOptions,
}

/// Any descriptor stored under `0x02 'd' id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// A database.
    Database(DatabaseDescriptor),
    /// A collection.
    Collection(CollectionDescriptor),
}

impl Descriptor {
    /// The descriptor id.
    #[must_use]
    pub fn id(&self) -> u32 {
        match self {
            Self::Database(d) => d.id,
            Self::Collection(c) => c.id,
        }
    }

    /// The descriptor version.
    #[must_use]
    pub fn version(&self) -> u64 {
        match self {
            Self::Database(d) => d.version,
            Self::Collection(c) => c.version,
        }
    }

    /// The object name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Database(d) => &d.name,
            Self::Collection(c) => &c.name,
        }
    }

    /// The parent id of the name-index entry ([`crate::keys::ROOT_PARENT_ID`] for databases).
    #[must_use]
    pub fn parent_id(&self) -> u32 {
        match self {
            Self::Database(_) => crate::keys::ROOT_PARENT_ID,
            Self::Collection(c) => c.database_id,
        }
    }

    /// The lifecycle state.
    #[must_use]
    pub fn state(&self) -> DescriptorState {
        match self {
            Self::Database(d) => d.state,
            Self::Collection(c) => c.state,
        }
    }
}
