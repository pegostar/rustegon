// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index descriptors (indexing.md §1; FR-IDX-001, FR-IDX-005) and their online schema-change
//! state machine (database-engine.md §2.3).
//!
//! - [`IndexDescriptor`]: the persisted catalog entry of one secondary index;
//! - [`codec`]: its persisted form, *index descriptor format* 1 (a canonical `RDoc`, strict
//!   decoding like the database/collection descriptors);
//! - [`ops`]: transaction-agnostic DDL (create, drop, list, state transitions), reads through
//!   [`crate::CatalogRead`], writes returned as [`crate::Mutation`]s.
//!
//! Index descriptors live in their own system sub-namespace (`0x02 'i' collection_id index_id`)
//! instead of under `0x02 'd'`, so that the frozen catalog format 1 records and their decoder are
//! untouched; index ids come from the shared descriptor id sequence, so they never collide with
//! database or collection ids.

pub mod codec;
pub mod ops;

use rustegon_doc::path::FieldPath;

use crate::error::{CatalogError, CatalogResult};

/// Maximum number of (non-dropping) indexes per collection (FR-IDX-005, system-overview §9).
pub const MAX_INDEXES_PER_COLLECTION: usize = 64;
/// Maximum number of fields of a compound index (FR-IDX-001, system-overview §9).
pub const MAX_COMPOUND_FIELDS: usize = 32;
/// Maximum number of covered (`INCLUDE`) fields. *Provisional (PD pending)*: not specified;
/// the compound-field limit is reused.
pub const MAX_INCLUDE_FIELDS: usize = 32;
/// Maximum index name length. *Provisional (PD pending)*: index names are not covered by
/// system-overview §9; the alphabet of collection names is used with a 128-character limit.
pub const MAX_INDEX_NAME_LEN: usize = 128;
/// Suffix of a wildcard path (`path.**`, indexing.md §3); `**` alone is the whole document.
pub const WILDCARD: &str = "**";

/// Kind of index (indexing.md §2). Only `secondary` exists in index descriptor format 1; the
/// other kinds (ttl, fulltext, geo, vector, mapreduce) carry kind-specific options and arrive
/// with their milestones as a new format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexKind {
    /// Single, compound, multikey, unique, sparse, partial and wildcard indexes (F05).
    Secondary,
}

/// Sort direction of one indexed field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOrder {
    /// Ascending.
    Asc,
    /// Descending (key bytes bit-inverted, data-model.md §3.1).
    Desc,
}

/// One indexed field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexField {
    /// Field path in dot notation (data-model.md §2.2); `a.**` / `**` for a wildcard index.
    pub path: String,
    /// Direction.
    pub order: IndexOrder,
}

impl IndexField {
    /// An ascending field.
    #[must_use]
    pub fn asc(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            order: IndexOrder::Asc,
        }
    }

    /// A descending field.
    #[must_use]
    pub fn desc(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            order: IndexOrder::Desc,
        }
    }

    /// Whether this is a wildcard field (`**` or `prefix.**`).
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.path == WILDCARD
            || self
                .path
                .strip_suffix(WILDCARD)
                .is_some_and(|p| p.ends_with('.'))
    }

    /// The path below which a wildcard field indexes every leaf (`None` = whole document), or
    /// `None` for a non-wildcard field as well; check [`IndexField::is_wildcard`] first.
    #[must_use]
    pub fn wildcard_prefix(&self) -> Option<&str> {
        self.path
            .strip_suffix(WILDCARD)
            .and_then(|p| p.strip_suffix('.'))
    }
}

/// Distribution scope (indexing.md §2): global by default, `LOCAL` only for tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IndexScope {
    /// Entries are spread over their own ranges (default).
    #[default]
    Global,
    /// Entries live under the partition prefix of a table (data-model.md §6).
    Local,
}

/// Who created the index (indexing.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IndexOrigin {
    /// `CREATE INDEX` by a user.
    #[default]
    Manual,
    /// The index advisor (`auto_…`).
    Auto,
}

/// State of the online schema-change state machine (database-engine.md §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexState {
    /// Writers delete entries but do not add them.
    DeleteOnly,
    /// Writers maintain the index; readers ignore it.
    WriteOnly,
    /// The backfill job writes entries for existing data; writers maintain the index.
    Backfilling,
    /// Uniqueness / count check; writers maintain the index.
    Validating,
    /// Usable by readers (the planner).
    Public,
    /// Dropped: nobody reads or writes it; its span waits for GC. The name is free again.
    Dropping,
}

impl IndexState {
    /// Whether writers must delete stale entries (every state but `Dropping`).
    #[must_use]
    pub fn deletes_entries(self) -> bool {
        self != Self::Dropping
    }

    /// Whether writers must add entries (database-engine.md §3 step 4: write-only or later).
    #[must_use]
    pub fn adds_entries(self) -> bool {
        matches!(
            self,
            Self::WriteOnly | Self::Backfilling | Self::Validating | Self::Public
        )
    }

    /// Whether readers (the planner) may use the index.
    #[must_use]
    pub fn readable(self) -> bool {
        self == Self::Public
    }

    /// Whether `self → to` is an edge of the state machine.
    ///
    /// The diagram of database-engine.md §2.3 is followed, plus `X → Dropping` from every build
    /// state: a failed or cancelled build drops the index (indexing.md §5 "Failure → index
    /// dropped"). *Provisional (PD pending)*: the diagram only shows `Validating → Dropping` and
    /// `Public → Dropping`.
    #[must_use]
    pub fn can_transition_to(self, to: Self) -> bool {
        use IndexState as S;
        matches!(
            (self, to),
            (S::DeleteOnly, S::WriteOnly)
                | (S::WriteOnly, S::Backfilling)
                | (S::Backfilling, S::Validating)
                | (S::Validating, S::Public)
                | (
                    S::DeleteOnly | S::WriteOnly | S::Backfilling | S::Validating | S::Public,
                    S::Dropping
                )
        )
    }
}

/// Descriptor of one index (indexing.md §1).
///
/// Usage statistics (`stats` in indexing.md §1: entries, bytes, last used, ops; FR-IDX-004) are
/// runtime counters and deliberately not part of the descriptor: every write would otherwise
/// bump the descriptor version. They are kept by the stats lane in their own keys.
// The flags mirror independent options of the catalog entry (indexing.md §1), not states.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDescriptor {
    /// Cluster-unique id (shared descriptor id sequence), never reused.
    pub id: u32,
    /// Owning database.
    pub database_id: u32,
    /// Owning collection.
    pub collection_id: u32,
    /// Name, unique among the non-dropping indexes of the collection.
    pub name: String,
    /// Kind.
    pub kind: IndexKind,
    /// Indexed fields in key order (1..=32).
    pub fields: Vec<IndexField>,
    /// Unique index (`U` family, value = `_id`).
    pub unique: bool,
    /// Documents missing every indexed field get no entry.
    pub sparse: bool,
    /// Partial-index predicate as query text (evaluated by the query layer), if any.
    pub partial: Option<String>,
    /// Maintained but ignored by the planner unless forced (FR-IDX-006).
    pub hidden: bool,
    /// Global or local.
    pub scope: IndexScope,
    /// Schema-change state.
    pub state: IndexState,
    /// Manual or auto.
    pub origin: IndexOrigin,
    /// Descriptor version, +1 on every change.
    pub version: u64,
    /// Covered fields stored in the entry value (`INCLUDE`).
    pub include: Vec<String>,
    /// Set once a document produced more than one entry or an array value (indexing.md §3):
    /// the planner can then not assume one entry per document.
    pub multikey: bool,
    /// Creation time, milliseconds since the Unix epoch (UTC).
    pub created_at_ms: i64,
}

impl IndexDescriptor {
    /// Whether this is a wildcard index.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.fields.first().is_some_and(IndexField::is_wildcard)
    }
}

/// Parameters of `CREATE INDEX`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSpec {
    /// Index name.
    pub name: String,
    /// Indexed fields.
    pub fields: Vec<IndexField>,
    /// Unique.
    pub unique: bool,
    /// Sparse.
    pub sparse: bool,
    /// Partial predicate text.
    pub partial: Option<String>,
    /// Hidden.
    pub hidden: bool,
    /// Scope.
    pub scope: IndexScope,
    /// Origin.
    pub origin: IndexOrigin,
    /// Covered fields.
    pub include: Vec<String>,
    /// Creation time (ms since the Unix epoch), supplied by the caller's clock.
    pub created_at_ms: i64,
}

impl IndexSpec {
    /// A manual, global, non-unique index on `fields` with no options.
    #[must_use]
    pub fn new(name: impl Into<String>, fields: Vec<IndexField>) -> Self {
        Self {
            name: name.into(),
            fields,
            unique: false,
            sparse: false,
            partial: None,
            hidden: false,
            scope: IndexScope::Global,
            origin: IndexOrigin::Manual,
            include: Vec::new(),
            created_at_ms: 0,
        }
    }

    /// The same spec, unique.
    #[must_use]
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    /// The same spec, sparse.
    #[must_use]
    pub fn sparse(mut self) -> Self {
        self.sparse = true;
        self
    }
}

/// Checks an index name: 1–128 chars `[A-Za-z0-9_.-]` (*Provisional*, see
/// [`MAX_INDEX_NAME_LEN`]).
///
/// # Errors
/// [`CatalogError::InvalidArgument`] (`RGN-1001`).
pub fn validate_index_name(name: &str) -> CatalogResult<()> {
    let reason = if name.is_empty() {
        Some("empty")
    } else if name.len() > MAX_INDEX_NAME_LEN {
        Some("longer than 128 characters")
    } else if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        Some("allowed characters are [A-Za-z0-9_.-]")
    } else {
        None
    };
    reason.map_or(Ok(()), |r| {
        Err(CatalogError::InvalidArgument(format!(
            "invalid index name: {r}"
        )))
    })
}

fn invalid(msg: impl Into<String>) -> CatalogError {
    CatalogError::InvalidArgument(msg.into())
}

/// Checks the definition part of a spec (fields, include list, option combinations).
///
/// Rules (indexing.md §3, FR-IDX-001): 1–32 fields with valid, distinct paths; a wildcard
/// field must be the only field and is not unique; covered fields are valid, distinct and not
/// wildcards; `LOCAL` scope is for tables only (checked by the caller that knows the collection
/// kind).
///
/// # Errors
/// [`CatalogError::InvalidArgument`] (`RGN-1001`).
pub fn validate_spec(spec: &IndexSpec) -> CatalogResult<()> {
    validate_index_name(&spec.name)?;
    if spec.fields.is_empty() {
        return Err(invalid("an index needs at least one field"));
    }
    if spec.fields.len() > MAX_COMPOUND_FIELDS {
        return Err(invalid(format!(
            "a compound index has at most {MAX_COMPOUND_FIELDS} fields"
        )));
    }
    let wildcard = spec.fields.iter().any(IndexField::is_wildcard);
    if wildcard && spec.fields.len() > 1 {
        return Err(invalid("a wildcard field must be the only indexed field"));
    }
    if wildcard && spec.unique {
        return Err(invalid("a wildcard index cannot be unique"));
    }
    for (i, f) in spec.fields.iter().enumerate() {
        check_path(&f.path, f.is_wildcard())?;
        if spec.fields[..i].iter().any(|g| g.path == f.path) {
            return Err(invalid(format!("field {:?} is indexed twice", f.path)));
        }
    }
    if spec.include.len() > MAX_INCLUDE_FIELDS {
        return Err(invalid(format!(
            "at most {MAX_INCLUDE_FIELDS} covered fields"
        )));
    }
    for (i, p) in spec.include.iter().enumerate() {
        check_path(p, false)?;
        if p == WILDCARD || p.ends_with(".**") {
            return Err(invalid("a covered field cannot be a wildcard"));
        }
        if spec.include[..i].contains(p) {
            return Err(invalid(format!("covered field {p:?} is listed twice")));
        }
    }
    if spec.partial.as_deref().is_some_and(|p| p.trim().is_empty()) {
        return Err(invalid("empty partial-index predicate"));
    }
    Ok(())
}

fn check_path(path: &str, wildcard: bool) -> CatalogResult<()> {
    let base = if wildcard {
        match path.strip_suffix(WILDCARD) {
            Some("") => return Ok(()),
            Some(p) => p.strip_suffix('.').unwrap_or(p),
            None => path,
        }
    } else {
        path
    };
    FieldPath::parse(base)
        .map(|_| ())
        .map_err(|e| invalid(format!("invalid field path {path:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_detection() {
        assert!(IndexField::asc("**").is_wildcard());
        assert!(IndexField::asc("a.b.**").is_wildcard());
        assert!(!IndexField::asc("a**").is_wildcard());
        assert!(!IndexField::asc("a").is_wildcard());
        assert_eq!(IndexField::asc("a.b.**").wildcard_prefix(), Some("a.b"));
        assert_eq!(IndexField::asc("**").wildcard_prefix(), None);
    }

    #[test]
    fn state_machine_edges() {
        use IndexState as S;
        let all = [
            S::DeleteOnly,
            S::WriteOnly,
            S::Backfilling,
            S::Validating,
            S::Public,
            S::Dropping,
        ];
        let forward = [
            (S::DeleteOnly, S::WriteOnly),
            (S::WriteOnly, S::Backfilling),
            (S::Backfilling, S::Validating),
            (S::Validating, S::Public),
        ];
        for from in all {
            for to in all {
                let expected =
                    forward.contains(&(from, to)) || (to == S::Dropping && from != S::Dropping);
                assert_eq!(from.can_transition_to(to), expected, "{from:?} -> {to:?}");
            }
        }
        assert!(!S::DeleteOnly.adds_entries() && S::DeleteOnly.deletes_entries());
        assert!(S::WriteOnly.adds_entries() && !S::WriteOnly.readable());
        assert!(S::Public.readable());
        assert!(!S::Dropping.deletes_entries() && !S::Dropping.adds_entries());
    }

    #[test]
    fn spec_validation() {
        let ok = IndexSpec::new("by_a", vec![IndexField::asc("a"), IndexField::desc("b.c")]);
        assert!(validate_spec(&ok).is_ok());
        let cases = [
            IndexSpec::new("", vec![IndexField::asc("a")]),
            IndexSpec::new("a b", vec![IndexField::asc("a")]),
            IndexSpec::new("x", vec![]),
            IndexSpec::new("x", vec![IndexField::asc("a"), IndexField::asc("a")]),
            IndexSpec::new("x", vec![IndexField::asc("a..b")]),
            IndexSpec::new("x", vec![IndexField::asc("a.**"), IndexField::asc("b")]),
            IndexSpec::new("x", vec![IndexField::asc("a.**")]).unique(),
            IndexSpec::new(
                "x",
                (0..33).map(|i| IndexField::asc(format!("f{i}"))).collect(),
            ),
        ];
        for spec in cases {
            assert!(validate_spec(&spec).is_err(), "{spec:?}");
        }
        assert!(validate_spec(&IndexSpec::new("w", vec![IndexField::asc("**")])).is_ok());
        let mut inc = IndexSpec::new("x", vec![IndexField::asc("a")]);
        inc.include = vec!["b".into(), "b".into()];
        assert!(validate_spec(&inc).is_err());
        assert!(validate_index_name(&"i".repeat(128)).is_ok());
        assert!(validate_index_name(&"i".repeat(129)).is_err());
    }
}
