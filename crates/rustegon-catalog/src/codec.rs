// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Descriptor persistence: catalog format v1 = a canonical `RDoc` (data-model.md §4) with fixed
//! fields (database-engine.md §2.5).
//!
//! ```text
//! database   { catalog_format: 1, type: "database", id, name, version, state,
//!              options: { implicitCollectionCreation: bool } }
//! collection { catalog_format: 1, type: "collection", id, database_id, name, kind, version,
//!              state, shard_key: { strategy, fields: [string] },
//!              options: { validator?: string, validationLevel, validationAction } }
//! ```
//! Integers are `int64`; ids must fit in u32 and versions are ≥ 1. Decoding is strict: unknown
//! fields, wrong types and unknown enum strings are corruption, because a new field or value
//! means a new `catalog_format` (implementation-rules.md §6) and silently dropping it on a
//! rewrite would lose metadata.

use rustegon_doc::{Document, Value, rdoc};

use crate::{
    descriptor::{
        CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor,
        DatabaseOptions, Descriptor, DescriptorState, ShardKey, ShardStrategy, ValidationAction,
        ValidationLevel,
    },
    error::{CatalogError, CatalogResult},
};

/// Catalog format written by this crate (the `catalog_format` field).
pub const CATALOG_FORMAT: i64 = 1;

const F_FORMAT: &str = "catalog_format";
const F_TYPE: &str = "type";
const F_ID: &str = "id";
const F_DATABASE_ID: &str = "database_id";
const F_NAME: &str = "name";
const F_KIND: &str = "kind";
const F_VERSION: &str = "version";
const F_STATE: &str = "state";
const F_SHARD_KEY: &str = "shard_key";
const F_STRATEGY: &str = "strategy";
const F_FIELDS: &str = "fields";
const F_OPTIONS: &str = "options";
const F_IMPLICIT: &str = "implicitCollectionCreation";
const F_VALIDATOR: &str = "validator";
const F_LEVEL: &str = "validationLevel";
const F_ACTION: &str = "validationAction";
const TYPE_DATABASE: &str = "database";
const TYPE_COLLECTION: &str = "collection";

/// String forms of the enums; one table per enum keeps encode and decode in sync.
const STATES: [(DescriptorState, &str); 2] = [
    (DescriptorState::Public, "public"),
    (DescriptorState::Dropping, "dropping"),
];
const KINDS: [(CollectionKind, &str); 3] = [
    (CollectionKind::Document, "document"),
    (CollectionKind::Table, "table"),
    (CollectionKind::Timeseries, "timeseries"),
];
const STRATEGIES: [(ShardStrategy, &str); 2] = [
    (ShardStrategy::Hashed, "hashed"),
    (ShardStrategy::Range, "range"),
];
const LEVELS: [(ValidationLevel, &str); 3] = [
    (ValidationLevel::Off, "off"),
    (ValidationLevel::Strict, "strict"),
    (ValidationLevel::Moderate, "moderate"),
];
const ACTIONS: [(ValidationAction, &str); 2] = [
    (ValidationAction::Error, "error"),
    (ValidationAction::Warn, "warn"),
];

fn to_str<T: PartialEq + Copy>(table: &[(T, &'static str)], v: T) -> &'static str {
    // Every enum variant has a row (checked by the round-trip tests), so the fallback is dead.
    table.iter().find(|(t, _)| *t == v).map_or("", |(_, s)| s)
}

fn from_str<T: Copy>(table: &[(T, &'static str)], field: &str, s: &str) -> CatalogResult<T> {
    table
        .iter()
        .find(|(_, n)| *n == s)
        .map(|(t, _)| *t)
        .ok_or_else(|| CatalogError::corrupt(format!("{field}: unknown value {s:?}")))
}

fn version_value(version: u64) -> CatalogResult<Value> {
    i64::try_from(version)
        .map(Value::Int64)
        .map_err(|_| CatalogError::InvalidArgument("descriptor version above i64::MAX".into()))
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// Encodes a descriptor into its canonical `RDoc` bytes.
///
/// # Errors
/// [`CatalogError::InvalidArgument`] if the version exceeds `i64::MAX`; [`CatalogError::Doc`]
/// if the document codec rejects it (e.g. size limits).
pub fn encode_descriptor(desc: &Descriptor) -> CatalogResult<Vec<u8>> {
    let mut doc = Document::new();
    doc.insert(F_FORMAT, Value::Int64(CATALOG_FORMAT));
    match desc {
        Descriptor::Database(d) => {
            doc.insert(F_TYPE, s(TYPE_DATABASE));
            doc.insert(F_ID, Value::Int64(i64::from(d.id)));
            doc.insert(F_NAME, s(&d.name));
            doc.insert(F_VERSION, version_value(d.version)?);
            doc.insert(F_STATE, s(to_str(&STATES, d.state)));
            let mut opts = Document::new();
            opts.insert(
                F_IMPLICIT,
                Value::Bool(d.options.implicit_collection_creation),
            );
            doc.insert(F_OPTIONS, Value::Object(opts));
        }
        Descriptor::Collection(c) => {
            doc.insert(F_TYPE, s(TYPE_COLLECTION));
            doc.insert(F_ID, Value::Int64(i64::from(c.id)));
            doc.insert(F_DATABASE_ID, Value::Int64(i64::from(c.database_id)));
            doc.insert(F_NAME, s(&c.name));
            doc.insert(F_KIND, s(to_str(&KINDS, c.kind)));
            doc.insert(F_VERSION, version_value(c.version)?);
            doc.insert(F_STATE, s(to_str(&STATES, c.state)));
            let mut shard = Document::new();
            shard.insert(F_STRATEGY, s(to_str(&STRATEGIES, c.shard_key.strategy)));
            shard.insert(
                F_FIELDS,
                Value::Array(c.shard_key.fields.iter().map(|f| s(f)).collect()),
            );
            doc.insert(F_SHARD_KEY, Value::Object(shard));
            let mut opts = Document::new();
            if let Some(v) = &c.options.validator {
                opts.insert(F_VALIDATOR, s(v));
            }
            opts.insert(F_LEVEL, s(to_str(&LEVELS, c.options.validation_level)));
            opts.insert(F_ACTION, s(to_str(&ACTIONS, c.options.validation_action)));
            doc.insert(F_OPTIONS, Value::Object(opts));
        }
    }
    Ok(rdoc::encode(&doc)?)
}

/// Strict field reader over one object: every field must be consumed exactly once.
struct Fields<'a> {
    doc: &'a Document,
    allowed: &'static [&'static str],
    ctx: &'static str,
}

impl<'a> Fields<'a> {
    fn new(
        doc: &'a Document,
        allowed: &'static [&'static str],
        ctx: &'static str,
    ) -> CatalogResult<Self> {
        if let Some((name, _)) = doc.iter().find(|(n, _)| !allowed.contains(n)) {
            return Err(CatalogError::corrupt(format!(
                "{ctx}: unknown field {name:?}"
            )));
        }
        Ok(Self { doc, allowed, ctx })
    }

    fn opt(&self, name: &str) -> Option<&'a Value> {
        debug_assert!(self.allowed.contains(&name), "field {name} not declared");
        self.doc.get(name)
    }

    fn req(&self, name: &str) -> CatalogResult<&'a Value> {
        self.opt(name)
            .ok_or_else(|| CatalogError::corrupt(format!("{}: missing field {name}", self.ctx)))
    }

    fn wrong(&self, name: &str, want: &str) -> CatalogError {
        CatalogError::corrupt(format!("{}: field {name} is not {want}", self.ctx))
    }

    fn string(&self, name: &str) -> CatalogResult<&'a str> {
        match self.req(name)? {
            Value::String(v) => Ok(v),
            _ => Err(self.wrong(name, "a string")),
        }
    }

    fn int(&self, name: &str) -> CatalogResult<i64> {
        match self.req(name)? {
            Value::Int64(v) => Ok(*v),
            _ => Err(self.wrong(name, "an int64")),
        }
    }

    fn id(&self, name: &str) -> CatalogResult<u32> {
        u32::try_from(self.int(name)?).map_err(|_| self.wrong(name, "a u32 id"))
    }

    fn version(&self) -> CatalogResult<u64> {
        u64::try_from(self.int(F_VERSION)?)
            .ok()
            .filter(|v| *v >= 1)
            .ok_or_else(|| self.wrong(F_VERSION, "a version >= 1"))
    }

    fn object(&self, name: &str) -> CatalogResult<&'a Document> {
        match self.req(name)? {
            Value::Object(v) => Ok(v),
            _ => Err(self.wrong(name, "an object")),
        }
    }
}

const DATABASE_FIELDS: &[&str] = &[
    F_FORMAT, F_TYPE, F_ID, F_NAME, F_VERSION, F_STATE, F_OPTIONS,
];
const COLLECTION_FIELDS: &[&str] = &[
    F_FORMAT,
    F_TYPE,
    F_ID,
    F_DATABASE_ID,
    F_NAME,
    F_KIND,
    F_VERSION,
    F_STATE,
    F_SHARD_KEY,
    F_OPTIONS,
];

/// Decodes a descriptor written by [`encode_descriptor`].
///
/// # Errors
/// [`CatalogError::Corrupt`] for bytes that are not a valid catalog-format-1 descriptor
/// (including an unsupported `catalog_format`).
pub fn decode_descriptor(bytes: &[u8]) -> CatalogResult<Descriptor> {
    let doc =
        rdoc::decode(bytes).map_err(|e| CatalogError::corrupt(format!("descriptor RDoc: {e}")))?;
    match doc.get(F_FORMAT) {
        Some(Value::Int64(CATALOG_FORMAT)) => {}
        Some(Value::Int64(v)) => {
            return Err(CatalogError::corrupt(format!(
                "unsupported catalog_format {v}"
            )));
        }
        _ => return Err(CatalogError::corrupt("missing catalog_format")),
    }
    match doc.get(F_TYPE) {
        Some(Value::String(t)) if t == TYPE_DATABASE => decode_database(&doc),
        Some(Value::String(t)) if t == TYPE_COLLECTION => decode_collection(&doc),
        _ => Err(CatalogError::corrupt("unknown descriptor type")),
    }
}

fn decode_database(doc: &Document) -> CatalogResult<Descriptor> {
    let f = Fields::new(doc, DATABASE_FIELDS, "database descriptor")?;
    let o = Fields::new(f.object(F_OPTIONS)?, &[F_IMPLICIT], "database options")?;
    let implicit = match o.req(F_IMPLICIT)? {
        Value::Bool(b) => *b,
        _ => return Err(o.wrong(F_IMPLICIT, "a bool")),
    };
    Ok(Descriptor::Database(DatabaseDescriptor {
        id: f.id(F_ID)?,
        name: f.string(F_NAME)?.to_owned(),
        version: f.version()?,
        state: from_str(&STATES, F_STATE, f.string(F_STATE)?)?,
        options: DatabaseOptions {
            implicit_collection_creation: implicit,
        },
    }))
}

fn decode_collection(doc: &Document) -> CatalogResult<Descriptor> {
    let f = Fields::new(doc, COLLECTION_FIELDS, "collection descriptor")?;
    let sk = Fields::new(f.object(F_SHARD_KEY)?, &[F_STRATEGY, F_FIELDS], "shard key")?;
    let fields = match sk.req(F_FIELDS)? {
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.clone()),
                _ => Err(sk.wrong(F_FIELDS, "an array of strings")),
            })
            .collect::<CatalogResult<Vec<_>>>()?,
        _ => return Err(sk.wrong(F_FIELDS, "a non-empty array")),
    };
    let o = Fields::new(
        f.object(F_OPTIONS)?,
        &[F_VALIDATOR, F_LEVEL, F_ACTION],
        "collection options",
    )?;
    let validator = match o.opt(F_VALIDATOR) {
        None => None,
        Some(Value::String(v)) => Some(v.clone()),
        Some(_) => return Err(o.wrong(F_VALIDATOR, "a string")),
    };
    Ok(Descriptor::Collection(CollectionDescriptor {
        id: f.id(F_ID)?,
        database_id: f.id(F_DATABASE_ID)?,
        name: f.string(F_NAME)?.to_owned(),
        kind: from_str(&KINDS, F_KIND, f.string(F_KIND)?)?,
        version: f.version()?,
        state: from_str(&STATES, F_STATE, f.string(F_STATE)?)?,
        shard_key: ShardKey {
            strategy: from_str(&STRATEGIES, F_STRATEGY, sk.string(F_STRATEGY)?)?,
            fields,
        },
        options: CollectionOptions {
            validator,
            validation_level: from_str(&LEVELS, F_LEVEL, o.string(F_LEVEL)?)?,
            validation_action: from_str(&ACTIONS, F_ACTION, o.string(F_ACTION)?)?,
        },
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn db() -> Descriptor {
        Descriptor::Database(DatabaseDescriptor {
            id: 100,
            name: "shop".into(),
            version: 1,
            state: DescriptorState::Public,
            options: DatabaseOptions::default(),
        })
    }

    #[test]
    fn database_round_trip() {
        let bytes = encode_descriptor(&db()).unwrap();
        assert_eq!(decode_descriptor(&bytes).unwrap(), db());
    }

    #[test]
    fn rejects_unknown_field_and_format() {
        let mut doc = rdoc::decode(&encode_descriptor(&db()).unwrap()).unwrap();
        doc.insert("extra", Value::Null);
        let err = decode_descriptor(&rdoc::encode(&doc).unwrap()).unwrap_err();
        assert!(matches!(err, CatalogError::Corrupt(_)), "{err}");
        doc = rdoc::decode(&encode_descriptor(&db()).unwrap()).unwrap();
        doc.insert(F_FORMAT, Value::Int64(2));
        let err = decode_descriptor(&rdoc::encode(&doc).unwrap()).unwrap_err();
        assert!(err.to_string().contains("catalog_format 2"), "{err}");
        assert!(decode_descriptor(b"junk").is_err());
    }

    #[test]
    fn rejects_out_of_range_id_and_zero_version() {
        let mut doc = rdoc::decode(&encode_descriptor(&db()).unwrap()).unwrap();
        doc.insert(F_ID, Value::Int64(i64::from(u32::MAX) + 1));
        assert!(decode_descriptor(&rdoc::encode(&doc).unwrap()).is_err());
        doc = rdoc::decode(&encode_descriptor(&db()).unwrap()).unwrap();
        doc.insert(F_VERSION, Value::Int64(0));
        assert!(decode_descriptor(&rdoc::encode(&doc).unwrap()).is_err());
    }
}
