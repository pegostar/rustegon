// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index descriptor format 1: a canonical `RDoc` with fixed fields (indexing.md §1,
//! database-engine.md §2.5 "Index descriptors").
//!
//! ```text
//! { index_format: 1, type: "index", id, database_id, collection_id, name, kind: "secondary",
//!   fields: [{ path: string, order: "asc"|"desc" }, …],
//!   unique: bool, sparse: bool, partial?: string, hidden: bool,
//!   scope: "global"|"local",
//!   state: "delete_only"|"write_only"|"backfilling"|"validating"|"public"|"dropping",
//!   origin: "manual"|"auto", version, include: [string], multikey: bool,
//!   created_at: datetime }
//! ```
//! Integers are `int64` (ids must fit in u32, `version ≥ 1`); `created_at` is a `datetime`.
//! Decoding is strict, as for catalog format 1 (`crate::codec`): an unknown field, a wrong type
//! or an unknown enum string is corruption, because a new field means index format 2
//! (implementation-rules.md §6) and dropping it silently on a rewrite would lose metadata.

use rustegon_doc::{Document, Value, rdoc};

use super::{
    IndexDescriptor, IndexField, IndexKind, IndexOrder, IndexOrigin, IndexScope, IndexState,
};
use crate::error::{CatalogError, CatalogResult};

/// Index descriptor format written by this crate (the `index_format` field).
pub const INDEX_FORMAT: i64 = 1;

const F_FORMAT: &str = "index_format";
const F_TYPE: &str = "type";
const F_ID: &str = "id";
const F_DATABASE_ID: &str = "database_id";
const F_COLLECTION_ID: &str = "collection_id";
const F_NAME: &str = "name";
const F_KIND: &str = "kind";
const F_FIELDS: &str = "fields";
const F_PATH: &str = "path";
const F_ORDER: &str = "order";
const F_UNIQUE: &str = "unique";
const F_SPARSE: &str = "sparse";
const F_PARTIAL: &str = "partial";
const F_HIDDEN: &str = "hidden";
const F_SCOPE: &str = "scope";
const F_STATE: &str = "state";
const F_ORIGIN: &str = "origin";
const F_VERSION: &str = "version";
const F_INCLUDE: &str = "include";
const F_MULTIKEY: &str = "multikey";
const F_CREATED_AT: &str = "created_at";
const TYPE_INDEX: &str = "index";

const TOP_FIELDS: &[&str] = &[
    F_FORMAT,
    F_TYPE,
    F_ID,
    F_DATABASE_ID,
    F_COLLECTION_ID,
    F_NAME,
    F_KIND,
    F_FIELDS,
    F_UNIQUE,
    F_SPARSE,
    F_PARTIAL,
    F_HIDDEN,
    F_SCOPE,
    F_STATE,
    F_ORIGIN,
    F_VERSION,
    F_INCLUDE,
    F_MULTIKEY,
    F_CREATED_AT,
];
const FIELD_FIELDS: &[&str] = &[F_PATH, F_ORDER];

/// String forms of the enums; one table per enum keeps encode and decode in sync.
const KINDS: [(IndexKind, &str); 1] = [(IndexKind::Secondary, "secondary")];
const ORDERS: [(IndexOrder, &str); 2] = [(IndexOrder::Asc, "asc"), (IndexOrder::Desc, "desc")];
const SCOPES: [(IndexScope, &str); 2] =
    [(IndexScope::Global, "global"), (IndexScope::Local, "local")];
const ORIGINS: [(IndexOrigin, &str); 2] =
    [(IndexOrigin::Manual, "manual"), (IndexOrigin::Auto, "auto")];
const STATES: [(IndexState, &str); 6] = [
    (IndexState::DeleteOnly, "delete_only"),
    (IndexState::WriteOnly, "write_only"),
    (IndexState::Backfilling, "backfilling"),
    (IndexState::Validating, "validating"),
    (IndexState::Public, "public"),
    (IndexState::Dropping, "dropping"),
];

fn to_str<T: PartialEq + Copy>(table: &[(T, &'static str)], v: T) -> &'static str {
    // Every variant has a row (checked by the round-trip tests), so the fallback is dead.
    table.iter().find(|(t, _)| *t == v).map_or("", |(_, s)| s)
}

fn from_str<T: Copy>(table: &[(T, &'static str)], field: &str, s: &str) -> CatalogResult<T> {
    table
        .iter()
        .find(|(_, n)| *n == s)
        .map(|(t, _)| *t)
        .ok_or_else(|| CatalogError::corrupt(format!("index {field}: unknown value {s:?}")))
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// Encodes an index descriptor into its canonical `RDoc` bytes.
///
/// # Errors
/// [`CatalogError::InvalidArgument`] if the version exceeds `i64::MAX`; [`CatalogError::Doc`]
/// if the document codec rejects it.
pub fn encode_index_descriptor(d: &IndexDescriptor) -> CatalogResult<Vec<u8>> {
    let version = i64::try_from(d.version)
        .map_err(|_| CatalogError::InvalidArgument("index version above i64::MAX".into()))?;
    let mut doc = Document::new();
    doc.insert(F_FORMAT, Value::Int64(INDEX_FORMAT));
    doc.insert(F_TYPE, s(TYPE_INDEX));
    doc.insert(F_ID, Value::Int64(i64::from(d.id)));
    doc.insert(F_DATABASE_ID, Value::Int64(i64::from(d.database_id)));
    doc.insert(F_COLLECTION_ID, Value::Int64(i64::from(d.collection_id)));
    doc.insert(F_NAME, s(&d.name));
    doc.insert(F_KIND, s(to_str(&KINDS, d.kind)));
    let fields = d
        .fields
        .iter()
        .map(|f| {
            let mut o = Document::new();
            o.insert(F_PATH, s(&f.path));
            o.insert(F_ORDER, s(to_str(&ORDERS, f.order)));
            Value::Object(o)
        })
        .collect();
    doc.insert(F_FIELDS, Value::Array(fields));
    doc.insert(F_UNIQUE, Value::Bool(d.unique));
    doc.insert(F_SPARSE, Value::Bool(d.sparse));
    if let Some(p) = &d.partial {
        doc.insert(F_PARTIAL, s(p));
    }
    doc.insert(F_HIDDEN, Value::Bool(d.hidden));
    doc.insert(F_SCOPE, s(to_str(&SCOPES, d.scope)));
    doc.insert(F_STATE, s(to_str(&STATES, d.state)));
    doc.insert(F_ORIGIN, s(to_str(&ORIGINS, d.origin)));
    doc.insert(F_VERSION, Value::Int64(version));
    doc.insert(
        F_INCLUDE,
        Value::Array(d.include.iter().map(|p| s(p)).collect()),
    );
    doc.insert(F_MULTIKEY, Value::Bool(d.multikey));
    doc.insert(F_CREATED_AT, Value::DateTime(d.created_at_ms));
    Ok(rdoc::encode(&doc)?)
}

/// Strict reader over one object: rejects undeclared fields.
struct Obj<'a> {
    doc: &'a Document,
    ctx: &'static str,
}

impl<'a> Obj<'a> {
    fn new(doc: &'a Document, allowed: &[&str], ctx: &'static str) -> CatalogResult<Self> {
        if let Some((name, _)) = doc.iter().find(|(n, _)| !allowed.contains(n)) {
            return Err(CatalogError::corrupt(format!(
                "{ctx}: unknown field {name:?}"
            )));
        }
        Ok(Self { doc, ctx })
    }

    fn wrong(&self, name: &str, want: &str) -> CatalogError {
        CatalogError::corrupt(format!("{}: field {name} is not {want}", self.ctx))
    }

    fn req(&self, name: &str) -> CatalogResult<&'a Value> {
        self.doc
            .get(name)
            .ok_or_else(|| CatalogError::corrupt(format!("{}: missing field {name}", self.ctx)))
    }

    fn string(&self, name: &str) -> CatalogResult<&'a str> {
        match self.req(name)? {
            Value::String(v) => Ok(v),
            _ => Err(self.wrong(name, "a string")),
        }
    }

    fn boolean(&self, name: &str) -> CatalogResult<bool> {
        match self.req(name)? {
            Value::Bool(v) => Ok(*v),
            _ => Err(self.wrong(name, "a bool")),
        }
    }

    fn id(&self, name: &str) -> CatalogResult<u32> {
        match self.req(name)? {
            Value::Int64(v) => u32::try_from(*v).map_err(|_| self.wrong(name, "a u32 id")),
            _ => Err(self.wrong(name, "an int64")),
        }
    }

    fn array(&self, name: &str) -> CatalogResult<&'a [Value]> {
        match self.req(name)? {
            Value::Array(v) => Ok(v),
            _ => Err(self.wrong(name, "an array")),
        }
    }
}

/// Decodes an index descriptor written by [`encode_index_descriptor`].
///
/// # Errors
/// [`CatalogError::Corrupt`] for bytes that are not a valid index-format-1 descriptor
/// (including an unsupported `index_format`).
pub fn decode_index_descriptor(bytes: &[u8]) -> CatalogResult<IndexDescriptor> {
    let doc = rdoc::decode(bytes)
        .map_err(|e| CatalogError::corrupt(format!("index descriptor RDoc: {e}")))?;
    match doc.get(F_FORMAT) {
        Some(Value::Int64(INDEX_FORMAT)) => {}
        Some(Value::Int64(v)) => {
            return Err(CatalogError::corrupt(format!(
                "unsupported index_format {v}"
            )));
        }
        _ => return Err(CatalogError::corrupt("missing index_format")),
    }
    let o = Obj::new(&doc, TOP_FIELDS, "index descriptor")?;
    if o.string(F_TYPE)? != TYPE_INDEX {
        return Err(CatalogError::corrupt(
            "index descriptor: type is not \"index\"",
        ));
    }
    let fields = o
        .array(F_FIELDS)?
        .iter()
        .map(|v| match v {
            Value::Object(f) => {
                let f = Obj::new(f, FIELD_FIELDS, "index field")?;
                Ok(IndexField {
                    path: f.string(F_PATH)?.to_owned(),
                    order: from_str(&ORDERS, F_ORDER, f.string(F_ORDER)?)?,
                })
            }
            _ => Err(o.wrong(F_FIELDS, "an array of objects")),
        })
        .collect::<CatalogResult<Vec<_>>>()?;
    if fields.is_empty() {
        return Err(o.wrong(F_FIELDS, "a non-empty array"));
    }
    let include = o
        .array(F_INCLUDE)?
        .iter()
        .map(|v| match v {
            Value::String(p) => Ok(p.clone()),
            _ => Err(o.wrong(F_INCLUDE, "an array of strings")),
        })
        .collect::<CatalogResult<Vec<_>>>()?;
    let partial = match doc.get(F_PARTIAL) {
        None => None,
        Some(Value::String(p)) => Some(p.clone()),
        Some(_) => return Err(o.wrong(F_PARTIAL, "a string")),
    };
    let version = match o.req(F_VERSION)? {
        Value::Int64(v) if *v >= 1 => u64::try_from(*v).map_err(|_| o.wrong(F_VERSION, "≥ 1"))?,
        _ => return Err(o.wrong(F_VERSION, "a version >= 1")),
    };
    let created_at_ms = match o.req(F_CREATED_AT)? {
        Value::DateTime(ms) => *ms,
        _ => return Err(o.wrong(F_CREATED_AT, "a datetime")),
    };
    Ok(IndexDescriptor {
        id: o.id(F_ID)?,
        database_id: o.id(F_DATABASE_ID)?,
        collection_id: o.id(F_COLLECTION_ID)?,
        name: o.string(F_NAME)?.to_owned(),
        kind: from_str(&KINDS, F_KIND, o.string(F_KIND)?)?,
        fields,
        unique: o.boolean(F_UNIQUE)?,
        sparse: o.boolean(F_SPARSE)?,
        partial,
        hidden: o.boolean(F_HIDDEN)?,
        scope: from_str(&SCOPES, F_SCOPE, o.string(F_SCOPE)?)?,
        state: from_str(&STATES, F_STATE, o.string(F_STATE)?)?,
        origin: from_str(&ORIGINS, F_ORIGIN, o.string(F_ORIGIN)?)?,
        version,
        include,
        multikey: o.boolean(F_MULTIKEY)?,
        created_at_ms,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity)]

    use super::*;

    fn sample() -> IndexDescriptor {
        IndexDescriptor {
            id: 117,
            database_id: 100,
            collection_id: 105,
            name: "idx_status_created".into(),
            kind: IndexKind::Secondary,
            fields: vec![IndexField::asc("status"), IndexField::desc("createdAt")],
            unique: false,
            sparse: true,
            partial: Some("total > 0".into()),
            hidden: false,
            scope: IndexScope::Global,
            state: IndexState::WriteOnly,
            origin: IndexOrigin::Auto,
            version: 3,
            include: vec!["total".into()],
            multikey: true,
            created_at_ms: 1_767_225_600_000,
        }
    }

    #[test]
    fn round_trip_every_enum_value() {
        for (state, _) in STATES {
            for (order, _) in ORDERS {
                for (scope, _) in SCOPES {
                    for (origin, _) in ORIGINS {
                        let mut d = sample();
                        d.state = state;
                        d.fields[0].order = order;
                        d.scope = scope;
                        d.origin = origin;
                        d.partial = None;
                        let bytes = encode_index_descriptor(&d).unwrap();
                        assert_eq!(decode_index_descriptor(&bytes).unwrap(), d);
                        assert_ne!(to_str(&STATES, state), "");
                    }
                }
            }
        }
    }

    #[test]
    fn strict_decoding() {
        let base = rdoc::decode(&encode_index_descriptor(&sample()).unwrap()).unwrap();
        let mutate = |f: &dyn Fn(&mut Document)| {
            let mut d = base.clone();
            f(&mut d);
            decode_index_descriptor(&rdoc::encode(&d).unwrap())
        };
        assert!(mutate(&|_| {}).is_ok());
        let bad: Vec<Box<dyn Fn(&mut Document)>> = vec![
            Box::new(|d| {
                d.insert("extra", Value::Null);
            }),
            Box::new(|d| {
                d.insert(F_FORMAT, Value::Int64(2));
            }),
            Box::new(|d| {
                d.insert(F_STATE, s("building"));
            }),
            Box::new(|d| {
                d.insert(F_VERSION, Value::Int64(0));
            }),
            Box::new(|d| {
                d.insert(F_ID, Value::Int64(-1));
            }),
            Box::new(|d| {
                d.insert(F_FIELDS, Value::Array(vec![]));
            }),
            Box::new(|d| {
                d.insert(F_CREATED_AT, Value::Int64(5));
            }),
            Box::new(|d| {
                d.insert(F_TYPE, s("collection"));
            }),
        ];
        for f in &bad {
            let err = mutate(f.as_ref()).unwrap_err();
            assert!(matches!(err, CatalogError::Corrupt(_)), "{err}");
        }
        assert!(decode_index_descriptor(b"junk").is_err());
    }
}
