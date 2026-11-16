// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction-agnostic index DDL (indexing.md §1, §5; database-engine.md §2.3, §2.5).
//!
//! Keys (system namespace, sub-namespace byte `'i'` owned by the catalog):
//! ```text
//! index descriptor   0x02 'i' collection_id(u32 BE) index_id(u32 BE)  -> index descriptor RDoc
//! ```
//! The indexes of a collection are one prefix scan (`0x02 'i' collection_id`), in id order.
//! There is no separate name index: names are unique among the (at most 64) non-dropping
//! indexes of one collection, checked by that scan.
//!
//! **Concurrency.** As for the other DDL ([`crate::ops`]), operations only read through
//! [`CatalogRead`] and return mutations for the caller's transaction. Every change of an index
//! descriptor also rewrites the owning **collection descriptor with `version + 1`**: writers
//! read the collection descriptor (and scan its indexes) in their transaction, so under
//! SERIALIZABLE a DDL and a concurrent write conflict (`RGN-2001`) instead of the writer
//! maintaining a stale index set; and version-keyed descriptor caches see the change. Two
//! concurrent creations additionally conflict on the id sequence.

use rustegon_doc::keyspace::NS_SYSTEM;

use super::{
    IndexDescriptor, IndexKind, IndexScope, IndexSpec, IndexState, MAX_INDEXES_PER_COLLECTION,
    codec::{decode_index_descriptor, encode_index_descriptor},
    validate_spec,
};
use crate::{
    codec::encode_descriptor,
    descriptor::{
        CollectionDescriptor, CollectionKind, Descriptor, DescriptorState, FIRST_VERSION,
    },
    error::{CatalogError, CatalogResult, ObjectKind},
    keys,
    ops::{CatalogRead, Created, Mutation, allocate_id, get_descriptor},
};

/// Sub-namespace byte of index descriptors.
pub const SUB_INDEX: u8 = b'i';

/// Key of the descriptor of index `index_id` of collection `collection_id`.
#[must_use]
pub fn index_descriptor_key(collection_id: u32, index_id: u32) -> Vec<u8> {
    let mut k = index_prefix(collection_id);
    k.extend_from_slice(&index_id.to_be_bytes());
    k
}

/// Prefix of the index descriptors of collection `collection_id`.
#[must_use]
pub fn index_prefix(collection_id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(10);
    k.extend_from_slice(&[NS_SYSTEM, SUB_INDEX]);
    k.extend_from_slice(&collection_id.to_be_bytes());
    k
}

/// Every index descriptor of the collection (all states, including dropping), in id order.
///
/// # Errors
/// [`CatalogError::Read`]; [`CatalogError::Corrupt`] for undecodable entries or an entry whose
/// key does not match its content.
pub fn list_indexes(
    r: &impl CatalogRead,
    collection_id: u32,
) -> CatalogResult<Vec<IndexDescriptor>> {
    let rows = r
        .scan_prefix(&index_prefix(collection_id))
        .map_err(CatalogError::Read)?;
    rows.iter()
        .map(|(k, v)| {
            let d = decode_index_descriptor(v)?;
            if *k != index_descriptor_key(d.collection_id, d.id) || d.collection_id != collection_id
            {
                return Err(CatalogError::corrupt(format!(
                    "index key does not match descriptor {} of collection {}",
                    d.id, d.collection_id
                )));
            }
            Ok(d)
        })
        .collect()
}

/// The indexes writers must maintain (every state but `Dropping`), in id order.
///
/// # Errors
/// As [`list_indexes`].
pub fn write_indexes(
    r: &impl CatalogRead,
    collection_id: u32,
) -> CatalogResult<Vec<IndexDescriptor>> {
    let mut all = list_indexes(r, collection_id)?;
    all.retain(|d| d.state.deletes_entries());
    Ok(all)
}

/// The non-dropping index `name` of the collection, if any.
///
/// # Errors
/// As [`list_indexes`].
pub fn get_index(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    name: &str,
) -> CatalogResult<Option<IndexDescriptor>> {
    Ok(list_indexes(r, collection.id)?
        .into_iter()
        .find(|d| d.name == name && d.state != IndexState::Dropping))
}

/// As [`get_index`], `RGN-1021 IndexNotFound` when missing.
///
/// # Errors
/// [`CatalogError::IndexNotFound`]; as [`list_indexes`].
pub fn require_index(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    name: &str,
) -> CatalogResult<IndexDescriptor> {
    get_index(r, collection, name)?.ok_or_else(|| CatalogError::IndexNotFound {
        collection: collection.name.clone(),
        name: name.to_owned(),
    })
}

/// Mutation rewriting the current collection descriptor with `version + 1` (module docs).
fn bump_collection(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
) -> CatalogResult<Mutation> {
    match get_descriptor(r, collection.id)? {
        Some(Descriptor::Collection(mut c)) if c.state == DescriptorState::Public => {
            c.version += 1;
            Ok(Mutation::Put {
                key: keys::descriptor_key(c.id),
                value: encode_descriptor(&Descriptor::Collection(c))?,
            })
        }
        _ => Err(CatalogError::NotFound {
            kind: ObjectKind::Collection,
            name: collection.name.clone(),
            hint: None,
        }),
    }
}

/// Prepares `CREATE INDEX` on `collection`: the new descriptor starts in
/// [`IndexState::DeleteOnly`] (database-engine.md §2.3); the caller walks it through the build
/// states with [`transition_index`].
///
/// # Errors
/// `RGN-1001` for an invalid spec (see [`super::validate_spec`]) or a `LOCAL` index on a
/// non-table; `RGN-1030` if the collection is gone; `RGN-1020` for a duplicate name; `RGN-1023`
/// beyond 64 indexes (FR-IDX-005); id allocation, read and encoding errors.
pub fn create_index(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    spec: IndexSpec,
) -> CatalogResult<Created<IndexDescriptor>> {
    validate_spec(&spec)?;
    if spec.scope == IndexScope::Local && collection.kind != CollectionKind::Table {
        return Err(CatalogError::InvalidArgument(
            "LOCAL indexes exist only on tables".into(),
        ));
    }
    let bump = bump_collection(r, collection)?;
    let live: Vec<_> = list_indexes(r, collection.id)?
        .into_iter()
        .filter(|d| d.state != IndexState::Dropping)
        .collect();
    if live.iter().any(|d| d.name == spec.name) {
        return Err(CatalogError::IndexAlreadyExists { name: spec.name });
    }
    if live.len() >= MAX_INDEXES_PER_COLLECTION {
        return Err(CatalogError::IndexLimitExceeded {
            collection: collection.name.clone(),
            limit: MAX_INDEXES_PER_COLLECTION,
        });
    }
    let (id, seq) = allocate_id(r)?;
    let descriptor = IndexDescriptor {
        id,
        database_id: collection.database_id,
        collection_id: collection.id,
        name: spec.name,
        kind: IndexKind::Secondary,
        fields: spec.fields,
        unique: spec.unique,
        sparse: spec.sparse,
        partial: spec.partial,
        hidden: spec.hidden,
        scope: spec.scope,
        state: IndexState::DeleteOnly,
        origin: spec.origin,
        version: FIRST_VERSION,
        include: spec.include,
        multikey: false,
        created_at_ms: spec.created_at_ms,
    };
    let mutations = vec![
        seq,
        Mutation::Put {
            key: index_descriptor_key(collection.id, id),
            value: encode_index_descriptor(&descriptor)?,
        },
        bump,
    ];
    Ok(Created {
        descriptor,
        mutations,
    })
}

/// Re-reads `index` at the caller's snapshot and checks that it is still the version the
/// caller holds (a stale copy must not write an older state back).
fn current(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    index: &IndexDescriptor,
) -> CatalogResult<IndexDescriptor> {
    let key = index_descriptor_key(collection.id, index.id);
    let bytes =
        r.get(&key)
            .map_err(CatalogError::Read)?
            .ok_or_else(|| CatalogError::IndexNotFound {
                collection: collection.name.clone(),
                name: index.name.clone(),
            })?;
    let cur = decode_index_descriptor(&bytes)?;
    if cur.version != index.version || cur.state != index.state {
        return Err(CatalogError::SchemaChangeInProgress(format!(
            "index {} is at version {} ({:?}), expected {} ({:?})",
            index.name, cur.version, cur.state, index.version, index.state
        )));
    }
    Ok(cur)
}

/// Mutations writing `next` (already bumped) and the collection bump.
fn rewrite(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    next: &IndexDescriptor,
) -> CatalogResult<Vec<Mutation>> {
    Ok(vec![
        Mutation::Put {
            key: index_descriptor_key(collection.id, next.id),
            value: encode_index_descriptor(next)?,
        },
        bump_collection(r, collection)?,
    ])
}

/// Prepares the state transition of `index` to `to` (database-engine.md §2.3), with
/// `version + 1`.
///
/// # Errors
/// `RGN-1033 SchemaChangeInProgress` if the stored index is not the version/state the caller
/// holds; `RGN-1001` for an edge the state machine does not have; `RGN-1021` if it is gone;
/// read and encoding errors.
pub fn transition_index(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    index: &IndexDescriptor,
    to: IndexState,
) -> CatalogResult<(IndexDescriptor, Vec<Mutation>)> {
    let mut next = current(r, collection, index)?;
    if !next.state.can_transition_to(to) {
        return Err(CatalogError::InvalidArgument(format!(
            "index {}: no transition {:?} -> {to:?}",
            index.name, next.state
        )));
    }
    next.state = to;
    next.version += 1;
    let mutations = rewrite(r, collection, &next)?;
    Ok((next, mutations))
}

/// Prepares `DROP INDEX name`: the index moves to [`IndexState::Dropping`] (its name is free
/// again, its id never reused); deleting its entries is the caller's (or the GC job's) work.
///
/// # Errors
/// `RGN-1021` if there is no such non-dropping index; as [`transition_index`].
pub fn drop_index(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    name: &str,
) -> CatalogResult<(IndexDescriptor, Vec<Mutation>)> {
    let index = require_index(r, collection, name)?;
    transition_index(r, collection, &index, IndexState::Dropping)
}

/// Prepares setting the `multikey` flag of `index` (indexing.md §3: set once a document with
/// an array value is indexed). `None` when it is already set at the caller's snapshot. Unlike
/// [`transition_index`] it does not require the caller's version: the flag is monotonic, so it
/// is applied to whatever version is current.
///
/// # Errors
/// `RGN-1021` if the index is gone; read and encoding errors.
pub fn mark_multikey(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    index: &IndexDescriptor,
) -> CatalogResult<Option<(IndexDescriptor, Vec<Mutation>)>> {
    let key = index_descriptor_key(collection.id, index.id);
    let Some(bytes) = r.get(&key).map_err(CatalogError::Read)? else {
        return Err(CatalogError::IndexNotFound {
            collection: collection.name.clone(),
            name: index.name.clone(),
        });
    };
    let mut next = decode_index_descriptor(&bytes)?;
    if next.multikey {
        return Ok(None);
    }
    next.multikey = true;
    next.version += 1;
    let mutations = rewrite(r, collection, &next)?;
    Ok(Some((next, mutations)))
}
