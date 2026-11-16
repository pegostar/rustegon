// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction-agnostic catalog operations (FR-SCH-001).
//!
//! The catalog never writes by itself: reads go through [`CatalogRead`], which the caller
//! implements over the snapshot of its transaction, and every DDL returns the list of
//! [`Mutation`]s the caller applies **inside the same transaction**. Correctness under
//! concurrency is therefore the transaction layer's job: two concurrent `create` calls both read
//! the id sequence and the name entry and write them, so serializable isolation makes one of
//! them conflict (`RGN-2001`) instead of producing a duplicate name or id.
//!
//! The reader must observe the transaction's own earlier writes (read-your-writes), otherwise
//! two DDLs in one transaction would allocate the same id.

use rustegon_common::Error;

use crate::{
    codec::{decode_descriptor, encode_descriptor},
    descriptor::{
        CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor,
        DatabaseOptions, Descriptor, DescriptorState, FIRST_VERSION, ShardKey,
    },
    error::{CatalogError, CatalogResult, ObjectKind},
    keys,
    name::{validate_collection_name, validate_database_name},
};

/// Key/value pairs returned by [`CatalogRead::scan_prefix`], in ascending key order.
pub type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Read access to the system keyspace at the caller's transaction snapshot.
pub trait CatalogRead {
    /// The committed (or own uncommitted) value of `key`, `None` if absent or deleted.
    ///
    /// # Errors
    /// Any error of the underlying store or transaction; propagated as [`CatalogError::Read`].
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// All live `(key, value)` pairs whose key starts with `prefix`, in ascending key order.
    ///
    /// # Errors
    /// As [`CatalogRead::get`].
    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error>;
}

/// One write the caller applies in its transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Write `value` at `key`.
    Put {
        /// System key.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Delete `key`.
    Delete {
        /// System key.
        key: Vec<u8>,
    },
}

/// Parameters of an explicit collection creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionSpec {
    /// Collection name.
    pub name: String,
    /// Kind (implicit creation always uses [`CollectionKind::Document`]).
    pub kind: CollectionKind,
    /// Shard key (default `hashed(_id)`).
    pub shard_key: ShardKey,
    /// Options (validator).
    pub options: CollectionOptions,
}

impl CollectionSpec {
    /// A document collection with default shard key and options, as implicit creation makes it.
    #[must_use]
    pub fn document(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: CollectionKind::Document,
            shard_key: ShardKey::default(),
            options: CollectionOptions::default(),
        }
    }
}

/// A descriptor to create plus the mutations that create it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created<D> {
    /// The new descriptor (version [`FIRST_VERSION`]).
    pub descriptor: D,
    /// Sequence bump, name entry and descriptor writes.
    pub mutations: Vec<Mutation>,
}

/// Outcome of [`resolve_collection_for_write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionForWrite {
    /// The collection exists.
    Existing(CollectionDescriptor),
    /// The collection is missing and implicit creation applies: apply the mutations in the
    /// writing transaction before the document write.
    Create(Created<CollectionDescriptor>),
}

fn read(r: &impl CatalogRead, key: &[u8]) -> CatalogResult<Option<Vec<u8>>> {
    r.get(key).map_err(CatalogError::Read)
}

/// The descriptor with id `id` (any state), if any.
///
/// # Errors
/// [`CatalogError::Read`] from the reader, [`CatalogError::Corrupt`] for undecodable entries.
pub fn get_descriptor(r: &impl CatalogRead, id: u32) -> CatalogResult<Option<Descriptor>> {
    let Some(bytes) = read(r, &keys::descriptor_key(id))? else {
        return Ok(None);
    };
    let desc = decode_descriptor(&bytes)?;
    if desc.id() != id {
        return Err(CatalogError::corrupt(format!(
            "descriptor key {id} holds descriptor {}",
            desc.id()
        )));
    }
    Ok(Some(desc))
}

/// Resolves a name entry to the descriptor it points to.
fn resolve_name(
    r: &impl CatalogRead,
    parent_id: u32,
    name: &str,
) -> CatalogResult<Option<Descriptor>> {
    let Some(value) = read(r, &keys::name_key(parent_id, name))? else {
        return Ok(None);
    };
    let id = keys::decode_id(&value)?;
    // A name entry without its descriptor, or pointing at another object, breaks the invariant
    // that both are written in the same transaction.
    let desc = get_descriptor(r, id)?
        .ok_or_else(|| CatalogError::corrupt(format!("name {name:?} points to missing id {id}")))?;
    if desc.name() != name || desc.parent_id() != parent_id {
        return Err(CatalogError::corrupt(format!(
            "name {name:?} points to descriptor {id} named {:?}",
            desc.name()
        )));
    }
    Ok(Some(desc))
}

/// The public database named `name`, if any.
///
/// # Errors
/// As [`get_descriptor`]; [`CatalogError::Corrupt`] if the name points to a collection.
pub fn get_database(r: &impl CatalogRead, name: &str) -> CatalogResult<Option<DatabaseDescriptor>> {
    match resolve_name(r, keys::ROOT_PARENT_ID, name)? {
        None => Ok(None),
        Some(Descriptor::Database(d)) => Ok(Some(d)),
        Some(Descriptor::Collection(c)) => Err(CatalogError::corrupt(format!(
            "database name {name:?} points to collection {}",
            c.id
        ))),
    }
}

/// The public collection `name` of database `database_id`, if any.
///
/// # Errors
/// As [`get_descriptor`]; [`CatalogError::Corrupt`] if the name points to a database.
pub fn get_collection(
    r: &impl CatalogRead,
    database_id: u32,
    name: &str,
) -> CatalogResult<Option<CollectionDescriptor>> {
    match resolve_name(r, database_id, name)? {
        None => Ok(None),
        Some(Descriptor::Collection(c)) => Ok(Some(c)),
        Some(Descriptor::Database(d)) => Err(CatalogError::corrupt(format!(
            "collection name {name:?} points to database {}",
            d.id
        ))),
    }
}

/// `(name, id)` of the entries under `parent_id` in name order: databases for
/// [`keys::ROOT_PARENT_ID`], otherwise the collections of that database.
///
/// # Errors
/// [`CatalogError::Read`]; [`CatalogError::Corrupt`] for malformed entries.
pub fn list_names(r: &impl CatalogRead, parent_id: u32) -> CatalogResult<Vec<(String, u32)>> {
    let entries = r
        .scan_prefix(&keys::name_prefix(parent_id))
        .map_err(CatalogError::Read)?;
    entries
        .iter()
        .map(|(k, v)| {
            let name = keys::name_from_key(parent_id, k)
                .ok_or_else(|| CatalogError::corrupt("malformed name-index key"))?;
            Ok((name.to_owned(), keys::decode_id(v)?))
        })
        .collect()
}

/// Reads and bumps the descriptor id sequence; returns the new id and its mutation.
///
/// # Errors
/// [`CatalogError::IdsExhausted`] after `u32::MAX`; read and corruption errors.
pub fn allocate_id(r: &impl CatalogRead) -> CatalogResult<(u32, Mutation)> {
    let key = keys::descriptor_id_sequence_key();
    let last = match read(r, &key)? {
        Some(v) => keys::decode_id(&v)?,
        None => keys::FIRST_USER_ID - 1,
    };
    let id = last.checked_add(1).ok_or(CatalogError::IdsExhausted)?;
    Ok((
        id,
        Mutation::Put {
            key,
            value: keys::encode_id(id),
        },
    ))
}

/// Mutations writing a new object: sequence bump, name entry, descriptor.
fn create_mutations(seq: Mutation, desc: &Descriptor) -> CatalogResult<Vec<Mutation>> {
    Ok(vec![
        seq,
        Mutation::Put {
            key: keys::name_key(desc.parent_id(), desc.name()),
            value: keys::encode_id(desc.id()),
        },
        Mutation::Put {
            key: keys::descriptor_key(desc.id()),
            value: encode_descriptor(desc)?,
        },
    ])
}

/// Prepares `CREATE DATABASE name`.
///
/// # Errors
/// [`CatalogError::InvalidName`], [`CatalogError::AlreadyExists`] (`RGN-1031`), id allocation,
/// read and encoding errors.
pub fn create_database(
    r: &impl CatalogRead,
    name: &str,
    options: DatabaseOptions,
) -> CatalogResult<Created<DatabaseDescriptor>> {
    validate_database_name(name)?;
    if read(r, &keys::name_key(keys::ROOT_PARENT_ID, name))?.is_some() {
        return Err(CatalogError::AlreadyExists {
            kind: ObjectKind::Database,
            name: name.to_owned(),
        });
    }
    let (id, seq) = allocate_id(r)?;
    let descriptor = DatabaseDescriptor {
        id,
        name: name.to_owned(),
        version: FIRST_VERSION,
        state: DescriptorState::Public,
        options,
    };
    let mutations = create_mutations(seq, &Descriptor::Database(descriptor.clone()))?;
    Ok(Created {
        descriptor,
        mutations,
    })
}

/// Prepares the creation of a collection in `database`.
///
/// # Errors
/// [`CatalogError::InvalidName`]; [`CatalogError::InvalidArgument`] for an empty shard key or
/// a validator that does not compile ([`crate::validator::Validator::compile`]);
/// [`CatalogError::NotFound`] if `database` is being dropped; [`CatalogError::AlreadyExists`]
/// (`RGN-1031`); id allocation, read and encoding errors.
pub fn create_collection(
    r: &impl CatalogRead,
    database: &DatabaseDescriptor,
    spec: CollectionSpec,
) -> CatalogResult<Created<CollectionDescriptor>> {
    validate_collection_name(&spec.name)?;
    // A validator is compiled before it is stored, so a stored one always compiles (FR-SCH-002).
    if let Some(text) = &spec.options.validator {
        crate::validator::Validator::compile(text)?;
    }
    if spec.shard_key.fields.is_empty() {
        return Err(CatalogError::InvalidArgument(
            "shard key needs at least one field".into(),
        ));
    }
    ensure_public_database(database)?;
    if read(r, &keys::name_key(database.id, &spec.name))?.is_some() {
        return Err(CatalogError::AlreadyExists {
            kind: ObjectKind::Collection,
            name: spec.name,
        });
    }
    let (id, seq) = allocate_id(r)?;
    let descriptor = CollectionDescriptor {
        id,
        database_id: database.id,
        name: spec.name,
        kind: spec.kind,
        version: FIRST_VERSION,
        state: DescriptorState::Public,
        shard_key: spec.shard_key,
        options: spec.options,
    };
    let mutations = create_mutations(seq, &Descriptor::Collection(descriptor.clone()))?;
    Ok(Created {
        descriptor,
        mutations,
    })
}

fn ensure_public_database(database: &DatabaseDescriptor) -> CatalogResult<()> {
    if database.state == DescriptorState::Public {
        Ok(())
    } else {
        Err(CatalogError::NotFound {
            kind: ObjectKind::Database,
            name: database.name.clone(),
            hint: Some("being dropped"),
        })
    }
}

/// Mutations marking one descriptor dropped: name entry removed (the name is free again),
/// descriptor rewritten as [`DescriptorState::Dropping`] with `version + 1` (the id is never
/// reused; the data span is reclaimed by a GC job in a later milestone).
fn drop_mutations(mut desc: Descriptor) -> CatalogResult<Vec<Mutation>> {
    let name_key = keys::name_key(desc.parent_id(), desc.name());
    match &mut desc {
        Descriptor::Database(d) => {
            d.state = DescriptorState::Dropping;
            d.version += 1;
        }
        Descriptor::Collection(c) => {
            c.state = DescriptorState::Dropping;
            c.version += 1;
        }
    }
    Ok(vec![
        Mutation::Delete { key: name_key },
        Mutation::Put {
            key: keys::descriptor_key(desc.id()),
            value: encode_descriptor(&desc)?,
        },
    ])
}

/// Re-reads a descriptor by id and checks it is the public object the caller resolved.
fn current_public(
    r: &impl CatalogRead,
    kind: ObjectKind,
    id: u32,
    name: &str,
) -> CatalogResult<Descriptor> {
    match get_descriptor(r, id)? {
        Some(d) if d.state() == DescriptorState::Public => Ok(d),
        _ => Err(CatalogError::NotFound {
            kind,
            name: name.to_owned(),
            hint: None,
        }),
    }
}

/// Prepares `DROP COLLECTION`. The descriptor is re-read at the caller's snapshot so that a
/// stale cached copy cannot write an older version back.
///
/// # Errors
/// [`CatalogError::NotFound`] if it is gone or already dropping; read and encoding errors.
pub fn drop_collection(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
) -> CatalogResult<Vec<Mutation>> {
    let current = current_public(r, ObjectKind::Collection, collection.id, &collection.name)?;
    drop_mutations(current)
}

/// Prepares `DROP DATABASE`: the database and every public collection in it are dropped.
///
/// # Errors
/// As [`drop_collection`].
pub fn drop_database(
    r: &impl CatalogRead,
    database: &DatabaseDescriptor,
) -> CatalogResult<Vec<Mutation>> {
    let current = current_public(r, ObjectKind::Database, database.id, &database.name)?;
    let mut mutations = Vec::new();
    for (name, id) in list_names(r, database.id)? {
        let coll = current_public(r, ObjectKind::Collection, id, &name)?;
        mutations.extend(drop_mutations(coll)?);
    }
    mutations.extend(drop_mutations(current)?);
    Ok(mutations)
}

/// Resolves the target collection of a write (FR-SCH-001, AC-SCH-001): the existing collection,
/// or — if it is missing and `implicitCollectionCreation` is on for the database — the
/// mutations creating a default document collection.
///
/// # Errors
/// [`CatalogError::NotFound`] (`RGN-1030`) if it is missing and implicit creation is off, or
/// the database is being dropped; [`CatalogError::InvalidName`] for an invalid new name; read,
/// allocation and encoding errors.
pub fn resolve_collection_for_write(
    r: &impl CatalogRead,
    database: &DatabaseDescriptor,
    name: &str,
) -> CatalogResult<CollectionForWrite> {
    ensure_public_database(database)?;
    if let Some(existing) = get_collection(r, database.id, name)? {
        return Ok(CollectionForWrite::Existing(existing));
    }
    if !database.options.implicit_collection_creation {
        return Err(CatalogError::NotFound {
            kind: ObjectKind::Collection,
            name: name.to_owned(),
            hint: Some("implicitCollectionCreation is false"),
        });
    }
    create_collection(r, database, CollectionSpec::document(name)).map(CollectionForWrite::Create)
}
