// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Catalog: descriptors, schema leases, validators and zone configurations.
//!
//! M2 scope (FR-SCH-001, TC-SCH-001; database-engine.md §2.5):
//! - [`descriptor`]: database and collection descriptors, persisted as canonical `RDoc`
//!   ([`codec`], `catalog_format` 1);
//! - [`keys`]: their system keys under the `0x02` namespace (descriptor by id, name index, id
//!   sequence);
//! - [`ops`]: transaction-agnostic DDL — reads through [`CatalogRead`], writes returned as
//!   [`Mutation`] lists the caller applies inside its own transaction; implicit collection
//!   creation ([`resolve_collection_for_write`]);
//! - [`lease`]: the local, version-keyed descriptor cache (cluster-wide schema leases are M6).
//!
//! - [`alter`] (M3): changing a collection's validator options;
//! - [`validator`] (M3, FR-SCH-002/003): JSON Schema subset validators compiled from the
//!   descriptor's validator text, validation levels/actions on the write path;
//! - [`index`]: index descriptors (indexing.md §1, own format `index_format` 1) and their
//!   DDL and online schema-change states (M3, FR-IDX-001/005).

pub mod alter;
pub mod codec;
pub mod descriptor;
pub mod error;
pub mod index;
pub mod keys;
pub mod lease;
pub mod name;
pub mod ops;
pub mod validator;

pub use crate::{
    alter::set_collection_options,
    codec::{CATALOG_FORMAT, decode_descriptor, encode_descriptor},
    descriptor::{
        CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor,
        DatabaseOptions, Descriptor, DescriptorState, ShardKey, ShardStrategy, ValidationAction,
        ValidationLevel,
    },
    error::{CatalogError, CatalogResult, ObjectKind},
    index::{
        IndexDescriptor, IndexField, IndexKind, IndexOrder, IndexOrigin, IndexScope, IndexSpec,
        IndexState,
    },
    lease::{CacheUpdate, LeaseCache},
    ops::{
        CatalogRead, CollectionForWrite, CollectionSpec, Created, Mutation, allocate_id,
        create_collection, create_database, drop_collection, drop_database, get_collection,
        get_database, get_descriptor, list_names, resolve_collection_for_write,
    },
    validator::{
        ValidationError, ValidationFailure, ValidationReport, Validator, ValidatorCache,
        WriteCheck, check_write,
    },
};
