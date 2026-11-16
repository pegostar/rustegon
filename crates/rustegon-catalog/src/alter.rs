// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Changing the options of an existing collection: validator, `validationLevel`,
//! `validationAction` (FR-SCH-002; feature-analysis F03 "adding a validator to a collection with
//! non-conforming documents is allowed").
//!
//! Like every catalog operation it only returns mutations, applied by the caller in its own
//! transaction (see [`crate::ops`]). Existing documents are **not** checked: a validator applies
//! to later writes, and `moderate` exists precisely so that documents written before it can
//! still be updated. The change is one descriptor write with `version + 1`; validator caches
//! are keyed by version, so the next write sees the new options. Cluster-wide propagation (the
//! two-version lease invariant of database-engine.md §2.2–§2.3) arrives with schema leases in
//! M6; on a single node the transaction makes the switch atomic.

use crate::{
    codec::encode_descriptor,
    descriptor::{CollectionDescriptor, CollectionOptions, Descriptor, DescriptorState},
    error::{CatalogError, CatalogResult, ObjectKind},
    keys,
    ops::{CatalogRead, Created, Mutation, get_descriptor},
    validator::Validator,
};

/// Prepares replacing the options of `collection` by `options`. The descriptor is re-read at
/// the caller's snapshot, so a stale cached copy cannot write an older version back.
///
/// The returned [`Created`] carries the updated descriptor (version + 1) and its single
/// mutation.
///
/// # Errors
/// [`CatalogError::NotFound`] if the collection is gone or being dropped;
/// [`CatalogError::InvalidArgument`] if the validator does not compile; read and encoding
/// errors.
pub fn set_collection_options(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    options: CollectionOptions,
) -> CatalogResult<Created<CollectionDescriptor>> {
    if let Some(text) = &options.validator {
        Validator::compile(text)?;
    }
    let mut current = match get_descriptor(r, collection.id)? {
        Some(Descriptor::Collection(c)) if c.state == DescriptorState::Public => c,
        _ => {
            return Err(CatalogError::NotFound {
                kind: ObjectKind::Collection,
                name: collection.name.clone(),
                hint: None,
            });
        }
    };
    current.options = options;
    current.version += 1;
    let value = encode_descriptor(&Descriptor::Collection(current.clone()))?;
    Ok(Created {
        mutations: vec![Mutation::Put {
            key: keys::descriptor_key(current.id),
            value,
        }],
        descriptor: current,
    })
}
