// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index descriptor DDL over an in-memory snapshot (FR-IDX-001, FR-IDX-005, TC-IDX-008;
//! indexing.md §1, database-engine.md §2.3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::MemCatalog;
use rustegon_catalog::{
    CatalogError, CollectionDescriptor, CollectionSpec, DatabaseOptions, Descriptor, IndexField,
    IndexScope, IndexSpec, IndexState, create_collection, create_database, get_descriptor,
    index::{
        MAX_INDEXES_PER_COLLECTION,
        ops::{
            create_index, drop_index, get_index, list_indexes, mark_multikey, require_index,
            transition_index, write_indexes,
        },
    },
};
use rustegon_common::{Error, ErrorCode};

fn setup() -> (MemCatalog, CollectionDescriptor) {
    let mut cat = MemCatalog::default();
    let db = create_database(&cat, "shop", DatabaseOptions::default()).unwrap();
    cat.apply(&db.mutations);
    let coll = create_collection(&cat, &db.descriptor, CollectionSpec::document("orders")).unwrap();
    cat.apply(&coll.mutations);
    (cat, coll.descriptor)
}

fn coll_version(cat: &MemCatalog, id: u32) -> u64 {
    match get_descriptor(cat, id).unwrap() {
        Some(Descriptor::Collection(c)) => c.version,
        other => panic!("{other:?}"),
    }
}

fn code(e: CatalogError) -> ErrorCode {
    Error::from(e).code()
}

#[test]
fn tc_idx_001_create_walks_states_and_bumps_collection_version() {
    let (mut cat, coll) = setup();
    let created = create_index(
        &cat,
        &coll,
        IndexSpec::new("by_status", vec![IndexField::asc("status")]),
    )
    .unwrap();
    cat.apply(&created.mutations);
    let mut idx = created.descriptor;
    assert_eq!(idx.state, IndexState::DeleteOnly);
    assert_eq!(idx.version, 1);
    assert!(idx.id >= 100 && idx.id != coll.id);
    assert_eq!(coll_version(&cat, coll.id), 2);
    for to in [
        IndexState::WriteOnly,
        IndexState::Backfilling,
        IndexState::Validating,
        IndexState::Public,
    ] {
        let (next, m) = transition_index(&cat, &coll, &idx, to).unwrap();
        cat.apply(&m);
        assert_eq!(next.version, idx.version + 1);
        idx = next;
    }
    assert_eq!(coll_version(&cat, coll.id), 6);
    assert_eq!(list_indexes(&cat, coll.id).unwrap(), vec![idx.clone()]);
    assert_eq!(
        get_index(&cat, &coll, "by_status").unwrap(),
        Some(idx.clone())
    );
    // Illegal edge and stale copy.
    let err = transition_index(&cat, &coll, &idx, IndexState::WriteOnly).unwrap_err();
    assert_eq!(code(err), ErrorCode::InvalidArgument);
    let mut stale = idx.clone();
    stale.version -= 1;
    let err = transition_index(&cat, &coll, &stale, IndexState::Dropping).unwrap_err();
    assert_eq!(code(err), ErrorCode::SchemaChangeInProgress);
}

#[test]
fn tc_idx_001_names_drop_and_reuse() {
    let (mut cat, coll) = setup();
    let spec = IndexSpec::new("by_a", vec![IndexField::asc("a")]);
    let first = create_index(&cat, &coll, spec.clone()).unwrap();
    cat.apply(&first.mutations);
    let err = create_index(&cat, &coll, spec.clone()).unwrap_err();
    assert_eq!(code(err), ErrorCode::IndexAlreadyExists);
    let err = require_index(&cat, &coll, "nope").unwrap_err();
    assert_eq!(code(err), ErrorCode::IndexNotFound);
    assert_eq!(
        Error::from(drop_index(&cat, &coll, "nope").unwrap_err())
            .code()
            .code(),
        1021
    );

    let (dropped, m) = drop_index(&cat, &coll, "by_a").unwrap();
    cat.apply(&m);
    assert_eq!(dropped.state, IndexState::Dropping);
    assert_eq!(get_index(&cat, &coll, "by_a").unwrap(), None);
    assert_eq!(write_indexes(&cat, coll.id).unwrap().len(), 0);
    // The name is free again; the id is new.
    let again = create_index(&cat, &coll, spec).unwrap();
    cat.apply(&again.mutations);
    assert_ne!(again.descriptor.id, first.descriptor.id);
    assert_eq!(list_indexes(&cat, coll.id).unwrap().len(), 2);
    assert_eq!(write_indexes(&cat, coll.id).unwrap().len(), 1);
}

#[test]
fn tc_idx_008_sixty_fifth_index_fails_rgn_1023() {
    let (mut cat, coll) = setup();
    for i in 0..MAX_INDEXES_PER_COLLECTION {
        let c = create_index(
            &cat,
            &coll,
            IndexSpec::new(format!("i{i}"), vec![IndexField::asc(format!("f{i}"))]),
        )
        .unwrap();
        cat.apply(&c.mutations);
    }
    let err = create_index(
        &cat,
        &coll,
        IndexSpec::new("i64", vec![IndexField::asc("x")]),
    )
    .unwrap_err();
    assert_eq!(code(err), ErrorCode::IndexLimitExceeded);
    assert_eq!(ErrorCode::IndexLimitExceeded.code(), 1023);
    // Dropping one frees a slot.
    let (_, m) = drop_index(&cat, &coll, "i0").unwrap();
    cat.apply(&m);
    assert!(
        create_index(
            &cat,
            &coll,
            IndexSpec::new("i64", vec![IndexField::asc("x")])
        )
        .is_ok()
    );
}

#[test]
fn invalid_specs_and_local_scope() {
    let (cat, coll) = setup();
    let mut local = IndexSpec::new("l", vec![IndexField::asc("a")]);
    local.scope = IndexScope::Local;
    assert_eq!(
        code(create_index(&cat, &coll, local).unwrap_err()),
        ErrorCode::InvalidArgument
    );
    let bad = IndexSpec::new("w", vec![IndexField::asc("a.**"), IndexField::asc("b")]);
    assert_eq!(
        code(create_index(&cat, &coll, bad).unwrap_err()),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn multikey_flag_is_set_once() {
    let (mut cat, coll) = setup();
    let c = create_index(
        &cat,
        &coll,
        IndexSpec::new("m", vec![IndexField::asc("tags")]),
    )
    .unwrap();
    cat.apply(&c.mutations);
    let (marked, m) = mark_multikey(&cat, &coll, &c.descriptor).unwrap().unwrap();
    cat.apply(&m);
    assert!(marked.multikey);
    assert_eq!(marked.version, 2);
    assert!(mark_multikey(&cat, &coll, &c.descriptor).unwrap().is_none());
}
