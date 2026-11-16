// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Catalog behaviour over an in-memory snapshot (FR-SCH-001, TC-SCH-001; database-engine.md
//! §2.5).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::MemCatalog;
use proptest::prelude::*;
use rustegon_catalog::{
    CacheUpdate, CatalogError, CollectionDescriptor, CollectionForWrite, CollectionKind,
    CollectionOptions, CollectionSpec, DatabaseDescriptor, DatabaseOptions, Descriptor,
    DescriptorState, LeaseCache, ShardKey, ShardStrategy, ValidationAction, ValidationLevel,
    allocate_id, create_collection, create_database, decode_descriptor, drop_collection,
    drop_database, encode_descriptor, get_collection, get_database, get_descriptor, keys,
    list_names, resolve_collection_for_write,
};
use rustegon_common::ErrorCode;

fn new_db(cat: &mut MemCatalog, name: &str, options: DatabaseOptions) -> DatabaseDescriptor {
    let created = create_database(cat, name, options).unwrap();
    cat.apply(&created.mutations);
    created.descriptor
}

fn new_coll(cat: &mut MemCatalog, db: &DatabaseDescriptor, name: &str) -> CollectionDescriptor {
    let created = create_collection(cat, db, CollectionSpec::document(name)).unwrap();
    cat.apply(&created.mutations);
    created.descriptor
}

// ---- descriptor round trip (proptest) ----

fn arb_state() -> impl Strategy<Value = DescriptorState> {
    prop_oneof![
        Just(DescriptorState::Public),
        Just(DescriptorState::Dropping)
    ]
}

fn arb_collection() -> impl Strategy<Value = Descriptor> {
    let kind = prop_oneof![
        Just(CollectionKind::Document),
        Just(CollectionKind::Table),
        Just(CollectionKind::Timeseries)
    ];
    let strategy = prop_oneof![Just(ShardStrategy::Hashed), Just(ShardStrategy::Range)];
    let level = prop_oneof![
        Just(ValidationLevel::Off),
        Just(ValidationLevel::Strict),
        Just(ValidationLevel::Moderate)
    ];
    let action = prop_oneof![Just(ValidationAction::Error), Just(ValidationAction::Warn)];
    (
        (any::<u32>(), any::<u32>(), "[A-Za-z0-9_.-]{1,120}", kind),
        (1..=i64::MAX as u64, arb_state()),
        (
            strategy,
            prop::collection::vec("[a-z_][a-z0-9_.]{0,20}", 1..4),
        ),
        (proptest::option::of(".{0,200}"), level, action),
    )
        .prop_map(
            |((id, database_id, name, kind), (version, state), (strategy, fields), opts)| {
                Descriptor::Collection(CollectionDescriptor {
                    id,
                    database_id,
                    name,
                    kind,
                    version,
                    state,
                    shard_key: ShardKey { strategy, fields },
                    options: CollectionOptions {
                        validator: opts.0,
                        validation_level: opts.1,
                        validation_action: opts.2,
                    },
                })
            },
        )
}

fn arb_database() -> impl Strategy<Value = Descriptor> {
    (
        any::<u32>(),
        "[a-z0-9-][a-z0-9_-]{0,63}",
        1..=i64::MAX as u64,
        arb_state(),
        any::<bool>(),
    )
        .prop_map(|(id, name, version, state, implicit)| {
            Descriptor::Database(DatabaseDescriptor {
                id,
                name,
                version,
                state,
                options: DatabaseOptions {
                    implicit_collection_creation: implicit,
                },
            })
        })
}

proptest! {
    /// TC-SCH-001: every descriptor survives encode → decode, and the encoding is canonical
    /// (re-encoding the decoded descriptor gives the same bytes).
    #[test]
    fn tc_sch_001_descriptor_round_trip(desc in prop_oneof![arb_database(), arb_collection()]) {
        let bytes = encode_descriptor(&desc).unwrap();
        let back = decode_descriptor(&bytes).unwrap();
        prop_assert_eq!(&back, &desc);
        prop_assert_eq!(encode_descriptor(&back).unwrap(), bytes);
    }
}

// ---- names and ids ----

#[test]
fn tc_sch_001_name_to_id_and_back() {
    let mut cat = MemCatalog::default();
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    let orders = new_coll(&mut cat, &db, "orders");
    let users = new_coll(&mut cat, &db, "Users");

    // name → id
    assert_eq!(get_database(&cat, "shop").unwrap(), Some(db.clone()));
    assert_eq!(
        get_collection(&cat, db.id, "orders").unwrap(),
        Some(orders.clone())
    );
    // id → descriptor → name
    let Some(Descriptor::Collection(c)) = get_descriptor(&cat, orders.id).unwrap() else {
        panic!("collection descriptor expected");
    };
    assert_eq!((c.name.as_str(), c.database_id), ("orders", db.id));
    // listing in name order (ASCII: upper case first)
    assert_eq!(
        list_names(&cat, db.id).unwrap(),
        vec![
            ("Users".to_owned(), users.id),
            ("orders".to_owned(), orders.id)
        ]
    );
    assert_eq!(
        list_names(&cat, keys::ROOT_PARENT_ID).unwrap(),
        vec![("shop".to_owned(), db.id)]
    );
    // names are scoped to their database
    let other = new_db(&mut cat, "other", DatabaseOptions::default());
    assert_eq!(get_collection(&cat, other.id, "orders").unwrap(), None);
    assert_eq!(get_database(&cat, "missing").unwrap(), None);
    // the stored entries are the documented layout
    assert_eq!(
        cat.kv.get(&keys::name_key(db.id, "orders")),
        Some(&keys::encode_id(orders.id))
    );
}

#[test]
fn tc_sch_001_duplicate_name_rejected() {
    let mut cat = MemCatalog::default();
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    new_coll(&mut cat, &db, "orders");
    let err = create_database(&cat, "shop", DatabaseOptions::default()).unwrap_err();
    assert!(matches!(err, CatalogError::AlreadyExists { .. }), "{err}");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    let err = create_collection(&cat, &db, CollectionSpec::document("orders")).unwrap_err();
    assert_eq!(err.code().code(), 1031);
    // case-sensitive names are distinct
    assert!(create_collection(&cat, &db, CollectionSpec::document("Orders")).is_ok());
}

#[test]
fn tc_sch_001_invalid_names_rejected() {
    let mut cat = MemCatalog::default();
    let err = create_database(&cat, "_system", DatabaseOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    let err = create_collection(&cat, &db, CollectionSpec::document("system.x")).unwrap_err();
    assert!(matches!(err, CatalogError::InvalidName { .. }), "{err}");
    let err = resolve_collection_for_write(&cat, &db, "bad name").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn tc_sch_001_id_sequence_monotonic() {
    let mut cat = MemCatalog::default();
    let mut last = 0;
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    assert_eq!(db.id, keys::FIRST_USER_ID);
    last = last.max(db.id);
    for i in 0..50 {
        let c = new_coll(&mut cat, &db, &format!("c{i}"));
        assert!(c.id > last, "id {} after {last}", c.id);
        last = c.id;
    }
    // Ids of dropped objects are never reused.
    let victim = get_collection(&cat, db.id, "c0").unwrap().unwrap();
    let m = drop_collection(&cat, &victim).unwrap();
    cat.apply(&m);
    let again = new_coll(&mut cat, &db, "c0");
    assert!(again.id > last && again.id != victim.id);
}

#[test]
fn tc_sch_001_id_sequence_exhaustion() {
    let mut cat = MemCatalog::default();
    cat.kv.insert(
        keys::descriptor_id_sequence_key(),
        keys::encode_id(u32::MAX),
    );
    let err = allocate_id(&cat).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
}

#[test]
fn tc_sch_001_unapplied_mutations_reallocate_same_id() {
    // The catalog does not write: without applying the mutations the reader sees no change.
    // This is why the caller's reader must see its own transaction's writes.
    let cat = MemCatalog::default();
    let a = create_database(&cat, "a", DatabaseOptions::default()).unwrap();
    let b = create_database(&cat, "b", DatabaseOptions::default()).unwrap();
    assert_eq!(a.descriptor.id, b.descriptor.id);
    assert!(cat.kv.is_empty());
}

// ---- implicit creation ----

#[test]
fn tc_sch_001_implicit_create_or_rgn_1030() {
    let mut cat = MemCatalog::default();
    let open = new_db(&mut cat, "open", DatabaseOptions::default());
    assert!(
        DatabaseOptions::default().implicit_collection_creation,
        "default is true"
    );
    let strict = new_db(
        &mut cat,
        "strict",
        DatabaseOptions {
            implicit_collection_creation: false,
        },
    );

    // Default: the missing collection is created as a document collection, hashed(_id).
    let CollectionForWrite::Create(created) =
        resolve_collection_for_write(&cat, &open, "events").unwrap()
    else {
        panic!("creation expected");
    };
    assert_eq!(created.descriptor.kind, CollectionKind::Document);
    assert_eq!(created.descriptor.shard_key, ShardKey::default());
    assert_eq!(created.descriptor.version, 1);
    cat.apply(&created.mutations);
    // Second write finds it.
    assert_eq!(
        resolve_collection_for_write(&cat, &open, "events").unwrap(),
        CollectionForWrite::Existing(created.descriptor)
    );

    // Disabled: RGN-1030, nothing to write.
    let err = resolve_collection_for_write(&cat, &strict, "events").unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(err.code().code(), 1030);
    assert!(
        err.to_string().contains("implicitCollectionCreation"),
        "{err}"
    );
    // Explicit creation still works on that database.
    let c = new_coll(&mut cat, &strict, "events");
    assert_eq!(
        resolve_collection_for_write(&cat, &strict, "events").unwrap(),
        CollectionForWrite::Existing(c)
    );
}

// ---- drop ----

#[test]
fn tc_sch_001_drop_releases_name_and_keeps_descriptor() {
    let mut cat = MemCatalog::default();
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    let c1 = new_coll(&mut cat, &db, "a");
    let c2 = new_coll(&mut cat, &db, "b");
    let m = drop_database(&cat, &db).unwrap();
    cat.apply(&m);
    assert_eq!(get_database(&cat, "shop").unwrap(), None);
    assert_eq!(get_collection(&cat, db.id, "a").unwrap(), None);
    for id in [db.id, c1.id, c2.id] {
        let d = get_descriptor(&cat, id).unwrap().unwrap();
        assert_eq!(d.state(), DescriptorState::Dropping);
        assert_eq!(d.version(), 2);
    }
    // Dropping twice, or creating in a dropping database, is NotFound.
    assert_eq!(
        drop_database(&cat, &db).unwrap_err().code(),
        ErrorCode::NotFound
    );
    let dropping = match get_descriptor(&cat, db.id).unwrap().unwrap() {
        Descriptor::Database(d) => d,
        Descriptor::Collection(_) => panic!("database expected"),
    };
    let err = resolve_collection_for_write(&cat, &dropping, "a").unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    // The name is free again, with a new id.
    let again = new_db(&mut cat, "shop", DatabaseOptions::default());
    assert!(again.id > c2.id);
}

#[test]
fn corrupt_name_entry_detected() {
    let mut cat = MemCatalog::default();
    cat.kv
        .insert(keys::name_key(0, "ghost"), keys::encode_id(4242));
    let err = get_database(&cat, "ghost").unwrap_err();
    assert_eq!(err.code(), ErrorCode::StorageCorruption);
}

// ---- local lease cache ----

#[test]
fn tc_sch_001_lease_cache_invalidation_by_version() {
    let mut cat = MemCatalog::default();
    let db = new_db(&mut cat, "shop", DatabaseOptions::default());
    let v1 = new_coll(&mut cat, &db, "orders");
    let mut v2 = v1.clone();
    v2.version = 2;
    v2.options.validator = Some(r#"{"$jsonSchema":{"required":["email"]}}"#.into());

    let mut cache = LeaseCache::new();
    assert_eq!(
        cache.insert(Descriptor::Collection(v1.clone())),
        CacheUpdate::Inserted
    );
    assert_eq!(
        cache.get_by_name(db.id, "orders").map(Descriptor::version),
        Some(1)
    );
    // Newer replaces older; older never overwrites newer.
    assert_eq!(
        cache.insert(Descriptor::Collection(v2.clone())),
        CacheUpdate::Replaced
    );
    assert_eq!(
        cache.insert(Descriptor::Collection(v1.clone())),
        CacheUpdate::Stale
    );
    assert_eq!(cache.get(v1.id), Some(&Descriptor::Collection(v2.clone())));
    // Observing a newer version elsewhere invalidates; an equal or older one does not.
    assert!(!cache.invalidate_older_than(v1.id, 2));
    assert!(cache.invalidate_older_than(v1.id, 3));
    assert!(cache.get(v1.id).is_none());
    assert!(cache.get_by_name(db.id, "orders").is_none());

    // A dropped version removes the name but keeps the id entry; the name can be reused.
    let mut dropped = v2.clone();
    dropped.version = 3;
    dropped.state = DescriptorState::Dropping;
    cache.insert(Descriptor::Collection(v2));
    cache.insert(Descriptor::Collection(dropped));
    assert!(cache.get_by_name(db.id, "orders").is_none());
    assert_eq!(cache.get(v1.id).map(Descriptor::version), Some(3));
    let mut reborn = v1.clone();
    reborn.id = v1.id + 1;
    cache.insert(Descriptor::Collection(reborn.clone()));
    assert_eq!(
        cache.get_by_name(db.id, "orders").map(Descriptor::id),
        Some(reborn.id)
    );
    // Removing the old id must not remove the name now owned by the new id.
    cache.remove(v1.id);
    assert_eq!(
        cache.get_by_name(db.id, "orders").map(Descriptor::id),
        Some(reborn.id)
    );
    assert_eq!(cache.len(), 1);
}
