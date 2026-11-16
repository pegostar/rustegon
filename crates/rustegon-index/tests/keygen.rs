// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index key generation (indexing.md §3, data-model.md §2.1/§3; FR-IDX-001, TC-IDX-001 part,
//! TC-IDX-004 multikey rules, TC-IDX-005 truncation).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cmp::Ordering;

use proptest::{collection::vec, prelude::*};
use rustegon_catalog::{
    IndexDescriptor, IndexField, IndexKind, IndexOrder, IndexOrigin, IndexScope, IndexState,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Decimal128, Document, ObjectId, Value, compare::compare, json::parse_document,
    keyenc::Direction,
};
use rustegon_index::{
    EntryValue, NoPartialFilter,
    entry::{TRUNCATED_KEY_PART, id_element_of_key},
    index_entries, key_directions,
    maintain::{ENTRY_PREFIX_LEN, plan_changes},
};

fn index(fields: Vec<IndexField>) -> IndexDescriptor {
    IndexDescriptor {
        id: 200,
        database_id: 100,
        collection_id: 101,
        name: "ix".into(),
        kind: IndexKind::Secondary,
        fields,
        unique: false,
        sparse: false,
        partial: None,
        hidden: false,
        scope: IndexScope::Global,
        state: IndexState::Public,
        origin: IndexOrigin::Manual,
        version: 1,
        include: vec![],
        multikey: false,
        created_at_ms: 0,
    }
}

fn doc(json: &str) -> Document {
    parse_document(json).unwrap()
}

fn id() -> Value {
    Value::Int64(1)
}

fn entries(ix: &IndexDescriptor, d: &Document) -> Vec<(Vec<u8>, Vec<u8>)> {
    index_entries(ix, &id(), d, &NoPartialFilter)
        .unwrap()
        .entries
        .into_iter()
        .collect()
}

/// The key part (without prefix and `_id`) of the only entry.
fn single_part(ix: &IndexDescriptor, d: &Document) -> Vec<u8> {
    let e = entries(ix, d);
    assert_eq!(e.len(), 1, "{e:?}");
    let key = &e[0].0;
    let mut id_enc = Vec::new();
    rustegon_doc::keyenc::encode_element(&mut id_enc, Some(&id()), Direction::Ascending).unwrap();
    let end = if ix.unique {
        key.len()
    } else {
        key.len() - id_enc.len()
    };
    key[ENTRY_PREFIX_LEN..end].to_vec()
}

fn arb_scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        prop_oneof![any::<i64>(), -20i64..20].prop_map(Value::Int64),
        prop_oneof![
            any::<u64>().prop_map(f64::from_bits),
            (-200i32..200).prop_map(|i| f64::from(i) / 8.0),
            Just(f64::NAN),
            Just(f64::INFINITY),
        ]
        .prop_map(Value::Float64),
        (any::<bool>(), 0u128..10_000, -4i32..4)
            .prop_map(|(n, c, e)| Value::Decimal(Decimal128::new(n, c, e).unwrap())),
        "[a-c\\x00é]{0,4}".prop_map(Value::String),
        any::<i64>().prop_map(Value::DateTime),
        any::<[u8; 12]>().prop_map(|b| Value::ObjectId(ObjectId(b))),
        vec(-5i64..5, 0..2).prop_map(|v| {
            let mut d = Document::new();
            for (i, x) in v.into_iter().enumerate() {
                d.insert(format!("k{i}"), Value::Int64(x));
            }
            Value::Object(d)
        }),
    ]
}

/// `None` = field missing.
fn arb_opt() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![1 => Just(None), 8 => arb_scalar().prop_map(Some)]
}

fn doc_of(values: &[Option<Value>]) -> Document {
    let mut d = Document::new();
    for (i, v) in values.iter().enumerate() {
        if let Some(v) = v {
            d.insert(format!("f{i}"), v.clone());
        }
    }
    d
}

fn expected(a: &[Option<Value>], b: &[Option<Value>], orders: &[IndexOrder]) -> Ordering {
    for ((x, y), o) in a.iter().zip(b).zip(orders) {
        let c = compare(x.as_ref(), y.as_ref());
        let c = if *o == IndexOrder::Desc {
            c.reverse()
        } else {
            c
        };
        if c != Ordering::Equal {
            return c;
        }
    }
    Ordering::Equal
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// TC-IDX-001 (key order): index key order equals the §2.1 total order of the indexed
    /// values, per field direction, lexicographically over compound fields.
    #[test]
    fn tc_idx_001_key_order_equals_value_order(
        a in vec(arb_opt(), 3),
        b in vec(arb_opt(), 3),
        orders in vec(prop_oneof![Just(IndexOrder::Asc), Just(IndexOrder::Desc)], 3),
        unique in any::<bool>(),
    ) {
        let mut ix = index(
            orders.iter().enumerate()
                .map(|(i, o)| IndexField { path: format!("f{i}"), order: *o })
                .collect(),
        );
        ix.unique = unique;
        let (pa, pb) = (single_part(&ix, &doc_of(&a)), single_part(&ix, &doc_of(&b)));
        prop_assert_eq!(pa.cmp(&pb), expected(&a, &b, &orders));
    }
}

#[test]
fn tc_idx_001_missing_orders_before_null_and_sparse_skips() {
    let ix = index(vec![IndexField::asc("a"), IndexField::asc("b")]);
    let missing = single_part(&ix, &doc(r#"{"x":1}"#));
    let null = single_part(&ix, &doc(r#"{"a":null}"#));
    assert!(missing < null);
    let mut sparse = ix.clone();
    sparse.sparse = true;
    assert_eq!(entries(&sparse, &doc(r#"{"x":1}"#)).len(), 0);
    // One indexed field present: indexed (compound sparse = all fields missing).
    assert_eq!(entries(&sparse, &doc(r#"{"b":2}"#)).len(), 1);
    assert_eq!(entries(&sparse, &doc(r#"{"a":null}"#)).len(), 1);
}

#[test]
fn tc_idx_004_multikey_distinct_elements_and_compound_rule() {
    let ix = index(vec![IndexField::asc("tags"), IndexField::desc("n")]);
    let out = index_entries(
        &ix,
        &id(),
        &doc(r#"{"tags":[1,2,2,1.0,"x"],"n":5}"#),
        &NoPartialFilter,
    )
    .unwrap();
    assert!(out.saw_array);
    assert_eq!(out.entries.len(), 3);
    let err = index_entries(
        &ix,
        &id(),
        &doc(r#"{"tags":[1,2],"n":[3,4]}"#),
        &NoPartialFilter,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::MultikeyCompoundArrays);
    assert_eq!(err.code().code(), 1025);
    // Empty array: one entry holding `[]`.
    let e = index_entries(&ix, &id(), &doc(r#"{"tags":[],"n":1}"#), &NoPartialFilter).unwrap();
    assert_eq!(e.entries.len(), 1);
    assert!(e.saw_array);
    // Fan-out through an array of objects counts as array-valued.
    let ab = index(vec![IndexField::asc("a.b"), IndexField::asc("c")]);
    let e = index_entries(
        &ab,
        &id(),
        &doc(r#"{"a":[{"b":1},{"b":2},{"z":0},3],"c":0}"#),
        &NoPartialFilter,
    )
    .unwrap();
    assert_eq!(e.entries.len(), 2);
    assert!(e.saw_array);
    let err = index_entries(
        &ab,
        &id(),
        &doc(r#"{"a":[{"b":1}],"c":[1,2]}"#),
        &NoPartialFilter,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::MultikeyCompoundArrays);
    // Positional path: no fan-out.
    let pos = index(vec![IndexField::asc("a.1")]);
    let e = index_entries(&pos, &id(), &doc(r#"{"a":[5,6]}"#), &NoPartialFilter).unwrap();
    assert_eq!(e.entries.len(), 1);
    assert!(!e.saw_array);
    assert_eq!(
        single_part(&pos, &doc(r#"{"a":[5,6]}"#)),
        single_part(&pos, &doc(r#"{"a":{"1":6}}"#))
    );
}

#[test]
fn unique_keys_carry_id_in_value_not_key() {
    let mut ix = index(vec![IndexField::asc("email")]);
    ix.unique = true;
    let e = entries(&ix, &doc(r#"{"email":"a@x"}"#));
    assert_eq!(e[0].0[10], b'U');
    let v = EntryValue::decode(&e[0].1).unwrap();
    let mut id_enc = Vec::new();
    rustegon_doc::keyenc::encode_element(&mut id_enc, Some(&id()), Direction::Ascending).unwrap();
    assert_eq!(v.id_element, Some(id_enc.clone()));
    assert!(!e[0].0.ends_with(&id_enc));
    // Non-unique: `I`, `_id` suffix, empty value.
    let plain = index(vec![IndexField::asc("email")]);
    let e = entries(&plain, &doc(r#"{"email":"a@x"}"#));
    assert_eq!(e[0].0[10], b'I');
    assert!(e[0].0.ends_with(&id_enc));
    assert_eq!(e[0].1.len(), 0);
}

#[test]
fn tc_idx_005_long_keys_truncate_or_fail_for_unique() {
    let long = "x".repeat(5000);
    let mut d = Document::new();
    d.insert("s", Value::String(long.clone()));
    let ix = index(vec![IndexField::desc("s")]);
    let e = entries(&ix, &d);
    let v = EntryValue::decode(&e[0].1).unwrap();
    assert!(v.truncated);
    let after = &e[0].0[ENTRY_PREFIX_LEN..];
    assert_eq!(
        id_element_of_key(after, &key_directions(&ix), true)
            .unwrap()
            .len(),
        after.len() - TRUNCATED_KEY_PART
    );
    // Two long values sharing the kept prefix stay distinct.
    let mut d2 = Document::new();
    d2.insert("s", Value::String(format!("{long}y")));
    assert_ne!(entries(&ix, &d2)[0].0, e[0].0);
    // Exactly at the limit: not truncated (1 class byte + 4093 bytes + 2 terminator bytes).
    let mut at = Document::new();
    at.insert("s", Value::String("x".repeat(4093)));
    assert!(
        !EntryValue::decode(&entries(&ix, &at)[0].1)
            .unwrap()
            .truncated
    );
    let mut over = Document::new();
    over.insert("s", Value::String("x".repeat(4094)));
    assert!(
        EntryValue::decode(&entries(&ix, &over)[0].1)
            .unwrap()
            .truncated
    );
    let mut u = ix.clone();
    u.unique = true;
    let err = index_entries(&u, &id(), &d, &NoPartialFilter).unwrap_err();
    assert_eq!(err.code(), ErrorCode::IndexKeyTooLarge);
    assert_eq!(err.code().code(), 1008);
}

#[test]
fn wildcard_indexes_every_leaf_with_its_path() {
    let ix = index(vec![IndexField::asc("attrs.**")]);
    let d = doc(
        r#"{"attrs":{"color":"red","size":{"w":1,"h":2},"tags":["a","b",["c"]],"e":{}},"x":1}"#,
    );
    let out = index_entries(&ix, &id(), &d, &NoPartialFilter).unwrap();
    assert!(out.saw_array);
    // color, size.w, size.h, tags×a, tags×b, tags×["c"], e×{}
    assert_eq!(out.entries.len(), 7);
    let dirs = key_directions(&ix);
    let paths: Vec<String> = out
        .entries
        .keys()
        .map(|k| {
            let vals =
                rustegon_doc::keyenc::decode_element(&k[ENTRY_PREFIX_LEN..], dirs[0]).unwrap();
            match vals.0 {
                Some(Value::String(s)) => s,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    for p in [
        "attrs.color",
        "attrs.size.w",
        "attrs.size.h",
        "attrs.tags",
        "attrs.e",
    ] {
        assert!(paths.iter().any(|q| q == p), "{p} in {paths:?}");
    }
    // Missing prefix: nothing. Root wildcard skips `_id` and server fields.
    assert_eq!(entries(&ix, &doc(r#"{"x":1}"#)).len(), 0);
    let root = index(vec![IndexField::asc("**")]);
    let e = entries(&root, &doc(r#"{"_id":1,"_rev":"r","a":1,"b":{"`c.d`":2}}"#));
    assert_eq!(e.len(), 2);
    // Parsing the `_id` back from wildcard keys works.
    for (k, _) in &e {
        assert!(id_element_of_key(&k[ENTRY_PREFIX_LEN..], &key_directions(&root), false).is_ok());
    }
}

#[test]
fn partial_filter_and_include() {
    let mut ix = index(vec![IndexField::asc("a")]);
    ix.partial = Some("total > 0".into());
    let positive = |_: &IndexDescriptor, d: &Document| -> Result<bool, Error> {
        Ok(matches!(d.get("total"), Some(Value::Int64(t)) if *t > 0))
    };
    let yes = index_entries(&ix, &id(), &doc(r#"{"a":1,"total":3}"#), &positive).unwrap();
    let no = index_entries(&ix, &id(), &doc(r#"{"a":1,"total":0}"#), &positive).unwrap();
    assert_eq!((yes.entries.len(), no.entries.len()), (1, 0));
    assert!(index_entries(&ix, &id(), &doc(r#"{"a":1}"#), &NoPartialFilter).is_err());

    let mut cov = index(vec![IndexField::asc("a")]);
    cov.include = vec!["b".into(), "c.d".into(), "zz".into()];
    let e = entries(&cov, &doc(r#"{"a":1,"b":"x","c":{"d":[1,2]}}"#));
    let v = EntryValue::decode(&e[0].1).unwrap();
    let inc = v.include.unwrap();
    assert_eq!(inc.get("b"), Some(&Value::String("x".into())));
    assert_eq!(
        inc.get("c.d"),
        Some(&Value::Array(vec![Value::Int64(1), Value::Int64(2)]))
    );
    assert_eq!(inc.get("zz"), None);
}

#[test]
fn tc_idx_001_plan_changes_diff_and_states() {
    let mut a = index(vec![IndexField::asc("a")]);
    let mut b = index(vec![IndexField::asc("b")]);
    b.id = 201;
    let old = doc(r#"{"a":1,"b":[1,2]}"#);
    let new = doc(r#"{"a":1,"b":[2,3]}"#);
    let ch = plan_changes(
        &[a.clone(), b.clone()],
        &id(),
        Some(&old),
        Some(&new),
        &NoPartialFilter,
    )
    .unwrap();
    // `a` unchanged; `b`: delete 1, put 3.
    assert_eq!((ch.delete_count(), ch.put_count()), (1, 1));
    assert_eq!(ch.newly_multikey, vec![201]);
    b.multikey = true;
    let ch = plan_changes(&[b.clone()], &id(), None, Some(&new), &NoPartialFilter).unwrap();
    assert_eq!(ch.newly_multikey.len(), 0);
    // DeleteOnly: deletes, no puts. Dropping: nothing.
    a.state = IndexState::DeleteOnly;
    let ch = plan_changes(
        &[a.clone()],
        &id(),
        Some(&old),
        Some(&doc(r#"{"a":2}"#)),
        &NoPartialFilter,
    )
    .unwrap();
    assert_eq!((ch.delete_count(), ch.put_count()), (1, 0));
    a.state = IndexState::Dropping;
    let ch = plan_changes(&[a], &id(), Some(&old), None, &NoPartialFilter).unwrap();
    assert!(ch.is_empty());
    // A new document breaking a rule is rejected; an old one that does is ignored.
    let c = index(vec![IndexField::asc("x"), IndexField::asc("y")]);
    let bad = doc(r#"{"x":[1],"y":[2]}"#);
    assert!(
        plan_changes(
            std::slice::from_ref(&c),
            &id(),
            None,
            Some(&bad),
            &NoPartialFilter
        )
        .is_err()
    );
    let ch = plan_changes(&[c], &id(), Some(&bad), None, &NoPartialFilter).unwrap();
    assert!(ch.is_empty());
}
