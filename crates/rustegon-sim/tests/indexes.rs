// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Secondary indexes through the embedded test API (M3 lane C): write-path maintenance in the
//! document's transaction (FR-IDX-002), unique enforcement including concurrent inserts
//! (TC-IDX-003, `RGN-1005`), the synchronous build and drop, and the first part of TC-IDX-001
//! (index range reads == filter over all documents, randomized; the planner-based TC-IDX-001
//! comes with the executor).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
    path::Path,
    sync::Arc,
};

use rustegon_catalog::{DatabaseOptions, IndexDescriptor, IndexField, IndexSpec};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    compare::compare,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::SystemClock;

const DB: &str = "shop";
const COLL: &str = "items";

fn open(seed: u64) -> EmbeddedDb {
    let fs = Arc::new(SimFileSystem::new());
    let db = EmbeddedDb::open(
        fs,
        Path::new("/store"),
        Arc::new(SystemClock::new()),
        Arc::new(SimRng::new(seed)),
    )
    .unwrap();
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    db
}

fn doc(fields: Vec<(&str, Value)>) -> Document {
    Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()).unwrap()
}

fn int(i: i64) -> Value {
    Value::Int64(i)
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn ids(rows: &[(rustegon_index::IndexHit, Document)]) -> BTreeSet<String> {
    rows.iter()
        .map(|(_, d)| value_to_json(d.get("_id").unwrap(), JsonMode::Canonical))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// TC-IDX-001 (part): randomized index-vs-scan equivalence through the embedded API.

/// Reference extraction of a top-level field (independent of `rustegon-index`): missing →
/// `[None]`; non-empty array → its elements; anything else (including `[]`) → itself.
fn values_of(d: &Document, field: &str) -> Vec<Option<Value>> {
    match d.get(field) {
        None => vec![None],
        Some(Value::Array(items)) if !items.is_empty() => items.iter().cloned().map(Some).collect(),
        Some(v) => vec![Some(v.clone())],
    }
}

fn within(v: Option<&Value>, lo: Option<&Value>, hi: Option<&Value>) -> bool {
    compare(v, lo) != Ordering::Less && compare(v, hi) != Ordering::Greater
}

fn rand_scalar(r: &SimRng) -> Option<Value> {
    match r.below(9) {
        0 => None,
        1 => Some(Value::Null),
        2 => Some(Value::Bool(r.chance(500))),
        3 | 4 => Some(int(i64::try_from(r.below(6)).unwrap() - 2)),
        5 => Some(Value::Float64(
            f64::from(u32::try_from(r.below(6)).unwrap()) - 2.5,
        )),
        6 => Some(Value::Float64(f64::from(
            u32::try_from(r.below(3)).unwrap(),
        ))),
        _ => Some(s(["a", "b", "c", "ab"][r.index(4)])),
    }
}

fn rand_a(r: &SimRng) -> Option<Value> {
    if r.chance(250) {
        let n = r.below(4);
        Some(Value::Array(
            (0..n)
                .filter_map(|_| rand_scalar(r).or(Some(Value::Null)))
                .collect(),
        ))
    } else {
        rand_scalar(r)
    }
}

fn rand_doc(r: &SimRng, id: i64) -> Document {
    let mut fields = vec![("_id", int(id))];
    if let Some(a) = rand_a(r) {
        fields.push(("a", a));
    }
    if let Some(b) = rand_scalar(r) {
        fields.push(("b", b));
    }
    if r.chance(600) {
        fields.push(("u", int(i64::try_from(r.below(40)).unwrap())));
    }
    doc(fields)
}

fn user_part(d: &Document) -> Document {
    doc(d
        .iter()
        .filter(|(n, _)| matches!(*n, "a" | "b" | "u"))
        .map(|(n, v)| (n, v.clone()))
        .collect())
}

fn specs() -> Vec<IndexSpec> {
    let mut cov = IndexSpec::new("by_a", vec![IndexField::asc("a")]);
    cov.include = vec!["b".into()];
    vec![
        cov,
        IndexSpec::new("by_b_a", vec![IndexField::asc("b"), IndexField::desc("a")]),
        IndexSpec::new("by_u", vec![IndexField::asc("u")])
            .unique()
            .sparse(),
    ]
}

fn check_equivalence(db: &EmbeddedDb, model: &BTreeMap<i64, Document>, r: &SimRng) {
    let all: Vec<&Document> = model.values().collect();
    let id_set = |pred: &dyn Fn(&Document) -> bool| -> BTreeSet<String> {
        model
            .iter()
            .filter(|(_, d)| pred(d))
            .map(|(id, _)| id.to_string())
            .collect()
    };
    // Full scans: entry counts equal the distinct values per document.
    let full = db
        .index_scan(DB, COLL, "by_a", Bound::Unbounded, Bound::Unbounded)
        .unwrap();
    let expected: usize = all
        .iter()
        .map(|d| {
            let mut vs: Vec<Option<Value>> = Vec::new();
            for v in values_of(d, "a") {
                if !vs
                    .iter()
                    .any(|w| compare(w.as_ref(), v.as_ref()) == Ordering::Equal)
                {
                    vs.push(v);
                }
            }
            vs.len()
        })
        .sum();
    assert_eq!(full.len(), expected, "by_a entry count");
    // Covered field `b` is the document's.
    for (hit, d) in &full {
        assert_eq!(
            hit.include.as_ref().map(|i| i.get("b")),
            Some(d.get("b")),
            "{hit:?} {d:?}"
        );
    }
    let unique = db
        .index_scan(DB, COLL, "by_u", Bound::Unbounded, Bound::Unbounded)
        .unwrap();
    assert_eq!(ids(&unique), id_set(&|d| d.get("u").is_some()));
    assert_eq!(
        unique.len(),
        all.iter().filter(|d| d.get("u").is_some()).count()
    );

    for _ in 0..12 {
        // Point lookup on `a` (equality, any element for arrays).
        let v = rand_scalar(r);
        let t = [v.clone()];
        let got = db
            .index_scan(DB, COLL, "by_a", Bound::Included(&t), Bound::Included(&t))
            .unwrap();
        let want = id_set(&|d| {
            values_of(d, "a")
                .iter()
                .any(|x| compare(x.as_ref(), v.as_ref()) == Ordering::Equal)
        });
        assert_eq!(ids(&got), want, "a = {v:?}");
        // Range on `a`.
        let (mut lo, mut hi) = (rand_scalar(r), rand_scalar(r));
        if compare(lo.as_ref(), hi.as_ref()) == Ordering::Greater {
            std::mem::swap(&mut lo, &mut hi);
        }
        let (tl, th) = ([lo.clone()], [hi.clone()]);
        let got = db
            .index_scan(DB, COLL, "by_a", Bound::Included(&tl), Bound::Included(&th))
            .unwrap();
        let want = id_set(&|d| {
            values_of(d, "a")
                .iter()
                .any(|x| within(x.as_ref(), lo.as_ref(), hi.as_ref()))
        });
        assert_eq!(ids(&got), want, "{lo:?} <= a <= {hi:?}");
        // Exclusive range on `a`.
        let got = db
            .index_scan(DB, COLL, "by_a", Bound::Excluded(&tl), Bound::Excluded(&th))
            .unwrap();
        let want = id_set(&|d| {
            values_of(d, "a").iter().any(|x| {
                compare(x.as_ref(), lo.as_ref()) == Ordering::Greater
                    && compare(x.as_ref(), hi.as_ref()) == Ordering::Less
            })
        });
        assert_eq!(ids(&got), want, "{lo:?} < a < {hi:?}");
        // Prefix lookup on the compound index: b = v.
        let bv = rand_scalar(r);
        let tb = [bv.clone()];
        let got = db
            .index_scan(
                DB,
                COLL,
                "by_b_a",
                Bound::Included(&tb),
                Bound::Included(&tb),
            )
            .unwrap();
        let want = id_set(&|d| compare(d.get("b"), bv.as_ref()) == Ordering::Equal);
        assert_eq!(ids(&got), want, "b = {bv:?}");
        // Compound point: b = v AND a = w (a descending in the key).
        let av = rand_scalar(r);
        let tba = [bv.clone(), av.clone()];
        let got = db
            .index_scan(
                DB,
                COLL,
                "by_b_a",
                Bound::Included(&tba),
                Bound::Included(&tba),
            )
            .unwrap();
        let want = id_set(&|d| {
            compare(d.get("b"), bv.as_ref()) == Ordering::Equal
                && values_of(d, "a")
                    .iter()
                    .any(|x| compare(x.as_ref(), av.as_ref()) == Ordering::Equal)
        });
        assert_eq!(ids(&got), want, "b = {bv:?} and a = {av:?}");
    }
}

#[test]
fn tc_idx_001_index_reads_equal_filtered_scan_randomized() {
    for seed in 1..=6u64 {
        let db = open(seed);
        let r = SimRng::new(seed * 7919);
        let mut model: BTreeMap<i64, Document> = BTreeMap::new();
        // Half the documents exist before the indexes (backfill), half after (write path).
        let mut next_id = 0i64;
        for _ in 0..30 {
            let d = rand_doc(&r, next_id);
            match db.insert(DB, COLL, &d) {
                Ok(_) => {
                    model.insert(next_id, user_part(&d));
                }
                Err(e) => panic!("{e}"),
            }
            next_id += 1;
        }
        // Existing data may hold duplicate `u` values: the unique build then fails (1022).
        let mut built = Vec::new();
        for spec in specs() {
            match db.create_index(DB, COLL, &spec) {
                Ok(ix) => built.push(ix),
                Err(e) if e.code() == ErrorCode::IndexBuildFailed => {
                    assert!(spec.unique);
                    // Remove the duplicates and build again.
                    let mut seen = BTreeSet::new();
                    for (id, d) in &model.clone() {
                        if let Some(u) = d.get("u")
                            && !seen.insert(value_to_json(u, JsonMode::Canonical))
                        {
                            db.delete(DB, COLL, &int(*id)).unwrap();
                            model.remove(id);
                        }
                    }
                    built.push(db.create_index(DB, COLL, &spec).unwrap());
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(built.len(), 3);
        check_equivalence(&db, &model, &r);
        for _ in 0..150 {
            let op = r.below(10);
            let existing: Vec<i64> = model.keys().copied().collect();
            if op < 5 || existing.is_empty() {
                let d = rand_doc(&r, next_id);
                let dup = d
                    .get("u")
                    .is_some_and(|u| model.values().any(|m| m.get("u") == Some(u)));
                match db.insert(DB, COLL, &d) {
                    Ok(_) => {
                        assert!(!dup);
                        model.insert(next_id, user_part(&d));
                    }
                    Err(e) => {
                        assert!(dup, "{e}");
                        assert_eq!(e.code(), ErrorCode::DuplicateKey);
                        assert_eq!(e.details().get("index").map(String::as_str), Some("by_u"));
                    }
                }
                next_id += 1;
            } else if op < 8 {
                let id = existing[r.index(existing.len())];
                let mut d = rand_doc(&r, id);
                d = user_part(&d);
                let dup = d
                    .get("u")
                    .is_some_and(|u| model.iter().any(|(k, m)| *k != id && m.get("u") == Some(u)));
                match db.replace(DB, COLL, &int(id), &d) {
                    Ok(_) => {
                        assert!(!dup);
                        model.insert(id, d);
                    }
                    Err(e) => {
                        assert!(dup, "{e}");
                        assert_eq!(e.code(), ErrorCode::DuplicateKey);
                    }
                }
            } else {
                let id = existing[r.index(existing.len())];
                assert!(db.delete(DB, COLL, &int(id)).unwrap().is_some());
                model.remove(&id);
            }
        }
        check_equivalence(&db, &model, &r);
        let by_a = db
            .list_indexes(DB, COLL)
            .unwrap()
            .into_iter()
            .find(|i| i.name == "by_a")
            .unwrap();
        let any_array = model
            .values()
            .any(|d| matches!(d.get("a"), Some(Value::Array(_))));
        if any_array {
            assert!(by_a.multikey, "multikey flag after array values");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// TC-IDX-003: unique enforcement under concurrent inserts.

#[test]
fn tc_idx_003_concurrent_unique_inserts_never_both_commit() {
    const ROUNDS: i64 = 40;
    const THREADS: i64 = 4;
    let db = Arc::new(open(11));
    db.create_index(
        DB,
        "users",
        &IndexSpec::new("by_email", vec![IndexField::asc("email")]).unique(),
    )
    .unwrap();
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                let mut won = Vec::new();
                for round in 0..ROUNDS {
                    let d = doc(vec![
                        ("_id", int(t * 1000 + round)),
                        ("email", s(&format!("user{round}@x"))),
                    ]);
                    match db.insert(DB, "users", &d) {
                        Ok(_) => won.push(round),
                        Err(e) => assert_eq!(e.code(), ErrorCode::DuplicateKey, "{e}"),
                    }
                }
                won
            })
        })
        .collect();
    let mut winners: BTreeMap<i64, usize> = BTreeMap::new();
    for h in handles {
        for round in h.join().unwrap() {
            *winners.entry(round).or_default() += 1;
        }
    }
    // Exactly one insert per email committed, and the index agrees with the documents.
    assert_eq!(winners.len(), usize::try_from(ROUNDS).unwrap());
    assert!(winners.values().all(|n| *n == 1), "{winners:?}");
    let entries = db
        .index_scan(DB, "users", "by_email", Bound::Unbounded, Bound::Unbounded)
        .unwrap();
    assert_eq!(entries.len(), usize::try_from(ROUNDS).unwrap());
    for (_, d) in &entries {
        let id = d.get("_id").unwrap();
        assert_eq!(db.get(DB, "users", id).unwrap().as_ref(), Some(d));
    }
}

// ---------------------------------------------------------------------------------------------
// Unique semantics, rejection atomicity, build and drop.

#[test]
fn unique_key_moves_with_replace_and_delete() {
    let db = open(2);
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("by_u", vec![IndexField::asc("u")]).unique(),
    )
    .unwrap();
    db.insert(DB, COLL, &doc(vec![("_id", int(1)), ("u", int(1))]))
        .unwrap();
    let err = db
        .insert(
            DB,
            COLL,
            &doc(vec![("_id", int(2)), ("u", Value::Float64(1.0))]),
        )
        .unwrap_err();
    assert_eq!(err.code().code(), 1005);
    assert_eq!(err.details().get("key").map(String::as_str), Some("[1]"));
    // The rejected insert left nothing behind.
    assert_eq!(db.get(DB, COLL, &int(2)).unwrap(), None);
    // Replace frees the old key; the same document may keep its key.
    db.replace(DB, COLL, &int(1), &doc(vec![("u", int(1)), ("x", int(0))]))
        .unwrap();
    db.replace(DB, COLL, &int(1), &doc(vec![("u", int(2))]))
        .unwrap();
    db.insert(DB, COLL, &doc(vec![("_id", int(2)), ("u", int(1))]))
        .unwrap();
    db.delete(DB, COLL, &int(1)).unwrap();
    db.insert(DB, COLL, &doc(vec![("_id", int(3)), ("u", int(2))]))
        .unwrap();
    // Non-sparse unique: a second document missing `u` collides on `missing`.
    db.insert(DB, COLL, &doc(vec![("_id", int(4))])).unwrap();
    assert_eq!(
        db.insert(DB, COLL, &doc(vec![("_id", int(5))]))
            .unwrap_err()
            .code(),
        ErrorCode::DuplicateKey
    );
}

#[test]
fn rejected_writes_leave_no_entries() {
    let db = open(3);
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("ab", vec![IndexField::asc("a"), IndexField::asc("b")]),
    )
    .unwrap();
    db.insert(DB, COLL, &doc(vec![("_id", int(1)), ("a", int(1))]))
        .unwrap();
    let two_arrays = doc(vec![
        ("_id", int(2)),
        ("a", Value::Array(vec![int(1)])),
        ("b", Value::Array(vec![int(2)])),
    ]);
    let err = db.insert(DB, COLL, &two_arrays).unwrap_err();
    assert_eq!(err.code(), ErrorCode::MultikeyCompoundArrays);
    let err = db
        .replace(DB, COLL, &int(1), &user_part(&two_arrays))
        .unwrap_err();
    assert_eq!(err.code().code(), 1025);
    let all = db
        .index_scan(DB, COLL, "ab", Bound::Unbounded, Bound::Unbounded)
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(db.get(DB, COLL, &int(2)).unwrap(), None);
    assert_eq!(
        db.get(DB, COLL, &int(1)).unwrap().unwrap().get("a"),
        Some(&int(1))
    );
}

#[test]
fn build_on_existing_data_unique_violation_and_drop() {
    let db = open(4);
    for (id, email) in [(1, "a"), (2, "b"), (3, "a")] {
        db.insert(DB, COLL, &doc(vec![("_id", int(id)), ("email", s(email))]))
            .unwrap();
    }
    let unique = IndexSpec::new("by_email", vec![IndexField::asc("email")]).unique();
    let err = db.create_index(DB, COLL, &unique).unwrap_err();
    assert_eq!(err.code(), ErrorCode::IndexBuildFailed);
    assert_eq!(err.code().code(), 1022);
    assert!(err.details().contains_key("offending_ids"));
    assert_eq!(
        db.list_indexes(DB, COLL).unwrap(),
        Vec::<IndexDescriptor>::new()
    );
    // A non-unique index builds; entries match.
    let plain = IndexSpec::new("by_email", vec![IndexField::asc("email")]);
    let ix = db.create_index(DB, COLL, &plain).unwrap();
    assert_eq!(ix.state, rustegon_catalog::IndexState::Public);
    let a = [Some(s("a"))];
    let rows = db
        .index_scan(
            DB,
            COLL,
            "by_email",
            Bound::Included(&a),
            Bound::Included(&a),
        )
        .unwrap();
    assert_eq!(
        ids(&rows),
        ["1", "3"].iter().map(|x| (*x).to_owned()).collect()
    );
    assert_eq!(
        db.create_index(DB, COLL, &plain).unwrap_err().code(),
        ErrorCode::IndexAlreadyExists
    );
    // Drop: entries gone, name free, writes no longer maintain it.
    db.drop_index(DB, COLL, "by_email").unwrap();
    assert_eq!(
        db.index_scan(DB, COLL, "by_email", Bound::Unbounded, Bound::Unbounded)
            .unwrap_err()
            .code(),
        ErrorCode::IndexNotFound
    );
    assert_eq!(
        db.drop_index(DB, COLL, "by_email")
            .unwrap_err()
            .code()
            .code(),
        1021
    );
    db.insert(DB, COLL, &doc(vec![("_id", int(4)), ("email", s("a"))]))
        .unwrap();
    let again = db.create_index(DB, COLL, &plain).unwrap();
    assert_ne!(again.id, ix.id);
    let rows = db
        .index_scan(
            DB,
            COLL,
            "by_email",
            Bound::Included(&a),
            Bound::Included(&a),
        )
        .unwrap();
    assert_eq!(rows.len(), 3);
}

#[test]
fn partial_and_wildcard_indexes_through_the_api() {
    let db = open(5);
    let mut partial = IndexSpec::new("paid", vec![IndexField::asc("total")]);
    // The query engine's evaluator is installed by default: an invalid predicate is rejected
    // when the index is created.
    partial.partial = Some("status = ".into());
    assert_eq!(
        db.create_index(DB, COLL, &partial).unwrap_err().code(),
        ErrorCode::QuerySyntaxError
    );
    partial.partial = Some("status = 'paid'".into());
    db.set_partial_filter(Arc::new(
        |_: &IndexDescriptor, d: &Document| -> Result<bool, Error> {
            Ok(d.get("status") == Some(&s("paid")))
        },
    ));
    db.create_index(DB, COLL, &partial).unwrap();
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("attrs", vec![IndexField::asc("attrs.**")]),
    )
    .unwrap();
    db.insert(
        DB,
        COLL,
        &doc(vec![
            ("_id", int(1)),
            ("status", s("paid")),
            ("total", int(5)),
        ]),
    )
    .unwrap();
    let mut attrs = Document::new();
    attrs.insert("color", s("red"));
    db.insert(
        DB,
        COLL,
        &doc(vec![
            ("_id", int(2)),
            ("status", s("open")),
            ("total", int(5)),
            ("attrs", Value::Object(attrs)),
        ]),
    )
    .unwrap();
    let paid = db
        .index_scan(DB, COLL, "paid", Bound::Unbounded, Bound::Unbounded)
        .unwrap();
    assert_eq!(ids(&paid), BTreeSet::from(["1".to_owned()]));
    let t = [Some(s("attrs.color")), Some(s("red"))];
    let rows = db
        .index_scan(DB, COLL, "attrs", Bound::Included(&t), Bound::Included(&t))
        .unwrap();
    assert_eq!(ids(&rows), BTreeSet::from(["2".to_owned()]));
    // Leaving the partial predicate removes the entry.
    db.replace(
        DB,
        COLL,
        &int(1),
        &doc(vec![("status", s("void")), ("total", int(5))]),
    )
    .unwrap();
    assert_eq!(
        db.index_scan(DB, COLL, "paid", Bound::Unbounded, Bound::Unbounded)
            .unwrap()
            .len(),
        0
    );
}
