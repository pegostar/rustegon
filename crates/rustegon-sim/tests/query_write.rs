// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write operators of the query engine through the embedded API (M3 lane F; FR-QL-001,
//! FR-DOC-006, FR-IDX-002, FR-SCH-002): INSERT (VALUE / VALUES / FROM query / ON CONFLICT /
//! RETURNING), UPDATE (every operator, PULL … WHERE, REPLACE WITH), DELETE, UPSERT, statement
//! atomicity, validators and index maintenance on the shared write path, explicit
//! transactions and DDL through RGQL. TC-QL-010.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{DB, code, load, open, plan, q, rows, rows_of, val};
use rustegon_catalog::{CollectionOptions, CollectionSpec};
use rustegon_common::ErrorCode;
use rustegon_doc::Value;
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::Params;

/// User fields of `coll` (server-maintained fields dropped), in `_id` order.
fn docs(db: &EmbeddedDb, coll: &str) -> String {
    rows_of(
        db,
        &format!("FROM {coll} SELECT -_rev, -_createdAt, -_updatedAt ORDER BY _id"),
    )
}

#[test]
fn tc_ql_010_insert_forms_and_returning() {
    let db = open(21);
    let r = q(
        &db,
        "INSERT INTO items VALUE {_id: 1, n: 'a'} RETURNING NEW _id, n",
    );
    assert_eq!(
        (r.inserted, rows(&r)),
        (1, vec![r#"{"_id":1,"n":"a"}"#.to_owned()])
    );
    let p = Params::new().with("docs", val(r#"[{"_id":2},{"_id":3,"n":"c"}]"#));
    let r = db
        .query(
            DB,
            "INSERT INTO items VALUES $docs, {_id: 4, n: upper('d')}",
            &p,
        )
        .unwrap();
    assert_eq!(r.inserted, 3);
    assert_eq!(
        docs(&db, "items"),
        r#"{"_id":1,"n":"a"} {"_id":2} {"_id":3,"n":"c"} {"_id":4,"n":"D"}"#
    );
    // Generated `_id`: an objectId.
    let r = q(&db, "INSERT INTO other VALUE {x: 1} RETURNING NEW _id");
    assert!(
        matches!(&r.rows[0], Value::Object(d) if matches!(d.get("_id"), Some(Value::ObjectId(_))))
    );
    // INSERT … FROM query.
    let r = q(
        &db,
        "INSERT INTO copies FROM items WHERE _id > 2 SELECT _id, n",
    );
    assert_eq!(r.inserted, 2);
    assert_eq!(
        docs(&db, "copies"),
        r#"{"_id":3,"n":"c"} {"_id":4,"n":"D"}"#
    );
    // Errors: duplicate `_id`, non-object rows, server-maintained fields, array `_id`.
    assert_eq!(
        code(&db, "INSERT INTO items VALUE {_id: 1}"),
        ErrorCode::DuplicateKey
    );
    assert_eq!(
        code(&db, "INSERT INTO items VALUE 5"),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        code(&db, "INSERT INTO items VALUE {_rev: 'x'}"),
        ErrorCode::InvalidFieldName
    );
    assert_eq!(
        code(&db, "INSERT INTO items VALUE {_id: [1]}"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(&db, "INSERT INTO items VALUE {a: qty}"),
        ErrorCode::QueryTypeError
    );
    // A failing row rolls back the whole statement.
    assert_eq!(
        code(&db, "INSERT INTO items VALUES {_id: 10}, {_id: 1}"),
        ErrorCode::DuplicateKey
    );
    assert_eq!(rows_of(&db, "FROM items WHERE _id = 10"), "");
}

#[test]
fn tc_ql_010_insert_on_conflict() {
    let db = open(22);
    load(&db, "items", &[r#"{"_id":1,"n":1}"#]);
    let r = q(
        &db,
        "INSERT INTO items VALUES {_id: 1, n: 9}, {_id: 2, n: 2} ON CONFLICT DO NOTHING",
    );
    assert_eq!((r.inserted, r.updated), (1, 0));
    let r = q(
        &db,
        "INSERT INTO items VALUE {_id: 1, n: 5} ON CONFLICT DO UPDATE INC n BY 10 RETURNING NEW n",
    );
    assert_eq!(
        (r.inserted, r.updated, rows(&r)),
        (0, 1, vec![r#"{"n":11}"#.to_owned()])
    );
    assert_eq!(docs(&db, "items"), r#"{"_id":1,"n":11} {"_id":2,"n":2}"#);
}

#[test]
fn tc_ql_010_update_operators() {
    let db = open(23);
    load(
        &db,
        "items",
        &[
            r#"{"_id":1,"n":1,"tags":["a","old","b"],"arr":[3,1],"colour":"red","lo":5,"hi":5,"q":[1,2,3],"items":[{"k":1},{"k":2}]}"#,
        ],
    );
    let r = q(
        &db,
        "UPDATE items SET m = n + 1 INC n BY 2 MUL lo BY 2 PULL tags WHERE tags = 'old' \
         PUSH arr VALUE 2 SORT arr POP q FIRST RENAME colour TO color \
         MIN hi WITH 3 CURRENT DATE seen PULL items WHERE k = 2 WHERE _id = 1 RETURNING OLD n",
    );
    assert_eq!((r.updated, rows(&r)), (1, vec![r#"{"n":1}"#.to_owned()]));
    let row = q(&db, "FROM items WHERE _id = 1").documents().remove(0);
    let get = |f: &str| common::js(row.get(f).unwrap());
    assert_eq!(get("m"), "2");
    assert_eq!(get("n"), "3");
    assert_eq!(get("lo"), "10");
    assert_eq!(get("tags"), r#"["a","b"]"#);
    assert_eq!(get("arr"), "[1,2,3]");
    assert_eq!(get("q"), "[2,3]");
    assert_eq!(get("color"), r#""red""#);
    assert_eq!(get("hi"), "3");
    assert_eq!(get("items"), r#"[{"k":1}]"#);
    assert!(matches!(row.get("seen"), Some(Value::DateTime(_))));
    assert!(row.get("colour").is_none());
    // SET of a missing value removes the field; UNSET; computed index steps.
    q(
        &db,
        "UPDATE items SET m = nothing UNSET lo SET arr[0] = 9 WHERE _id = 1",
    );
    let row = q(&db, "FROM items WHERE _id = 1").documents().remove(0);
    assert!(row.get("m").is_none() && row.get("lo").is_none());
    assert_eq!(common::js(row.get("arr").unwrap()), "[9,2,3]");
    // PUSH with SLICE / POSITION; MAX; ADD TO SET (an equal element is not added twice).
    q(
        &db,
        "UPDATE items PUSH q VALUE 0 POSITION 0 SLICE 2 MAX hi WITH 8 ADD TO SET tags VALUE 'a' \
         WHERE _id = 1",
    );
    q(&db, "UPDATE items ADD TO SET tags VALUE 'c' WHERE _id = 1");
    assert_eq!(
        rows_of(&db, "FROM items SELECT q, hi, tags"),
        r#"{"q":[0,2],"hi":8,"tags":["a","b","c"]}"#
    );
    // Conflicting targets are rejected by the update engine.
    assert_eq!(
        code(
            &db,
            "UPDATE items PULL tags WHERE tags = 'a' ADD TO SET tags VALUE 'x' WHERE _id = 1"
        ),
        ErrorCode::InvalidArgument
    );
    // Operator errors are those of rustegon-doc (data-model.md §2.3).
    assert_eq!(
        code(&db, "UPDATE items INC color BY 1 WHERE _id = 1"),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        code(&db, "UPDATE items SET _id = 5 WHERE _id = 1"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(&db, "UPDATE items SET _rev = 'x' WHERE _id = 1"),
        ErrorCode::InvalidFieldName
    );
    // `_rev` advances, `_createdAt` is kept.
    let before = q(&db, "FROM items").documents().remove(0);
    q(&db, "UPDATE items SET z = 1 WHERE _id = 1");
    let after = q(&db, "FROM items").documents().remove(0);
    assert_ne!(before.get("_rev"), after.get("_rev"));
    assert_eq!(before.get("_createdAt"), after.get("_createdAt"));
}

#[test]
fn tc_ql_010_update_replace_limit_and_full_scan_guard() {
    let db = open(24);
    load(
        &db,
        "items",
        &[
            r#"{"_id":1,"n":1}"#,
            r#"{"_id":2,"n":2}"#,
            r#"{"_id":3,"n":3}"#,
        ],
    );
    let r = q(
        &db,
        "UPDATE items AS i REPLACE WITH {n: i.n * 10, was: i.n} WHERE i.n >= 2 LIMIT 1",
    );
    assert_eq!(r.updated, 1);
    assert_eq!(
        code(&db, "UPDATE items SET n = 0"),
        ErrorCode::QueryTooComplex
    );
    let r = q(
        &db,
        "UPDATE items SET k = true OPTIONS (allow_full_scan_write = true)",
    );
    assert_eq!(r.updated, 3);
    assert_eq!(
        code(&db, "UPDATE items REPLACE WITH {_id: 9} WHERE _id = 1"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(&db, "UPDATE nothing SET a = 1 WHERE b = 1"),
        ErrorCode::NotFound
    );
}

#[test]
fn tc_ql_010_delete_and_upsert() {
    let db = open(25);
    load(
        &db,
        "items",
        &[
            r#"{"_id":1,"k":"a"}"#,
            r#"{"_id":2,"k":"b"}"#,
            r#"{"_id":3,"k":"b"}"#,
        ],
    );
    let r = q(
        &db,
        "DELETE FROM items WHERE k = 'b' LIMIT 1 RETURNING OLD _id",
    );
    assert_eq!((r.deleted, r.rows.len()), (1, 1));
    assert_eq!(code(&db, "DELETE FROM items"), ErrorCode::QueryTooComplex);
    // UPSERT by `_id`: replace, then insert.
    let r = q(
        &db,
        "UPSERT INTO items VALUE {_id: 1, k: 'z'} RETURNING NEW k",
    );
    assert_eq!(
        (r.updated, r.inserted, rows(&r)),
        (1, 0, vec![r#"{"k":"z"}"#.to_owned()])
    );
    let r = q(&db, "UPSERT INTO items VALUE {_id: 7, k: 'n'}");
    assert_eq!(r.inserted, 1);
    // UPSERT ON other fields keeps the matched `_id`.
    q(&db, "UPSERT INTO items VALUE {k: 'z', extra: 1} ON k");
    assert_eq!(
        rows_of(&db, "FROM items WHERE k = 'z' SELECT _id, extra"),
        r#"{"_id":1,"extra":1}"#
    );
    q(&db, "INSERT INTO items VALUE {_id: 8, k: 'z'}");
    assert_eq!(
        code(&db, "UPSERT INTO items VALUE {k: 'z'} ON k"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(&db, "UPSERT INTO items VALUE {x: 1} ON k"),
        ErrorCode::InvalidArgument
    );
    // A `null` key is rejected like a `missing` one (converged with the reference, §4.3).
    assert_eq!(
        code(&db, "UPSERT INTO items VALUE {k: null} ON k"),
        ErrorCode::InvalidArgument
    );
    // UPSERT into a missing collection creates it.
    q(&db, "UPSERT INTO fresh VALUE {_id: 1}");
    assert_eq!(rows_of(&db, "FROM fresh SELECT VALUE _id"), "1");
    let r = q(&db, "DELETE FROM items WHERE _id IN [1, 7, 99]");
    assert_eq!(r.deleted, 2);
}

#[test]
fn tc_ql_010_statement_atomicity_with_unique_index() {
    let db = open(26);
    load(
        &db,
        "users",
        &[r#"{"_id":1,"email":"a"}"#, r#"{"_id":2,"email":"b"}"#],
    );
    q(&db, "CREATE UNIQUE INDEX ux_email ON users (email)");
    assert_eq!(
        code(&db, "UPDATE users SET email = 'same' WHERE _id IN [1, 2]"),
        ErrorCode::DuplicateKey
    );
    // Nothing of the failed statement survives, the index included.
    assert_eq!(
        docs(&db, "users"),
        r#"{"_id":1,"email":"a"} {"_id":2,"email":"b"}"#
    );
    assert_eq!(rows_of(&db, "FROM users WHERE email = 'same'"), "");
    assert!(plan(&db, "FROM users WHERE email = 'a'").contains("ux_email"));
    assert_eq!(
        rows_of(&db, "FROM users WHERE email = 'a' SELECT VALUE _id"),
        "1"
    );
}

#[test]
fn tc_ql_010_indexes_follow_query_writes() {
    let db = open(27);
    q(&db, "CREATE INDEX by_n ON items (n) WITH (sparse = true)");
    q(
        &db,
        "CREATE INDEX paid ON items (total) WITH (partial = 'status = ''paid''')",
    );
    load(
        &db,
        "items",
        &[
            r#"{"_id":1,"n":1,"status":"paid","total":5}"#,
            r#"{"_id":2,"n":2}"#,
        ],
    );
    q(&db, "UPDATE items SET n = 20, status = 'new' WHERE _id = 1");
    q(&db, "DELETE FROM items WHERE _id = 2");
    q(
        &db,
        "INSERT INTO items VALUE {_id: 3, status: 'paid', total: 9}",
    );
    assert!(plan(&db, "FROM items WHERE n = 20").contains("by_n"));
    assert_eq!(
        rows_of(&db, "FROM items WHERE n = 20 SELECT VALUE _id"),
        "1"
    );
    assert_eq!(rows_of(&db, "FROM items WHERE n = 2"), "");
    let paid = "FROM items WHERE status = 'paid' AND total > 1 SELECT VALUE _id";
    assert!(plan(&db, paid).contains("items.paid"));
    assert_eq!(rows_of(&db, paid), "3");
    q(&db, "DROP INDEX items.paid");
    assert!(!plan(&db, paid).contains("items.paid"));
    assert_eq!(
        code(&db, "CREATE INDEX bad ON items (x) WITH (partial = 'x = ')"),
        ErrorCode::QuerySyntaxError
    );
}

#[test]
fn tc_ql_010_validators_apply_to_query_writes() {
    let db = open(28);
    let mut spec = CollectionSpec::document("users");
    spec.options = CollectionOptions {
        validator: Some(r#"{"$jsonSchema":{"required":["email"]}}"#.into()),
        ..CollectionOptions::default()
    };
    db.create_collection(DB, &spec).unwrap();
    q(&db, "INSERT INTO users VALUE {_id: 1, email: 'x'}");
    assert_eq!(
        code(&db, "INSERT INTO users VALUE {_id: 2}"),
        ErrorCode::SchemaValidationFailed
    );
    assert_eq!(
        code(&db, "UPDATE users UNSET email WHERE _id = 1"),
        ErrorCode::SchemaValidationFailed
    );
    assert_eq!(
        code(&db, "UPSERT INTO users VALUE {_id: 1}"),
        ErrorCode::SchemaValidationFailed
    );
    assert_eq!(docs(&db, "users"), r#"{"_id":1,"email":"x"}"#);
}

#[test]
fn tc_ql_010_explicit_transactions() {
    let db = open(29);
    load(
        &db,
        "acc",
        &[r#"{"_id":1,"bal":10}"#, r#"{"_id":2,"bal":0}"#],
    );
    let p = Params::new();
    db.transaction(|t| {
        t.query(DB, "UPDATE acc INC bal BY -5 WHERE _id = 1", &p)?;
        // A failing statement is rolled back alone; the transaction goes on.
        assert!(t.query(DB, "INSERT INTO acc VALUE {_id: 1}", &p).is_err());
        t.query(DB, "UPDATE acc INC bal BY 5 WHERE _id = 2", &p)?;
        // Own writes are visible.
        let r = t.query(DB, "FROM acc SELECT VALUE bal ORDER BY _id", &p)?;
        assert_eq!(rows(&r), ["5", "5"]);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        rows_of(&db, "FROM acc SELECT VALUE bal ORDER BY _id"),
        "5 5"
    );
    // A body error rolls the whole transaction back.
    let err = db
        .transaction(|t| {
            t.query(DB, "DELETE FROM acc WHERE _id = 1", &p)?;
            t.query(DB, "FROM nowhere.acc", &p)
        })
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(
        rows_of(&db, "FROM acc SELECT VALUE _id ORDER BY _id"),
        "1 2"
    );
    // DDL is refused inside a transaction.
    let err = db
        .transaction(|t| t.query(DB, "CREATE INDEX i ON acc (bal)", &p))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}
