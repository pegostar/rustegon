// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SCH-006: collection validators end to end through the embedded API (FR-SCH-002/003,
//! AC-SCH-002): a collection created with a validator rejects or warns on inserts and replaces
//! per `validationLevel` / `validationAction`, the validator survives a reopen, and an invalid
//! validator is refused at creation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rustegon_catalog::{
    CollectionOptions, CollectionSpec, DatabaseOptions, ValidationAction, ValidationLevel,
};
use rustegon_common::ErrorCode;
use rustegon_doc::{Document, Value, json::parse_document};
use rustegon_engine::embedded::{EmbeddedDb, ID};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{Rng, SystemClock};

const ROOT: &str = "/store";
const SCHEMA: &str = r#"{"$jsonSchema":{"type":"object","required":["email"],
    "properties":{"email":{"type":"string","pattern":"^[^@]+@[^@]+$"},
                  "age":{"type":"int64","minimum":0}}}}"#;

/// Seeded `SplitMix64`.
#[derive(Debug)]
struct SeededRng(Mutex<u64>);

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let mut s = self.0.lock().unwrap();
        for chunk in buf.chunks_mut(8) {
            *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let v = (z ^ (z >> 31)).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn open(fs: &Arc<SimFileSystem>) -> EmbeddedDb {
    EmbeddedDb::open(
        fs.clone(),
        Path::new(ROOT),
        Arc::new(SystemClock::new()),
        Arc::new(SeededRng(Mutex::new(7))),
    )
    .unwrap()
}

/// A store with database `app` and collection `users` using [`SCHEMA`].
fn store(level: ValidationLevel, action: ValidationAction) -> (EmbeddedDb, Arc<SimFileSystem>) {
    let fs = Arc::new(SimFileSystem::new());
    let db = open(&fs);
    db.create_database("app", &DatabaseOptions::default())
        .unwrap();
    let mut spec = CollectionSpec::document("users");
    spec.options = CollectionOptions {
        validator: Some(SCHEMA.into()),
        validation_level: level,
        validation_action: action,
    };
    db.create_collection("app", &spec).unwrap();
    (db, fs)
}

fn doc(json: &str) -> Document {
    parse_document(json).unwrap()
}

#[test]
fn tc_sch_006_strict_error_rejects_invalid_inserts_and_replaces() {
    let (db, _fs) = store(ValidationLevel::Strict, ValidationAction::Error);
    let ok = db
        .insert("app", "users", &doc(r#"{"_id":1,"email":"a@b","age":3}"#))
        .unwrap();
    assert_eq!(ok.get(ID), Some(&Value::Int64(1)));
    // Missing `email`: RGN-1006 pointing at /email, keyword `required`; nothing is written.
    let err = db
        .insert("app", "users", &doc(r#"{"_id":2,"age":3}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    assert_eq!(
        err.details().get("path").map(String::as_str),
        Some("/email")
    );
    assert_eq!(
        err.details().get("keyword").map(String::as_str),
        Some("required")
    );
    assert!(db.get("app", "users", &Value::Int64(2)).unwrap().is_none());
    // Replace into an invalid document: rejected, the stored version is unchanged.
    let err = db
        .replace(
            "app",
            "users",
            &Value::Int64(1),
            &doc(r#"{"email":"a@b","age":-1}"#),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    assert_eq!(err.details().get("path").map(String::as_str), Some("/age"));
    assert_eq!(
        err.details().get("keyword").map(String::as_str),
        Some("minimum")
    );
    let current = db.get("app", "users", &Value::Int64(1)).unwrap().unwrap();
    assert_eq!(current.get("age"), Some(&Value::Int64(3)));
    // A valid replace goes through; system fields do not trip the validator.
    db.replace("app", "users", &Value::Int64(1), &doc(r#"{"email":"c@d"}"#))
        .unwrap();
}

#[test]
fn tc_sch_006_warn_accepts_and_counts() {
    let (db, _fs) = store(ValidationLevel::Strict, ValidationAction::Warn);
    db.insert("app", "users", &doc(r#"{"_id":1,"name":"no email"}"#))
        .unwrap();
    assert!(db.get("app", "users", &Value::Int64(1)).unwrap().is_some());
    assert_eq!(db.validation_warnings(), 1);
    db.insert("app", "users", &doc(r#"{"_id":2,"email":"a@b"}"#))
        .unwrap();
    assert_eq!(db.validation_warnings(), 1, "valid writes do not warn");
}

#[test]
fn tc_sch_006_moderate_validates_inserts_and_off_skips_validation() {
    let fs = Arc::new(SimFileSystem::new());
    let db = open(&fs);
    db.create_database("app", &DatabaseOptions::default())
        .unwrap();
    for (name, level) in [
        ("legacy_off", ValidationLevel::Off),
        ("users", ValidationLevel::Moderate),
    ] {
        let mut spec = CollectionSpec::document(name);
        spec.options.validator = Some(SCHEMA.into());
        spec.options.validation_level = level;
        db.create_collection("app", &spec).unwrap();
    }
    db.insert("app", "legacy_off", &doc(r#"{"_id":1,"name":"x"}"#))
        .unwrap();
    // Moderate: inserts are validated.
    assert_eq!(
        db.insert("app", "users", &doc(r#"{"_id":1,"name":"x"}"#))
            .unwrap_err()
            .code(),
        ErrorCode::SchemaValidationFailed
    );
    db.insert("app", "users", &doc(r#"{"_id":2,"email":"a@b"}"#))
        .unwrap();
    // A valid document cannot be updated into an invalid one.
    assert_eq!(
        db.replace("app", "users", &Value::Int64(2), &doc(r#"{"name":"y"}"#))
            .unwrap_err()
            .code(),
        ErrorCode::SchemaValidationFailed
    );
    // `off` stores anything: the document is invalid for the (unenforced) validator.
    db.replace(
        "app",
        "legacy_off",
        &Value::Int64(1),
        &doc(r#"{"name":"y"}"#),
    )
    .unwrap();
}

#[test]
fn tc_sch_006_moderate_exempts_documents_invalid_before_the_validator() {
    // A collection without validator holds a document that the later validator rejects
    // (feature-analysis F03: adding a validator to non-conforming data is allowed).
    let fs = Arc::new(SimFileSystem::new());
    let db = open(&fs);
    db.create_database("app", &DatabaseOptions::default())
        .unwrap();
    db.insert("app", "users", &doc(r#"{"_id":1,"name":"legacy"}"#))
        .unwrap();
    db.insert("app", "users", &doc(r#"{"_id":2,"email":"a@b"}"#))
        .unwrap();
    let moderate = CollectionOptions {
        validator: Some(SCHEMA.into()),
        validation_level: ValidationLevel::Moderate,
        validation_action: ValidationAction::Error,
    };
    let altered = db
        .set_collection_options("app", "users", &moderate)
        .unwrap();
    assert_eq!(altered.version, 2);
    // The legacy (invalid) document can still be updated, even into another invalid one.
    db.replace(
        "app",
        "users",
        &Value::Int64(1),
        &doc(r#"{"name":"still legacy"}"#),
    )
    .unwrap();
    // A valid document cannot become invalid, and inserts are validated.
    let err = db
        .replace("app", "users", &Value::Int64(2), &doc(r#"{"name":"y"}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    let err = db
        .insert("app", "users", &doc(r#"{"_id":3,"name":"z"}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    // Under `strict` the same legacy update is rejected.
    let strict = CollectionOptions {
        validation_level: ValidationLevel::Strict,
        ..moderate
    };
    db.set_collection_options("app", "users", &strict).unwrap();
    let err = db
        .replace(
            "app",
            "users",
            &Value::Int64(1),
            &doc(r#"{"name":"again"}"#),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    // An invalid validator is refused and the options stay as they were.
    let bad = CollectionOptions {
        validator: Some(r#"{"$jsonSchema":{"type":"date"}}"#.into()),
        ..CollectionOptions::default()
    };
    assert_eq!(
        db.set_collection_options("app", "users", &bad)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        db.insert("app", "users", &doc(r#"{"_id":4}"#))
            .unwrap_err()
            .code(),
        ErrorCode::SchemaValidationFailed
    );
}

#[test]
fn tc_sch_006_validator_survives_reopen_and_invalid_one_is_refused() {
    let (db, fs) = store(ValidationLevel::Strict, ValidationAction::Error);
    drop(db);
    let db = open(&fs);
    assert_eq!(
        db.insert("app", "users", &doc(r#"{"name":"x"}"#))
            .unwrap_err()
            .code(),
        ErrorCode::SchemaValidationFailed
    );
    let mut spec = CollectionSpec::document("bad");
    spec.options.validator = Some(r#"{"$jsonSchema":{"format":"email"}}"#.into());
    let err = db.create_collection("app", &spec).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    // Implicitly created collections have no validator.
    db.insert("app", "free", &doc(r#"{"anything":true}"#))
        .unwrap();
}
