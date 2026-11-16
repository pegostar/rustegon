// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Validators beyond the JSON-Schema-Test-Suite (FR-SCH-002/003, AC-SCH-002; data-model.md §5):
//! - TC-SCH-003: Rustegon type names and their mapping onto values beyond JSON;
//! - TC-SCH-004: violation reports (JSON pointer + keyword, bounds, `RGN-1006` details) and
//!   rejection of invalid validators;
//! - TC-SCH-005: `validationLevel` / `validationAction` semantics of `check_write`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::MemCatalog;
use rustegon_catalog::{
    CatalogError, CollectionDescriptor, CollectionOptions, CollectionSpec, DatabaseOptions,
    ValidationAction, ValidationLevel, Validator, ValidatorCache, WriteCheck, check_write,
    create_collection, create_database, drop_collection, get_collection, set_collection_options,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Decimal128, Document, ObjectId, Timestamp, Value,
    json::{parse_document, parse_value},
};

fn compile(schema: &str) -> Validator {
    Validator::compile(&format!("{{\"$jsonSchema\":{schema}}}"))
        .unwrap_or_else(|e| panic!("{schema}: {e}"))
}

fn valid(schema: &str, value: &Value) -> bool {
    compile(schema).is_valid(value)
}

fn doc(json: &str) -> Document {
    parse_document(json).unwrap()
}

// ---------------------------------------------------------------- TC-SCH-003: type names

#[test]
fn tc_sch_003_rustegon_type_names_match_their_values() {
    let cases: Vec<(&str, Value)> = vec![
        ("null", Value::Null),
        ("bool", Value::Bool(true)),
        ("boolean", Value::Bool(false)),
        ("int64", Value::Int64(7)),
        ("float64", Value::Float64(1.5)),
        (
            "decimal128",
            Value::Decimal(Decimal128::parse("12.50").unwrap()),
        ),
        ("string", Value::String("s".into())),
        (
            "binary",
            Value::Binary {
                subtype: 0,
                data: vec![1, 2],
            },
        ),
        ("datetime", Value::DateTime(1_700_000_000_000)),
        (
            "timestamp",
            Value::Timestamp(Timestamp {
                wall: 5,
                logical: 1,
            }),
        ),
        ("objectId", Value::ObjectId(ObjectId([7; 12]))),
        ("uuid", Value::Uuid([3; 16])),
        ("array", Value::Array(vec![])),
        ("object", Value::Object(Document::new())),
        ("vector_f32", Value::VectorF32(vec![0.5, 1.0])),
        ("minKey", Value::MinKey),
        ("maxKey", Value::MaxKey),
    ];
    for (name, value) in &cases {
        let schema = format!("{{\"type\":\"{name}\"}}");
        assert!(valid(&schema, value), "{name} must match its own type");
        // Exactly one tag matches, apart from the documented aliases and `number`.
        for (other, v) in &cases {
            let alias = matches!((*name, *other), ("bool", "boolean") | ("boolean", "bool"));
            if other != name && !alias {
                assert!(!valid(&schema, v), "{name} must not match a {other}");
            }
        }
    }
}

#[test]
fn tc_sch_003_json_schema_names_map_onto_rustegon_types() {
    let int = Value::Int64(1);
    let float = Value::Float64(1.0);
    let dec = Value::Decimal(Decimal128::parse("1").unwrap());
    // `number` = any numeric type.
    for v in [&int, &float, &dec] {
        assert!(valid(r#"{"type":"number"}"#, v));
    }
    // `integer` = int64 only (data-model.md §5), so a float with zero fraction is not one.
    assert!(valid(r#"{"type":"integer"}"#, &int));
    assert!(!valid(r#"{"type":"integer"}"#, &float));
    assert!(!valid(r#"{"type":"integer"}"#, &dec));
    // Non-JSON types are none of the JSON names.
    let dt = Value::DateTime(0);
    for t in [
        "string", "number", "integer", "object", "array", "null", "boolean",
    ] {
        assert!(!valid(&format!("{{\"type\":\"{t}\"}}"), &dt), "{t}");
    }
    // A vector is not an `array`, a uuid not a `binary`.
    assert!(!valid(r#"{"type":"array"}"#, &Value::VectorF32(vec![1.0])));
    assert!(!valid(r#"{"type":"binary"}"#, &Value::Uuid([0; 16])));
    // Type unions.
    assert!(valid(r#"{"type":["datetime","null"]}"#, &dt));
    assert!(valid(r#"{"type":["datetime","null"]}"#, &Value::Null));
}

#[test]
fn tc_sch_003_extended_json_literals_and_cross_type_numbers() {
    // `const` / `enum` literals use extended JSON, so non-JSON values can be constrained.
    let v = compile(r#"{"properties":{"at":{"const":{"$date":"2026-01-01T00:00:00.000Z"}}}}"#);
    let ok = parse_value(r#"{"at":{"$date":"2026-01-01T00:00:00.000Z"}}"#).unwrap();
    let bad = parse_value(r#"{"at":{"$date":"2026-01-02T00:00:00.000Z"}}"#).unwrap();
    assert!(v.is_valid(&ok));
    assert!(!v.is_valid(&bad));
    // Bounds compare numerically across int64 / float64 / decimal128.
    let v = compile(r#"{"minimum":{"$decimal":"0.5"},"exclusiveMaximum":10}"#);
    assert!(v.is_valid(&Value::Int64(1)));
    assert!(v.is_valid(&Value::Float64(0.5)));
    assert!(!v.is_valid(&Value::Decimal(Decimal128::parse("0.49").unwrap())));
    assert!(!v.is_valid(&Value::Float64(10.0)));
    // NaN satisfies no bound.
    assert!(!valid(r#"{"maximum":1}"#, &Value::Float64(f64::NAN)));
    assert!(!valid(r#"{"minimum":1}"#, &Value::Float64(f64::NAN)));
    // Bounds ignore non-numbers (JSON Schema): a datetime is not compared.
    assert!(valid(r#"{"minimum":1}"#, &Value::DateTime(-5)));
}

// ---------------------------------------------------------------- TC-SCH-004: reports

#[test]
fn tc_sch_004_violations_report_json_pointer_and_keyword() {
    let v = compile(
        r#"{"type":"object","required":["email","name"],
            "properties":{"email":{"type":"string","pattern":"^[^@]+@[^@]+$"},
                          "age":{"type":"int64","minimum":0},
                          "tags":{"items":{"maxLength":3}},
                          "a/b~c":{"type":"string"}}}"#,
    );
    let d = Value::Object(doc(
        r#"{"email":"nope","age":-1,"tags":["ok","toolong"],"a/b~c":5}"#,
    ));
    let r = v.validate(&d);
    let got: Vec<(&str, &str)> = r
        .errors
        .iter()
        .map(|e| (e.path.as_str(), e.keyword))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/name", "required"),
            ("/email", "pattern"),
            ("/age", "minimum"),
            ("/tags/1", "maxLength"),
            ("/a~1b~0c", "type"),
        ]
    );
    assert_eq!(r.total, 5);
    // Messages carry schema facts, never document values.
    for e in &r.errors {
        assert!(
            !e.message.contains("nope") && !e.message.contains("toolong"),
            "{e:?}"
        );
    }
    // Root-level violation: empty pointer.
    let r = compile(r#"{"type":"object"}"#).validate(&Value::Int64(1));
    assert_eq!(r.errors[0].path, "");
    assert_eq!(r.errors[0].keyword, "type");
}

#[test]
fn tc_sch_004_reports_are_bounded_but_count_everything() {
    let v = compile(r#"{"items":{"type":"string"}}"#);
    let arr = Value::Array((0..100).map(Value::Int64).collect());
    let r = v.validate(&arr);
    assert_eq!(
        r.errors.len(),
        rustegon_catalog::validator::MAX_REPORTED_ERRORS
    );
    assert_eq!(r.total, 100);
    assert_eq!(r.errors[0].path, "/0");
    let r = v.validate_with_limit(&arr, 2);
    assert_eq!((r.errors.len(), r.total), (2, 100));
}

#[test]
fn tc_sch_004_combinators_report_their_own_keyword() {
    let v = compile(r#"{"properties":{"x":{"anyOf":[{"type":"string"},{"minimum":5}]}}}"#);
    let r = v.validate(&Value::Object(doc(r#"{"x":1}"#)));
    assert_eq!(
        (r.errors[0].path.as_str(), r.errors[0].keyword),
        ("/x", "anyOf")
    );
    let v = compile(r#"{"oneOf":[{"type":"int64"},{"minimum":0}]}"#);
    assert_eq!(v.validate(&Value::Int64(3)).errors[0].keyword, "oneOf");
    let v = compile(r#"{"properties":{"x":false}}"#);
    let r = v.validate(&Value::Object(doc(r#"{"x":1}"#)));
    assert_eq!(
        (r.errors[0].path.as_str(), r.errors[0].keyword),
        ("/x", "false")
    );
}

#[test]
fn tc_sch_004_rejection_maps_to_rgn_1006_with_details() {
    let opts = options(ValidationLevel::Strict, ValidationAction::Error);
    let v = compile(r#"{"required":["email"],"properties":{"age":{"type":"int64"}}}"#);
    let failure = check_write(&opts, Some(&v), None, &doc(r#"{"age":"x"}"#)).unwrap_err();
    let err: Error = failure.into();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    assert_eq!(err.code().code(), 1006);
    let d = err.details();
    assert_eq!(d.get("path").map(String::as_str), Some("/email"));
    assert_eq!(d.get("keyword").map(String::as_str), Some("required"));
    assert!(d.contains_key("message"));
    assert_eq!(d.get("violations").map(String::as_str), Some("2"));
    let list: serde_json::Value = serde_json::from_str(&d["errors"]).unwrap();
    assert_eq!(list[1]["path"], "/age");
    assert_eq!(list[1]["keyword"], "type");
}

#[test]
fn tc_sch_004_invalid_validators_are_rejected_with_rgn_1001() {
    let bad = [
        "not json",
        r#"{"type":"object"}"#,                  // missing $jsonSchema wrapper
        r#"{"$jsonSchema":{},"other":1}"#,       // extra top-level key
        r#"{"$jsonSchema":5}"#,                  // not a schema
        r#"{"$jsonSchema":{"type":"date"}}"#,    // unknown type name
        r#"{"$jsonSchema":{"format":"email"}}"#, // unsupported keyword
        r#"{"$jsonSchema":{"pattern":"("}}"#,    // invalid regex
        r#"{"$jsonSchema":{"pattern":"(a)\\1"}}"#, // backreference: not linear time
        r#"{"$jsonSchema":{"minLength":-1}}"#,   // not a non-negative integer
        r#"{"$jsonSchema":{"required":["a","a"]}}"#, // duplicate names
        r#"{"$jsonSchema":{"anyOf":[]}}"#,       // empty combinator
        r#"{"$jsonSchema":{"enum":[{"$bad":1}]}}"#, // not a document literal
    ];
    for text in bad {
        let err = Validator::compile(text).unwrap_err();
        assert!(
            matches!(err, CatalogError::InvalidArgument(_)),
            "{text}: {err:?}"
        );
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{text}");
    }
    // Nesting is bounded.
    let deep = format!(
        "{{\"$jsonSchema\":{}true{}}}",
        "{\"not\":".repeat(40),
        "}".repeat(40)
    );
    assert!(Validator::compile(&deep).is_err());
    // Annotations are accepted.
    assert!(
        Validator::compile(
            r#"{"$jsonSchema":{"title":"t","description":"d","$comment":"c","default":1}}"#
        )
        .is_ok()
    );
}

#[test]
fn tc_sch_004_create_collection_rejects_an_invalid_validator() {
    let mut cat = MemCatalog::default();
    let db = create_database(&cat, "db", DatabaseOptions::default()).unwrap();
    cat.apply(&db.mutations);
    let mut spec = CollectionSpec::document("users");
    spec.options.validator = Some(r#"{"$jsonSchema":{"bogus":1}}"#.into());
    let err = create_collection(&cat, &db.descriptor, spec.clone()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    spec.options.validator = Some(r#"{"$jsonSchema":{"required":["email"]}}"#.into());
    let created = create_collection(&cat, &db.descriptor, spec).unwrap();
    assert!(created.descriptor.options.validator.is_some());
}

// ---------------------------------------------------------------- TC-SCH-005: levels

fn options(level: ValidationLevel, action: ValidationAction) -> CollectionOptions {
    CollectionOptions {
        validator: Some(r#"{"$jsonSchema":{"required":["email"]}}"#.into()),
        validation_level: level,
        validation_action: action,
    }
}

fn email_validator() -> Validator {
    compile(r#"{"required":["email"]}"#)
}

#[test]
fn tc_sch_005_strict_validates_inserts_and_every_update() {
    let v = email_validator();
    let opts = options(ValidationLevel::Strict, ValidationAction::Error);
    let good = doc(r#"{"email":"a@b"}"#);
    let bad = doc(r#"{"name":"x"}"#);
    assert_eq!(
        check_write(&opts, Some(&v), None, &good),
        Ok(WriteCheck::Valid)
    );
    assert!(check_write(&opts, Some(&v), None, &bad).is_err());
    // Even an update of an already-invalid document is rejected.
    assert!(check_write(&opts, Some(&v), Some(&bad), &bad).is_err());
    // Fixing an invalid document is always allowed.
    assert_eq!(
        check_write(&opts, Some(&v), Some(&bad), &good),
        Ok(WriteCheck::Valid)
    );
}

#[test]
fn tc_sch_005_moderate_exempts_updates_of_already_invalid_documents() {
    let v = email_validator();
    let opts = options(ValidationLevel::Moderate, ValidationAction::Error);
    let good = doc(r#"{"email":"a@b"}"#);
    let bad = doc(r#"{"name":"x"}"#);
    // Inserts are validated.
    assert!(check_write(&opts, Some(&v), None, &bad).is_err());
    // Update of an invalid document: not validated.
    assert_eq!(
        check_write(&opts, Some(&v), Some(&bad), &bad),
        Ok(WriteCheck::Exempt)
    );
    // Update of a valid document into an invalid one: rejected.
    assert!(check_write(&opts, Some(&v), Some(&good), &bad).is_err());
}

#[test]
fn tc_sch_005_warn_accepts_and_reports() {
    let v = email_validator();
    let opts = options(ValidationLevel::Strict, ValidationAction::Warn);
    let bad = doc(r#"{"name":"x"}"#);
    let Ok(WriteCheck::Warned(report)) = check_write(&opts, Some(&v), None, &bad) else {
        panic!("warn must accept the write");
    };
    assert_eq!(report.errors[0].keyword, "required");
    assert_eq!(report.errors[0].path, "/email");
}

#[test]
fn tc_sch_005_off_and_no_validator_skip_validation() {
    let v = email_validator();
    let bad = doc(r#"{"name":"x"}"#);
    let off = options(ValidationLevel::Off, ValidationAction::Error);
    assert_eq!(
        check_write(&off, Some(&v), None, &bad),
        Ok(WriteCheck::Unchecked)
    );
    let strict = options(ValidationLevel::Strict, ValidationAction::Error);
    assert_eq!(
        check_write(&strict, None, None, &bad),
        Ok(WriteCheck::Unchecked)
    );
}

#[test]
fn tc_sch_005_server_maintained_fields_are_invisible_to_validators() {
    let v = compile(r#"{"properties":{"email":{"type":"string"}},"additionalProperties":false}"#);
    let opts = options(ValidationLevel::Strict, ValidationAction::Error);
    let stored = doc(
        r#"{"email":"a@b","_rev":"r","_createdAt":{"$date":"2026-01-01T00:00:00.000Z"},
            "_updatedAt":{"$date":"2026-01-01T00:00:00.000Z"}}"#,
    );
    assert_eq!(
        check_write(&opts, Some(&v), None, &stored),
        Ok(WriteCheck::Valid)
    );
    // `_id` is user data and is validated.
    let with_id = doc(r#"{"_id":1,"email":"a@b"}"#);
    assert!(check_write(&opts, Some(&v), None, &with_id).is_err());
}

#[test]
fn tc_sch_005_cache_compiles_per_descriptor_version_and_counts_warnings() {
    let cache = ValidatorCache::new();
    let mut coll = CollectionDescriptor {
        id: 100,
        database_id: 1,
        name: "c".into(),
        kind: rustegon_catalog::CollectionKind::Document,
        version: 1,
        state: rustegon_catalog::DescriptorState::Public,
        shard_key: rustegon_catalog::ShardKey::default(),
        options: options(ValidationLevel::Strict, ValidationAction::Warn),
    };
    let a = cache.get(&coll).unwrap().unwrap();
    let b = cache.get(&coll).unwrap().unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&a, &b),
        "same version is compiled once"
    );
    let bad = doc(r#"{"name":"x"}"#);
    assert!(matches!(
        cache.check(&coll, None, &bad),
        Ok(WriteCheck::Warned(_))
    ));
    assert_eq!(cache.warnings(), 1);
    // A new version with action `error` rejects.
    coll.version = 2;
    coll.options.validation_action = ValidationAction::Error;
    let err = cache.check(&coll, None, &bad).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    // Level off: no compiled validator at all.
    coll.version = 3;
    coll.options.validation_level = ValidationLevel::Off;
    assert!(cache.get(&coll).unwrap().is_none());
}

#[test]
fn tc_sch_005_set_collection_options_bumps_version_and_checks_state() {
    let mut cat = MemCatalog::default();
    let db = create_database(&cat, "db", DatabaseOptions::default()).unwrap();
    cat.apply(&db.mutations);
    let coll = create_collection(&cat, &db.descriptor, CollectionSpec::document("c")).unwrap();
    cat.apply(&coll.mutations);
    let opts = options(ValidationLevel::Moderate, ValidationAction::Warn);
    let altered = set_collection_options(&cat, &coll.descriptor, opts.clone()).unwrap();
    cat.apply(&altered.mutations);
    assert_eq!(altered.descriptor.version, 2);
    let stored = get_collection(&cat, db.descriptor.id, "c")
        .unwrap()
        .unwrap();
    assert_eq!(stored.options, opts);
    // Invalid validator: refused.
    let bad = CollectionOptions {
        validator: Some("{}".into()),
        ..CollectionOptions::default()
    };
    assert_eq!(
        set_collection_options(&cat, &stored, bad)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
    // Dropped collection: not found.
    cat.apply(&drop_collection(&cat, &stored).unwrap());
    assert_eq!(
        set_collection_options(&cat, &stored, opts)
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
}
