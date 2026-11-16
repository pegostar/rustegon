// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Static checks of the cross-driver conformance suite `drivers/conformance/` (FR-DRV-003,
//! AC-DRV-003), so the suite cannot rot before (and between) runs of the driver runners:
//! - every test file validates against `schema/test.schema.json` (a small JSON Schema
//!   validator for the keywords the schema uses; `pattern` rules are checked by hand below);
//! - test ids are unique and named `TC-DRV-CONF-<CATEGORY>-NNN` after their directory;
//! - `covers` names operations of `model.yaml` with status `r1`, and every `r1` operation is
//!   covered at least once (the AC-DRV-003 coverage figure);
//! - operation names are known for the object they are called on, saved names are defined
//!   before use, data files referenced by runner operations exist;
//! - `model.yaml`, `connstring.yaml` and `retry.yaml` are well formed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod drivers_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use drivers_support::{conformance_dir, load_yaml};
use serde_json::Value as Json;

/// Test directories (= categories) of the suite.
const CATEGORIES: &[&str] = &[
    "crud", "query", "cursor", "bulk", "txn", "errors", "schema", "auth", "client",
];

/// Operations a runner implements itself (README.md, "Runner operations").
const RUNNER_OPS: &[&str] = &[
    "sleep",
    "throwApplicationError",
    "assertLastErrorHasTraceId",
    "checkErrorMapping",
    "checkValueVectors",
    "checkDocumentVectors",
    "checkInvalidVectors",
    "checkAstVectors",
    "checkConnectionStrings",
    "runRetryScenarios",
    "checkScramVectors",
];

const CLIENT_OPS: &[&str] = &[
    "open",
    "openFromConnectionString",
    "getServerInfo",
    "listDatabaseNames",
    "createDatabase",
    "dropDatabase",
    "startSession",
    "beginTransaction",
    "withTransaction",
    "manualTransaction",
    "changePassword",
    "close",
];
const DATABASE_OPS: &[&str] = &[
    "query",
    "createCollection",
    "dropCollection",
    "listCollectionNames",
];
const COLLECTION_OPS: &[&str] = &[
    "insertOne",
    "insertMany",
    "findById",
    "find",
    "updateOne",
    "updateMany",
    "replaceOne",
    "deleteOne",
    "deleteMany",
    "bulkWrite",
    "createIndex",
    "dropIndex",
    "listIndexes",
];
const TRANSACTION_OPS: &[&str] = &["query", "commit", "rollback", "close", "resolve"];
const CURSOR_OPS: &[&str] = &["next", "close"];
const SESSION_OPS: &[&str] = &["close", "causalityToken"];

// ---------------------------------------------------------------------------------------------
// A small JSON Schema (2020-12 subset) validator
// ---------------------------------------------------------------------------------------------

/// Keywords that only document the schema (or are checked by hand: `pattern`).
const IGNORED_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "$defs",
    "title",
    "description",
    "pattern",
    "$comment",
];

fn type_matches(t: &str, v: &Json) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "integer" => v.is_i64() || v.is_u64(),
        "number" => v.is_number(),
        other => panic!("schema: unknown type `{other}`"),
    }
}

fn resolve<'a>(root: &'a Json, reference: &str) -> &'a Json {
    let pointer = reference
        .strip_prefix('#')
        .unwrap_or_else(|| panic!("schema: only local references are supported: {reference}"));
    root.pointer(pointer)
        .unwrap_or_else(|| panic!("schema: unresolved reference {reference}"))
}

/// Validates `v` against `schema`; pushes `<json path>: <problem>` lines into `errors`.
fn validate(root: &Json, schema: &Json, v: &Json, at: &str, errors: &mut Vec<String>) {
    let Some(s) = schema.as_object() else {
        assert!(
            schema == &Json::Bool(true),
            "schema at {at}: unsupported boolean schema"
        );
        return;
    };
    for (k, kv) in s {
        match k.as_str() {
            k if IGNORED_KEYWORDS.contains(&k) => {}
            "$ref" => validate(root, resolve(root, kv.as_str().unwrap()), v, at, errors),
            "type" => {
                let ok = match kv {
                    Json::String(t) => type_matches(t, v),
                    Json::Array(ts) => ts.iter().any(|t| type_matches(t.as_str().unwrap(), v)),
                    _ => panic!("schema: bad `type`"),
                };
                if !ok {
                    errors.push(format!("{at}: expected type {kv}, found {v}"));
                }
            }
            "enum" => {
                if !kv.as_array().unwrap().contains(v) {
                    errors.push(format!("{at}: {v} is not one of {kv}"));
                }
            }
            "const" => {
                if kv != v {
                    errors.push(format!("{at}: expected {kv}"));
                }
            }
            "minLength" => {
                if let Some(text) = v.as_str()
                    && (text.chars().count() as u64) < kv.as_u64().unwrap()
                {
                    errors.push(format!("{at}: string shorter than {kv}"));
                }
            }
            "minItems" => {
                if let Some(items) = v.as_array()
                    && (items.len() as u64) < kv.as_u64().unwrap()
                {
                    errors.push(format!("{at}: fewer than {kv} items"));
                }
            }
            "items" => {
                if let Some(items) = v.as_array() {
                    for (i, item) in items.iter().enumerate() {
                        validate(root, kv, item, &format!("{at}[{i}]"), errors);
                    }
                }
            }
            "required" => {
                if let Some(obj) = v.as_object() {
                    for name in kv.as_array().unwrap() {
                        if !obj.contains_key(name.as_str().unwrap()) {
                            errors.push(format!(
                                "{at}: missing required `{}`",
                                name.as_str().unwrap()
                            ));
                        }
                    }
                }
            }
            "properties" => {
                if let Some(obj) = v.as_object() {
                    for (name, sub) in kv.as_object().unwrap() {
                        if let Some(x) = obj.get(name) {
                            validate(root, sub, x, &format!("{at}.{name}"), errors);
                        }
                    }
                }
            }
            "additionalProperties" => {
                if let Some(obj) = v.as_object() {
                    let declared = s.get("properties").and_then(Json::as_object);
                    for (name, x) in obj {
                        if declared.is_some_and(|d| d.contains_key(name)) {
                            continue;
                        }
                        match kv {
                            Json::Bool(false) => {
                                errors.push(format!("{at}: unexpected member `{name}`"));
                            }
                            Json::Bool(true) => {}
                            sub => validate(root, sub, x, &format!("{at}.{name}"), errors),
                        }
                    }
                }
            }
            "oneOf" | "anyOf" => {
                let passing = kv
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|sub| {
                        let mut e = Vec::new();
                        validate(root, sub, v, at, &mut e);
                        e.is_empty()
                    })
                    .count();
                let ok = if k == "oneOf" {
                    passing == 1
                } else {
                    passing >= 1
                };
                if !ok {
                    errors.push(format!("{at}: {k} matched {passing} alternatives"));
                }
            }
            other => panic!("schema: keyword `{other}` is not supported by this validator"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------------

struct Model {
    /// id → status.
    status: BTreeMap<String, String>,
}

fn is_op_id(id: &str) -> bool {
    let Some((a, b)) = id.split_once('.') else {
        return false;
    };
    [a, b].iter().all(|p| {
        p.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && p.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

fn is_valid_status(s: &str) -> bool {
    s == "r1"
        || s.strip_prefix("deferred(M")
            .and_then(|r| r.strip_suffix(')'))
            .is_some_and(|m| {
                !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
}

fn load_model() -> Model {
    let doc = load_yaml(&conformance_dir().join("model.yaml"));
    assert_eq!(doc["version"], 1, "model.yaml: version");
    let mut status = BTreeMap::new();
    for op in doc["operations"]
        .as_array()
        .expect("model.yaml: operations")
    {
        let id = op["id"].as_str().expect("model.yaml: id");
        assert!(is_op_id(id), "model.yaml: id `{id}`");
        let s = op["status"]
            .as_str()
            .unwrap_or_else(|| panic!("model.yaml: {id}: status"));
        assert!(is_valid_status(s), "model.yaml: {id}: status `{s}`");
        let kind = op["kind"]
            .as_str()
            .unwrap_or_else(|| panic!("model.yaml: {id}: kind"));
        assert!(
            ["operation", "builder", "codec", "behavior"].contains(&kind),
            "model.yaml: {id}: kind `{kind}`"
        );
        for lang in ["dotnet", "java"] {
            assert!(
                op[lang].as_str().is_some_and(|x| !x.is_empty()),
                "model.yaml: {id}: `{lang}` member"
            );
        }
        if let Some(rpcs) = op.get("rpc") {
            for r in rpcs.as_array().unwrap() {
                let r = r.as_str().unwrap();
                assert!(
                    r.split_once('.')
                        .is_some_and(|(svc, m)| svc.ends_with("Service") && !m.is_empty()),
                    "model.yaml: {id}: rpc `{r}`"
                );
            }
        }
        assert!(
            status.insert(id.to_owned(), s.to_owned()).is_none(),
            "model.yaml: duplicate `{id}`"
        );
    }
    Model { status }
}

// ---------------------------------------------------------------------------------------------
// Test files
// ---------------------------------------------------------------------------------------------

/// What an object name refers to inside one test.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Entity {
    Client,
    Database,
    Collection,
    Runner,
    Session,
    Transaction,
    Cursor,
    Unknown,
}

fn ops_of(e: Entity) -> Vec<&'static str> {
    match e {
        Entity::Client => [CLIENT_OPS, COLLECTION_OPS].concat(),
        Entity::Database => DATABASE_OPS.to_vec(),
        Entity::Collection => COLLECTION_OPS.to_vec(),
        Entity::Runner => RUNNER_OPS.to_vec(),
        Entity::Session => SESSION_OPS.to_vec(),
        Entity::Transaction => [TRANSACTION_OPS, COLLECTION_OPS].concat(),
        Entity::Cursor => CURSOR_OPS.to_vec(),
        Entity::Unknown => Vec::new(),
    }
}

/// The entity an operation saves with `saveAs`.
fn saved_entity(on: Entity, op: &Json) -> Entity {
    match (on, op["name"].as_str().unwrap()) {
        (Entity::Client, "open" | "openFromConnectionString") => Entity::Client,
        (Entity::Client, "startSession") => Entity::Session,
        (Entity::Client, "beginTransaction") => Entity::Transaction,
        (Entity::Collection | Entity::Transaction | Entity::Client, "find")
            if op["then"] == "cursor" =>
        {
            Entity::Cursor
        }
        _ => Entity::Unknown,
    }
}

/// Every `$$ref:<name>[.path]` string in `v`.
fn refs(v: &Json, out: &mut Vec<String>) {
    match v {
        Json::String(s) => {
            if let Some(r) = s.strip_prefix("$$ref:") {
                out.push(r.split('.').next().unwrap().to_owned());
            }
        }
        Json::Array(items) => items.iter().for_each(|i| refs(i, out)),
        Json::Object(m) => m.values().for_each(|i| refs(i, out)),
        _ => {}
    }
}

/// Checks a list of operations (a test body, a callback or manual-transaction steps).
fn check_ops(
    ops: &[Json],
    scope: &mut BTreeMap<String, Entity>,
    ctx: &str,
    problems: &mut Vec<String>,
) {
    for (i, op) in ops.iter().enumerate() {
        let at = format!("{ctx} operation {i}");
        let object = op["object"].as_str().unwrap_or_default();
        let name = op["name"].as_str().unwrap_or_default();
        let entity = match object {
            "client" => Entity::Client,
            "database" => Entity::Database,
            "collection" => Entity::Collection,
            "runner" => Entity::Runner,
            other => *scope.get(other).unwrap_or_else(|| {
                problems.push(format!(
                    "{at}: unknown object `{other}` (not saved earlier)"
                ));
                &Entity::Unknown
            }),
        };
        if entity != Entity::Unknown && !ops_of(entity).contains(&name) {
            problems.push(format!(
                "{at}: `{object}` ({entity:?}) has no operation `{name}`"
            ));
        }
        if let Some(session) = op.get("session").and_then(Json::as_str)
            && scope.get(session) != Some(&Entity::Session)
        {
            problems.push(format!("{at}: `session: {session}` is not a saved session"));
        }
        let mut used = Vec::new();
        refs(&op["args"], &mut used);
        for r in used {
            if !scope.contains_key(&r) {
                problems.push(format!("{at}: $$ref to `{r}` before it is saved"));
            }
        }
        if entity == Entity::Runner
            && let Some(file) = op["args"].get("file").and_then(Json::as_str)
            && !conformance_dir().join(file).is_file()
        {
            problems.push(format!("{at}: runner data file `{file}` does not exist"));
        }
        // Nested operation lists run with `transaction` bound.
        for key in ["callback", "steps"] {
            if let Some(inner) = op["args"].get(key).and_then(Json::as_array) {
                let mut inner_scope = scope.clone();
                inner_scope.insert("transaction".into(), Entity::Transaction);
                check_ops(inner, &mut inner_scope, &format!("{at}.{key}"), problems);
            }
        }
        if let Some(saved) = op.get("saveAs").and_then(Json::as_str) {
            scope.insert(saved.to_owned(), saved_entity(entity, op));
        }
    }
}

/// Every YAML test file: `(category, path)`.
fn test_files() -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    for cat in CATEGORIES {
        let dir = conformance_dir().join(cat);
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no test files in {cat}/");
        out.extend(files.into_iter().map(|p| ((*cat).to_owned(), p)));
    }
    out
}

fn rel(p: &Path) -> String {
    p.strip_prefix(conformance_dir())
        .unwrap_or(p)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// AC-DRV-003 / FR-DRV-003: every test file is valid, and the suite covers every `r1`
/// operation of the Driver Conceptual Model.
#[test]
fn tc_drv_conf_suite_files_are_valid_and_cover_every_r1_operation() {
    let schema: Json = serde_json::from_str(
        &std::fs::read_to_string(conformance_dir().join("schema/test.schema.json")).unwrap(),
    )
    .expect("schema/test.schema.json is JSON");
    let model = load_model();
    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    let mut covered: BTreeMap<String, usize> = BTreeMap::new();
    let mut tests = 0usize;
    for (cat, path) in test_files() {
        let file = rel(&path);
        let doc = load_yaml(&path);
        let mut errors = Vec::new();
        validate(&schema, &schema, &doc, &file, &mut errors);
        problems.extend(errors);
        let prefix = format!("TC-DRV-CONF-{}-", cat.to_uppercase());
        for t in doc["tests"].as_array().into_iter().flatten() {
            tests += 1;
            let id = t["id"].as_str().unwrap_or_default();
            let number = id.strip_prefix(&prefix);
            if !number.is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit())) {
                problems.push(format!("{file}: test id `{id}` must be {prefix}NNN"));
            }
            if !ids.insert(id.to_owned()) {
                problems.push(format!("{file}: duplicate test id `{id}`"));
            }
            for c in t["covers"].as_array().into_iter().flatten() {
                let c = c.as_str().unwrap_or_default();
                match model.status.get(c).map(String::as_str) {
                    Some("r1") => *covered.entry(c.to_owned()).or_default() += 1,
                    Some(s) => problems.push(format!(
                        "{file} {id}: covers `{c}` with status {s} (not r1)"
                    )),
                    None => problems.push(format!("{file} {id}: covers unknown operation `{c}`")),
                }
            }
            let mut scope = BTreeMap::new();
            check_ops(
                t["operations"].as_array().map_or(&[][..], Vec::as_slice),
                &mut scope,
                &format!("{file} {id}"),
                &mut problems,
            );
        }
    }
    let r1: Vec<&String> = model
        .status
        .iter()
        .filter(|(_, s)| *s == "r1")
        .map(|(id, _)| id)
        .collect();
    let uncovered: Vec<&&String> = r1
        .iter()
        .filter(|id| !covered.contains_key(id.as_str()))
        .collect();
    for id in &uncovered {
        problems.push(format!(
            "model.yaml: r1 operation `{id}` is not covered by any test"
        ));
    }
    assert!(
        problems.is_empty(),
        "conformance suite problems:\n{}",
        problems.join("\n")
    );
    let deferred = model.status.len() - r1.len();
    // Reported in the test output (nextest --no-capture) and quoted by README.md.
    println!(
        "conformance suite: {tests} tests, {} r1 operations covered ({} deferred), coverage 100 %",
        r1.len(),
        deferred
    );
}

/// `connstring.yaml` and `retry.yaml` are well formed and only use known settings,
/// operations and classes.
#[test]
fn tc_drv_conf_data_files_are_well_formed() {
    let model = load_model();
    let classes: BTreeSet<String> =
        load_yaml(&conformance_dir().join("errors-map.yaml"))["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect();

    let cs = load_yaml(&conformance_dir().join("connstring.yaml"));
    let defaults = cs["defaults"]
        .as_object()
        .expect("connstring.yaml: defaults");
    let mut names = BTreeSet::new();
    let (mut valid, mut invalid) = (0, 0);
    for c in cs["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert!(
            names.insert(name),
            "connstring.yaml: duplicate case `{name}`"
        );
        let uri = c["uri"]
            .as_str()
            .unwrap_or_else(|| panic!("connstring.yaml: {name}: uri"));
        assert!(!uri.is_empty(), "connstring.yaml: {name}: empty uri");
        match c["valid"].as_bool() {
            Some(true) => {
                valid += 1;
                for k in c["expect"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{name}: expect"))
                    .keys()
                {
                    assert!(
                        defaults.contains_key(k),
                        "connstring.yaml: {name}: unknown setting `{k}`"
                    );
                }
            }
            Some(false) => {
                invalid += 1;
                assert!(
                    c.get("expect").is_none(),
                    "connstring.yaml: {name}: invalid case with expect"
                );
            }
            None => panic!("connstring.yaml: {name}: `valid` must be a boolean"),
        }
    }
    assert!(
        valid >= 10 && invalid >= 10,
        "connstring.yaml: too few cases"
    );

    let retry = load_yaml(&conformance_dir().join("retry.yaml"));
    let setting_keys: BTreeSet<&str> = retry["defaults"]["settings"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut names = BTreeSet::new();
    for s in retry["scenarios"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        assert!(
            names.insert(name),
            "retry.yaml: duplicate scenario `{name}`"
        );
        for c in s["covers"]
            .as_array()
            .unwrap_or_else(|| panic!("retry.yaml: {name}: covers"))
        {
            let c = c.as_str().unwrap();
            assert_eq!(
                model.status.get(c).map(String::as_str),
                Some("r1"),
                "retry.yaml: {name}: covers `{c}`"
            );
        }
        if let Some(settings) = s.get("settings").and_then(Json::as_object) {
            for k in settings.keys() {
                assert!(
                    setting_keys.contains(k.as_str()),
                    "retry.yaml: {name}: setting `{k}`"
                );
            }
        }
        for (rpc, replies) in s
            .get("server")
            .and_then(Json::as_object)
            .into_iter()
            .flatten()
        {
            assert!(rpc.contains("Service."), "retry.yaml: {name}: rpc `{rpc}`");
            for r in replies.as_array().unwrap() {
                let kinds = ["ok", "error", "transport"]
                    .iter()
                    .filter(|k| r.get(**k).is_some())
                    .count();
                assert_eq!(
                    kinds, 1,
                    "retry.yaml: {name}: {rpc}: reply needs exactly one of ok/error/transport"
                );
            }
        }
        let outcome = &s["expect"]["outcome"];
        assert!(
            outcome.get("result").is_some() ^ outcome.get("error").is_some(),
            "retry.yaml: {name}: outcome is result or error"
        );
        if let Some(class) = outcome["error"].get("exception").and_then(Json::as_str) {
            assert!(
                classes.contains(class),
                "retry.yaml: {name}: exception `{class}`"
            );
        }
        assert!(
            s["expect"]["calls"].is_object(),
            "retry.yaml: {name}: expect.calls"
        );
    }

    // mapping/vectors.yaml: known models, unique names, JSON texts that parse.
    let mapping = load_yaml(&conformance_dir().join("mapping/vectors.yaml"));
    let models: BTreeSet<&str> = mapping["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    let mut names = BTreeSet::new();
    for (section, texts) in [
        ("roundTrip", &["json"][..]),
        ("build", &["json", "value"][..]),
        ("invalid", &["input"][..]),
    ] {
        for v in mapping[section].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            assert!(
                names.insert(name),
                "mapping/vectors.yaml: duplicate `{name}`"
            );
            let model = v["model"].as_str().unwrap_or_default();
            assert!(
                models.contains(model),
                "mapping/vectors.yaml: {name}: model `{model}`"
            );
            for key in texts {
                assert!(v[key].is_string(), "mapping/vectors.yaml: {name}: `{key}`");
            }
            for key in ["json", "input"] {
                if let Some(text) = v[key].as_str() {
                    serde_json::from_str::<Json>(text)
                        .unwrap_or_else(|e| panic!("mapping/vectors.yaml: {name}: {key}: {e}"));
                }
            }
        }
    }
}

/// The JSON Schema validator itself rejects what it should (so a pass above means something).
#[test]
fn tc_drv_conf_schema_validator_rejects_invalid_files() {
    let schema: Json = serde_json::from_str(
        &std::fs::read_to_string(conformance_dir().join("schema/test.schema.json")).unwrap(),
    )
    .unwrap();
    let check = |yaml: &str| {
        let doc = drivers_support::yaml_to_json(yaml, "inline");
        let mut e = Vec::new();
        validate(&schema, &schema, &doc, "inline", &mut e);
        e
    };
    let ok = "description: x\ntests:\n  - {id: TC-DRV-CONF-CRUD-999, description: d, covers: [Collection.InsertOne], operations: [{object: collection, name: insertOne}]}\n";
    assert!(check(ok).is_empty(), "{:?}", check(ok));
    for bad in [
        "tests: []\n",
        "description: x\ntests: []\n",
        "description: x\nextra: 1\ntests:\n  - {id: a, description: d, covers: [A.B], operations: [{object: c, name: n}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [], operations: [{object: c, name: n}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [A.B], operations: [{object: c}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [A.B], operations: [{object: c, name: n, expect: {}}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [A.B], operations: [{object: c, name: n, expect: {result: 1, error: {code: 1}}}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [A.B], operations: [{object: c, name: n, expect: {error: {exception: Nope}}}]}\n",
        "description: x\ntests:\n  - {id: a, description: d, covers: [A.B], requires: [magic], operations: [{object: c, name: n}]}\n",
    ] {
        assert!(!check(bad).is_empty(), "accepted: {bad}");
    }
}
