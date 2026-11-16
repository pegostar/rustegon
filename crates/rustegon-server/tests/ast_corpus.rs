// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! FR-QL-002 over gRPC (PD-053): every statement of the RGQL grammar golden corpus
//! (`rustegon-query/tests/golden/grammar.rgql`) survives AST → `AstStatement` (protobuf
//! bytes) → AST unchanged, and its proto form maps onto exactly the JSON the AST serializes
//! to. This pins the descriptor-driven mapping of `grpc::ast` for every statement kind.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use prost::Message;
use rustegon_proto::v1::AstStatement;
use rustegon_query::parse_script;
use rustegon_server::grpc::ast::{statement_from_proto, statement_to_proto};

fn corpus() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rustegon-query/tests/golden/grammar.rgql");
    let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    // Case inputs are the lines between a `=== name` header and the first `--- section`.
    let mut inputs = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("=== ") {
            if let Some(input) = current.take() {
                inputs.push(input);
            }
            current = Some(String::new());
        } else if line.starts_with("--- ") {
            if let Some(input) = current.take() {
                inputs.push(input);
            }
        } else if let Some(input) = current.as_mut() {
            input.push_str(line);
            input.push('\n');
        }
    }
    if let Some(input) = current {
        inputs.push(input);
    }
    inputs
}

#[test]
fn fr_ql_002_grammar_corpus_round_trips_through_ast_proto() {
    let mut statements = 0;
    for input in corpus() {
        // Error cases of the corpus are not statements; only parseable inputs are mapped.
        let Ok(stmts) = parse_script(&input) else {
            continue;
        };
        for stmt in stmts {
            let proto = statement_to_proto(&stmt)
                .unwrap_or_else(|e| panic!("to proto failed for `{input}`: {e:?}"));
            let bytes = proto.encode_to_vec();
            let decoded = AstStatement::decode(bytes.as_slice()).unwrap();
            let back = statement_from_proto(&decoded)
                .unwrap_or_else(|e| panic!("from proto failed for `{input}`: {e:?}"));
            assert_eq!(back, stmt, "round trip of `{input}`");
            statements += 1;
        }
    }
    assert!(
        statements > 100,
        "only {statements} statements in the corpus"
    );
}

/// Every `[db.]collection` name in the JSON form of `v` (a `QualifiedName`: an object with a
/// string `name`, an optional `database` and nothing else but, as a `FROM` source, `kind:
/// "collection"`), plus the collection argument of `load(id, 'db.coll')`.
fn named_collections(v: &serde_json::Value, session: &str, out: &mut Vec<(String, String)>) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let qualified = map.get("name").is_some_and(Value::is_string)
                && map.get("database").is_none_or(Value::is_string)
                && map.get("kind").is_none_or(|k| k == "collection")
                && map
                    .keys()
                    .all(|k| matches!(k.as_str(), "name" | "database" | "kind"));
            if qualified {
                let db = map
                    .get("database")
                    .and_then(Value::as_str)
                    .unwrap_or(session);
                let name = map["name"].as_str().unwrap();
                out.push((db.to_owned(), name.to_owned()));
            }
            if map.get("kind").is_some_and(|k| k == "call")
                && map["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case("load"))
                && let Some(target) = map["args"]
                    .get(1)
                    .filter(|a| a["kind"] == "literal" && a.get("type").is_none())
                    .and_then(|a| a["value"].as_str())
            {
                out.push(match target.split_once('.') {
                    Some((db, coll)) => (db.to_owned(), coll.to_owned()),
                    None => (session.to_owned(), target.to_owned()),
                });
            }
            for child in map.values() {
                named_collections(child, session, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                named_collections(item, session, out);
            }
        }
        _ => {}
    }
}

/// TC-SEC-001 / PD-056: for every statement of the grammar corpus, `statement_privileges`
/// returns without panicking and checks a privilege on **every** collection the statement
/// names anywhere — found independently of the walk, in the statement's JSON form — and
/// `find` on `cluster` when it has an `INCLUDE`.
#[test]
fn tc_sec_001_corpus_statements_check_every_named_collection() {
    use rustegon_security::rbac::{Action, Resource};
    use rustegon_server::services::privileges::statement_privileges;

    let mut statements = 0;
    let mut references = 0;
    for input in corpus() {
        let Ok(stmts) = parse_script(&input) else {
            continue;
        };
        for stmt in stmts {
            let checks = statement_privileges(&stmt, "session");
            let json = serde_json::to_value(&stmt).unwrap();
            let mut named = Vec::new();
            named_collections(&json, "session", &mut named);
            for (db, coll) in named {
                let resource = Resource::collection(db, coll);
                assert!(
                    checks.iter().any(|(r, _)| *r == resource),
                    "`{input}` names {resource} but checks only {checks:?}"
                );
                references += 1;
            }
            if json.to_string().contains("\"include\":") {
                assert!(
                    checks.contains(&(Resource::Cluster, Action::Find)),
                    "`{input}`: INCLUDE must need find on cluster, got {checks:?}"
                );
            }
            statements += 1;
        }
    }
    assert!(statements > 100, "only {statements} statements");
    assert!(references > 100, "only {references} collection references");
}
