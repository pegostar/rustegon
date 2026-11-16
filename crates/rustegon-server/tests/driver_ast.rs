// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Golden builder → AST vectors for the drivers (FR-DRV-003, FR-QL-002, PD-070).
//!
//! The driver filter/update/sort/projection builders produce the structured AST of
//! `proto/rustegon/v1/query_ast.proto`, never RGQL text (PD-070). This test pins what they
//! must produce: every case is written in the language-neutral builder DSL of
//! `drivers/conformance/README.md` ("Builder DSL"), translated here to RGQL text, parsed by the
//! server's parser and mapped to `AstStatement` exactly as `QueryService.Execute` receives it.
//! The files carry the DSL, the parameters (canonical extended JSON + value-encoding hex), the
//! RGQL text and the canonical protobuf JSON (lowerCamelCase names, enum names, 64-bit
//! integers as strings, default values omitted) of the AST:
//! - `drivers/conformance/ast/filters.json`: `Filter.*` → `AstStatement` of
//!   ``FROM `c` WHERE <filter>`` and its `where` expression;
//! - `drivers/conformance/ast/updates.json`: `Update.*` → `repeated AstUpdateOp`
//!   (`DocumentService.Update.operations`);
//! - `drivers/conformance/ast/statements.json`: find/update/replace/delete with filters,
//!   sort, limit, skip and projection → `AstStatement` (`QueryService.Execute.ast`).
//!
//! Every AST is also decoded back by `grpc::ast::statement_from_proto` — the server's
//! validated, canonical-form decoder — so a vector is something the server accepts.
//! It lives in `rustegon-server` (not `rustegon-query`) because the proto mapping does.
//! A stale file fails the test; re-bless with
//! `RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-server --test driver_ast`.

// Test code: short names (`f`, `p`, `a`) mirror the DSL; statements are built by appending.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::format_push_string
)]

use std::path::{Path, PathBuf};

use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use rustegon_doc::{
    json::{JsonMode, parse_value, value_to_json},
    rdoc::encode_value,
};
use rustegon_query::parse_statement;
use rustegon_server::grpc::ast::{statement_from_proto, statement_to_proto, update_ops_from_proto};
use serde_json::{Map, Value as Json, json};

const BLESS_ENV: &str = "RGN_FIXTURES_BLESS";
const BLESS_COMMAND: &str = "cargo nextest run -p rustegon-server --test driver_ast";
const COLLECTION: &str = "c";

fn out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../drivers/conformance/ast")
}

fn check_or_bless(name: &str, content: &str) {
    let path = out_dir().join(name);
    if std::env::var(BLESS_ENV).is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(out_dir()).unwrap();
        std::fs::write(&path, content).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e} (generate with {BLESS_ENV}=1 {BLESS_COMMAND})",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert!(
        committed == content,
        "{} is stale; re-bless with {BLESS_ENV}=1 {BLESS_COMMAND} and review the diff",
        path.display()
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---------------------------------------------------------------------------------------------
// Builder DSL → RGQL
// ---------------------------------------------------------------------------------------------

/// Collects the parameters of one builder (`f` filter, `u` update) in occurrence order.
struct Params {
    prefix: char,
    values: Vec<(String, Json)>,
}

impl Params {
    fn new(prefix: char) -> Self {
        Self {
            prefix,
            values: Vec::new(),
        }
    }

    fn bind(&mut self, v: &Json) -> String {
        let name = format!("{}{}", self.prefix, self.values.len());
        self.values.push((name.clone(), v.clone()));
        format!("${name}")
    }

    /// `{name: {ext_json, hex}}`, checked through the real codec.
    fn to_json(&self) -> Json {
        let mut out = Map::new();
        for (name, v) in &self.values {
            let value =
                parse_value(&v.to_string()).unwrap_or_else(|e| panic!("param {name} = {v}: {e}"));
            out.insert(
                name.clone(),
                json!({
                    "ext_json": value_to_json(&value, JsonMode::Canonical),
                    "hex": hex(&encode_value(&value).unwrap()),
                }),
            );
        }
        Json::Object(out)
    }
}

/// A DSL path (`"a.b.0"`) as RGQL: every field back-quoted (reserved words are fine as field
/// names then), all-digit segments as positions.
fn path(p: &Json) -> String {
    let text = p
        .as_str()
        .unwrap_or_else(|| panic!("path must be a string: {p}"));
    text.split('.')
        .enumerate()
        .map(|(i, seg)| {
            if i > 0 && !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                seg.to_owned()
            } else {
                assert!(!seg.contains('`'), "backtick in a test path");
                format!("`{seg}`")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn single(f: &Json) -> (&str, &Json) {
    let map = f
        .as_object()
        .unwrap_or_else(|| panic!("DSL node must be an object: {f}"));
    assert_eq!(map.len(), 1, "DSL node must have one key: {f}");
    let (k, v) = map.iter().next().unwrap();
    (k.as_str(), v)
}

fn pair(v: &Json) -> (&Json, &Json) {
    let a = v
        .as_array()
        .unwrap_or_else(|| panic!("expected [a, b]: {v}"));
    assert_eq!(a.len(), 2, "expected [a, b]: {v}");
    (&a[0], &a[1])
}

/// Flattens nested `and`/`or` of the same kind: the parser builds n-ary nodes, and a
/// structured AST is accepted only in canonical form (`query_ast.proto` header), so builders
/// must flatten too.
fn flattened<'a>(kind: &str, args: &'a [Json], out: &mut Vec<&'a Json>) {
    for a in args {
        match a
            .as_object()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.get(kind))
        {
            Some(Json::Array(inner)) => flattened(kind, inner, out),
            _ => out.push(a),
        }
    }
}

fn is_compound(f: &Json) -> bool {
    matches!(single(f).0, "and" | "or" | "not" | "elemMatch")
}

fn filter(f: &Json, p: &mut Params) -> String {
    let (op, a) = single(f);
    let cmp = |sym: &str, p: &mut Params| {
        let (l, r) = pair(a);
        format!("{} {sym} {}", path(l), p.bind(r))
    };
    match op {
        "eq" => cmp("=", p),
        "ne" => cmp("!=", p),
        "gt" => cmp(">", p),
        "gte" => cmp(">=", p),
        "lt" => cmp("<", p),
        "lte" => cmp("<=", p),
        "in" => cmp("IN", p),
        "nin" => cmp("NOT IN", p),
        "contains" => cmp("CONTAINS", p),
        "containsAny" => cmp("CONTAINS ANY", p),
        "containsAll" => cmp("CONTAINS ALL", p),
        "like" => cmp("LIKE", p),
        "regex" => cmp("MATCHES", p),
        "id" => format!("`_id` = {}", p.bind(a)),
        "exists" => {
            let (l, r) = pair(a);
            let not = if r.as_bool().unwrap() { " NOT" } else { "" };
            format!("{} IS{not} MISSING", path(l))
        }
        "isNull" => format!("{} IS NULL", path(a)),
        "and" | "or" => {
            let mut args = Vec::new();
            flattened(op, a.as_array().unwrap(), &mut args);
            assert!(
                args.len() >= 2,
                "`{op}` needs two operands after flattening: {f}"
            );
            args.iter()
                .map(|x| {
                    let s = filter(x, p);
                    if is_compound(x) { format!("({s})") } else { s }
                })
                .collect::<Vec<_>>()
                .join(if op == "and" { " AND " } else { " OR " })
        }
        "not" => format!("NOT ({})", filter(a, p)),
        "elemMatch" => {
            let (l, inner) = pair(a);
            format!("ELEM MATCH ({}, {})", path(l), filter(inner, p))
        }
        other => panic!("unknown filter op `{other}`"),
    }
}

/// `None` for the empty filter `{}` (match everything).
fn where_clause(f: &Json, p: &mut Params) -> Option<String> {
    if f.as_object().is_some_and(Map::is_empty) {
        None
    } else {
        Some(filter(f, p))
    }
}

fn update(ops: &Json, p: &mut Params) -> String {
    ops.as_array()
        .unwrap_or_else(|| panic!("update must be a list: {ops}"))
        .iter()
        .map(|o| {
            let (op, a) = single(o);
            match op {
                "set" => {
                    let (l, r) = pair(a);
                    format!("SET {} = {}", path(l), p.bind(r))
                }
                "unset" => format!("UNSET {}", path(a)),
                "inc" | "mul" => {
                    let (l, r) = pair(a);
                    format!("{} {} BY {}", op.to_uppercase(), path(l), p.bind(r))
                }
                "min" | "max" => {
                    let (l, r) = pair(a);
                    format!("{} {} WITH {}", op.to_uppercase(), path(l), p.bind(r))
                }
                "push" => {
                    let (l, r) = pair(a);
                    format!("PUSH {} VALUE {}", path(l), p.bind(r))
                }
                "addToSet" => {
                    let (l, r) = pair(a);
                    format!("ADD TO SET {} VALUE {}", path(l), p.bind(r))
                }
                "pull" => {
                    // `PULL path WHERE p` binds the element to the last field name of `path`.
                    let (l, r) = pair(a);
                    let last = l.as_str().unwrap().rsplit('.').next().unwrap();
                    format!("PULL {} WHERE `{last}` = {}", path(l), p.bind(r))
                }
                "pop" => {
                    let (l, r) = pair(a);
                    format!("POP {} {}", path(l), r.as_str().unwrap().to_uppercase())
                }
                "rename" => {
                    let (l, r) = pair(a);
                    format!("RENAME {} TO {}", path(l), path(r))
                }
                "currentDate" => format!("CURRENT DATE {}", path(a)),
                "replace" => format!("REPLACE WITH {}", p.bind(a)),
                other => panic!("unknown update op `{other}`"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sort(s: &Json) -> String {
    s.as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let k = k.as_str().unwrap();
            match k.strip_prefix('-') {
                Some(f) => format!("{} DESC", path(&json!(f))),
                None => path(&json!(k)),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn projection(pr: &Json) -> String {
    let (kind, paths) = single(pr);
    let items = paths.as_array().unwrap().iter().map(|x| match kind {
        "include" => path(x),
        "exclude" => format!("-{}", path(x)),
        other => panic!("projection kind `{other}`"),
    });
    items.collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------------------------
// RGQL → AST (proto JSON)
// ---------------------------------------------------------------------------------------------

fn pool() -> DescriptorPool {
    DescriptorPool::decode(rustegon_proto::FILE_DESCRIPTOR_SET).unwrap()
}

/// Parses `rgql`, maps it to `AstStatement`, checks the server decodes it back to the same
/// statement, and returns its canonical protobuf JSON.
fn ast_json(rgql: &str) -> Json {
    let stmt = parse_statement(rgql).unwrap_or_else(|e| panic!("`{rgql}`: {e}"));
    let proto = statement_to_proto(&stmt).unwrap();
    let back = statement_from_proto(&proto)
        .unwrap_or_else(|e| panic!("`{rgql}`: server refuses the AST: {e:?}"));
    assert_eq!(back, stmt, "`{rgql}`: AST round trip");
    let desc = pool()
        .get_message_by_name("rustegon.v1.AstStatement")
        .unwrap();
    let dynamic = DynamicMessage::decode(desc, proto.encode_to_vec().as_slice()).unwrap();
    dynamic
        .serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------------------------

fn filter_cases() -> Vec<(&'static str, Json)> {
    vec![
        ("eq_string", json!({"eq": ["status", "paid"]})),
        ("eq_int64", json!({"eq": ["qty", 5]})),
        ("eq_float64", json!({"eq": ["price", 9.5]})),
        ("eq_null", json!({"eq": ["note", null]})),
        ("eq_bool", json!({"eq": ["active", true]})),
        (
            "eq_decimal",
            json!({"eq": ["total", {"$decimal": "100.00"}]}),
        ),
        (
            "eq_datetime",
            json!({"eq": ["createdAt", {"$date": "2026-01-01T00:00:00.000Z"}]}),
        ),
        (
            "eq_object_id",
            json!({"eq": ["ref", {"$oid": "65a1b2c3d4e5f60718293a4b"}]}),
        ),
        (
            "eq_uuid",
            json!({"eq": ["key", {"$uuid": "01234567-89ab-cdef-0123-456789abcdef"}]}),
        ),
        (
            "eq_binary",
            json!({"eq": ["blob", {"$binary": {"base64": "AQID", "subType": "00"}}]}),
        ),
        (
            "eq_int64_wrapped",
            json!({"eq": ["big", {"$int64": "9223372036854775807"}]}),
        ),
        (
            "eq_embedded_document",
            json!({"eq": ["address", {"city": "Rome", "zip": "00100"}]}),
        ),
        ("eq_array_value", json!({"eq": ["tags", ["a", "b"]]})),
        ("id", json!({"id": 42})),
        ("ne", json!({"ne": ["status", "cancelled"]})),
        ("gt", json!({"gt": ["qty", 10]})),
        ("gte", json!({"gte": ["total", {"$decimal": "100"}]})),
        ("lt", json!({"lt": ["price", 2.5]})),
        (
            "lte",
            json!({"lte": ["createdAt", {"$date": "2026-06-30T23:59:59.999Z"}]}),
        ),
        ("in", json!({"in": ["status", ["paid", "shipped"]]})),
        ("nin", json!({"nin": ["status", ["cancelled"]]})),
        ("in_empty_list", json!({"in": ["status", []]})),
        ("exists_true", json!({"exists": ["email", true]})),
        ("exists_false", json!({"exists": ["email", false]})),
        ("is_null", json!({"isNull": "deletedAt"})),
        (
            "nested_path",
            json!({"eq": ["customer.address.city", "Rome"]}),
        ),
        ("array_position_path", json!({"eq": ["items.0.sku", "A-1"]})),
        (
            "reserved_word_field_names",
            json!({"eq": ["value.order", 1]}),
        ),
        ("contains", json!({"contains": ["tags", "red"]})),
        (
            "contains_any",
            json!({"containsAny": ["tags", ["red", "blue"]]}),
        ),
        (
            "contains_all",
            json!({"containsAll": ["tags", ["red", "blue"]]}),
        ),
        (
            "elem_match",
            json!({"elemMatch": ["items", {"and": [{"gt": ["qty", 2]}, {"lt": ["price", 10]}]}]}),
        ),
        ("like", json!({"like": ["name", "Ro%"]})),
        ("regex", json!({"regex": ["name", "^R.*e$"]})),
        (
            "and",
            json!({"and": [{"eq": ["status", "paid"]}, {"gte": ["total", 100]}]}),
        ),
        (
            "and_three",
            json!({"and": [{"eq": ["a", 1]}, {"eq": ["b", 2]}, {"eq": ["c", 3]}]}),
        ),
        (
            "and_nested_is_flattened",
            json!({"and": [{"and": [{"eq": ["a", 1]}, {"eq": ["b", 2]}]}, {"eq": ["c", 3]}]}),
        ),
        (
            "or",
            json!({"or": [{"eq": ["status", "paid"]}, {"eq": ["status", "shipped"]}]}),
        ),
        (
            "or_inside_and",
            json!({"and": [{"or": [{"eq": ["a", 1]}, {"eq": ["b", 2]}]}, {"eq": ["c", 3]}]}),
        ),
        (
            "and_inside_or",
            json!({"or": [{"and": [{"eq": ["a", 1]}, {"eq": ["b", 2]}]}, {"eq": ["c", 3]}]}),
        ),
        ("not_eq", json!({"not": {"eq": ["status", "paid"]}})),
        (
            "not_and",
            json!({"not": {"and": [{"eq": ["a", 1]}, {"eq": ["b", 2]}]}}),
        ),
        ("not_exists", json!({"not": {"exists": ["email", true]}})),
    ]
}

fn update_cases() -> Vec<(&'static str, Json)> {
    vec![
        ("set", json!([{"set": ["status", "shipped"]}])),
        (
            "set_nested_path",
            json!([{"set": ["address.city", "Milan"]}]),
        ),
        (
            "set_document_value",
            json!([{"set": ["address", {"city": "Milan", "zip": "20100"}]}]),
        ),
        (
            "set_two_fields",
            json!([{"set": ["a", 1]}, {"set": ["b", "x"]}]),
        ),
        ("unset", json!([{"unset": "legacy"}])),
        ("inc", json!([{"inc": ["views", 1]}])),
        (
            "inc_negative_decimal",
            json!([{"inc": ["balance", {"$decimal": "-10.50"}]}]),
        ),
        ("mul", json!([{"mul": ["price", 1.1]}])),
        ("min", json!([{"min": ["low", 3]}])),
        ("max", json!([{"max": ["high", 9]}])),
        ("push", json!([{"push": ["tags", "new"]}])),
        (
            "push_document",
            json!([{"push": ["items", {"qty": 1, "sku": "A-1"}]}]),
        ),
        ("add_to_set", json!([{"addToSet": ["tags", "new"]}])),
        ("pull", json!([{"pull": ["tags", "old"]}])),
        ("pull_nested_path", json!([{"pull": ["meta.tags", "old"]}])),
        ("pop_first", json!([{"pop": ["queue", "first"]}])),
        ("pop_last", json!([{"pop": ["queue", "last"]}])),
        ("rename", json!([{"rename": ["colour", "color"]}])),
        ("current_date", json!([{"currentDate": "updatedAt"}])),
        (
            "set_and_inc",
            json!([{"set": ["status", "shipped"]}, {"inc": ["version", 1]}]),
        ),
        ("replace", json!([{"replace": {"name": "x", "qty": 2}}])),
    ]
}

/// `(name, op, args)` for statements.
fn statement_cases() -> Vec<(&'static str, &'static str, Json)> {
    let paid = json!({"eq": ["status", "paid"]});
    vec![
        ("find_all", "find", json!({"filter": {}})),
        ("find_filter", "find", json!({"filter": paid})),
        (
            "find_sort_desc_then_asc",
            "find",
            json!({"filter": paid, "sort": ["-createdAt", "_id"]}),
        ),
        ("find_limit", "find", json!({"filter": paid, "limit": 50})),
        ("find_skip", "find", json!({"filter": {}, "skip": 10})),
        (
            "find_limit_skip",
            "find",
            json!({"filter": {}, "sort": ["_id"], "limit": 10, "skip": 20}),
        ),
        (
            "find_projection_include",
            "find",
            json!({"filter": paid, "projection": {"include": ["_id", "total", "customer.name"]}}),
        ),
        (
            "find_projection_exclude",
            "find",
            json!({"filter": {}, "projection": {"exclude": ["secret", "meta"]}}),
        ),
        (
            "find_everything",
            "find",
            json!({"filter": {"and": [paid, {"gte": ["total", 100]}]}, "sort": ["-total"], "limit": 5, "skip": 5, "projection": {"include": ["_id", "total"]}}),
        ),
        (
            "update_one",
            "updateOne",
            json!({"filter": paid, "update": [{"set": ["status", "shipped"]}]}),
        ),
        (
            "update_many",
            "updateMany",
            json!({"filter": paid, "update": [{"inc": ["version", 1]}]}),
        ),
        (
            "update_many_empty_filter",
            "updateMany",
            json!({"filter": {}, "update": [{"set": ["flag", true]}]}),
        ),
        (
            "update_one_empty_filter",
            "updateOne",
            json!({"filter": {}, "update": [{"set": ["flag", true]}]}),
        ),
        (
            "replace_one",
            "replaceOne",
            json!({"filter": paid, "replacement": {"status": "archived"}}),
        ),
        ("delete_one", "deleteOne", json!({"filter": paid})),
        (
            "delete_many",
            "deleteMany",
            json!({"filter": {"lt": ["createdAt", {"$date": "2026-01-01T00:00:00.000Z"}]}}),
        ),
        (
            "delete_many_empty_filter",
            "deleteMany",
            json!({"filter": {}}),
        ),
    ]
}

const FULL_SCAN_WRITE: &str = "OPTIONS (allow_full_scan_write = TRUE)";

fn statement_rgql(op: &str, args: &Json, f: &mut Params, u: &mut Params) -> String {
    let coll = format!("`{COLLECTION}`");
    match op {
        "find" => {
            let mut s = format!("FROM {coll}");
            if let Some(w) = where_clause(&args["filter"], f) {
                s.push_str(&format!(" WHERE {w}"));
            }
            if let Some(pr) = args.get("projection") {
                s.push_str(&format!(" SELECT {}", projection(pr)));
            }
            if let Some(so) = args.get("sort") {
                s.push_str(&format!(" ORDER BY {}", sort(so)));
            }
            // Limit and skip are int64 literals, not parameters (README, "Builder DSL").
            if let Some(l) = args.get("limit") {
                s.push_str(&format!(" LIMIT {l}"));
            }
            if let Some(o) = args.get("skip") {
                s.push_str(&format!(" OFFSET {o}"));
            }
            s
        }
        "updateOne" | "updateMany" | "replaceOne" => {
            let ops = if op == "replaceOne" {
                update(&json!([{"replace": args["replacement"]}]), u)
            } else {
                update(&args["update"], u)
            };
            let mut s = format!("UPDATE {coll} {ops}");
            let w = where_clause(&args["filter"], f);
            if let Some(w) = &w {
                s.push_str(&format!(" WHERE {w}"));
            }
            if op != "updateMany" {
                s.push_str(" LIMIT 1");
            }
            if w.is_none() {
                s.push(' ');
                s.push_str(FULL_SCAN_WRITE);
            }
            s
        }
        "deleteOne" | "deleteMany" => {
            let mut s = format!("DELETE FROM {coll}");
            let w = where_clause(&args["filter"], f);
            if let Some(w) = &w {
                s.push_str(&format!(" WHERE {w}"));
            }
            if op == "deleteOne" {
                s.push_str(" LIMIT 1");
            }
            if w.is_none() {
                s.push(' ');
                s.push_str(FULL_SCAN_WRITE);
            }
            s
        }
        other => panic!("unknown statement op `{other}`"),
    }
}

fn file(description: &str, cases: &[Json]) -> String {
    let doc = json!({
        "description": description,
        "generatedBy": "crates/rustegon-server/tests/driver_ast.rs (re-bless: RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-server --test driver_ast); format: drivers/conformance/README.md",
        "version": 1,
        "collection": COLLECTION,
        "cases": cases,
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

fn filters_file() -> String {
    let cases = filter_cases()
        .into_iter()
        .map(|(name, dsl)| {
            let mut p = Params::new('f');
            let w = filter(&dsl, &mut p);
            let rgql = format!("FROM `{COLLECTION}` WHERE {w}");
            let ast = ast_json(&rgql);
            let expr = ast["query"]["where"].clone();
            assert!(!expr.is_null(), "{name}: no where");
            json!({"name": name, "filter": dsl, "params": p.to_json(), "rgql": rgql, "where": expr, "statement": ast})
        })
        .collect::<Vec<_>>();
    file(
        "Filter builder -> AstExpr (`where`) and the AstStatement of FROM `c` WHERE <filter>. Parameters f0, f1, ... in DSL order.",
        &cases,
    )
}

fn updates_file() -> String {
    let cases = update_cases()
        .into_iter()
        .map(|(name, dsl)| {
            let mut f = Params::new('f');
            let mut u = Params::new('u');
            let ops = update(&dsl, &mut u);
            let id = f.bind(&json!(1));
            let rgql = format!("UPDATE `{COLLECTION}` {ops} WHERE `_id` = {id}");
            let ast = ast_json(&rgql);
            let operations = ast["update"]["ops"].clone();
            // The operators alone are what DocumentService.Update / BulkUpdate carry.
            let typed = statement_to_proto(&parse_statement(&rgql).unwrap()).unwrap();
            let Some(rustegon_proto::v1::ast_statement::Kind::Update(upd)) = typed.kind else {
                panic!("{name}: not an update");
            };
            update_ops_from_proto(&upd.ops).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            json!({"name": name, "update": dsl, "params": u.to_json(), "rgql": ops, "operations": operations})
        })
        .collect::<Vec<_>>();
    file(
        "Update builder -> repeated AstUpdateOp (DocumentService.Update.operations, BulkUpdate.operations). `rgql` is the operator text only; parameters u0, u1, ... in DSL order.",
        &cases,
    )
}

fn statements_file() -> String {
    let cases = statement_cases()
        .into_iter()
        .map(|(name, op, args)| {
            let mut f = Params::new('f');
            let mut u = Params::new('u');
            let rgql = statement_rgql(op, &args, &mut f, &mut u);
            let ast = ast_json(&rgql);
            let mut params = f.to_json().as_object().unwrap().clone();
            params.extend(u.to_json().as_object().unwrap().clone());
            json!({"name": name, "op": op, "args": args, "params": params, "rgql": rgql, "statement": ast})
        })
        .collect::<Vec<_>>();
    file(
        "Collection operations with non-id filters -> AstStatement for QueryService.Execute. One-document writes use LIMIT 1 (documents are visited in _id order); an empty filter adds OPTIONS (allow_full_scan_write = true).",
        &cases,
    )
}

/// FR-DRV-003 / PD-070: the builder → AST golden vectors are current and accepted by the
/// server's structured-query decoder.
#[test]
fn tc_drv_conf_builder_ast_vectors_are_current() {
    check_or_bless("filters.json", &filters_file());
    check_or_bless("updates.json", &updates_file());
    check_or_bless("statements.json", &statements_file());
}

/// PD-070: RGQL has single-document UPDATE/DELETE forms (`LIMIT 1`), so `UpdateOne`,
/// `ReplaceOne` and `DeleteOne` with a non-id filter need no `Many` fallback.
#[test]
fn tc_drv_conf_single_row_update_and_delete_parse() {
    for rgql in [
        "UPDATE `c` SET `a` = $u0 WHERE `b` = $f0 LIMIT 1",
        "UPDATE `c` REPLACE WITH $u0 WHERE `b` = $f0 LIMIT 1",
        "DELETE FROM `c` WHERE `b` = $f0 LIMIT 1",
    ] {
        let ast = ast_json(rgql);
        let limit = ast.get("update").or_else(|| ast.get("delete")).unwrap()["limit"].clone();
        assert_eq!(limit, json!({"literal": {"intValue": "1"}}), "{rgql}");
    }
}
