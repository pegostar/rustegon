// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-001: grammar golden corpus (query-language.md §15, AC-QL-001) — every production of
//! §3, every expression form of §4 and every statement of §5–§12 has at least one golden case,
//! checked by the production coverage test below.
//!
//! Golden file: `tests/golden/grammar.rgql` (canonical text + structured JSON per case).
//! Regenerate with `RGQL_BLESS=1 cargo nextest run -p rustegon-query tc_ql_001` and review.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::golden;
use rustegon_query::{Statement, parse_script, parse_statement, print_script, print_statement};

const FILE: &str = "grammar.rgql";

/// Productions and syntax forms of query-language.md (§2 lexical, §3 grammar, §4 expressions,
/// §5–§12 statements) plus data-model §6/§7 DDL. Each must be tagged by ≥ 1 golden case.
const PRODUCTIONS: &[&str] = &[
    // §2 lexical structure
    "keyword_case_insensitive",
    "quoted_identifier",
    "string_literal",
    "string_escape",
    "int_literal",
    "negative_literal",
    "float_literal",
    "decimal_literal",
    "bool_literal",
    "null_literal",
    "datetime_literal",
    "oid_literal",
    "uuid_literal",
    "interval_literal",
    "array_literal",
    "object_literal",
    "param_named",
    "param_positional",
    "comment_line",
    "comment_block",
    "statement_separator",
    "script",
    // §3 statement, explain
    "explain",
    "explain_analyze",
    // §3 query
    "query",
    "from_clause",
    "from_alias",
    "from_as_of",
    "source_subquery",
    "source_index",
    "qualified_name",
    "qualified_name_default_db",
    "lookup_clause",
    "lookup_alias",
    "where_clause",
    "group_clause",
    "group_key_alias",
    "having_clause",
    "select_clause",
    "select_star",
    "select_value",
    "projection_alias",
    "projection_wildcard",
    "projection_exclude",
    "order_clause",
    "limit_clause",
    "limit_offset",
    "offset_only",
    "include_clause",
    "path_each",
    "options_clause",
    "pipe_stage",
    // §3 writes
    "insert",
    "insert_value",
    "insert_values",
    "insert_query",
    "insert_tuples",
    "on_conflict_do_nothing",
    "on_conflict_do_update",
    "using_ttl",
    "update",
    "update_alias",
    "update_set",
    "set_item",
    "update_without_set",
    "update_replace",
    "update_unset",
    "update_inc",
    "update_mul",
    "update_push",
    "push_mods",
    "update_pull",
    "update_add_to_set",
    "update_pop",
    "update_rename",
    "update_min",
    "update_max",
    "update_current_date",
    "update_limit",
    "update_options",
    "upsert",
    "upsert_on",
    "delete",
    "delete_columns",
    "delete_limit",
    "delete_options",
    "returning_old",
    "returning_new",
    "returning_projection",
    // §3 path, §4.1 operators
    "path_dot",
    "path_position",
    "path_index",
    "access_path",
    "paren_expr",
    "unary_neg",
    "unary_not",
    "mul_op",
    "div_op",
    "mod_op",
    "add_op",
    "sub_op",
    "concat_op",
    "eq_op",
    "eq_whole_op",
    "ne_op",
    "lt_op",
    "le_op",
    "gt_op",
    "ge_op",
    "in_op",
    "not_in_op",
    "like_op",
    "ilike_op",
    "matches_op",
    "between_op",
    "is_null",
    "is_not_null",
    "is_missing",
    "is_not_missing",
    "contains_op",
    "contains_any_op",
    "contains_all_op",
    "and_op",
    "or_op",
    "quantifier_any",
    "quantifier_every",
    "elem_match",
    // §4.2 call forms
    "call",
    "call_no_args",
    "call_star",
    "named_argument_as_eq",
    "extract",
    "case_searched",
    "case_simple",
    "lambda",
    "lambda_multi",
    // §7 stages
    "stage_match",
    "stage_project",
    "stage_set",
    "stage_unset",
    "stage_group",
    "agg_item",
    "stage_sort",
    "stage_limit",
    "stage_skip",
    "stage_unwind",
    "stage_lookup",
    "lookup_pipeline",
    "stage_count",
    "stage_facet",
    "stage_bucket",
    "stage_bucket_auto",
    "stage_sample",
    "stage_replace_root",
    "stage_sort_by_count",
    "stage_graph_lookup",
    "stage_union_with",
    "stage_window",
    "stage_out",
    "stage_merge",
    // §11 DDL and admin (+ data-model §6, §7)
    "create_database",
    "with_options",
    "create_collection",
    "create_table",
    "create_timeseries",
    "create_index",
    "index_key_direction",
    "create_unique_index",
    "create_ttl_index",
    "expire_after",
    "create_fulltext_index",
    "index_key_analyzer_boost",
    "create_vector_index",
    "create_geo_index",
    "create_local_index",
    "create_mapreduce_index",
    "create_continuous_aggregate",
    "create_change_subscription",
    "alter_collection_set",
    "alter_collection_split",
    "alter_index",
    "index_name",
    "drop_index",
    "drop_collection",
    "drop_database",
    "show_collections",
    "show_indexes",
    "show_ranges",
    "show_transactions",
    "kill_query",
    "kill_transaction",
    // §12 transactions
    "begin",
    "begin_isolation",
    "begin_read_only",
    "begin_priority",
    "begin_as_of",
    "savepoint",
    "rollback_to_savepoint",
    "release_savepoint",
    "commit",
    "rollback",
];

fn produce(case: &golden::Case) -> Vec<(String, String)> {
    let stmts = parse_script(&case.input)
        .unwrap_or_else(|e| panic!("case `{}` does not parse: {e}", case.name));
    let canonical = print_script(&stmts);
    let json = stmts
        .iter()
        .map(|s| serde_json::to_string_pretty(s).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    vec![
        ("canonical".to_owned(), canonical.trim_end().to_owned()),
        ("json".to_owned(), json),
    ]
}

#[test]
fn tc_ql_001_golden_corpus_matches() {
    let cases = golden::load(FILE);
    let produced: Vec<_> = cases.iter().map(produce).collect();
    let failures = golden::check(FILE, &cases, &produced);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// AC-QL-001 coverage script: every production has a golden case, every tag is a production.
#[test]
fn tc_ql_001_every_production_has_a_golden_case() {
    let cases = golden::load(FILE);
    let tagged: BTreeSet<&str> = cases
        .iter()
        .flat_map(|c| c.tags.iter().map(String::as_str))
        .collect();
    let known: BTreeSet<&str> = PRODUCTIONS.iter().copied().collect();
    let uncovered: Vec<_> = known.difference(&tagged).collect();
    let unknown: Vec<_> = tagged.difference(&known).collect();
    assert!(
        uncovered.is_empty(),
        "productions without a golden case: {uncovered:?}"
    );
    assert!(
        unknown.is_empty(),
        "tags that are not productions: {unknown:?}"
    );
    assert_eq!(known.len(), PRODUCTIONS.len(), "duplicate production names");
}

/// The canonical text is a fixed point and both the text and the JSON form give the same AST.
#[test]
fn tc_ql_001_golden_cases_round_trip() {
    for case in golden::load(FILE) {
        let stmts = parse_script(&case.input).unwrap();
        for stmt in &stmts {
            let text = print_statement(stmt);
            let again = parse_statement(&text)
                .unwrap_or_else(|e| panic!("`{}`: canonical text `{text}` fails: {e}", case.name));
            assert_eq!(&again, stmt, "`{}`: parse(print(ast)) != ast", case.name);
            assert_eq!(
                print_statement(&again),
                text,
                "`{}`: not a fixed point",
                case.name
            );
            let json = stmt.to_json().unwrap();
            let from_json = Statement::from_json(&json)
                .unwrap_or_else(|e| panic!("`{}`: JSON rejected: {e}\n{json}", case.name));
            assert_eq!(&from_json, stmt, "`{}`: JSON round trip", case.name);
        }
    }
}

/// The structured JSON form and `proto/rustegon/v1/query_ast.proto` stay in sync: every
/// `"kind"` value produced for the golden corpus is a `oneof kind` field of the proto.
#[test]
fn tc_ql_001_json_kinds_are_mirrored_in_query_ast_proto() {
    let proto_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../proto/rustegon/v1/query_ast.proto");
    let proto = std::fs::read_to_string(proto_path).unwrap();
    let mut kinds = BTreeSet::new();
    for case in golden::load(FILE) {
        for stmt in parse_script(&case.input).unwrap() {
            let json = stmt.to_json().unwrap();
            for part in json.split(r#""kind":""#).skip(1) {
                kinds.insert(part.split('"').next().unwrap().to_owned());
            }
        }
    }
    let missing: Vec<_> = kinds
        .iter()
        .filter(|k| !proto.contains(&format!(" {k} = ")))
        .collect();
    assert!(kinds.len() > 80, "only {} kinds seen", kinds.len());
    assert!(
        missing.is_empty(),
        "kinds missing from query_ast.proto: {missing:?}"
    );
}

/// Reserved words are valid bare option names (`WITH (include = [...])` of indexing.md §2,
/// PD-038): the parser accepts them and the canonical printer does not quote them.
#[test]
fn tc_ql_001_reserved_words_as_option_names_round_trip() {
    for (text, canonical) in [
        (
            "CREATE INDEX i ON t (a) WITH (include = ['b', 'c'])",
            "CREATE INDEX i ON t (a) WITH (include = ['b', 'c'])",
        ),
        (
            "FROM t OPTIONS (limit = 1, `select` = 2, Index = 'i')",
            "FROM t OPTIONS (limit = 1, select = 2, Index = 'i')",
        ),
    ] {
        let stmt = parse_statement(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        let printed = print_statement(&stmt);
        assert_eq!(printed, canonical);
        assert_eq!(parse_statement(&printed).unwrap(), stmt, "{printed}");
    }
}
