// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RGQL query engine: lexer, parser, binder, planner, optimizer, executor and reference interpreter.
//!
//! M3 lane B delivers the front end (query-language.md §2–§13, ADR-013):
//! [`parse`] (lexer + Pratt/recursive-descent parser, `RGN-1010`/`RGN-1013` errors),
//! [`ast`] (the AST and its structured JSON form, mirrored by
//! `proto/rustegon/v1/query_ast.proto`) and [`print`](mod@print) (canonical printer;
//! `parse(print(ast)) == ast`). Requirements FR-QL-001/002; tests TC-QL-001…005.
//!
//! M3 wave 2 lane G adds [`stats`]: optimizer statistics (HLL NDV, MCV, equi-depth
//! histograms), the persisted stats record, the cardinality estimator and the §3 cost formula
//! (query-engine.md §2.1, §3), plus per-index usage counters (FR-IDX-004).
//!
//! [`reference`](mod@reference) is the naive reference interpreter used as the oracle of
//! differential testing (query-engine.md §11); the `testkit` cargo feature adds `testkit` —
//! data/query generators, the `QueryEngine` adapter trait and the differential, TLP and `NoREC`
//! oracles — for tests of this and other crates (TC-QL-009/010).
//!
//! M3 lane F delivers the engine core (query-engine.md §1–§5, §9; FR-QL-001/003/008):
//! [`bind`] (names, parameters, functions → bound statements), [`expr`] (bound expressions and
//! the evaluator), [`plan`] (rule rewrites, logical plan, access paths, physical plan with an
//! [`AccessPathChooser`](plan::AccessPathChooser) hook for the cost-based optimizer), [`exec`]
//! (batched pull operators and write operators over a [`QueryStore`]) and
//! [`partial`] (partial-index predicates). The entry point is [`exec::execute`].

pub mod ast;
pub mod bind;
pub mod error;
pub mod exec;
pub mod expr;
pub mod params;
pub mod parse;
pub mod partial;
pub mod plan;
pub mod print;
pub mod reference;
pub mod stats;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use crate::{
    ast::Statement,
    error::{ExecError, ExecResult},
    exec::{
        CursorBatch, CursorLimits, ExecOptions, Interrupt, Optimizer, QueryCursor, QueryResult,
        QueryStore, execute, open_cursor,
    },
    params::Params,
    parse::{ParseError, parse_expr, parse_script, parse_statement},
    print::{print_expr, print_script, print_statement},
};
