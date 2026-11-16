// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `EXPLAIN` and `EXPLAIN ANALYZE` (FR-QL-005, TC-QL-006): one result row in *explain format 1*
//! (query-language.md §5.1).
//!
//! The plan tree is built from the same [`stages`] list the executor builds its pipeline from,
//! so every node corresponds to exactly one operator and, under `ANALYZE`, to one profile slot
//! (rows, batches, inclusive time on the executor's clock).
//!
//! `EXPLAIN ANALYZE` executes the statement. For `UPDATE` / `DELETE` the writes are rolled back
//! to the statement savepoint afterwards (*Provisional (PD-041)*), so analyzing a write never
//! changes data; the `Update` / `Delete` node reports the documents it would have written.
//!
//! Estimates come from the cost-based optimizer ([`PhysicalPlan::estimate`], query-engine.md §3):
//! [`estimated_rows`] maps them onto the operators and the root reports the plan's `est_cost`.
//! A plan chosen without statistics (rule-based) has no estimates: `est_rows` / `est_cost` are
//! `null`.

use std::{sync::Arc, time::Duration};

use rustegon_doc::{Document, Value};

use super::{
    ExecCtx, STATEMENT_SAVEPOINT,
    read::{self, OpStats, Profile, Stage, order_keys, stages},
    write,
};
use crate::{
    bind::{BoundQuery, BoundStatement},
    error::{ExecResult, unsupported},
    expr::print_bexpr,
    plan::{
        AccessPath, LogicalPlan, OrderStrategy, PhysicalPlan,
        logical::{render_keys, render_limit, render_select},
    },
};

/// Version of the `EXPLAIN` output schema (query-language.md §5.1).
pub const EXPLAIN_FORMAT: i64 = 1;

/// `EXPLAIN [ANALYZE] stmt` as one row (module docs).
pub(super) fn explain(
    cx: &mut ExecCtx<'_>,
    stmt: &BoundStatement,
    analyze: bool,
) -> ExecResult<Value> {
    let (kind, source, with_projection) = match stmt {
        BoundStatement::Query(q) => ("query", q, true),
        BoundStatement::Update(u) => ("update", &u.source, false),
        BoundStatement::Delete(d) => ("delete", &d.source, false),
        _ => return Err(unsupported("EXPLAIN of INSERT / UPSERT", "a later milestone").into()),
    };
    // The same planning path as execution (index override, cost-based chooser with the
    // collection's statistics), so the explained plan is the executed one.
    let plan = Arc::new(super::plan_read(&mut *cx.store, source, cx.opts)?);
    let q: &BoundQuery = source;
    let stage_list = stages(&plan, with_projection, false);

    let mut execution = Value::Null;
    let mut stats: Vec<OpStats> = Vec::new();
    let mut write_node: Option<OpStats> = None;
    if analyze {
        let profile = Profile::default();
        cx.profile = Some(profile.clone());
        let clock = cx.opts.clock.clone();
        let start = clock.as_ref().map(|c| c.monotonic());
        let outcome = run_analyzed(cx, stmt, &plan);
        cx.profile = None;
        let (rows, affected) = outcome?;
        let total = match (&clock, start) {
            (Some(c), Some(s)) => Some(c.monotonic().saturating_sub(s)),
            _ => None,
        };
        stats = profile.snapshot();
        if kind != "query" {
            write_node = Some(OpStats {
                rows: affected,
                batches: u64::from(affected > 0),
                time: total,
            });
        }
        let mut e = Document::new();
        e.insert("rows", int(rows));
        e.insert("affected", int(affected));
        e.insert("time_ms", millis(total));
        e.insert("warnings", int(cx.eval.warnings()));
        execution = Value::Object(e);
    }

    // Nodes, innermost first, then nested so that the root is the outermost operator.
    let mut node: Option<Document> = None;
    for (slot, stage) in stage_list.iter().enumerate() {
        let mut n = stage_node(&plan, *stage);
        n.insert("est_rows", opt_float(estimated_rows(&plan, *stage)));
        if analyze {
            put_actual(&mut n, &stats.get(slot).cloned().unwrap_or_default());
        }
        n.insert(
            "children",
            Value::Array(node.take().map(Value::Object).into_iter().collect()),
        );
        node = Some(n);
    }
    if kind != "query" {
        let mut n = Document::new();
        n.insert(
            "op",
            Value::String(if kind == "update" { "Update" } else { "Delete" }.into()),
        );
        n.insert("detail", Value::String(plan.name.clone()));
        n.insert("index", Value::Null);
        // Every row the source returns is written.
        n.insert(
            "est_rows",
            opt_float(plan.estimate.as_ref().map(|e| e.est_rows)),
        );
        if let Some(s) = &write_node {
            put_actual(&mut n, s);
        }
        n.insert(
            "children",
            Value::Array(node.take().map(Value::Object).into_iter().collect()),
        );
        node = Some(n);
    }

    let mut d = Document::new();
    d.insert("explain_format", Value::Int64(EXPLAIN_FORMAT));
    d.insert("statement", Value::String(kind.into()));
    d.insert("analyze", Value::Bool(analyze));
    d.insert(
        "indexes_used",
        Value::Array(
            index_name(&plan)
                .map(|n| Value::String(n.to_owned()))
                .into_iter()
                .collect(),
        ),
    );
    d.insert(
        "est_cost",
        opt_float(plan.estimate.as_ref().map(|e| e.est_cost)),
    );
    d.insert("plan", node.map_or(Value::Null, Value::Object));
    d.insert("execution", execution);
    d.insert("logical", Value::String(LogicalPlan::of(q).render()));
    d.insert("physical", Value::String(plan.render()));
    Ok(Value::Object(d))
}

/// Runs the analyzed statement: `(rows returned, documents written)`. Writes are rolled back to
/// the statement savepoint (module docs).
fn run_analyzed(
    cx: &mut ExecCtx<'_>,
    stmt: &BoundStatement,
    plan: &Arc<PhysicalPlan>,
) -> ExecResult<(u64, u64)> {
    let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    match stmt {
        BoundStatement::Query(_) => Ok((count(read::collect(cx, plan)?.len()), 0)),
        BoundStatement::Update(u) => {
            let r = write::update(cx, u)?;
            cx.store.rollback_to_savepoint(STATEMENT_SAVEPOINT)?;
            Ok((count(r.rows.len()), r.affected()))
        }
        BoundStatement::Delete(d) => {
            let r = write::delete(cx, d)?;
            cx.store.rollback_to_savepoint(STATEMENT_SAVEPOINT)?;
            Ok((count(r.rows.len()), r.affected()))
        }
        _ => Err(unsupported("EXPLAIN ANALYZE of INSERT / UPSERT", "a later milestone").into()),
    }
}

/// The optimizer's row estimate for the operator `stage` of `plan` (`None`: the plan has no
/// estimates). The source produces `access_rows`; the filter keeps `filter_rows`, which a sort
/// passes through; `TopK` keeps at most `k`; the limit and the projection return `est_rows`
/// (after `OFFSET` / `LIMIT`).
fn estimated_rows(plan: &PhysicalPlan, stage: Stage) -> Option<f64> {
    let e = plan.estimate.as_ref()?;
    Some(match stage {
        Stage::Source => e.access_rows,
        Stage::Filter | Stage::Resume | Stage::Sort => e.filter_rows,
        Stage::TopK => match &plan.order {
            // Precision loss above 2^53 rows is irrelevant for an estimate.
            #[allow(clippy::cast_precision_loss)]
            OrderStrategy::TopK { k, .. } => e.filter_rows.min(*k as f64),
            _ => e.filter_rows,
        },
        Stage::Limit | Stage::Project => e.est_rows,
    })
}

fn index_name(plan: &PhysicalPlan) -> Option<&str> {
    match &plan.access {
        AccessPath::IndexScan { index, .. } => Some(&index.name),
        _ => None,
    }
}

/// `{op, detail, index}` of one operator (`est_rows`, actuals and children are added by the
/// caller).
fn stage_node(plan: &PhysicalPlan, stage: Stage) -> Document {
    let (op, detail, index) = match stage {
        Stage::Source => {
            let op = match &plan.access {
                AccessPath::Empty => "Empty",
                AccessPath::PrimaryGet { .. } => "PrimaryGet",
                AccessPath::PrimaryScan { .. } => "PrimaryScan",
                AccessPath::IndexScan { .. } => "IndexScan",
                AccessPath::CollectionScan => "CollectionScan",
            };
            // The access line of the text plan is its last (innermost) line.
            let rendered = plan.render();
            let mut detail = rendered
                .lines()
                .last()
                .unwrap_or_default()
                .trim()
                .to_owned();
            if let OrderStrategy::IndexOrder(k) = &plan.order {
                detail.push_str(" order ");
                detail.push_str(&render_keys(k));
            }
            (op, detail, index_name(plan).map(str::to_owned))
        }
        Stage::Filter => {
            let detail = match (&plan.residual, &plan.recheck) {
                (Some(r), _) => print_bexpr(r),
                (None, Some(r)) => format!("recheck {}", print_bexpr(r)),
                (None, None) => String::new(),
            };
            ("Filter", detail, None)
        }
        Stage::Resume => ("Resume", String::new(), None),
        Stage::Sort => ("Sort", render_keys(order_keys(plan)), None),
        Stage::TopK => {
            let k = match &plan.order {
                OrderStrategy::TopK { k, .. } => *k,
                _ => 0,
            };
            (
                "TopK",
                format!("k={k} {}", render_keys(order_keys(plan))),
                None,
            )
        }
        Stage::Limit => ("Limit", render_limit(plan.limit, plan.offset), None),
        Stage::Project => ("Project", render_select(&plan.select), None),
    };
    let mut d = Document::new();
    d.insert("op", Value::String(op.to_owned()));
    d.insert("detail", Value::String(detail));
    d.insert("index", index.map_or(Value::Null, Value::String));
    d
}

fn put_actual(n: &mut Document, s: &OpStats) {
    n.insert("actual_rows", int(s.rows));
    n.insert("batches", int(s.batches));
    n.insert("time_ms", millis(s.time));
}

fn int(n: u64) -> Value {
    Value::Int64(i64::try_from(n).unwrap_or(i64::MAX))
}

fn opt_float(v: Option<f64>) -> Value {
    v.map_or(Value::Null, Value::Float64)
}

fn millis(d: Option<Duration>) -> Value {
    opt_float(d.map(|d| d.as_secs_f64() * 1000.0))
}
