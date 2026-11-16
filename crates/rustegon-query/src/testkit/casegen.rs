// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded generator of test cases: data plus a sequence of statements.
//!
//! Every generated statement goes through the text front end: it is printed canonically and
//! parsed back, and the parsed AST is what engines execute, so the printed text in a failure
//! report is exactly what ran. A statement whose text does not parse back is reported by the
//! runner as a front-end round-trip failure.

use rustegon_doc::{Document, Value};

use super::{
    Params,
    datagen::{ExprGen, GenConfig, documents, literal, path, scalar},
    rng::{Rng, mix},
};
use crate::{
    ast::{
        Delete, Expr, FromClause, Image, Insert, InsertSource, Literal, OnConflict, OptionItem,
        OrderItem, PopEnd, Projection, QualifiedName, Query, Returning, Segment, Select, SetItem,
        Source, Statement, Update, UpdateOp, Upsert,
    },
    parse_statement, print_statement,
};

/// The collection every case uses.
pub const COLLECTION: &str = "t";

/// One statement of a case.
#[derive(Debug, Clone)]
pub struct Step {
    /// Canonical text (what failure reports print).
    pub text: String,
    /// The parsed statement (`Err` = the text did not parse back: a front-end bug).
    pub statement: Result<Statement, String>,
    /// Parameters.
    pub params: Params,
    /// The `WHERE` predicate the TLP / `NoREC` oracles partition on (reads only).
    pub predicate: Option<Expr>,
}

/// A generated test case.
#[derive(Debug, Clone)]
pub struct Case {
    /// Seed that regenerates this case with [`generate`].
    pub seed: u64,
    /// Initial documents of [`COLLECTION`].
    pub documents: Vec<Document>,
    /// Statements, executed in order.
    pub steps: Vec<Step>,
}

/// Generates the case of `seed`.
#[must_use]
pub fn generate(seed: u64, config: &GenConfig) -> Case {
    let mut rng = Rng::new(mix(seed));
    let documents = documents(&mut rng, config.max_docs);
    let steps = (0..config.steps)
        .map(|_| {
            if rng.chance(config.write_percent) {
                write_step(&mut rng, config)
            } else {
                read_step(&mut rng, config)
            }
        })
        .collect();
    Case {
        seed,
        documents,
        steps,
    }
}

fn finish(stmt: &Statement, params: Params, predicate: Option<Expr>) -> Step {
    let text = print_statement(stmt);
    let statement = parse_statement(&text).map_err(|e| e.to_string());
    // Predicates also take the round trip, so TLP runs exactly what the text says.
    let predicate = match (&statement, predicate) {
        (Ok(Statement::Query(q)), Some(_)) => q.filter.clone(),
        _ => None,
    };
    Step {
        text,
        statement,
        params,
        predicate,
    }
}

fn target() -> QualifiedName {
    QualifiedName::new(None, COLLECTION)
}

fn read_step(rng: &mut Rng, config: &GenConfig) -> Step {
    let alias = rng.chance(30).then(|| "r".to_owned());
    let mut g = ExprGen {
        rng,
        alias: alias.clone(),
        params: Params::new(),
        config: config.clone(),
    };
    let depth = config.max_depth;
    let mut q = Query::from_source(Source::Collection(target()));
    q.from = FromClause {
        source: Source::Collection(target()),
        alias,
        as_of: None,
    };
    q.filter = g.rng.chance(85).then(|| g.predicate(depth));
    q.select = match g.rng.below(6) {
        0 | 1 => None,
        2 => Some(Select::Star),
        3 => Some(Select::Value {
            expr: g.scalar(depth),
        }),
        _ => Some(select_items(&mut g, depth)),
    };
    let limited = g.rng.chance(30);
    if g.rng.chance(50) || limited {
        let n = g.rng.below(3);
        for _ in 0..n {
            let expr = g.scalar(depth.saturating_sub(1));
            q.order_by.push(OrderItem {
                expr,
                descending: g.rng.chance(40),
            });
        }
        // A trailing `_id` makes the order total, so engines must agree row by row.
        if limited || g.rng.chance(50) {
            q.order_by.push(OrderItem {
                expr: Expr::Path { path: path("_id") },
                descending: g.rng.chance(30),
            });
        }
    }
    if limited {
        q.limit = Some(count_expr(&mut g, 0, 6));
        if g.rng.chance(40) {
            q.offset = Some(count_expr(&mut g, 0, 3));
        }
    }
    let predicate = q.filter.clone();
    finish(&Statement::Query(q), g.params, predicate)
}

fn count_expr(g: &mut ExprGen<'_>, lo: i64, hi: i64) -> Expr {
    let n = g.rng.range(lo, hi);
    if g.rng.chance(20) {
        let name = format!("p{}", g.params.len() + 1);
        g.params.insert(name.clone(), Value::Int64(n));
        Expr::Param { name }
    } else {
        Expr::Literal(Literal::Int(n))
    }
}

fn select_items(g: &mut ExprGen<'_>, depth: usize) -> Select {
    if g.rng.chance(15) {
        let items = (0..g.rng.range(1, 2))
            .map(|_| Projection::Exclude {
                path: path(g.rng.pick(&["b", "c.x", "tags", "nope"])),
            })
            .collect();
        return Select::Items { items };
    }
    let n = g.rng.range(1, 3);
    let mut items = Vec::new();
    for i in 0..n {
        items.push(match g.rng.below(5) {
            0 | 1 => Projection::Expr {
                expr: g.path_expr(),
                alias: None,
            },
            2 => Projection::Wildcard { path: path("c") },
            _ => Projection::Expr {
                expr: g.scalar(depth),
                alias: Some(format!("f{i}")),
            },
        });
    }
    if g.rng.chance(20) {
        items.push(Projection::Exclude { path: path("b") });
    }
    Select::Items { items }
}

/// A document to insert: a fresh `_id` (100+) or, sometimes, an existing one.
fn new_document(g: &mut ExprGen<'_>) -> Expr {
    let id = if g.rng.chance(25) {
        Value::Int64(g.rng.range(0, 5))
    } else {
        Value::Int64(g.rng.range(100, 140))
    };
    let d = super::datagen::document(g.rng, id);
    // NaN has no literal syntax (it would print as the path `NaN`); replace it everywhere.
    literal(&without_nan(Value::Object(d)))
}

fn without_nan(v: Value) -> Value {
    match v {
        Value::Float64(f) if f.is_nan() => Value::Float64(1.5),
        Value::Array(items) => Value::Array(items.into_iter().map(without_nan).collect()),
        Value::Object(d) => {
            let mut out = Document::new();
            for (k, x) in d.into_fields() {
                out.insert(k, without_nan(x));
            }
            Value::Object(out)
        }
        other => other,
    }
}

fn write_step(rng: &mut Rng, config: &GenConfig) -> Step {
    let mut g = ExprGen {
        rng,
        alias: None,
        params: Params::new(),
        config: config.clone(),
    };
    let depth = config.max_depth.saturating_sub(1);
    let returning = g.rng.chance(30).then(|| Returning {
        image: if g.rng.chance(50) {
            Image::Old
        } else {
            Image::New
        },
        items: Vec::new(),
    });
    let stmt = match g.rng.below(10) {
        0..=2 => {
            let source = if g.rng.chance(70) {
                InsertSource::Value {
                    expr: new_document(&mut g),
                }
            } else {
                InsertSource::Values {
                    rows: vec![new_document(&mut g), new_document(&mut g)],
                }
            };
            let on_conflict = match g.rng.below(4) {
                0 => Some(OnConflict::DoNothing),
                1 => Some(OnConflict::DoUpdate {
                    ops: update_ops(&mut g, depth),
                }),
                _ => None,
            };
            Statement::Insert(Insert {
                target: target(),
                source,
                on_conflict,
                ttl: None,
                returning,
            })
        }
        3..=6 => {
            let filter = g.rng.chance(85).then(|| g.predicate(depth));
            let options = full_scan_option(&mut g, filter.is_none());
            Statement::Update(Update {
                target: target(),
                alias: None,
                ops: update_ops(&mut g, depth),
                filter,
                limit: g.rng.chance(20).then(|| count_expr(&mut g, 0, 3)),
                options,
                returning,
            })
        }
        7 => Statement::Upsert(Upsert {
            target: target(),
            value: new_document(&mut g),
            // `ON a` exercises key matching (none, one or several matches, missing/null key).
            on: if g.rng.chance(30) {
                vec![path("a")]
            } else {
                Vec::new()
            },
            returning,
        }),
        _ => {
            let filter = g.rng.chance(90).then(|| g.predicate(depth));
            let options = full_scan_option(&mut g, filter.is_none());
            Statement::Delete(Delete {
                columns: Vec::new(),
                target: target(),
                filter,
                limit: g.rng.chance(20).then(|| count_expr(&mut g, 0, 3)),
                options,
                returning,
            })
        }
    };
    finish(&stmt, g.params, None)
}

fn full_scan_option(g: &mut ExprGen<'_>, no_filter: bool) -> Vec<OptionItem> {
    if no_filter && g.rng.chance(80) {
        vec![OptionItem {
            name: "allow_full_scan_write".into(),
            value: Expr::Literal(Literal::Bool(true)),
        }]
    } else {
        Vec::new()
    }
}

/// 1–3 update operators (conflicting paths are allowed: they must fail identically).
fn update_ops(g: &mut ExprGen<'_>, depth: usize) -> Vec<UpdateOp> {
    if g.rng.chance(8) {
        return vec![UpdateOp::Replace {
            value: new_document(g),
        }];
    }
    let n = g.rng.range(1, 3);
    (0..n).map(|_| update_op(g, depth)).collect()
}

// One arm per operator shape: a flat table keeps the operator mix easy to audit.
#[allow(clippy::too_many_lines)]
fn update_op(g: &mut ExprGen<'_>, depth: usize) -> UpdateOp {
    let p = |s: &str| path(s);
    let filtered = |var: &str, pred: Expr, rest: &str| {
        let mut segs = vec![
            Segment::Field("items".into()),
            Segment::Index(Box::new(Expr::Lambda {
                params: vec![var.into()],
                body: Box::new(pred),
            })),
        ];
        segs.push(Segment::Field(rest.into()));
        crate::ast::Path(segs)
    };
    match g.rng.below(16) {
        0 | 1 => UpdateOp::Set {
            items: vec![SetItem {
                path: p(g
                    .rng
                    .pick(&["a", "b", "c.x", "c.y.z", "new", "tags.0", "items.0.qty"])),
                value: g.scalar(depth),
            }],
        },
        2 => UpdateOp::Unset {
            paths: vec![p(g.rng.pick(&["a", "b", "c.x", "tags.1", "nope"]))],
        },
        3 => UpdateOp::Inc {
            path: p(g.rng.pick(&["n", "a", "c.y.z", "cnt"])),
            by: literal(&scalar(g.rng, true)),
        },
        4 => UpdateOp::Mul {
            path: p(g.rng.pick(&["n", "a"])),
            by: literal(&Value::Int64(g.rng.range(-2, 3))),
        },
        5 => UpdateOp::Push {
            path: p(g.rng.pick(&["tags", "newarr", "b"])),
            value: g.constant(),
            position: g
                .rng
                .chance(30)
                .then(|| Expr::Literal(Literal::Int(g.rng.range(-2, 2)))),
            slice: g
                .rng
                .chance(30)
                .then(|| Expr::Literal(Literal::Int(g.rng.range(-3, 3)))),
            sort: Vec::new(),
        },
        6 => UpdateOp::Push {
            path: p("items"),
            value: literal(&scalar(g.rng, true)),
            position: None,
            slice: None,
            sort: vec![OrderItem {
                expr: Expr::Path { path: p("qty") },
                descending: g.rng.chance(50),
            }],
        },
        7 => {
            let target = Expr::Path { path: p("tags") };
            UpdateOp::Pull {
                path: p("tags"),
                predicate: crate::ast::Expr::Binary {
                    op: crate::ast::BinaryOp::Eq,
                    left: Box::new(target),
                    right: Box::new(g.constant()),
                },
            }
        }
        8 => UpdateOp::Pull {
            path: p("items"),
            predicate: g.predicate(0),
        },
        9 => UpdateOp::AddToSet {
            path: p(g.rng.pick(&["tags", "set"])),
            value: g.constant(),
        },
        10 => UpdateOp::Pop {
            path: p(g.rng.pick(&["tags", "items", "b"])),
            end: if g.rng.chance(50) {
                PopEnd::First
            } else {
                PopEnd::Last
            },
        },
        11 => UpdateOp::Rename {
            from: p(g.rng.pick(&["b", "c.x", "nope"])),
            to: p(g.rng.pick(&["b2", "c.w", "a"])),
        },
        12 => {
            let value = g.constant();
            if g.rng.chance(50) {
                UpdateOp::Min {
                    path: p("a"),
                    value,
                }
            } else {
                UpdateOp::Max {
                    path: p("a"),
                    value,
                }
            }
        }
        13 if g.config.time_dependent => UpdateOp::CurrentDate { path: p("touched") },
        13 | 14 => {
            let pred = crate::ast::Expr::Binary {
                op: crate::ast::BinaryOp::Ge,
                left: Box::new(Expr::Path { path: p("x.qty") }),
                right: Box::new(Expr::Literal(Literal::Int(g.rng.range(0, 4)))),
            };
            UpdateOp::Inc {
                path: filtered("x", pred, "qty"),
                by: Expr::Literal(Literal::Int(1)),
            }
        }
        _ => UpdateOp::Set {
            items: vec![SetItem {
                path: filtered("x", Expr::Literal(Literal::Bool(true)), "seen"),
                value: g.constant(),
            }],
        },
    }
}
