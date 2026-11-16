// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Logical plans (query-engine.md §1): the relational shape of a bound read before access
//! paths are chosen — `Scan → Filter → Sort → Limit → Project`.

use std::fmt::Write as _;

use crate::{
    bind::{BoundProjection, BoundQuery, BoundSelect, SortKey},
    expr::{path_text, print_bexpr},
};

/// A logical operator tree.
#[derive(Debug, Clone, PartialEq)]
pub enum LogicalPlan {
    /// All documents of a collection.
    Scan {
        /// `database.collection`.
        collection: String,
    },
    /// Keeps rows whose predicate is true.
    Filter {
        /// Predicate (normalised).
        predicate: crate::expr::BExpr,
        /// Input.
        input: Box<LogicalPlan>,
    },
    /// Orders rows (ties by `_id`).
    Sort {
        /// Keys.
        keys: Vec<SortKey>,
        /// Input.
        input: Box<LogicalPlan>,
    },
    /// Skips `offset` rows, then returns at most `limit`.
    Limit {
        /// Maximum rows.
        limit: Option<u64>,
        /// Skipped rows.
        offset: u64,
        /// Input.
        input: Box<LogicalPlan>,
    },
    /// Shapes the output rows.
    Project {
        /// Projection.
        select: BoundSelect,
        /// Input.
        input: Box<LogicalPlan>,
    },
}

impl LogicalPlan {
    /// The logical plan of a bound query.
    #[must_use]
    pub fn of(q: &BoundQuery) -> Self {
        let mut plan = Self::Scan {
            collection: format!("{}.{}", q.target.database.name, q.target.name),
        };
        if let Some(p) = &q.filter {
            plan = Self::Filter {
                predicate: p.clone(),
                input: Box::new(plan),
            };
        }
        if !q.order.is_empty() {
            plan = Self::Sort {
                keys: q.order.clone(),
                input: Box::new(plan),
            };
        }
        if q.limit.is_some() || q.offset > 0 {
            plan = Self::Limit {
                limit: q.limit,
                offset: q.offset,
                input: Box::new(plan),
            };
        }
        if q.select != BoundSelect::Document {
            plan = Self::Project {
                select: q.select.clone(),
                input: Box::new(plan),
            };
        }
        plan
    }

    /// Indented text rendering (one operator per line, input below).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut node = Some(self);
        let mut depth = 0;
        while let Some(n) = node {
            let pad = "  ".repeat(depth);
            node = match n {
                Self::Scan { collection } => {
                    let _ = writeln!(out, "{pad}Scan {collection}");
                    None
                }
                Self::Filter { predicate, input } => {
                    let _ = writeln!(out, "{pad}Filter {}", print_bexpr(predicate));
                    Some(input)
                }
                Self::Sort { keys, input } => {
                    let _ = writeln!(out, "{pad}Sort {}", render_keys(keys));
                    Some(input)
                }
                Self::Limit {
                    limit,
                    offset,
                    input,
                } => {
                    let _ = writeln!(out, "{pad}Limit {}", render_limit(*limit, *offset));
                    Some(input)
                }
                Self::Project { select, input } => {
                    let _ = writeln!(out, "{pad}Project {}", render_select(select));
                    Some(input)
                }
            };
            depth += 1;
        }
        out.trim_end().to_owned()
    }
}

/// `a ASC, b DESC`.
#[must_use]
pub fn render_keys(keys: &[SortKey]) -> String {
    keys.iter()
        .map(|k| {
            format!(
                "{} {}",
                print_bexpr(&k.expr),
                if k.descending { "DESC" } else { "ASC" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `limit=10 offset=5`.
#[must_use]
pub fn render_limit(limit: Option<u64>, offset: u64) -> String {
    let mut s = match limit {
        Some(l) => format!("limit={l}"),
        None => "limit=all".to_owned(),
    };
    if offset > 0 {
        let _ = write!(s, " offset={offset}");
    }
    s
}

/// Text of a projection.
#[must_use]
pub fn render_select(select: &BoundSelect) -> String {
    match select {
        BoundSelect::Document => "*".to_owned(),
        BoundSelect::Value(e) => format!("VALUE {}", print_bexpr(e)),
        BoundSelect::Items(items) => items
            .iter()
            .map(|p| match p {
                BoundProjection::Field { name, expr } => format!("{} AS {name}", print_bexpr(expr)),
                BoundProjection::Wildcard(e) => format!("{}.*", print_bexpr(e)),
                BoundProjection::Exclude(steps) => format!("-{}", path_text(steps)),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}
