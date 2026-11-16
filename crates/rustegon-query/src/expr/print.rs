// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Text rendering of bound expressions for plans (EXPLAIN, golden plan tests). The output is
//! RGQL-like and fully parenthesised so that the normalised structure is visible; it is not
//! meant to be parsed back.

use std::fmt::Write as _;

use rustegon_doc::{Value, json};

use super::{BExpr, ContainsMode, IsKind, Step, path_text};

/// Renders a value: strings single-quoted, everything else as canonical JSON.
#[must_use]
pub fn print_value(v: Option<&Value>) -> String {
    match v {
        None => "MISSING".to_owned(),
        Some(Value::String(s)) => format!("'{}'", s.replace('\'', "''")),
        Some(other) => json::value_to_json(other, json::JsonMode::Canonical),
    }
}

fn steps(out: &mut String, base: &str, st: &[Step]) {
    out.push_str(base);
    for s in st {
        match s {
            Step::Field { .. } => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&path_text(std::slice::from_ref(s)));
            }
            Step::Dyn(e) => {
                let _ = write!(out, "[{}]", print_bexpr(e));
            }
        }
    }
}

fn list(items: &[BExpr], sep: &str) -> String {
    items.iter().map(print_bexpr).collect::<Vec<_>>().join(sep)
}

/// Renders a bound expression (module docs).
// One arm per expression variant: splitting the match would only scatter the rendering.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn print_bexpr(e: &BExpr) -> String {
    let mut out = String::new();
    match e {
        BExpr::Const(v) => out.push_str(&print_value(v.as_ref())),
        BExpr::Field(st) if st.is_empty() => out.push_str("$row"),
        BExpr::Field(st) => steps(&mut out, "", st),
        BExpr::Var {
            name, steps: st, ..
        } => steps(&mut out, name, st),
        BExpr::Access { base, steps: st } => {
            steps(&mut out, &format!("({})", print_bexpr(base)), st);
        }
        BExpr::Cmp { op, left, right } => {
            let _ = write!(
                out,
                "({} {} {})",
                print_bexpr(left),
                op.symbol(),
                print_bexpr(right)
            );
        }
        BExpr::Arith { op, left, right } => {
            let _ = write!(
                out,
                "({} {} {})",
                print_bexpr(left),
                op.symbol(),
                print_bexpr(right)
            );
        }
        BExpr::And(v) => {
            let _ = write!(out, "({})", list(v, " AND "));
        }
        BExpr::Or(v) => {
            let _ = write!(out, "({})", list(v, " OR "));
        }
        BExpr::Not(x) => {
            let _ = write!(out, "(NOT {})", print_bexpr(x));
        }
        BExpr::Neg(x) => {
            let _ = write!(out, "(-{})", print_bexpr(x));
        }
        BExpr::In {
            expr,
            list: l,
            negated,
        } => {
            let kw = if *negated { "NOT IN" } else { "IN" };
            let _ = write!(out, "({} {kw} {})", print_bexpr(expr), print_bexpr(l));
        }
        BExpr::Like {
            expr,
            pattern,
            case_insensitive,
        } => {
            let kw = if *case_insensitive { "ILIKE" } else { "LIKE" };
            let _ = write!(out, "({} {kw} {})", print_bexpr(expr), print_bexpr(pattern));
        }
        BExpr::Matches { expr, pattern, .. } => {
            let _ = write!(
                out,
                "({} MATCHES {})",
                print_bexpr(expr),
                print_bexpr(pattern)
            );
        }
        BExpr::Contains { expr, arg, mode } => {
            let kw = match mode {
                ContainsMode::One => "CONTAINS",
                ContainsMode::Any => "CONTAINS ANY",
                ContainsMode::All => "CONTAINS ALL",
            };
            let _ = write!(out, "({} {kw} {})", print_bexpr(expr), print_bexpr(arg));
        }
        BExpr::Is {
            expr,
            kind,
            negated,
        } => {
            let not = if *negated { "NOT " } else { "" };
            let what = match kind {
                IsKind::Null => "NULL",
                IsKind::Missing => "MISSING",
            };
            let _ = write!(out, "({} IS {not}{what})", print_bexpr(expr));
        }
        BExpr::Call { func, args } => {
            let _ = write!(out, "{}({})", func.name(), list(args, ", "));
        }
        BExpr::Case {
            operand,
            whens,
            otherwise,
        } => {
            out.push_str("CASE");
            if let Some(o) = operand {
                let _ = write!(out, " {}", print_bexpr(o));
            }
            for (w, t) in whens {
                let _ = write!(out, " WHEN {} THEN {}", print_bexpr(w), print_bexpr(t));
            }
            if let Some(o) = otherwise {
                let _ = write!(out, " ELSE {}", print_bexpr(o));
            }
            out.push_str(" END");
        }
        BExpr::Lambda { params, body, .. } => {
            let _ = write!(out, "({}) -> {}", params.join(", "), print_bexpr(body));
        }
        BExpr::Quantified {
            every,
            var,
            source,
            predicate,
            ..
        } => {
            let q = if *every { "EVERY" } else { "ANY" };
            let _ = write!(
                out,
                "({q} {var} IN {} SATISFIES {})",
                print_bexpr(source),
                print_bexpr(predicate)
            );
        }
        BExpr::ElemMatch {
            source, predicate, ..
        } => {
            let _ = write!(
                out,
                "ELEM MATCH ({}, {})",
                print_bexpr(source),
                print_bexpr(predicate)
            );
        }
        BExpr::Array(items) => {
            let _ = write!(out, "[{}]", list(items, ", "));
        }
        BExpr::Object(fields) => {
            let body: Vec<String> = fields
                .iter()
                .map(|(n, v)| {
                    format!(
                        "{}: {}",
                        print_value(Some(&Value::String(n.clone()))),
                        print_bexpr(v)
                    )
                })
                .collect();
            let _ = write!(out, "{{{}}}", body.join(", "));
        }
    }
    out
}
