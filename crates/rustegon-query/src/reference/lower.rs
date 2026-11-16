// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Lowering of RGQL update operators (query-language.md §3 `update_ops`) to the document
//! model's `rustegon_doc::update` operators (data-model §2.3), for the reference interpreter.
//! The path and predicate rules are documented in [`super::write`].

use std::sync::Arc;

use rustegon_common::Error;
use rustegon_doc::{
    Document, Value,
    keyenc::Direction,
    path::{FieldPath, Segment as DocSegment},
    update::{self as upd, ElementPredicate, PushSort, UpdatePath, UpdateSegment},
};

use super::{
    Params,
    error::{invalid, type_error},
    eval::{Ctx, Env, Tri, Val, eval, truth},
};
use crate::ast::{Expr, Path, PopEnd, Segment, UpdateOp};

fn val(e: &Expr, env: &Env<'_>) -> Result<Val, Error> {
    eval(e, env)
}

// One arm per RGQL operator, each a direct lowering to its data-model §2.3 counterpart.
#[allow(clippy::too_many_lines)]
pub(crate) fn lower(
    op: &UpdateOp,
    env: &Env<'_>,
    out: &mut Vec<upd::UpdateOp>,
) -> Result<(), Error> {
    let present = |e: &Expr| -> Result<Value, Error> { Ok(val(e, env)?.unwrap_or(Value::Null)) };
    match op {
        UpdateOp::Set { items } => {
            for item in items {
                let path = lower_path(&item.path, env)?;
                out.push(match val(&item.value, env)? {
                    Some(value) => upd::UpdateOp::Set { path, value },
                    None => upd::UpdateOp::Unset { path },
                });
            }
        }
        UpdateOp::Unset { paths } => {
            for p in paths {
                out.push(upd::UpdateOp::Unset {
                    path: lower_path(p, env)?,
                });
            }
        }
        UpdateOp::Inc { path, by } => out.push(upd::UpdateOp::Inc {
            path: lower_path(path, env)?,
            by: present(by)?,
        }),
        UpdateOp::Mul { path, by } => out.push(upd::UpdateOp::Mul {
            path: lower_path(path, env)?,
            by: present(by)?,
        }),
        UpdateOp::Push {
            path,
            value,
            position,
            slice,
            sort,
        } => {
            let int = |e: &Option<Expr>| -> Result<Option<i64>, Error> {
                match e.as_ref().map(|e| val(e, env)).transpose()?.flatten() {
                    None => Ok(None),
                    Some(Value::Int64(i)) => Ok(Some(i)),
                    Some(_) => Err(type_error("PUSH POSITION/SLICE must be an integer")),
                }
            };
            let sort = if sort.is_empty() {
                None
            } else {
                let mut keys = Vec::with_capacity(sort.len());
                for item in sort {
                    let Expr::Path { path } = &item.expr else {
                        return Err(type_error("PUSH SORT keys must be field paths"));
                    };
                    let dir = if item.descending {
                        Direction::Descending
                    } else {
                        Direction::Ascending
                    };
                    keys.push((field_path(path)?, dir));
                }
                Some(PushSort::Fields(keys))
            };
            out.push(upd::UpdateOp::Push(upd::Push {
                path: lower_path(path, env)?,
                values: vec![present(value)?],
                position: int(position)?,
                sort,
                slice: int(slice)?,
            }));
        }
        UpdateOp::Pull { path, predicate } => {
            let var = path.0.iter().rev().find_map(|s| match s {
                Segment::Field(n) => Some(n.clone()),
                _ => None,
            });
            out.push(upd::UpdateOp::Pull {
                path: lower_path(path, env)?,
                predicate: element_predicate(predicate, var, true, env.ctx),
            });
        }
        UpdateOp::AddToSet { path, value } => out.push(upd::UpdateOp::AddToSet {
            path: lower_path(path, env)?,
            values: vec![present(value)?],
        }),
        UpdateOp::Pop { path, end } => out.push(upd::UpdateOp::Pop {
            path: lower_path(path, env)?,
            end: match end {
                PopEnd::First => upd::PopEnd::First,
                PopEnd::Last => upd::PopEnd::Last,
            },
        }),
        UpdateOp::Rename { from, to } => out.push(upd::UpdateOp::Rename {
            from: lower_path(from, env)?,
            to: lower_path(to, env)?,
        }),
        UpdateOp::Min { path, value } => out.push(upd::UpdateOp::Min {
            path: lower_path(path, env)?,
            value: present(value)?,
        }),
        UpdateOp::Max { path, value } => out.push(upd::UpdateOp::Max {
            path: lower_path(path, env)?,
            value: present(value)?,
        }),
        UpdateOp::CurrentDate { path } => out.push(upd::UpdateOp::CurrentDate {
            path: lower_path(path, env)?,
        }),
        UpdateOp::Replace { .. } => {
            return Err(invalid("REPLACE WITH must be the only update operation"));
        }
    }
    Ok(())
}

/// A predicate evaluated per array element. The closure owns copies of what it needs because
/// `ElementPredicate` is `'static` (the update engine may keep it beyond this call).
fn element_predicate(
    body: &Expr,
    var: Option<String>,
    element_is_row: bool,
    ctx: &Ctx<'_>,
) -> ElementPredicate {
    let body = Arc::new(body.clone());
    let params: Arc<Params> = Arc::new(ctx.params.clone());
    let now_ms = ctx.now_ms;
    ElementPredicate::new(move |element: &Value| {
        let ctx = Ctx {
            params: &params,
            now_ms,
        };
        let empty = Value::Object(Document::new());
        let row = if element_is_row { element } else { &empty };
        let mut env = Env::new(&ctx, row, None);
        if let Some(v) = &var {
            env = env.with_var(v, Some(element.clone()));
        }
        Ok(truth(&body, &env)? == Tri::True)
    })
}

fn lower_path(path: &Path, env: &Env<'_>) -> Result<UpdatePath, Error> {
    let segs = skip_alias(&path.0, env.alias);
    let mut out = Vec::with_capacity(segs.len());
    for s in segs {
        out.push(match s {
            Segment::Field(name) => UpdateSegment::Field(DocSegment {
                name: name.clone(),
                index: None,
            }),
            Segment::Position(p) => UpdateSegment::Field(index_segment(u64::from(*p))),
            Segment::Index(e) => match e.as_ref() {
                Expr::Lambda { params, body } if params.len() == 1 => UpdateSegment::Filtered(
                    element_predicate(body, Some(params[0].clone()), true, env.ctx),
                ),
                other => match val(other, env)? {
                    Some(Value::Int64(i)) if i >= 0 => {
                        UpdateSegment::Field(index_segment(i.unsigned_abs()))
                    }
                    Some(Value::String(name)) => {
                        UpdateSegment::Field(DocSegment { name, index: None })
                    }
                    _ => {
                        return Err(type_error(
                            "an update path index must be an integer or string",
                        ));
                    }
                },
            },
            Segment::Each => return Err(type_error("`[]` is only allowed in INCLUDE paths")),
        });
    }
    Ok(UpdatePath::new(out))
}

fn index_segment(i: u64) -> DocSegment {
    DocSegment {
        name: i.to_string(),
        index: usize::try_from(i).ok(),
    }
}

fn skip_alias<'p>(segs: &'p [Segment], alias: Option<&str>) -> &'p [Segment] {
    match segs.split_first() {
        Some((Segment::Field(first), rest))
            if Some(first.as_str()) == alias && !rest.is_empty() =>
        {
            rest
        }
        _ => segs,
    }
}

fn field_path(path: &Path) -> Result<FieldPath, Error> {
    let mut segs = Vec::with_capacity(path.0.len());
    for s in &path.0 {
        segs.push(match s {
            Segment::Field(name) => DocSegment {
                name: name.clone(),
                index: None,
            },
            Segment::Position(p) => index_segment(u64::from(*p)),
            _ => return Err(type_error("PUSH SORT keys must be plain field paths")),
        });
    }
    Ok(FieldPath::from_segments(segs))
}
