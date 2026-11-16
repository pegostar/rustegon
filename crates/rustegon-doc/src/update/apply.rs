// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Validation and application of update operators (FR-DOC-006). Semantics and error order are
//! documented on the parent module; the reference interpreter of TC-DOC-009…012 re-implements
//! them independently.

use std::cmp::Ordering;

use super::{
    ElementPredicate, PopEnd, Push, PushSort, UpdateContext, UpdateError, UpdateOp, UpdatePath,
    UpdateResult, UpdateSegment,
    arith::{self, ArithError, ArithOp},
};
use crate::{
    compare::{compare, compare_values, values_equal},
    decimal::Decimal128,
    error::DocError,
    keyenc::Direction,
    limits::{SERVER_MAINTAINED_FIELDS, validate_field_name},
    path::{FieldPath, Segment, get_path},
    value::{Document, Value},
};

/// The immutable document key (FR-DOC-002).
const ID: &str = "_id";

/// Applies `ops` to `doc` atomically and returns the updated document (FR-DOC-006).
///
/// # Errors
/// The first error in the order documented on [`crate::update`]: `RGN-1004` (field names,
/// server-maintained fields, unstorable values), `RGN-1001` (`_id` change, conflicting paths,
/// array index past the end, numeric overflow, malformed operator), `RGN-1011` (type mismatch),
/// or the error of a caller-supplied predicate. On error `doc` is unchanged (it is only read).
pub fn apply_updates(
    doc: &Document,
    ops: &[UpdateOp],
    ctx: &UpdateContext,
) -> UpdateResult<Document> {
    let mut skip = Vec::with_capacity(ops.len());
    for op in ops {
        skip.push(validate(doc, op)?);
    }
    check_conflicts(ops)?;
    // Atomicity: every operator mutates this copy; an error drops it and `doc` is untouched.
    let mut root = doc.clone();
    for (op, skip) in ops.iter().zip(skip) {
        if !skip {
            apply_op(&mut root, op, *ctx)?;
        }
    }
    Ok(root)
}

// ---------------------------------------------------------------- validation

/// The target paths of an operator (`RENAME`: source, then destination).
fn op_paths(op: &UpdateOp) -> Vec<&UpdatePath> {
    match op {
        UpdateOp::Set { path, .. }
        | UpdateOp::Unset { path }
        | UpdateOp::Inc { path, .. }
        | UpdateOp::Mul { path, .. }
        | UpdateOp::Min { path, .. }
        | UpdateOp::Max { path, .. }
        | UpdateOp::CurrentDate { path }
        | UpdateOp::Push(Push { path, .. })
        | UpdateOp::Pull { path, .. }
        | UpdateOp::PullAll { path, .. }
        | UpdateOp::AddToSet { path, .. }
        | UpdateOp::Pop { path, .. } => vec![path],
        UpdateOp::Rename { from, to } => vec![from, to],
    }
}

fn first_field(path: &UpdatePath) -> Option<&str> {
    match path.segments().first() {
        Some(UpdateSegment::Field(s)) => Some(s.name.as_str()),
        _ => None,
    }
}

/// Static checks of one operator; returns `true` when it is a no-op to skip (`SET _id` to an
/// equal value).
fn validate(doc: &Document, op: &UpdateOp) -> UpdateResult<bool> {
    let paths = op_paths(op);
    for path in &paths {
        if path.segments().is_empty() {
            return Err(UpdateError::InvalidOperator("empty path".into()));
        }
        for seg in path.segments() {
            if let UpdateSegment::Field(s) = seg {
                validate_field_name(&s.name)?;
            }
        }
    }
    for path in &paths {
        if let Some(name) = first_field(path).filter(|n| SERVER_MAINTAINED_FIELDS.contains(n)) {
            return Err(
                DocError::InvalidFieldName(format!("{name} is maintained by the server")).into(),
            );
        }
    }
    let mut skip = false;
    for path in &paths {
        if first_field(path) == Some(ID) {
            // AC-DOC-003: changing `_id` is RGN-1001. Setting it to an equal value (same key
            // encoding, §2.1 equality) changes nothing and is accepted as a no-op, as a replace
            // carrying the unchanged `_id` is.
            let same = match op {
                UpdateOp::Set { value, .. } if path.segments().len() == 1 => doc
                    .get(ID)
                    .is_some_and(|cur| values_equal(Some(cur), Some(value))),
                _ => false,
            };
            if !same {
                return Err(UpdateError::ImmutableId);
            }
            skip = true;
        }
    }
    validate_operands(op)?;
    Ok(skip)
}

fn validate_operands(op: &UpdateOp) -> UpdateResult<()> {
    match op {
        UpdateOp::Set { value, .. } | UpdateOp::Min { value, .. } | UpdateOp::Max { value, .. } => {
            check_storable(value)
        }
        UpdateOp::Push(Push { values, .. }) | UpdateOp::AddToSet { values, .. } => {
            values.iter().try_for_each(check_storable)
        }
        UpdateOp::Inc { path, by } | UpdateOp::Mul { path, by } => {
            if arith::is_numeric(by) {
                Ok(())
            } else {
                Err(UpdateError::TypeMismatch(
                    path.display(),
                    "operand is not a number",
                ))
            }
        }
        UpdateOp::Rename { from, to } => {
            let positional = |p: &UpdatePath| {
                p.segments()
                    .iter()
                    .any(|s| !matches!(s, UpdateSegment::Field(_)))
            };
            if positional(from) || positional(to) {
                Err(UpdateError::InvalidOperator(
                    "RENAME paths cannot contain positional segments".into(),
                ))
            } else {
                Ok(())
            }
        }
        UpdateOp::Unset { .. }
        | UpdateOp::CurrentDate { .. }
        | UpdateOp::Pull { .. }
        | UpdateOp::PullAll { .. }
        | UpdateOp::Pop { .. } => Ok(()),
    }
}

/// A value written into the document must obey the stored-document rules: valid field names at
/// every level (§2.2) and no `counter` (read-only projection) — `RGN-1004`.
fn check_storable(v: &Value) -> UpdateResult<()> {
    match v {
        Value::Counter(_) => Err(DocError::InvalidFieldName(
            "counter values are read-only and cannot be stored".into(),
        )
        .into()),
        Value::Array(items) => items.iter().try_for_each(check_storable),
        Value::Object(d) => d.iter().try_for_each(|(name, v)| {
            validate_field_name(name)?;
            check_storable(v)
        }),
        _ => Ok(()),
    }
}

/// Two targets conflict when one is equal to or a prefix of the other; positional segments match
/// any segment (the elements they select are not known statically).
fn check_conflicts(ops: &[UpdateOp]) -> UpdateResult<()> {
    let paths: Vec<&UpdatePath> = ops.iter().flat_map(op_paths).collect();
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            let overlap = a
                .segments()
                .iter()
                .zip(b.segments())
                .all(|pair| match pair {
                    (UpdateSegment::Field(x), UpdateSegment::Field(y)) => x.name == y.name,
                    _ => true,
                });
            if overlap {
                return Err(UpdateError::ConflictingPaths(a.display(), b.display()));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- application

/// What an operator does to its target slot.
enum Action {
    Keep,
    Replace(Value),
    Remove,
}

/// Whether an operator creates its target (and missing intermediate objects).
fn creates(op: &UpdateOp) -> bool {
    matches!(
        op,
        UpdateOp::Set { .. }
            | UpdateOp::Inc { .. }
            | UpdateOp::Mul { .. }
            | UpdateOp::Min { .. }
            | UpdateOp::Max { .. }
            | UpdateOp::CurrentDate { .. }
            | UpdateOp::Push(_)
            | UpdateOp::AddToSet { .. }
    )
}

fn apply_op(root: &mut Document, op: &UpdateOp, ctx: UpdateContext) -> UpdateResult<()> {
    if let UpdateOp::Rename { from, to } = op {
        return rename(root, from, to);
    }
    let Some(path) = op_paths(op).into_iter().next() else {
        return Ok(());
    };
    let walk = Walk {
        path,
        creates: creates(op),
    };
    let mut f = |old: Option<&mut Value>| transform(op, old, ctx, path);
    match path.segments().split_first() {
        Some((UpdateSegment::Field(s), rest)) => walk.object(root, s, rest, &mut f),
        Some(_) => Err(walk.not_array()),
        None => Ok(()),
    }
}

type SlotFn<'f> = dyn FnMut(Option<&mut Value>) -> UpdateResult<Action> + 'f;

/// Path resolution of [`UpdatePath`] (documented there), calling the operator on every target.
struct Walk<'p> {
    path: &'p UpdatePath,
    creates: bool,
}

impl Walk<'_> {
    fn not_array(&self) -> UpdateError {
        UpdateError::TypeMismatch(self.path.display(), "positional segment requires an array")
    }

    fn object(
        &self,
        d: &mut Document,
        s: &Segment,
        rest: &[UpdateSegment],
        f: &mut SlotFn<'_>,
    ) -> UpdateResult<()> {
        if rest.is_empty() {
            match f(d.get_mut(&s.name))? {
                Action::Keep => {}
                Action::Replace(v) => {
                    d.insert(s.name.clone(), v);
                }
                Action::Remove => {
                    d.remove(&s.name);
                }
            }
            return Ok(());
        }
        if d.get(&s.name).is_none() {
            if !self.creates {
                return Ok(());
            }
            d.insert(s.name.clone(), Value::Object(Document::new()));
        }
        match d.get_mut(&s.name) {
            Some(child) => self.value(child, rest, f),
            None => Ok(()),
        }
    }

    fn value(
        &self,
        cur: &mut Value,
        segs: &[UpdateSegment],
        f: &mut SlotFn<'_>,
    ) -> UpdateResult<()> {
        let Some((seg, rest)) = segs.split_first() else {
            return Ok(());
        };
        match (seg, cur) {
            (UpdateSegment::Field(s), Value::Object(d)) => self.object(d, s, rest, f),
            (UpdateSegment::Field(s), Value::Array(items)) => {
                match s.index.filter(|i| *i < items.len()) {
                    Some(i) => self.element(items, i, rest, f),
                    None if !self.creates => Ok(()),
                    None if s.index.is_some() => Err(UpdateError::InvalidOperator(format!(
                        "array index past the end in '{}'",
                        self.path.display()
                    ))),
                    None => Err(UpdateError::TypeMismatch(
                        self.path.display(),
                        "cannot create a field inside an array",
                    )),
                }
            }
            (UpdateSegment::Field(_), _) if self.creates => Err(UpdateError::TypeMismatch(
                self.path.display(),
                "cannot create a field inside a scalar",
            )),
            (UpdateSegment::Field(_), _) => Ok(()),
            (UpdateSegment::AllElements, Value::Array(items)) => {
                (0..items.len()).try_for_each(|i| self.element(items, i, rest, f))
            }
            (UpdateSegment::Filtered(p), Value::Array(items)) => {
                for i in 0..items.len() {
                    if p.matches(&items[i]).map_err(UpdateError::Predicate)? {
                        self.element(items, i, rest, f)?;
                    }
                }
                Ok(())
            }
            _ => Err(self.not_array()),
        }
    }

    fn element(
        &self,
        items: &mut [Value],
        i: usize,
        rest: &[UpdateSegment],
        f: &mut SlotFn<'_>,
    ) -> UpdateResult<()> {
        if !rest.is_empty() {
            return self.value(&mut items[i], rest, f);
        }
        match f(Some(&mut items[i]))? {
            Action::Keep => {}
            Action::Replace(v) => items[i] = v,
            // Removing an element would shift its successors: it becomes null instead.
            Action::Remove => items[i] = Value::Null,
        }
        Ok(())
    }
}

/// The effect of `op` on one target slot (`None` = missing).
fn transform(
    op: &UpdateOp,
    old: Option<&mut Value>,
    ctx: UpdateContext,
    path: &UpdatePath,
) -> UpdateResult<Action> {
    let arith_err = |e: ArithError| match e {
        ArithError::NotNumeric => {
            UpdateError::TypeMismatch(path.display(), "target is not a number")
        }
        ArithError::Overflow => UpdateError::NumericOverflow(path.display()),
    };
    let not_array = || UpdateError::TypeMismatch(path.display(), "target is not an array");
    Ok(match (op, old) {
        (UpdateOp::Set { value, .. }, _) => Action::Replace(value.clone()),
        (UpdateOp::Unset { .. }, old) => {
            if old.is_some() {
                Action::Remove
            } else {
                Action::Keep
            }
        }
        (UpdateOp::Inc { by, .. }, None) => Action::Replace(by.clone()),
        (UpdateOp::Inc { by, .. }, Some(cur)) => {
            Action::Replace(arith::apply(ArithOp::Add, cur, by).map_err(arith_err)?)
        }
        (UpdateOp::Mul { by, .. }, None) => Action::Replace(zero_like(by)),
        (UpdateOp::Mul { by, .. }, Some(cur)) => {
            Action::Replace(arith::apply(ArithOp::Mul, cur, by).map_err(arith_err)?)
        }
        (UpdateOp::Min { value, .. } | UpdateOp::Max { value, .. }, None) => {
            Action::Replace(value.clone())
        }
        (UpdateOp::Min { value, .. }, Some(cur)) => replace_if(value, cur, Ordering::Less),
        (UpdateOp::Max { value, .. }, Some(cur)) => replace_if(value, cur, Ordering::Greater),
        (UpdateOp::CurrentDate { .. }, _) => Action::Replace(Value::DateTime(ctx.now_ms)),
        (UpdateOp::Push(p), None) => {
            let mut items = Vec::new();
            push(&mut items, p);
            Action::Replace(Value::Array(items))
        }
        (UpdateOp::AddToSet { values, .. }, None) => {
            let mut items = Vec::new();
            add_to_set(&mut items, values);
            Action::Replace(Value::Array(items))
        }
        (UpdateOp::Pull { .. } | UpdateOp::PullAll { .. } | UpdateOp::Pop { .. }, None)
        | (UpdateOp::Rename { .. }, _) => Action::Keep,
        (_, Some(Value::Array(items))) => {
            array_op(op, items)?;
            Action::Keep
        }
        (_, Some(_)) => return Err(not_array()),
    })
}

/// In-place array operators on an existing array.
fn array_op(op: &UpdateOp, items: &mut Vec<Value>) -> UpdateResult<()> {
    match op {
        UpdateOp::Push(p) => push(items, p),
        UpdateOp::AddToSet { values, .. } => add_to_set(items, values),
        UpdateOp::Pull { predicate, .. } => pull(items, predicate)?,
        UpdateOp::PullAll { values, .. } => {
            items.retain(|e| !values.iter().any(|v| values_equal(Some(e), Some(v))));
        }
        UpdateOp::Pop {
            end: PopEnd::First, ..
        } if !items.is_empty() => {
            items.remove(0);
        }
        UpdateOp::Pop {
            end: PopEnd::Last, ..
        } => {
            items.pop();
        }
        _ => {}
    }
    Ok(())
}

fn replace_if(candidate: &Value, cur: &Value, wanted: Ordering) -> Action {
    if compare_values(candidate, cur) == wanted {
        Action::Replace(candidate.clone())
    } else {
        Action::Keep
    }
}

/// `MUL` on a missing field stores zero of the factor's type (MongoDB `$mul`).
fn zero_like(by: &Value) -> Value {
    match by {
        Value::Float64(_) => Value::Float64(0.0),
        Value::Decimal(_) => Value::Decimal(Decimal128::from_i64(0)),
        _ => Value::Int64(0),
    }
}

/// `PUSH` with its modifiers in MongoDB order: position, sort, slice.
fn push(items: &mut Vec<Value>, p: &Push) {
    let len = items.len();
    let at = match p.position {
        None => len,
        Some(n) if n >= 0 => usize::try_from(n).unwrap_or(usize::MAX).min(len),
        Some(n) => len.saturating_sub(usize::try_from(n.unsigned_abs()).unwrap_or(usize::MAX)),
    };
    items.splice(at..at, p.values.iter().cloned());
    if let Some(sort) = &p.sort {
        // `sort_by` is stable: equal keys keep their relative order.
        items.sort_by(|a, b| sort_cmp(sort, a, b));
    }
    if let Some(n) = p.slice {
        if n >= 0 {
            items.truncate(usize::try_from(n).unwrap_or(usize::MAX));
        } else {
            let keep = usize::try_from(n.unsigned_abs()).unwrap_or(usize::MAX);
            let excess = items.len().saturating_sub(keep);
            items.drain(..excess);
        }
    }
}

fn directed(o: Ordering, dir: Direction) -> Ordering {
    match dir {
        Direction::Ascending => o,
        Direction::Descending => o.reverse(),
    }
}

fn sort_cmp(sort: &PushSort, a: &Value, b: &Value) -> Ordering {
    match sort {
        PushSort::Elements(dir) => directed(compare_values(a, b), *dir),
        PushSort::Fields(keys) => {
            fn field<'v>(v: &'v Value, p: &FieldPath) -> Option<&'v Value> {
                match v {
                    Value::Object(d) => get_path(d, p),
                    _ => None,
                }
            }
            keys.iter()
                .map(|(p, dir)| directed(compare(field(a, p), field(b, p)), *dir))
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        }
    }
}

fn add_to_set(items: &mut Vec<Value>, values: &[Value]) {
    for v in values {
        if !items.iter().any(|e| values_equal(Some(e), Some(v))) {
            items.push(v.clone());
        }
    }
}

fn pull(items: &mut Vec<Value>, predicate: &ElementPredicate) -> UpdateResult<()> {
    let mut kept = Vec::with_capacity(items.len());
    for e in items.drain(..) {
        if !predicate.matches(&e).map_err(UpdateError::Predicate)? {
            kept.push(e);
        }
    }
    *items = kept;
    Ok(())
}

// ---------------------------------------------------------------- RENAME

fn field_names(path: &UpdatePath) -> Vec<&str> {
    path.segments()
        .iter()
        .filter_map(|s| match s {
            UpdateSegment::Field(f) => Some(f.name.as_str()),
            _ => None,
        })
        .collect()
}

/// `RENAME`: detach `from` (no-op when missing), then store it at `to`. Both paths are object
/// fields only (validated: no positional segments); traversing an array is `RGN-1011`.
fn rename(root: &mut Document, from: &UpdatePath, to: &UpdatePath) -> UpdateResult<()> {
    let array_err = |p: &UpdatePath| {
        UpdateError::TypeMismatch(p.display(), "RENAME paths must traverse objects only")
    };
    let Some(v) = take_field(root, &field_names(from)).map_err(|()| array_err(from))? else {
        return Ok(());
    };
    put_field(root, &field_names(to), v).map_err(|()| array_err(to))
}

/// Removes and returns the field at `names`; `Err` when an array is on the way.
fn take_field(d: &mut Document, names: &[&str]) -> Result<Option<Value>, ()> {
    match names {
        [] => Ok(None),
        [last] => Ok(d.remove(last)),
        [first, rest @ ..] => match d.get_mut(first) {
            Some(Value::Object(child)) => take_field(child, rest),
            Some(Value::Array(_)) => Err(()),
            _ => Ok(None),
        },
    }
}

/// Stores `v` at `names`, creating missing intermediate objects; `Err` when a non-object is on
/// the way.
fn put_field(d: &mut Document, names: &[&str], v: Value) -> Result<(), ()> {
    match names {
        [] => Ok(()),
        [last] => {
            d.insert(*last, v);
            Ok(())
        }
        [first, rest @ ..] => {
            if d.get(first).is_none() {
                d.insert(*first, Value::Object(Document::new()));
            }
            match d.get_mut(first) {
                Some(Value::Object(child)) => put_field(child, rest, v),
                _ => Err(()),
            }
        }
    }
}
