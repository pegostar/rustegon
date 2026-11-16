// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Operator semantics (query-language.md §4.1, data-model.md §2.1).
//!
//! - **Three-valued logic**: a predicate is `Some(true)`, `Some(false)` or `None` (unknown);
//!   comparisons with a `null` or `missing` operand are unknown, `IS` tests never are.
//! - **Comparisons** use the §2.1 total order (`1 = 1.0`, strings by bytes, cross-type by class).
//! - **Multikey** (symmetric, query-language.md §4.3): when exactly one operand of `=`, `<`,
//!   `<=`, `>`, `>=`, `IN`, `LIKE`, `ILIKE` or `MATCHES` is an array, the predicate is the
//!   Kleene `OR` of the test over its elements — the semantics secondary indexes implement (one
//!   entry per element). A `null` element makes its test unknown, `[]` gives `false`; two arrays
//!   compare as whole values; `==` always compares whole values. `!=` is `NOT (=)`, so
//!   `tags != 'x'` holds when no element equals `'x'` (and none is `null`).
//! - **Arithmetic** (§4.3): a `missing` operand gives `missing`, else a `null` one `null`; the
//!   numeric rules of the update operators (data-model.md §2.3: `int64` stays `int64`,
//!   `float64` contaminates, `decimal128` wins), but total: overflow, division by zero and type
//!   mismatches yield `null` and count a warning (§4.2 "functions are total"). `/` is true
//!   division (`7 / 2 = 3.5`, a `float64` unless a `decimal128` is involved);
//!   `datetime ± int64` adds milliseconds; `datetime - datetime` is the difference in
//!   milliseconds; an `INTERVAL` literal is its length in milliseconds.

use std::{borrow::Cow, cmp::Ordering};

use rustegon_doc::{
    Decimal128, Document, Value,
    compare::{compare_values, values_equal},
    path::Segment,
    update::{UpdateContext, UpdateOp, UpdatePath, UpdateSegment, apply_updates},
};

use super::{ArithOp, CmpOp, ContainsMode, IsKind};

/// A three-valued truth value (`None` = unknown).
pub type Tri = Option<bool>;

/// Truth of a value used as a predicate: only booleans are true or false.
#[must_use]
pub fn truth(v: Option<&Value>) -> Tri {
    match v {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// The value of a truth value (`unknown` is `null`).
#[must_use]
pub fn tri_value(t: Tri) -> Value {
    t.map_or(Value::Null, Value::Bool)
}

/// Three-valued `NOT`.
#[must_use]
pub fn not(t: Tri) -> Tri {
    t.map(|b| !b)
}

fn is_unknown(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

fn ordering_holds(op: CmpOp, o: Ordering) -> bool {
    match op {
        CmpOp::Eq | CmpOp::EqWhole => o == Ordering::Equal,
        CmpOp::Ne => o != Ordering::Equal,
        CmpOp::Lt => o == Ordering::Less,
        CmpOp::Le => o != Ordering::Greater,
        CmpOp::Gt => o == Ordering::Greater,
        CmpOp::Ge => o != Ordering::Less,
    }
}

/// Evaluates a comparison (module docs).
#[must_use]
pub fn compare(op: CmpOp, l: Option<&Value>, r: Option<&Value>) -> Tri {
    let (Some(l), Some(r)) = (l, r) else {
        return None;
    };
    if matches!(l, Value::Null) || matches!(r, Value::Null) {
        // A `null` operand makes the comparison unknown before any multikey fan-out, so
        // `[] = null` is unknown (not the `false` of an empty Kleene `OR`) and a comparison
        // with a literal `NULL` folds to `null` at bind time (query-language.md §4.3).
        return None;
    }
    match op {
        CmpOp::EqWhole => Some(values_equal(Some(l), Some(r))),
        CmpOp::Ne => not(compare(CmpOp::Eq, Some(l), Some(r))),
        _ => match (l, r) {
            (Value::Array(_), Value::Array(_)) => scalar_compare(op, l, r),
            (Value::Array(items), _) => any(items.iter().map(|e| scalar_compare(op, e, r))),
            (_, Value::Array(items)) => any(items.iter().map(|e| scalar_compare(op, l, e))),
            _ => scalar_compare(op, l, r),
        },
    }
}

/// One comparison of two values in the §2.1 total order (`null` is unknown).
fn scalar_compare(op: CmpOp, l: &Value, r: &Value) -> Tri {
    if matches!(l, Value::Null) || matches!(r, Value::Null) {
        return None;
    }
    Some(ordering_holds(op, compare_values(l, r)))
}

/// Kleene `OR` of a sequence (`false` when empty).
pub fn any(items: impl IntoIterator<Item = Tri>) -> Tri {
    let mut out = Some(false);
    for t in items {
        match t {
            Some(true) => return Some(true),
            None => out = None,
            Some(false) => {}
        }
    }
    out
}

/// Kleene `AND` of a sequence (`true` when empty).
pub fn all(items: impl IntoIterator<Item = Tri>) -> Tri {
    let mut out = Some(true);
    for t in items {
        match t {
            Some(false) => return Some(false),
            None => out = None,
            Some(true) => {}
        }
    }
    out
}

/// `expr IN list` = `expr = e₁ OR expr = e₂ …` (Kleene, multikey); `list` must be an array,
/// otherwise unknown.
#[must_use]
pub fn in_list(v: Option<&Value>, list: Option<&Value>) -> Tri {
    let Some(Value::Array(items)) = list else {
        return None;
    };
    any(items.iter().map(|x| compare(CmpOp::Eq, v, Some(x))))
}

/// Applies a string predicate to a value, element-wise on arrays (multikey, Kleene `OR`); a
/// non-string (including `null`) is unknown, `missing` too.
pub fn string_predicate(v: Option<&Value>, mut f: impl FnMut(&str) -> bool) -> Tri {
    let mut one = |e: &Value| match e {
        Value::String(s) => Some(f(s)),
        _ => None,
    };
    match v {
        None => None,
        Some(Value::Array(items)) => any(items.iter().map(&mut one)),
        Some(other) => one(other),
    }
}

/// SQL `LIKE`: `%` any sequence, `_` one character, `\` escapes the next character.
#[must_use]
pub fn like(text: &str, pattern: &str, case_insensitive: bool) -> bool {
    let (t, p): (Vec<char>, Vec<char>) = if case_insensitive {
        (
            text.to_lowercase().chars().collect(),
            pattern.to_lowercase().chars().collect(),
        )
    } else {
        (text.chars().collect(), pattern.chars().collect())
    };
    like_chars(&t, &p)
}

/// Iterative wildcard matching with backtracking to the last `%` (linear in practice, at worst
/// O(|t|·|p|); no recursion, so no stack growth on long patterns).
fn like_chars(t: &[char], p: &[char]) -> bool {
    let (mut ti, mut pi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('%') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some('_') => {
                ti += 1;
                pi += 1;
            }
            Some('\\') if p.get(pi + 1).is_some_and(|c| *c == t[ti]) => {
                ti += 1;
                pi += 2;
            }
            Some(c) if *c != '\\' && *c == t[ti] => {
                ti += 1;
                pi += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '%')
}

/// `CONTAINS [ANY|ALL]`.
#[must_use]
pub fn contains(l: Option<&Value>, r: Option<&Value>, mode: ContainsMode) -> Tri {
    if is_unknown(l) || is_unknown(r) {
        return None;
    }
    let (Some(l), Some(r)) = (l, r) else {
        return None;
    };
    let has = |needle: &Value| -> Option<bool> {
        match (l, needle) {
            (Value::Array(items), n) => Some(items.iter().any(|e| values_equal(Some(e), Some(n)))),
            (Value::String(s), Value::String(n)) => Some(s.contains(n.as_str())),
            _ => None,
        }
    };
    match mode {
        ContainsMode::One => has(r),
        ContainsMode::Any | ContainsMode::All => {
            let Value::Array(needles) = r else {
                return None;
            };
            // Kleene over the candidates: `ANY []` is `false`, `ALL []` is `true`; a `null`
            // candidate is unknown.
            let each = needles.iter().map(|n| {
                if matches!(n, Value::Null) {
                    None
                } else {
                    has(n)
                }
            });
            if mode == ContainsMode::Any {
                any(each)
            } else {
                all(each)
            }
        }
    }
}

/// `IS [NOT] NULL|MISSING` (never unknown; whole value).
#[must_use]
pub fn is_test(v: Option<&Value>, kind: IsKind, negated: bool) -> bool {
    let hit = match kind {
        IsKind::Null => is_unknown(v),
        IsKind::Missing => v.is_none(),
    };
    hit != negated
}

/// Outcome of an arithmetic operation: `None` means `null` with a warning (module docs).
pub type ArithResult = Option<Value>;

fn is_number(v: &Value) -> bool {
    matches!(
        v,
        Value::Int64(_) | Value::Float64(_) | Value::Decimal(_) | Value::Counter(_)
    )
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        // Exactness is not required here: only used when a float is already involved.
        #[allow(clippy::cast_precision_loss)]
        Value::Int64(i) | Value::Counter(i) => Some(*i as f64),
        Value::Float64(f) => Some(*f),
        Value::Decimal(d) => d.to_string().parse().ok(),
        _ => None,
    }
}

/// `float64` → `decimal128` through the shortest round-trip text (data-model.md §2.3).
fn f64_to_dec(f: f64) -> Option<Value> {
    if f.is_nan() {
        return Some(Value::Decimal(Decimal128::NaN));
    }
    if f.is_infinite() {
        return Some(Value::Decimal(Decimal128::Infinity { negative: f < 0.0 }));
    }
    Decimal128::parse(&format!("{f:e}"))
        .ok()
        .map(Value::Decimal)
}

/// Adds or multiplies two numbers with the update-operator numeric rules (exactly the `INC` /
/// `MUL` arithmetic of `rustegon_doc::update`, reused so both layers agree on every type pair).
fn update_arith(a: &Value, b: &Value, mul: bool) -> Option<Value> {
    let mut d = Document::new();
    d.insert("v", a.clone());
    let path = UpdatePath::new(vec![UpdateSegment::Field(Segment {
        name: "v".to_owned(),
        index: None,
    })]);
    let op = if mul {
        UpdateOp::Mul {
            path,
            by: b.clone(),
        }
    } else {
        UpdateOp::Inc {
            path,
            by: b.clone(),
        }
    };
    let out = apply_updates(&d, &[op], &UpdateContext { now_ms: 0 }).ok()?;
    out.get("v").cloned()
}

/// Negates a number (`int64::MIN` overflows → `None`).
#[must_use]
pub fn negate(v: &Value) -> ArithResult {
    match v {
        Value::Int64(i) | Value::Counter(i) => i.checked_neg().map(Value::Int64),
        Value::Float64(f) => Some(Value::Float64(-f)),
        Value::Decimal(d) => Some(Value::Decimal(match *d {
            Decimal128::Finite {
                negative,
                coefficient,
                exponent,
            } => Decimal128::Finite {
                negative: !negative,
                coefficient,
                exponent,
            },
            Decimal128::Infinity { negative } => Decimal128::Infinity {
                negative: !negative,
            },
            Decimal128::NaN => Decimal128::NaN,
        })),
        _ => None,
    }
}

/// Binary arithmetic and concatenation on present, non-null operands (module docs).
#[must_use]
pub fn arith(op: ArithOp, a: &Value, b: &Value) -> ArithResult {
    use Value as V;
    match (op, a, b) {
        (ArithOp::Concat, V::String(x), V::String(y)) => Some(V::String(format!("{x}{y}"))),
        (ArithOp::Concat, V::Array(x), V::Array(y)) => {
            Some(V::Array(x.iter().chain(y).cloned().collect()))
        }
        (ArithOp::Concat, ..) => None,
        // `datetime ± int64` only (§4.3): fractional or decimal milliseconds have no defined
        // rounding, and `int64 + datetime` is not a documented form.
        (ArithOp::Add, V::DateTime(d), V::Int64(n)) => d.checked_add(*n).map(V::DateTime),
        (ArithOp::Sub, V::DateTime(d), V::Int64(n)) => d.checked_sub(*n).map(V::DateTime),
        (ArithOp::Sub, V::DateTime(x), V::DateTime(y)) => x.checked_sub(*y).map(V::Int64),
        _ if !is_number(a) || !is_number(b) => None,
        (ArithOp::Add, V::Int64(x), V::Int64(y)) => x.checked_add(*y).map(V::Int64),
        (ArithOp::Sub, V::Int64(x), V::Int64(y)) => x.checked_sub(*y).map(V::Int64),
        (ArithOp::Mul, V::Int64(x), V::Int64(y)) => x.checked_mul(*y).map(V::Int64),
        (ArithOp::Add, V::Float64(x), V::Float64(y)) => Some(V::Float64(x + y)),
        (ArithOp::Add, ..) => update_arith(a, b, false),
        (ArithOp::Sub, ..) => update_arith(a, &negate(b)?, false),
        (ArithOp::Mul, ..) => update_arith(a, b, true),
        (ArithOp::Div, ..) => divide(a, b, false),
        (ArithOp::Mod, ..) => divide(a, b, true),
    }
}

/// `/` and `%` (division by zero → `None`).
#[allow(clippy::many_single_char_names)] // Operands `a / b`, their values `x / y`, result `r`.
fn divide(a: &Value, b: &Value, modulo: bool) -> ArithResult {
    if let (Value::Int64(x), Value::Int64(y)) = (a, b) {
        if *y == 0 {
            return None;
        }
        if modulo {
            return x.checked_rem(*y).map(Value::Int64);
        }
    }
    let (x, y) = (as_f64(a)?, as_f64(b)?);
    if y == 0.0 {
        return None;
    }
    let r = if modulo { x % y } else { x / y };
    if matches!(a, Value::Decimal(_)) || matches!(b, Value::Decimal(_)) {
        f64_to_dec(r)
    } else {
        Some(Value::Float64(r))
    }
}

/// Converts a value to `f64` when it is a number.
#[must_use]
pub fn number_f64(v: &Value) -> Option<f64> {
    if is_number(v) { as_f64(v) } else { None }
}

/// Whether the value is a number.
#[must_use]
pub fn is_numeric(v: &Value) -> bool {
    is_number(v)
}

/// `f64` → `decimal128` (shortest round-trip text).
#[must_use]
pub fn float_to_decimal(f: f64) -> Option<Value> {
    f64_to_dec(f)
}

/// An integer argument (`int64`, or a float / decimal with an integral value).
#[must_use]
pub fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int64(i) | Value::Counter(i) => Some(*i),
        Value::Float64(f) if f.fract() == 0.0 && f.is_finite() => {
            // Range-checked: only exact integral values within i64 are accepted.
            #[allow(clippy::cast_possible_truncation)]
            let i = *f as i64;
            #[allow(clippy::cast_precision_loss)]
            let back = i as f64;
            // Exact comparison intended: the round trip must be lossless.
            #[allow(clippy::float_cmp)]
            let exact = back == *f;
            exact.then_some(i)
        }
        Value::Decimal(_) => as_f64(v).and_then(|f| as_int(&Value::Float64(f))),
        _ => None,
    }
}

/// Approximate in-memory size of a value in bytes (for memory limits; not an exact count).
#[must_use]
pub fn approx_size(v: &Value) -> usize {
    const BASE: usize = 32;
    BASE + match v {
        Value::String(s) => s.len(),
        Value::Binary { data, .. } => data.len(),
        Value::Array(items) => items.iter().map(approx_size).sum(),
        Value::Object(d) => d.iter().map(|(n, v)| n.len() + approx_size(v)).sum(),
        Value::VectorF32(x) => x.len() * 4,
        _ => 0,
    }
}

/// Clones a borrowed or owned value.
#[must_use]
pub fn owned(v: Option<Cow<'_, Value>>) -> Option<Value> {
    v.map(Cow::into_owned)
}
