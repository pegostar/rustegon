// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Comparison-level operators (query-language.md §4.1 level 5) of the reference interpreter.
//!
//! - **`missing` / `null`.** An operand that is `missing` or `null` makes every comparison
//!   *unknown* (§4.1); only `IS` tests (in [`super::eval`]) see the difference.
//! - **Scalars** compare in the data-model §2.1 total order (`1 = 1.0`; `5 < 'a'` is `true`
//!   because numbers sort before strings; no type bracketing).
//! - **Arrays (multikey).** When exactly one operand is an array, `a op b` is the Kleene `OR` of
//!   `e op b` over its elements `e` (so `tags = 'x'` is "some element equals `'x'`", and a `null`
//!   element is *unknown*); when both are arrays they compare as whole values (§2.1). `==`
//!   always compares whole values. `!=` is `NOT (=)`, so `tags != 'x'` means "no element is
//!   `'x'`" (*Provisional*).
//! - **`IN`.** `x IN arr` is `x = e₁ OR x = e₂ OR …` with the `=` above (`false` for `[]`); a
//!   right operand that is not an array is *unknown*. `NOT IN` is its negation.
//! - **`LIKE` / `ILIKE`.** `%` any sequence, `_` one character, `\` escapes the next character;
//!   whole-string match on Unicode scalar values; `ILIKE` lowercases both sides
//!   (`str::to_lowercase`). `MATCHES` is an unanchored search with the Rust `regex` syntax; an
//!   invalid pattern is *unknown*. A non-string operand is *unknown*; an array left operand is
//!   multikey as above (*Provisional*).
//! - **`CONTAINS v`.** On an array: some element `=` `v` (whole-value §2.1 equality); on a string
//!   with a string `v`: substring. `CONTAINS ANY` / `CONTAINS ALL` take an array of candidates
//!   (`ANY []` is `false`, `ALL []` is `true`). Other operand types are *unknown*.

use std::cmp::Ordering;

use rustegon_doc::{
    Value,
    compare::{compare_values, values_equal},
};

use super::eval::{Tri, Val};
use crate::ast::BinaryOp;

/// `l op r` for `= == != < <= > >=` (module docs).
#[must_use]
pub fn compare_op(op: BinaryOp, l: &Val, r: &Val) -> Tri {
    let (Some(l), Some(r)) = (l, r) else {
        return Tri::Unknown;
    };
    if is_null(l) || is_null(r) {
        // Checked before the multikey fan-out: `[] = null` is unknown, not the `false` of an
        // empty Kleene `OR` (query-language.md §4.3).
        return Tri::Unknown;
    }
    match op {
        BinaryOp::Ne => compare_op(BinaryOp::Eq, &Some(l.clone()), &Some(r.clone())).negate(),
        BinaryOp::EqWhole => Tri::from(values_equal(Some(l), Some(r))),
        _ => multikey(l, r, |a, b| scalar(op, a, b)),
    }
}

/// Applies a scalar test with multikey semantics: an array on exactly one side fans out.
fn multikey(l: &Value, r: &Value, test: impl Fn(&Value, &Value) -> Tri) -> Tri {
    match (l, r) {
        (Value::Array(_), Value::Array(_)) => test(l, r),
        (Value::Array(items), _) => Tri::any(items.iter().map(|e| test(e, r))),
        (_, Value::Array(items)) => Tri::any(items.iter().map(|e| test(l, e))),
        _ => test(l, r),
    }
}

fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

/// One comparison of two values in the §2.1 total order; `null` is unknown.
fn scalar(op: BinaryOp, a: &Value, b: &Value) -> Tri {
    if is_null(a) || is_null(b) {
        return Tri::Unknown;
    }
    let ord = compare_values(a, b);
    Tri::from(match op {
        BinaryOp::Eq | BinaryOp::EqWhole => ord == Ordering::Equal,
        BinaryOp::Ne => ord != Ordering::Equal,
        BinaryOp::Lt => ord == Ordering::Less,
        BinaryOp::Le => ord != Ordering::Greater,
        BinaryOp::Gt => ord == Ordering::Greater,
        BinaryOp::Ge => ord != Ordering::Less,
        _ => return Tri::Unknown,
    })
}

/// `x IN arr`.
#[must_use]
pub fn in_list(x: &Val, list: &Val) -> Tri {
    match list {
        Some(Value::Array(items)) => Tri::any(
            items
                .iter()
                .map(|e| compare_op(BinaryOp::Eq, x, &Some(e.clone()))),
        ),
        _ => Tri::Unknown,
    }
}

/// `s LIKE p` / `s ILIKE p`.
#[must_use]
pub fn like(s: &Val, pattern: &Val, case_insensitive: bool) -> Tri {
    let Some(Value::String(p)) = pattern else {
        return Tri::Unknown;
    };
    let p: Vec<char> = if case_insensitive {
        p.to_lowercase().chars().collect()
    } else {
        p.chars().collect()
    };
    string_test(s, |text| {
        let t: Vec<char> = if case_insensitive {
            text.to_lowercase().chars().collect()
        } else {
            text.chars().collect()
        };
        like_match(&t, &p)
    })
}

/// `s MATCHES regex`.
#[must_use]
pub fn matches(s: &Val, pattern: &Val) -> Tri {
    let Some(Value::String(p)) = pattern else {
        return Tri::Unknown;
    };
    let Ok(re) = regex::Regex::new(p) else {
        return Tri::Unknown;
    };
    string_test(s, |text| re.is_match(text))
}

/// Applies a string test to a string or, multikey, to the elements of an array.
fn string_test(subject: &Val, check: impl Fn(&str) -> bool) -> Tri {
    let one = |v: &Value| match v {
        Value::String(text) => Tri::from(check(text)),
        _ => Tri::Unknown,
    };
    match subject {
        Some(Value::Array(items)) => Tri::any(items.iter().map(one)),
        Some(v) => one(v),
        None => Tri::Unknown,
    }
}

/// Classic `LIKE` matcher by dynamic programming over (text position, pattern position).
fn like_match(text: &[char], pattern: &[char]) -> bool {
    // Tokenise the pattern first so the escape is handled once.
    enum Tok {
        Any,
        One,
        Lit(char),
    }
    let mut toks = Vec::with_capacity(pattern.len());
    let mut it = pattern.iter();
    while let Some(&c) = it.next() {
        toks.push(match c {
            '%' => Tok::Any,
            '_' => Tok::One,
            // A trailing backslash matches itself.
            '\\' => Tok::Lit(it.next().copied().unwrap_or('\\')),
            c => Tok::Lit(c),
        });
    }
    // reach[j] = the pattern prefix of length j matches the text prefix processed so far.
    let mut reach = vec![false; toks.len() + 1];
    reach[0] = true;
    for j in 0..toks.len() {
        if matches!(toks[j], Tok::Any) && reach[j] {
            reach[j + 1] = true;
        }
    }
    for &c in text {
        let mut next = vec![false; toks.len() + 1];
        for j in 0..toks.len() {
            next[j + 1] = match toks[j] {
                Tok::Any => reach[j + 1] || next[j],
                Tok::One => reach[j],
                Tok::Lit(l) => reach[j] && l == c,
            };
        }
        reach = next;
    }
    reach[toks.len()]
}

/// `container CONTAINS v`.
#[must_use]
pub fn contains(container: &Val, v: &Val) -> Tri {
    match (container, v) {
        (None | Some(Value::Null), _) | (_, None | Some(Value::Null)) => Tri::Unknown,
        (Some(Value::Array(items)), Some(v)) => {
            Tri::from(items.iter().any(|e| values_equal(Some(e), Some(v))))
        }
        (Some(Value::String(s)), Some(Value::String(sub))) => Tri::from(s.contains(sub.as_str())),
        _ => Tri::Unknown,
    }
}

/// `container CONTAINS ANY list` (`all` = false) / `CONTAINS ALL list` (`all` = true).
#[must_use]
pub fn contains_set(container: &Val, list: &Val, all: bool) -> Tri {
    let Some(Value::Array(candidates)) = list else {
        return Tri::Unknown;
    };
    if matches!(container, None | Some(Value::Null)) {
        // A `missing` / `null` operand is unknown even for an empty candidate list (§4.3).
        return Tri::Unknown;
    }
    let each = candidates
        .iter()
        .map(|c| contains(container, &Some(c.clone())));
    if all { Tri::all(each) } else { Tri::any(each) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)] // `Val` is the operand type.
    fn s(t: &str) -> Val {
        Some(Value::String(t.into()))
    }

    #[test]
    fn like_wildcards_and_escape() {
        let cases = [
            ("abc", "a%", true),
            ("abc", "%c", true),
            ("abc", "a_c", true),
            ("abc", "a_", false),
            ("", "%", true),
            ("", "_", false),
            ("a%c", "a\\%c", true),
            ("abc", "a\\%c", false),
            ("aXbXc", "%X%X%", true),
        ];
        for (text, pat, want) in cases {
            assert_eq!(
                like(&s(text), &s(pat), false),
                Tri::from(want),
                "{text} {pat}"
            );
        }
        assert_eq!(like(&s("ABC"), &s("a%"), true), Tri::True);
        assert_eq!(like(&Some(Value::Int64(1)), &s("1"), false), Tri::Unknown);
    }
}
