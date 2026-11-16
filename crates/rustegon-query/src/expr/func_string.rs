// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! String functions (query-language.md §4.2).
//!
//! *Provisional (PD pending)* conventions, not fixed by the specification: positions and
//! lengths count Unicode scalar values (not bytes); `substr(s, start [, len])` and `index_of`
//! are 0-based (`index_of` returns -1 when absent); `length` is for strings only (`size` counts array elements);
//! `format(fmt, …)` replaces each `{}` with the next argument (`to_string` form) and `{{`/`}}`
//! with braces; `regex_extract(s, re [, group])` returns the first match (or capture group)
//! or `null`.

use rustegon_doc::Value;

use super::{EvalCtx, Func, func, ops};

/// Evaluates a string function on present, non-null arguments.
pub(super) fn call(f: Func, a: &[Value], ctx: &EvalCtx) -> Option<Value> {
    if f == Func::Length {
        // A string function only: arrays are counted by `size` (query-language.md §4.2/§4.3;
        // TC-QL-010 seed 6840335469013540751).
        return match &a[0] {
            Value::String(s) => i64::try_from(s.chars().count()).ok().map(Value::Int64),
            _ => None,
        };
    }
    if f == Func::Format {
        return format(a);
    }
    let Value::String(s) = &a[0] else {
        return None;
    };
    let text = |i: usize| match a.get(i) {
        Some(Value::String(t)) => Some(t.as_str()),
        _ => None,
    };
    let int = |i: usize| a.get(i).and_then(ops::as_int);
    let string = |t: String| Some(Value::String(t));
    match f {
        Func::Lower => string(s.to_lowercase()),
        Func::Upper => string(s.to_uppercase()),
        Func::Trim => string(s.trim().to_owned()),
        Func::Ltrim => string(s.trim_start().to_owned()),
        Func::Rtrim => string(s.trim_end().to_owned()),
        Func::Substr => {
            let start = usize::try_from(int(1)?).ok()?;
            let chars = s.chars().skip(start);
            match a.get(2) {
                Some(_) => string(chars.take(usize::try_from(int(2)?).ok()?).collect()),
                None => string(chars.collect()),
            }
        }
        Func::IndexOf => {
            let needle = text(1)?;
            Some(Value::Int64(match s.find(needle) {
                Some(byte) => i64::try_from(s[..byte].chars().count()).ok()?,
                None => -1,
            }))
        }
        Func::Replace => string(s.replace(text(1)?, text(2)?)),
        Func::Split => {
            let sep = text(1)?;
            if sep.is_empty() {
                return Some(Value::Array(
                    s.chars().map(|c| Value::String(c.to_string())).collect(),
                ));
            }
            Some(Value::Array(
                s.split(sep).map(|p| Value::String(p.to_owned())).collect(),
            ))
        }
        Func::StartsWith => Some(Value::Bool(s.starts_with(text(1)?))),
        Func::EndsWith => Some(Value::Bool(s.ends_with(text(1)?))),
        Func::RegexMatch => {
            let re = func::compile_regex(text(1)?, ctx)?;
            Some(Value::Bool(re.is_match(s)))
        }
        Func::RegexExtract => {
            let re = func::compile_regex(text(1)?, ctx)?;
            let group = match a.get(2) {
                Some(_) => usize::try_from(int(2)?).ok()?,
                None => 0,
            };
            Some(
                re.captures(s)
                    .and_then(|c| c.get(group))
                    .map_or(Value::Null, |m| Value::String(m.as_str().to_owned())),
            )
        }
        _ => None,
    }
}

/// `format(fmt, args…)` (module docs).
fn format(a: &[Value]) -> Option<Value> {
    let Value::String(fmt) = &a[0] else {
        return None;
    };
    let mut args = a[1..].iter();
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' if chars.peek() == Some(&'}') => {
                chars.next();
                let v = args.next()?;
                match v {
                    Value::String(s) => out.push_str(s),
                    other => out.push_str(&rustegon_doc::json::value_to_json(
                        other,
                        rustegon_doc::json::JsonMode::Canonical,
                    )),
                }
            }
            other => out.push(other),
        }
    }
    Some(Value::String(out))
}
