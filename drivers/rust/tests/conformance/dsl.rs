// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The builder DSL of README §4 translated into the driver's builders.

use rustegon::{Filter, Projection, Sort, Update, Value};

use crate::yaml::{Y, Yaml};

type Val<'a> = &'a dyn Fn(&Yaml) -> Value;

fn path(l: &[Yaml]) -> &str {
    l.first().and_then(Yaml::as_str).unwrap_or("")
}

fn second(l: &[Yaml]) -> &Yaml {
    l.get(1).unwrap_or(&Yaml::BadValue)
}

fn values(l: &[Yaml], val: Val<'_>) -> Vec<Value> {
    second(l)
        .as_vec()
        .map(|v| v.iter().map(val).collect())
        .unwrap_or_default()
}

/// A DSL filter.
pub fn dsl_filter(y: &Yaml, val: Val<'_>) -> Result<Filter, String> {
    let Some(h) = y.as_hash() else {
        return Err("filter must be a mapping".into());
    };
    if h.is_empty() {
        return Ok(Filter::empty());
    }
    let (op, a) = y.single().ok_or("a filter has one operator")?;
    let l: &[Yaml] = a.as_vec().map_or(&[], Vec::as_slice);
    let p = path(l);
    let sub = |x: &Yaml| dsl_filter(x, val);
    Ok(match op {
        "eq" => Filter::eq(p, val(second(l))),
        "ne" => Filter::ne(p, val(second(l))),
        "gt" => Filter::gt(p, val(second(l))),
        "gte" => Filter::gte(p, val(second(l))),
        "lt" => Filter::lt(p, val(second(l))),
        "lte" => Filter::lte(p, val(second(l))),
        "in" => Filter::r#in(p, values(l, val)),
        "nin" => Filter::nin(p, values(l, val)),
        "exists" => Filter::exists(p, second(l).as_bool().unwrap_or(false)),
        "isNull" => Filter::is_null(a.as_str().unwrap_or("")),
        "contains" => Filter::contains(p, val(second(l))),
        "containsAny" => Filter::contains_any(p, values(l, val)),
        "containsAll" => Filter::contains_all(p, values(l, val)),
        "elemMatch" => Filter::elem_match(p, sub(second(l))?),
        "like" => Filter::like(p, second(l).as_str().unwrap_or("")),
        "regex" => Filter::regex(p, second(l).as_str().unwrap_or("")),
        "and" => Filter::and(l.iter().map(sub).collect::<Result<Vec<_>, _>>()?),
        "or" => Filter::or(l.iter().map(sub).collect::<Result<Vec<_>, _>>()?),
        "not" => Filter::not(sub(a)?),
        "id" => Filter::id(val(a)),
        _ => return Err(format!("unknown filter operator {op}")),
    })
}

/// A DSL update (a list of one-key operators).
pub fn dsl_update(ops: &[Yaml], val: Val<'_>) -> Result<Update, String> {
    if ops.is_empty() {
        return Err("empty update".into());
    }
    let mut u = Update::new();
    for item in ops {
        let (op, a) = item.single().ok_or("an update item has one operator")?;
        let l: &[Yaml] = a.as_vec().map_or(&[], Vec::as_slice);
        let p = path(l);
        let s = a.as_str().unwrap_or("");
        u = match op {
            "set" => u.set(p, val(second(l))),
            "unset" => u.unset(s),
            "inc" => u.inc(p, val(second(l))),
            "mul" => u.mul(p, val(second(l))),
            "min" => u.min(p, val(second(l))),
            "max" => u.max(p, val(second(l))),
            "push" => u.push(p, val(second(l))),
            "addToSet" => u.add_to_set(p, val(second(l))),
            "pull" => u.pull(p, val(second(l))),
            "pop" if second(l).as_str() == Some("first") => u.pop_first(p),
            "pop" => u.pop_last(p),
            "rename" => u.rename(p, second(l).as_str().unwrap_or("")),
            "currentDate" => u.current_date(s),
            _ => return Err(format!("unknown update operator {op}")),
        };
    }
    Ok(u)
}

fn sort_from(keys: impl Iterator<Item = (String, bool)>) -> Sort {
    let mut s: Option<Sort> = None;
    for (p, desc) in keys {
        s = Some(match (s, desc) {
            (None, false) => Sort::asc(&p),
            (None, true) => Sort::desc(&p),
            (Some(s), false) => s.then_asc(&p),
            (Some(s), true) => s.then_desc(&p),
        });
    }
    s.unwrap_or_default()
}

/// `sort: [path, -path, …]`.
pub fn sort_of(keys: &[Yaml]) -> Sort {
    sort_from(keys.iter().map(|k| {
        let p = k.as_str().unwrap_or("");
        match p.strip_prefix('-') {
            Some(p) => (p.to_owned(), true),
            None => (p.to_owned(), false),
        }
    }))
}

/// `keys: [{path, descending?}]`.
pub fn keys_of(keys: &[Yaml]) -> Sort {
    sort_from(
        keys.iter()
            .map(|k| (k.str_("path").to_owned(), k.is_true("descending"))),
    )
}

/// `projection: {include: [...]} | {exclude: [...]}`.
pub fn projection_of(p: &Yaml) -> Projection {
    let paths = |k: &str| -> Vec<String> {
        p.list(k)
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect()
    };
    if p.has("include") {
        Projection::include(paths("include"))
    } else {
        Projection::exclude(paths("exclude"))
    }
}
