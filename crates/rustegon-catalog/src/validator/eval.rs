// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Evaluation of a compiled [`Schema`] against a document value (FR-SCH-002/003).
//!
//! One recursive walk serves two modes, selected by the [`Sink`]:
//! - **report**: collect violations (JSON pointer + keyword + message) up to a limit, so a
//!   client sees several problems at once but a huge invalid document cannot make the error
//!   unbounded;
//! - **probe**: answer valid/invalid only, stopping at the first violation. Combinators
//!   (`anyOf`, `oneOf`, `not`, …) probe their branches, then report one violation of their own
//!   keyword at the current path: per-branch detail of a failed `anyOf` is noise to clients.
//!
//! Messages never contain instance values — they may be sensitive and warnings are logged
//! (coding-standards.md §3.6); they name only schema-side facts (bounds, type names, property
//! names from the schema).

use std::cmp::Ordering;

use rustegon_doc::{Document, Value, compare::compare_values};

use super::{
    ValidationError,
    compile::{Keywords, Schema, TypeName, escape_pointer, is_numeric, type_name_of},
};

/// One step of the instance path; rendered to a JSON pointer only when a violation is
/// recorded, so valid documents pay no string formatting.
#[derive(Clone, Copy)]
enum Step<'a> {
    Key(&'a str),
    Index(usize),
}

/// Where violations go (module docs).
pub(crate) struct Sink {
    errors: Vec<ValidationError>,
    /// Maximum number of violations kept; `0` = probe mode (record nothing, stop at first).
    limit: usize,
    /// Number of violations found (may exceed `errors.len()` when truncated).
    found: usize,
}

impl Sink {
    pub(crate) fn report(limit: usize) -> Self {
        Self {
            errors: Vec::new(),
            limit,
            found: 0,
        }
    }

    fn probe() -> Self {
        Self::report(0)
    }

    /// Whether evaluation may stop: only probes stop early (at the first violation). Reports
    /// walk the whole document so that `found` is the true total; the walk is linear in
    /// document × schema size either way, only the stored errors are bounded.
    fn done(&self) -> bool {
        self.limit == 0 && self.found > 0
    }

    fn push(&mut self, path: &[Step<'_>], keyword: &'static str, message: impl FnOnce() -> String) {
        self.found += 1;
        if self.errors.len() < self.limit {
            self.errors.push(ValidationError {
                path: render(path),
                keyword,
                message: message(),
            });
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<ValidationError>, usize) {
        (self.errors, self.found)
    }
}

fn render(path: &[Step<'_>]) -> String {
    let mut out = String::new();
    for step in path {
        out.push('/');
        match step {
            Step::Key(k) => out.push_str(&escape_pointer(k)),
            Step::Index(i) => out.push_str(&i.to_string()),
        }
    }
    out
}

/// Evaluates `schema` on `value` (the document root) into `sink`.
pub(crate) fn evaluate(schema: &Schema, value: &Value, sink: &mut Sink) {
    // Path steps borrow from both the schema (missing `required` names) and the instance.
    let mut path = Vec::new();
    eval(schema, value, &mut path, sink);
}

/// Whether `value` satisfies `schema` (probe mode).
pub(crate) fn is_valid(schema: &Schema, value: &Value) -> bool {
    let mut sink = Sink::probe();
    eval(schema, value, &mut Vec::new(), &mut sink);
    sink.found == 0
}

fn eval<'a>(schema: &'a Schema, value: &'a Value, path: &mut Vec<Step<'a>>, sink: &mut Sink) {
    match schema {
        Schema::Bool(true) => {}
        Schema::Bool(false) => sink.push(path, "false", || "no value is allowed here".into()),
        Schema::Keywords(k) => eval_keywords(k, value, path, sink),
    }
}

/// Runs each keyword group; each returns early once the sink is done.
fn eval_keywords<'a>(k: &'a Keywords, value: &'a Value, path: &mut Vec<Step<'a>>, sink: &mut Sink) {
    eval_type_and_literals(k, value, path, sink);
    if sink.done() {
        return;
    }
    match value {
        Value::String(s) => eval_string(k, s, path, sink),
        Value::Array(items) => eval_array(k, items, path, sink),
        Value::Object(doc) => eval_object(k, doc, path, sink),
        v if is_numeric(v) => eval_number(k, v, path, sink),
        _ => {}
    }
    if sink.done() {
        return;
    }
    eval_combinators(k, value, path, sink);
}

fn eval_type_and_literals(k: &Keywords, value: &Value, path: &[Step<'_>], sink: &mut Sink) {
    if let Some(types) = &k.types
        && !types.iter().any(|t| t.matches(value))
    {
        sink.push(path, "type", || {
            let names: Vec<&str> = types.iter().map(|t| TypeName::name(*t)).collect();
            format!(
                "expected type {}, found {}",
                names.join("|"),
                type_name_of(value)
            )
        });
        if sink.done() {
            return;
        }
    }
    if let Some(c) = &k.const_value
        && !json_equal(c, value)
    {
        sink.push(path, "const", || "value does not equal the constant".into());
        if sink.done() {
            return;
        }
    }
    if let Some(values) = &k.enum_values
        && !values.iter().any(|e| json_equal(e, value))
    {
        sink.push(path, "enum", || {
            format!("value is not one of the {} allowed values", values.len())
        });
    }
}

/// (bound, keyword, accepted orderings of `value` vs bound, operator for the message).
type BoundCheck<'k> = (
    &'k Option<Value>,
    &'static str,
    fn(Ordering) -> bool,
    &'static str,
);

fn eval_number(k: &Keywords, v: &Value, path: &[Step<'_>], sink: &mut Sink) {
    // NaN satisfies no bound (in the §2.1 order NaN is lowest, which would make it pass every
    // `maximum`; JSON Schema has no NaN, so the conservative reading is "not comparable").
    let nan = match v {
        Value::Float64(f) => f.is_nan(),
        Value::Decimal(d) => d.is_nan(),
        _ => false,
    };
    let checks: [BoundCheck<'_>; 4] = [
        (&k.minimum, "minimum", Ordering::is_ge, ">="),
        (&k.maximum, "maximum", Ordering::is_le, "<="),
        (
            &k.exclusive_minimum,
            "exclusiveMinimum",
            Ordering::is_gt,
            ">",
        ),
        (
            &k.exclusive_maximum,
            "exclusiveMaximum",
            Ordering::is_lt,
            "<",
        ),
    ];
    for (bound, keyword, ok, op) in checks {
        if let Some(b) = bound
            && (nan || !ok(compare_values(v, b)))
        {
            sink.push(path, keyword, || {
                format!(
                    "value must be {op} {}",
                    rustegon_doc::json::value_to_json(b, rustegon_doc::json::JsonMode::Canonical)
                )
            });
            if sink.done() {
                return;
            }
        }
    }
}

fn eval_string(k: &Keywords, s: &str, path: &[Step<'_>], sink: &mut Sink) {
    // Lengths are in Unicode code points (JSON Schema 2020-12 §6.3.1), not bytes.
    if k.min_length.is_some() || k.max_length.is_some() {
        let len = s.chars().count() as u64;
        if let Some(min) = k.min_length
            && len < min
        {
            sink.push(path, "minLength", || {
                format!("string is shorter than {min} characters")
            });
            if sink.done() {
                return;
            }
        }
        if let Some(max) = k.max_length
            && len > max
        {
            sink.push(path, "maxLength", || {
                format!("string is longer than {max} characters")
            });
            if sink.done() {
                return;
            }
        }
    }
    // `pattern` is unanchored (ECMA-262 `test` semantics, JSON Schema §6.3.3).
    if let Some(re) = &k.pattern
        && !re.is_match(s)
    {
        sink.push(path, "pattern", || {
            format!("string does not match pattern {}", re.as_str())
        });
    }
}

fn eval_array<'a>(k: &'a Keywords, items: &'a [Value], path: &mut Vec<Step<'a>>, sink: &mut Sink) {
    let len = items.len() as u64;
    if let Some(min) = k.min_items
        && len < min
    {
        sink.push(path, "minItems", || {
            format!("array has fewer than {min} items")
        });
        if sink.done() {
            return;
        }
    }
    if let Some(max) = k.max_items
        && len > max
    {
        sink.push(path, "maxItems", || {
            format!("array has more than {max} items")
        });
        if sink.done() {
            return;
        }
    }
    if k.unique_items && !all_unique(items) {
        sink.push(path, "uniqueItems", || "array items are not unique".into());
        if sink.done() {
            return;
        }
    }
    if let Some(item_schema) = &k.items {
        for (i, item) in items.iter().enumerate() {
            path.push(Step::Index(i));
            eval(item_schema, item, path, sink);
            path.pop();
            if sink.done() {
                return;
            }
        }
    }
}

fn eval_object<'a>(k: &'a Keywords, doc: &'a Document, path: &mut Vec<Step<'a>>, sink: &mut Sink) {
    for name in &k.required {
        if doc.get(name).is_none() {
            // The pointer names the missing property itself: that is the location the client
            // has to fix (FR-SCH-003).
            path.push(Step::Key(name));
            sink.push(path, "required", || {
                format!("required property `{name}` is missing")
            });
            path.pop();
            if sink.done() {
                return;
            }
        }
    }
    if k.properties.is_empty() && k.additional_properties.is_none() {
        return;
    }
    // Document order, so the reported violations are deterministic.
    for (name, v) in doc.iter() {
        let schema = match k.properties.get(name) {
            Some(s) => s,
            None => match &k.additional_properties {
                Some(s) => s,
                None => continue,
            },
        };
        path.push(Step::Key(name));
        eval(schema, v, path, sink);
        path.pop();
        if sink.done() {
            return;
        }
    }
}

fn eval_combinators(k: &Keywords, value: &Value, path: &[Step<'_>], sink: &mut Sink) {
    if let Some(all) = &k.all_of
        && let Some(i) = all.iter().position(|s| !is_valid(s, value))
    {
        sink.push(path, "allOf", || {
            format!("value does not match allOf schema {i}")
        });
        if sink.done() {
            return;
        }
    }
    if let Some(any) = &k.any_of
        && !any.iter().any(|s| is_valid(s, value))
    {
        sink.push(path, "anyOf", || {
            "value matches none of the anyOf schemas".into()
        });
        if sink.done() {
            return;
        }
    }
    if let Some(one) = &k.one_of {
        let mut matched = 0usize;
        for s in one {
            if is_valid(s, value) {
                matched += 1;
                if matched > 1 {
                    break;
                }
            }
        }
        if matched != 1 {
            sink.push(path, "oneOf", || {
                if matched == 0 {
                    "value matches none of the oneOf schemas".into()
                } else {
                    "value matches more than one oneOf schema".into()
                }
            });
            if sink.done() {
                return;
            }
        }
    }
    if let Some(not) = &k.not
        && is_valid(not, value)
    {
        sink.push(path, "not", || {
            "value must not match the `not` schema".into()
        });
    }
}

/// JSON Schema equality (2020-12 §4.2.2), used by `enum` and `const`: numbers are equal by
/// mathematical value across `int64` / `float64` / `decimal128` (`1 == 1.0`), objects are equal
/// when they have the same names with equal values **in any order**, arrays element-wise. Other
/// types use the document equality of data-model.md §2.1.
pub(crate) fn json_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(n, v)| y.get(n).is_some_and(|w| json_equal(v, w)))
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_equal(p, q))
        }
        _ => compare_values(a, b) == Ordering::Equal,
    }
}

/// `uniqueItems` in O(n log n): items are normalized (object fields sorted by name, recursively)
/// so that the §2.1 total order — numeric across numeric types, field-wise for objects — has
/// exactly [`json_equal`] as its equality; then equal items are adjacent after sorting. A
/// pairwise scan would be quadratic on arrays of up to the document size limit.
fn all_unique(items: &[Value]) -> bool {
    if items.len() < 2 {
        return true;
    }
    let mut normalized: Vec<Value> = items.iter().map(normalize).collect();
    normalized.sort_by(compare_values);
    normalized
        .windows(2)
        .all(|w| compare_values(&w[0], &w[1]) != Ordering::Equal)
}

fn normalize(v: &Value) -> Value {
    match v {
        Value::Object(d) => {
            let mut fields: Vec<(String, Value)> = d
                .iter()
                .map(|(n, v)| (n.to_owned(), normalize(v)))
                .collect();
            fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            // Names come from a valid document, so they are unique and this cannot fail; fall
            // back to the unnormalized object rather than panic.
            Document::try_from_fields(fields).map_or_else(|_| v.clone(), Value::Object)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}
