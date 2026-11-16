// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compilation of a validator's JSON text into an evaluable [`Schema`] (FR-SCH-002,
//! data-model.md §5).
//!
//! Compilation happens once per descriptor version (see [`super::ValidatorCache`]); every
//! check the evaluator would otherwise repeat per document — keyword shape, regex syntax,
//! literal conversion — is done here, so evaluation never fails, only reports violations.
//!
//! Unknown keywords are **rejected**, not ignored as JSON Schema would: a user writing
//! `format` or `patternProperties` must not believe it is enforced (provisional, PD pending).
//! Pure annotations (`title`, `description`, …) are accepted and ignored.

use std::collections::HashMap;

use regex::{Regex, RegexBuilder};
use rustegon_doc::{Value, json::parse_value};
use serde_json::{Map, Value as Json};

use crate::error::{CatalogError, CatalogResult};

/// Maximum nesting depth of subschemas. Bounds compile and evaluation recursion (the evaluator
/// never recurses deeper than the schema) so a hostile validator cannot exhaust the stack.
pub const MAX_SCHEMA_DEPTH: usize = 32;
/// Maximum compiled size of one `pattern` regex (bytes): `regex` guarantees linear-time
/// matching, this bounds its memory (data-model.md §5 "linear time").
pub const MAX_REGEX_SIZE: usize = 1 << 20;

/// Keywords accepted and ignored (annotations, JSON Schema 2020-12 meta-data vocabulary).
const ANNOTATIONS: [&str; 9] = [
    "$schema",
    "$comment",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
];

/// A type name accepted by the `type` keyword (data-model.md §2, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeName {
    Null,
    Bool,
    /// `int64`, and JSON Schema `integer` (= `int64`, data-model.md §5).
    Int64,
    Float64,
    Decimal128,
    /// JSON Schema `number`: any numeric type.
    Number,
    String,
    Binary,
    DateTime,
    Timestamp,
    ObjectId,
    Uuid,
    Array,
    Object,
    VectorF32,
    MinKey,
    MaxKey,
}

impl TypeName {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "null" => Self::Null,
            "bool" | "boolean" => Self::Bool,
            "int64" | "integer" => Self::Int64,
            "float64" => Self::Float64,
            "decimal128" => Self::Decimal128,
            "number" => Self::Number,
            "string" => Self::String,
            "binary" => Self::Binary,
            "datetime" => Self::DateTime,
            "timestamp" => Self::Timestamp,
            "objectId" => Self::ObjectId,
            "uuid" => Self::Uuid,
            "array" => Self::Array,
            "object" => Self::Object,
            "vector_f32" => Self::VectorF32,
            "minKey" => Self::MinKey,
            "maxKey" => Self::MaxKey,
            _ => return None,
        })
    }

    /// Whether `v` is of this type. `counter` (a read-only projection, never written) counts as
    /// an integer so that a validator applied to a projected document behaves sensibly.
    pub(crate) fn matches(self, v: &Value) -> bool {
        match self {
            Self::Null => matches!(v, Value::Null),
            Self::Bool => matches!(v, Value::Bool(_)),
            Self::Int64 => matches!(v, Value::Int64(_) | Value::Counter(_)),
            Self::Float64 => matches!(v, Value::Float64(_)),
            Self::Decimal128 => matches!(v, Value::Decimal(_)),
            Self::Number => is_numeric(v),
            Self::String => matches!(v, Value::String(_)),
            Self::Binary => matches!(v, Value::Binary { .. }),
            Self::DateTime => matches!(v, Value::DateTime(_)),
            Self::Timestamp => matches!(v, Value::Timestamp(_)),
            Self::ObjectId => matches!(v, Value::ObjectId(_)),
            Self::Uuid => matches!(v, Value::Uuid(_)),
            Self::Array => matches!(v, Value::Array(_)),
            Self::Object => matches!(v, Value::Object(_)),
            Self::VectorF32 => matches!(v, Value::VectorF32(_)),
            Self::MinKey => matches!(v, Value::MinKey),
            Self::MaxKey => matches!(v, Value::MaxKey),
        }
    }

    /// The canonical name (used in error messages).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Int64 => "int64",
            Self::Float64 => "float64",
            Self::Decimal128 => "decimal128",
            Self::Number => "number",
            Self::String => "string",
            Self::Binary => "binary",
            Self::DateTime => "datetime",
            Self::Timestamp => "timestamp",
            Self::ObjectId => "objectId",
            Self::Uuid => "uuid",
            Self::Array => "array",
            Self::Object => "object",
            Self::VectorF32 => "vector_f32",
            Self::MinKey => "minKey",
            Self::MaxKey => "maxKey",
        }
    }
}

/// The type name of a value, as reported in `type` errors.
pub(crate) fn type_name_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Int64(_) => "int64",
        Value::Float64(_) => "float64",
        Value::Decimal(_) => "decimal128",
        Value::String(_) => "string",
        Value::Binary { .. } => "binary",
        Value::DateTime(_) => "datetime",
        Value::Timestamp(_) => "timestamp",
        Value::ObjectId(_) => "objectId",
        Value::Uuid(_) => "uuid",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::VectorF32(_) => "vector_f32",
        Value::Counter(_) => "counter",
        Value::MinKey => "minKey",
        Value::MaxKey => "maxKey",
    }
}

/// Whether `v` is a number (`int64`, `float64`, `decimal128`, `counter`).
pub(crate) fn is_numeric(v: &Value) -> bool {
    matches!(
        v,
        Value::Int64(_) | Value::Float64(_) | Value::Decimal(_) | Value::Counter(_)
    )
}

/// A compiled (sub)schema. JSON Schema 2020-12 allows `true` / `false` as schemas.
#[derive(Debug)]
pub(crate) enum Schema {
    /// `true` accepts everything, `false` nothing.
    Bool(bool),
    /// An object schema.
    Keywords(Box<Keywords>),
}

/// The supported keywords of one object schema (data-model.md §5). Absent keyword = `None` /
/// empty.
#[derive(Debug, Default)]
pub(crate) struct Keywords {
    pub types: Option<Vec<TypeName>>,
    pub required: Vec<String>,
    pub properties: HashMap<String, Schema>,
    pub additional_properties: Option<Schema>,
    pub enum_values: Option<Vec<Value>>,
    pub const_value: Option<Value>,
    pub minimum: Option<Value>,
    pub maximum: Option<Value>,
    pub exclusive_minimum: Option<Value>,
    pub exclusive_maximum: Option<Value>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub pattern: Option<Regex>,
    pub items: Option<Schema>,
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    pub unique_items: bool,
    pub all_of: Option<Vec<Schema>>,
    pub any_of: Option<Vec<Schema>>,
    pub one_of: Option<Vec<Schema>>,
    pub not: Option<Schema>,
}

/// Compiles one (sub)schema found at `at` (a JSON pointer into the validator, for messages).
pub(crate) fn compile_schema(json: &Json, at: &str, depth: usize) -> CatalogResult<Schema> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(invalid(
            at,
            format!("schema nesting exceeds {MAX_SCHEMA_DEPTH} levels"),
        ));
    }
    match json {
        Json::Bool(b) => Ok(Schema::Bool(*b)),
        Json::Object(map) => Ok(Schema::Keywords(Box::new(compile_keywords(
            map, at, depth,
        )?))),
        _ => Err(invalid(at, "a schema must be an object or a boolean")),
    }
}

fn compile_keywords(map: &Map<String, Json>, at: &str, depth: usize) -> CatalogResult<Keywords> {
    let mut k = Keywords::default();
    for (name, v) in map {
        let here = format!("{at}/{}", escape_pointer(name));
        let sub = |json: &Json| compile_schema(json, &here, depth + 1);
        match name.as_str() {
            "type" => k.types = Some(compile_types(v, &here)?),
            "required" => k.required = string_set(v, &here)?,
            "properties" => {
                let Json::Object(props) = v else {
                    return Err(invalid(&here, "must be an object"));
                };
                for (p, s) in props {
                    let ps =
                        compile_schema(s, &format!("{here}/{}", escape_pointer(p)), depth + 1)?;
                    k.properties.insert(p.clone(), ps);
                }
            }
            "additionalProperties" => k.additional_properties = Some(sub(v)?),
            "enum" => {
                let Json::Array(items) = v else {
                    return Err(invalid(&here, "must be an array"));
                };
                k.enum_values = Some(
                    items
                        .iter()
                        .map(|i| literal(i, &here))
                        .collect::<CatalogResult<_>>()?,
                );
            }
            "const" => k.const_value = Some(literal(v, &here)?),
            "minimum" => k.minimum = Some(number(v, &here)?),
            "maximum" => k.maximum = Some(number(v, &here)?),
            "exclusiveMinimum" => k.exclusive_minimum = Some(number(v, &here)?),
            "exclusiveMaximum" => k.exclusive_maximum = Some(number(v, &here)?),
            "minLength" => k.min_length = Some(non_negative(v, &here)?),
            "maxLength" => k.max_length = Some(non_negative(v, &here)?),
            "pattern" => k.pattern = Some(compile_pattern(v, &here)?),
            "items" => k.items = Some(sub(v)?),
            "minItems" => k.min_items = Some(non_negative(v, &here)?),
            "maxItems" => k.max_items = Some(non_negative(v, &here)?),
            "uniqueItems" => {
                let Json::Bool(b) = v else {
                    return Err(invalid(&here, "must be a boolean"));
                };
                k.unique_items = *b;
            }
            "allOf" => k.all_of = Some(schema_list(v, &here, depth)?),
            "anyOf" => k.any_of = Some(schema_list(v, &here, depth)?),
            "oneOf" => k.one_of = Some(schema_list(v, &here, depth)?),
            "not" => k.not = Some(sub(v)?),
            other if ANNOTATIONS.contains(&other) => {}
            _ => return Err(invalid(at, format!("unsupported keyword `{name}`"))),
        }
    }
    Ok(k)
}

fn compile_types(v: &Json, at: &str) -> CatalogResult<Vec<TypeName>> {
    let one = |j: &Json| match j {
        Json::String(s) => {
            TypeName::parse(s).ok_or_else(|| invalid(at, format!("unknown type name `{s}`")))
        }
        _ => Err(invalid(at, "type names must be strings")),
    };
    match v {
        Json::Array(items) => {
            let types = items.iter().map(one).collect::<CatalogResult<Vec<_>>>()?;
            if types.is_empty() {
                return Err(invalid(at, "must not be empty"));
            }
            Ok(types)
        }
        single => Ok(vec![one(single)?]),
    }
}

fn string_set(v: &Json, at: &str) -> CatalogResult<Vec<String>> {
    let Json::Array(items) = v else {
        return Err(invalid(at, "must be an array of strings"));
    };
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        let Json::String(s) = i else {
            return Err(invalid(at, "must be an array of strings"));
        };
        if out.contains(s) {
            return Err(invalid(at, "names must be unique"));
        }
        out.push(s.clone());
    }
    Ok(out)
}

fn schema_list(v: &Json, at: &str, depth: usize) -> CatalogResult<Vec<Schema>> {
    match v {
        Json::Array(items) if !items.is_empty() => items
            .iter()
            .enumerate()
            .map(|(i, s)| compile_schema(s, &format!("{at}/{i}"), depth + 1))
            .collect(),
        _ => Err(invalid(at, "must be a non-empty array of schemas")),
    }
}

fn compile_pattern(v: &Json, at: &str) -> CatalogResult<Regex> {
    let Json::String(p) = v else {
        return Err(invalid(at, "must be a string"));
    };
    // Rust `regex` syntax (data-model.md §5): no backreferences or look-around, so matching is
    // linear in the input; the size limits bound compile memory for hostile patterns.
    RegexBuilder::new(p)
        .size_limit(MAX_REGEX_SIZE)
        .dfa_size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| invalid(at, format!("invalid pattern: {e}")))
}

/// A JSON Schema "non-negative integer": an integral, non-negative number (`2.0` is allowed).
fn non_negative(v: &Json, at: &str) -> CatalogResult<u64> {
    let Json::Number(n) = v else {
        return Err(invalid(at, "must be a non-negative integer"));
    };
    if let Some(u) = n.as_u64() {
        return Ok(u);
    }
    match n.as_f64() {
        // Exact: the guard proves the value is a non-negative integer below 2^64.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(f) if f >= 0.0 && f.fract() == 0.0 && f < 18_446_744_073_709_551_616.0 => Ok(f as u64),
        _ => Err(invalid(at, "must be a non-negative integer")),
    }
}

/// A numeric bound: a JSON number or a numeric extended-JSON literal (`{"$decimal": …}`),
/// converted with the document parser's number rules (data-model.md §2).
fn number(v: &Json, at: &str) -> CatalogResult<Value> {
    let n = literal(v, at)?;
    if is_numeric(&n) {
        Ok(n)
    } else {
        Err(invalid(at, "must be a number"))
    }
}

/// Converts a schema literal (`enum`, `const`, bounds) to a document [`Value`] through the
/// extended-JSON parser, so `{"$date": …}`, `{"$decimal": …}` etc. work in validators and
/// numbers follow exactly the rules documents are parsed with.
fn literal(v: &Json, at: &str) -> CatalogResult<Value> {
    parse_value(&v.to_string()).map_err(|e| invalid(at, format!("unsupported literal: {e}")))
}

/// RFC 6901 escaping of one reference token.
pub(crate) fn escape_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn invalid(at: &str, reason: impl std::fmt::Display) -> CatalogError {
    let at = if at.is_empty() { "/" } else { at };
    CatalogError::InvalidArgument(format!("invalid validator at {at}: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_escaping_follows_rfc_6901() {
        assert_eq!(escape_pointer("a/b~c"), "a~1b~0c");
        assert_eq!(escape_pointer("plain"), "plain");
    }

    #[test]
    fn non_negative_accepts_integral_floats_only() {
        assert_eq!(non_negative(&serde_json::json!(2.0), "").ok(), Some(2));
        assert!(non_negative(&serde_json::json!(2.5), "").is_err());
        assert!(non_negative(&serde_json::json!(-1), "").is_err());
    }
}
