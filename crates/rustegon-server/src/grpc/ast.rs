// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Structured RGQL over gRPC (FR-QL-002, query-language.md §13, PD-053): `query_ast.proto`
//! messages ↔ `rustegon_query::ast`.
//!
//! The proto "mirrors the JSON form of `rustegon_query::ast` exactly" (header of
//! `query_ast.proto`), and the AST already has a validated JSON decoder
//! ([`Statement::from_json`]: schema, canonical form, parser limits). So instead of ~100
//! hand-written message converters, a message is mapped onto that JSON form through its
//! descriptor (`prost-reflect`) by the mirror rules of the proto header:
//! - a message with a `oneof kind` is a JSON object `{"kind": <member field name>, …}` whose
//!   other entries are the fields of the member message (inlined);
//! - field names are the JSON names; unset optional scalars and unset messages are omitted,
//!   lists and non-optional scalars are always written (`false`, `""` and `[]` deserialize like
//!   their omitted form); an enum is its value name without the `<ENUM_NAME>_` prefix in lower
//!   case, and its zero value (`*_UNSPECIFIED`, "not set") is omitted;
//! - the documented exceptions: `AstPath`, `AstTuple` and `AstPipeline` are JSON arrays,
//!   `AstSegment` is a string / integer / `{"index": e}` / `{"each": true}`, and `AstLiteral`
//!   is `{"value": v}` or `{"type": t, "value": "text"}`.
//!
//! The reverse mapping (JSON → message) serves responses carrying AST fragments
//! (`IndexInfo.definition`) and the round-trip test over the RGQL golden corpus, which pins the
//! mapping for every statement kind the parser produces. A message this mapping gets wrong is
//! rejected by the JSON decoder (`RGN-1010`), never misread: the decoder denies unknown fields
//! and the canonical check re-parses the printed statement.

use std::sync::OnceLock;

use prost_reflect::{
    DescriptorPool, DynamicMessage, EnumDescriptor, FieldDescriptor, Kind, MessageDescriptor,
    ReflectMessage, Value as Dyn,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_proto::v1::{AstCreateIndex, AstStatement, AstUpdateOp};
use rustegon_query::ast::{AstError, CreateIndex, Statement, UpdateOp};
use serde_json::{Map, Number, Value as Json};

/// Messages written as a JSON array of their single repeated field.
const ARRAY_MESSAGES: [(&str, &str); 3] = [
    ("AstPath", "segments"),
    ("AstTuple", "values"),
    ("AstPipeline", "stages"),
];
/// Typed literal members of `AstLiteral` (JSON `{"type": name, "value": text}`).
const TYPED_LITERALS: [&str; 5] = ["decimal", "datetime", "object_id", "uuid", "interval"];
/// Bound on the nesting of the JSON built here (also bounded by prost's decode recursion
/// limit, 100 messages): the AST decoder refuses deeper input anyway (`RGN-1013`).
const MAX_DEPTH: usize = 256;

fn malformed(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::QuerySyntaxError, message.into())
        .with_detail("reason", "malformed structured query")
}

/// The descriptor pool of `rustegon.v1`, decoded once.
fn pool() -> Result<&'static DescriptorPool, Error> {
    static POOL: OnceLock<Result<DescriptorPool, String>> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(rustegon_proto::FILE_DESCRIPTOR_SET).map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| {
        tracing::error!(error = %e, "rustegon.v1 descriptor set does not decode");
        Error::new(ErrorCode::Internal, "protocol descriptors unavailable")
    })
}

fn descriptor(name: &str) -> Result<MessageDescriptor, Error> {
    pool()?
        .get_message_by_name(&format!("rustegon.v1.{name}"))
        .ok_or_else(|| Error::new(ErrorCode::Internal, format!("no descriptor for {name}")))
}

fn dynamic<T: prost::Message>(name: &str, message: &T) -> Result<DynamicMessage, Error> {
    let mut dynamic = DynamicMessage::new(descriptor(name)?);
    dynamic
        .transcode_from(message)
        .map_err(|e| malformed(format!("cannot read {name}: {e}")))?;
    Ok(dynamic)
}

/// Maps an [`AstError`] onto the codes of query-language.md §13/§14.
fn ast_error(e: AstError) -> Error {
    match e {
        AstError::Malformed(m) => malformed(m),
        AstError::TooComplex(m) => Error::new(ErrorCode::QueryTooComplex, m),
        AstError::NonCanonical(m) => Error::new(ErrorCode::QuerySyntaxError, m),
        AstError::Parse(p) => p.into_error(),
    }
}

/// A structured statement (`ExecuteRequest.ast`) as a validated AST.
///
/// # Errors
/// `RGN-1010` for a malformed or non-canonical AST, `RGN-1013` beyond the nesting limits.
pub fn statement_from_proto(ast: &AstStatement) -> Result<Statement, Error> {
    let json = message_to_json(&dynamic("AstStatement", ast)?, 0)?;
    statement_from_json(&json.to_string())
}

/// A statement in the JSON form of `rustegon_query::ast` (query-language.md §13): the REST
/// form of `ExecuteRequest.ast`, decoded by the same validated decoder.
///
/// # Errors
/// As [`statement_from_proto`].
pub fn statement_from_json(json: &str) -> Result<Statement, Error> {
    Statement::from_json(json).map_err(ast_error)
}

/// A statement as its structured form (drivers, tests).
///
/// # Errors
/// `RGN-5001` if the AST has no JSON form (never for parser output).
pub fn statement_to_proto(stmt: &Statement) -> Result<AstStatement, Error> {
    let json: Json = serde_json::to_value(stmt)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("AST to JSON: {e}")))?;
    json_to_typed("AstStatement", &json)
}

/// Update operators (`UpdateRequest.operations`). They are checked again as part of the
/// statement the caller builds from them ([`Statement::validate`]).
///
/// # Errors
/// `RGN-1010` for malformed operators.
pub fn update_ops_from_proto(ops: &[AstUpdateOp]) -> Result<Vec<UpdateOp>, Error> {
    let mut items = Vec::with_capacity(ops.len());
    for op in ops {
        items.push(message_to_json(&dynamic("AstUpdateOp", op)?, 0)?);
    }
    update_ops_from_json(&Json::Array(items).to_string())
}

/// Update operators as a JSON array in the AST's JSON form (REST `PATCH` of a document).
///
/// # Errors
/// As [`update_ops_from_proto`].
pub fn update_ops_from_json(json: &str) -> Result<Vec<UpdateOp>, Error> {
    serde_json::from_str(json).map_err(|e| malformed(e.to_string()))
}

/// A structured `CREATE INDEX` (`CreateIndexRequest.definition`), validated like the statement.
///
/// # Errors
/// `RGN-1010` for a malformed or non-canonical definition.
pub fn create_index_from_proto(ast: &AstCreateIndex) -> Result<CreateIndex, Error> {
    let json = message_to_json(&dynamic("AstCreateIndex", ast)?, 0)?;
    create_index_from_json(&json.to_string())
}

/// A `CREATE INDEX` in the AST's JSON form (REST index creation), validated like the
/// statement.
///
/// # Errors
/// As [`create_index_from_proto`].
pub fn create_index_from_json(json: &str) -> Result<CreateIndex, Error> {
    let ci: CreateIndex = serde_json::from_str(json).map_err(|e| malformed(e.to_string()))?;
    let stmt = Statement::CreateIndex(ci);
    stmt.validate().map_err(ast_error)?;
    match stmt {
        Statement::CreateIndex(ci) => Ok(ci),
        _ => Err(Error::new(
            ErrorCode::Internal,
            "unreachable statement kind",
        )),
    }
}

/// A `CREATE INDEX` AST as its structured form (`IndexInfo.definition`).
///
/// # Errors
/// `RGN-5001` if the AST has no JSON form.
pub fn create_index_to_proto(ci: &CreateIndex) -> Result<AstCreateIndex, Error> {
    let json: Json = serde_json::to_value(ci)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("AST to JSON: {e}")))?;
    json_to_typed("AstCreateIndex", &json)
}

fn json_to_typed<T: prost::Message + Default>(name: &str, json: &Json) -> Result<T, Error> {
    let message = json_to_message(json, &descriptor(name)?, 0).map_err(|e| {
        Error::new(
            ErrorCode::Internal,
            format!("AST to proto: {}", e.message()),
        )
    })?;
    message
        .transcode_to::<T>()
        .map_err(|e| Error::new(ErrorCode::Internal, format!("AST to proto: {e}")))
}

// ---------------------------------------------------------------------------------------------
// Message → JSON
// ---------------------------------------------------------------------------------------------

fn message_to_json(msg: &DynamicMessage, depth: usize) -> Result<Json, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::new(
            ErrorCode::QueryTooComplex,
            "structured query nested too deeply",
        ));
    }
    let desc = msg.descriptor();
    let name = desc.name();
    if let Some((_, field)) = ARRAY_MESSAGES.iter().find(|(m, _)| *m == name) {
        let field = desc
            .get_field_by_name(field)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "array message without its field"))?;
        return field_to_json(msg, &field, depth);
    }
    match name {
        "AstSegment" => return segment_to_json(msg, depth),
        "AstLiteral" => return literal_to_json(msg),
        _ => {}
    }
    let mut obj = Map::new();
    if let Some(kind) = desc.oneofs().find(|o| o.name() == "kind") {
        let member = kind
            .fields()
            .find(|f| msg.has_field(f))
            .ok_or_else(|| malformed(format!("{name}: `kind` not set")))?;
        obj.insert("kind".to_owned(), Json::String(member.name().to_owned()));
        match msg.get_field(&member).as_ref() {
            Dyn::Message(inner) => match message_to_json(inner, depth + 1)? {
                Json::Object(entries) => {
                    for (k, v) in entries {
                        if obj.insert(k.clone(), v).is_some() {
                            return Err(malformed(format!("{name}: duplicate field {k}")));
                        }
                    }
                }
                _ => {
                    return Err(malformed(format!(
                        "{name}: `{}` is not inlinable",
                        member.name()
                    )));
                }
            },
            _ => return Err(malformed(format!("{name}: scalar `kind` member"))),
        }
    }
    for field in desc.fields() {
        if field
            .containing_oneof()
            .is_some_and(|o| !o.is_synthetic() && o.name() == "kind")
        {
            continue;
        }
        if !field.is_list() && field.supports_presence() && !msg.has_field(&field) {
            continue;
        }
        if let Kind::Enum(_) = field.kind()
            && !field.is_list()
            && matches!(msg.get_field(&field).as_ref(), Dyn::EnumNumber(0))
        {
            continue;
        }
        let value = field_to_json(msg, &field, depth)?;
        if obj.insert(field.name().to_owned(), value).is_some() {
            return Err(malformed(format!(
                "{name}: duplicate field {}",
                field.name()
            )));
        }
    }
    Ok(Json::Object(obj))
}

fn field_to_json(
    msg: &DynamicMessage,
    field: &FieldDescriptor,
    depth: usize,
) -> Result<Json, Error> {
    if field.is_map() {
        return Err(malformed(format!(
            "map field {} in a structured query",
            field.name()
        )));
    }
    let value = msg.get_field(field);
    let kind = field.kind();
    match value.as_ref() {
        Dyn::List(items) => items
            .iter()
            .map(|v| value_to_json(v, &kind, depth))
            .collect::<Result<Vec<_>, _>>()
            .map(Json::Array),
        v => value_to_json(v, &kind, depth),
    }
}

fn value_to_json(value: &Dyn, kind: &Kind, depth: usize) -> Result<Json, Error> {
    Ok(match value {
        Dyn::Bool(b) => Json::Bool(*b),
        Dyn::I32(i) => Json::from(*i),
        Dyn::I64(i) => Json::from(*i),
        Dyn::U32(u) => Json::from(*u),
        Dyn::U64(u) => Json::from(*u),
        Dyn::F32(f) => float(f64::from(*f))?,
        Dyn::F64(f) => float(*f)?,
        Dyn::String(s) => Json::String(s.clone()),
        Dyn::EnumNumber(n) => match kind {
            Kind::Enum(e) => Json::String(enum_to_json(e, *n)?),
            _ => return Err(malformed("enum value of a non-enum field")),
        },
        Dyn::Message(m) => message_to_json(m, depth + 1)?,
        Dyn::Bytes(_) | Dyn::List(_) | Dyn::Map(_) => {
            return Err(malformed("unsupported field type in a structured query"));
        }
    })
}

fn float(f: f64) -> Result<Json, Error> {
    // JSON keeps the integer/float distinction of literals: `Number::from_f64(10.0)` prints
    // `10.0`, which the AST decoder reads as a float.
    Number::from_f64(f)
        .map(Json::Number)
        .ok_or_else(|| malformed("non-finite float in a structured query"))
}

/// `"AstBinaryOp"` → `"AST_BINARY_OP_"`.
fn enum_prefix(e: &EnumDescriptor) -> String {
    let mut out = String::new();
    for (i, c) in e.name().chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out.push('_');
    out
}

fn enum_to_json(e: &EnumDescriptor, number: i32) -> Result<String, Error> {
    let value = e.get_value(number).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown {} value {number}", e.name()),
        )
    })?;
    value
        .name()
        .strip_prefix(&enum_prefix(e))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| Error::new(ErrorCode::Internal, "enum value without its prefix"))
}

fn set_member(msg: &DynamicMessage, oneof: &str) -> Result<(FieldDescriptor, Dyn), Error> {
    let desc = msg.descriptor();
    let member = desc
        .oneofs()
        .find(|o| o.name() == oneof)
        .and_then(|o| o.fields().find(|f| msg.has_field(f)))
        .ok_or_else(|| malformed(format!("{}: `{oneof}` not set", desc.name())))?;
    let value = msg.get_field(&member).into_owned();
    Ok((member, value))
}

fn segment_to_json(msg: &DynamicMessage, depth: usize) -> Result<Json, Error> {
    let (member, value) = set_member(msg, "segment")?;
    Ok(match (member.name(), value) {
        ("field", Dyn::String(s)) => Json::String(s),
        ("position", Dyn::U32(p)) => Json::from(p),
        ("index", Dyn::Message(m)) => {
            let mut obj = Map::new();
            obj.insert("index".to_owned(), message_to_json(&m, depth + 1)?);
            Json::Object(obj)
        }
        ("each", Dyn::Bool(true)) => {
            let mut obj = Map::new();
            obj.insert("each".to_owned(), Json::Bool(true));
            Json::Object(obj)
        }
        _ => return Err(malformed("invalid path segment")),
    })
}

fn literal_to_json(msg: &DynamicMessage) -> Result<Json, Error> {
    let (member, value) = set_member(msg, "value")?;
    let mut obj = Map::new();
    let name = member.name();
    let json = match (name, value) {
        ("null", _) => Json::Null,
        ("bool_value", Dyn::Bool(b)) => Json::Bool(b),
        ("int_value", Dyn::I64(i)) => Json::from(i),
        ("float_value", Dyn::F64(f)) => float(f)?,
        ("string_value", Dyn::String(s)) => Json::String(s),
        (typed, Dyn::String(s)) if TYPED_LITERALS.contains(&typed) => {
            obj.insert("type".to_owned(), Json::String(typed.to_owned()));
            Json::String(s)
        }
        _ => return Err(malformed("invalid literal")),
    };
    obj.insert("value".to_owned(), json);
    Ok(Json::Object(obj))
}

// ---------------------------------------------------------------------------------------------
// JSON → message
// ---------------------------------------------------------------------------------------------

fn json_to_message(
    json: &Json,
    desc: &MessageDescriptor,
    depth: usize,
) -> Result<DynamicMessage, Error> {
    if depth > MAX_DEPTH {
        return Err(malformed("AST nested too deeply"));
    }
    let mut msg = DynamicMessage::new(desc.clone());
    let name = desc.name();
    if let Some((_, field)) = ARRAY_MESSAGES.iter().find(|(m, _)| *m == name) {
        let field = desc
            .get_field_by_name(field)
            .ok_or_else(|| malformed("array message without its field"))?;
        msg.set_field(&field, json_to_field(json, &field, depth)?);
        return Ok(msg);
    }
    match name {
        "AstSegment" => return segment_from_json(json, desc, depth),
        "AstLiteral" => return literal_from_json(json, desc),
        _ => {}
    }
    let obj = json
        .as_object()
        .ok_or_else(|| malformed(format!("{name}: expected an object")))?;
    let mut rest = obj.clone();
    if desc.oneofs().any(|o| o.name() == "kind") {
        let kind = rest
            .remove("kind")
            .and_then(|k| k.as_str().map(str::to_owned))
            .ok_or_else(|| malformed(format!("{name}: missing `kind`")))?;
        let member = desc
            .get_field_by_name(&kind)
            .filter(|f| f.containing_oneof().is_some_and(|o| o.name() == "kind"))
            .ok_or_else(|| malformed(format!("{name}: unknown kind {kind}")))?;
        // Entries naming a field of the outer message stay there; the rest is the member's.
        let mut inner = Map::new();
        let keys: Vec<String> = rest.keys().cloned().collect();
        for k in keys {
            let own = desc
                .get_field_by_name(&k)
                .is_some_and(|f| f.containing_oneof().is_none_or(|o| o.name() != "kind"));
            if !own && let Some(v) = rest.remove(&k) {
                inner.insert(k, v);
            }
        }
        let Kind::Message(member_desc) = member.kind() else {
            return Err(malformed(format!("{name}: scalar kind member")));
        };
        let value = json_to_message(&Json::Object(inner), &member_desc, depth + 1)?;
        msg.set_field(&member, Dyn::Message(value));
    }
    for (k, v) in &rest {
        let field = desc
            .get_field_by_name(k)
            .ok_or_else(|| malformed(format!("{name}: unknown field {k}")))?;
        if v.is_null() {
            continue;
        }
        msg.set_field(&field, json_to_field(v, &field, depth)?);
    }
    Ok(msg)
}

fn json_to_field(json: &Json, field: &FieldDescriptor, depth: usize) -> Result<Dyn, Error> {
    let kind = field.kind();
    if field.is_list() {
        let items = json
            .as_array()
            .ok_or_else(|| malformed(format!("{}: expected an array", field.name())))?;
        return items
            .iter()
            .map(|v| json_to_value(v, &kind, depth))
            .collect::<Result<Vec<_>, _>>()
            .map(Dyn::List);
    }
    json_to_value(json, &kind, depth)
}

fn json_to_value(json: &Json, kind: &Kind, depth: usize) -> Result<Dyn, Error> {
    let bad = || malformed(format!("value {json} does not fit {kind:?}"));
    Ok(match kind {
        Kind::Bool => Dyn::Bool(json.as_bool().ok_or_else(bad)?),
        Kind::String => Dyn::String(json.as_str().ok_or_else(bad)?.to_owned()),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Dyn::I64(json.as_i64().ok_or_else(bad)?),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Dyn::I32(
            json.as_i64()
                .and_then(|i| i32::try_from(i).ok())
                .ok_or_else(bad)?,
        ),
        Kind::Uint32 | Kind::Fixed32 => Dyn::U32(
            json.as_u64()
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(bad)?,
        ),
        Kind::Uint64 | Kind::Fixed64 => Dyn::U64(json.as_u64().ok_or_else(bad)?),
        Kind::Double => Dyn::F64(json.as_f64().ok_or_else(bad)?),
        Kind::Enum(e) => {
            let text = json.as_str().ok_or_else(bad)?;
            let full = format!("{}{}", enum_prefix(e), text.to_ascii_uppercase());
            Dyn::EnumNumber(e.get_value_by_name(&full).ok_or_else(bad)?.number())
        }
        Kind::Message(m) => Dyn::Message(json_to_message(json, m, depth + 1)?),
        Kind::Float | Kind::Bytes => return Err(bad()),
    })
}

fn segment_from_json(
    json: &Json,
    desc: &MessageDescriptor,
    depth: usize,
) -> Result<DynamicMessage, Error> {
    let mut msg = DynamicMessage::new(desc.clone());
    let field = |n: &str| {
        desc.get_field_by_name(n)
            .ok_or_else(|| malformed("AstSegment field missing"))
    };
    match json {
        Json::String(s) => msg.set_field(&field("field")?, Dyn::String(s.clone())),
        Json::Number(n) => {
            let p = n
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or_else(|| malformed("invalid path position"))?;
            msg.set_field(&field("position")?, Dyn::U32(p));
        }
        Json::Object(o) if o.get("each") == Some(&Json::Bool(true)) => {
            msg.set_field(&field("each")?, Dyn::Bool(true));
        }
        Json::Object(o) if o.contains_key("index") => {
            let f = field("index")?;
            let Kind::Message(expr) = f.kind() else {
                return Err(malformed("AstSegment.index is not a message"));
            };
            let index = o.get("index").unwrap_or(&Json::Null);
            msg.set_field(&f, Dyn::Message(json_to_message(index, &expr, depth + 1)?));
        }
        _ => return Err(malformed("invalid path segment")),
    }
    Ok(msg)
}

fn literal_from_json(json: &Json, desc: &MessageDescriptor) -> Result<DynamicMessage, Error> {
    let mut msg = DynamicMessage::new(desc.clone());
    let field = |n: &str| {
        desc.get_field_by_name(n)
            .ok_or_else(|| malformed("AstLiteral field missing"))
    };
    let obj = json
        .as_object()
        .ok_or_else(|| malformed("literal: expected an object"))?;
    let value = obj.get("value").unwrap_or(&Json::Null);
    if let Some(ty) = obj.get("type").and_then(Json::as_str) {
        if !TYPED_LITERALS.contains(&ty) {
            return Err(malformed(format!("unknown literal type {ty}")));
        }
        let text = value
            .as_str()
            .ok_or_else(|| malformed("typed literal value must be a string"))?;
        msg.set_field(&field(ty)?, Dyn::String(text.to_owned()));
        return Ok(msg);
    }
    match value {
        Json::Null => {
            let f = field("null")?;
            let Kind::Message(m) = f.kind() else {
                return Err(malformed("AstLiteral.null is not a message"));
            };
            msg.set_field(&f, Dyn::Message(DynamicMessage::new(m)));
        }
        Json::Bool(b) => msg.set_field(&field("bool_value")?, Dyn::Bool(*b)),
        Json::String(s) => msg.set_field(&field("string_value")?, Dyn::String(s.clone())),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                msg.set_field(&field("int_value")?, Dyn::I64(i));
            } else {
                let f = n
                    .as_f64()
                    .ok_or_else(|| malformed("invalid number literal"))?;
                msg.set_field(&field("float_value")?, Dyn::F64(f));
            }
        }
        _ => return Err(malformed("invalid literal value")),
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use rustegon_query::parse_statement;

    use super::*;

    #[test]
    fn fr_ql_002_enum_prefix_is_screaming_snake_of_the_type() {
        let e = pool()
            .unwrap()
            .get_enum_by_name("rustegon.v1.AstBinaryOp")
            .unwrap();
        assert_eq!(enum_prefix(&e), "AST_BINARY_OP_");
        assert_eq!(enum_to_json(&e, 1).unwrap(), "eq");
        assert_eq!(
            enum_to_json(&e, 9999).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn fr_ql_002_statement_round_trips_through_proto() {
        for text in [
            "FROM shop.orders AS o WHERE o.status = $s AND o.total >= 10.0 SELECT o._id LIMIT 10",
            "UPDATE c SET a = 1, b.c = 'x' INC n BY 2 WHERE _id = OID '0123456789abcdef01234567'",
            "CREATE UNIQUE INDEX i ON db.c (a, b DESC) WITH (sparse = true)",
            "FROM c WHERE tags[0] IS NOT NULL SELECT VALUE x",
        ] {
            let stmt = parse_statement(text).unwrap();
            let proto = statement_to_proto(&stmt).unwrap();
            assert_eq!(statement_from_proto(&proto).unwrap(), stmt, "{text}");
        }
    }

    #[test]
    fn fr_ql_002_unset_kind_is_rgn_1010() {
        let err = statement_from_proto(&AstStatement::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::QuerySyntaxError);
    }
}
