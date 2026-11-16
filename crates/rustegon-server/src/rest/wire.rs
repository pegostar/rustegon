// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! JSON ↔ service-layer types shared by the data-plane REST adapters (protocol.md §4
//! conventions; PD-055).
//!
//! Documents and values travel as extended JSON (data-model.md §2, `rustegon_doc::json`):
//! requests carry them as raw JSON text ([`RawValue`]) that goes to the extended-JSON parser
//! unchanged — a `serde_json::Value` would reorder fields and silently keep the last of
//! duplicate names, both of which the document model must see — and responses embed the
//! canonical serialization as raw JSON. Enumerations are lowercase snake-case strings; an
//! unknown value fails the body with RGN-1001 (`details.body` = `data`), as unknown enum values
//! do on gRPC.

use std::{collections::BTreeMap, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, parse_document, parse_value, to_json, value_to_json},
};
use rustegon_engine::{Isolation, Priority};
use rustegon_query::Params;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use utoipa::{IntoParams, ToSchema};

use super::context::single;
use crate::{
    grpc::convert::params_from_values,
    services::{ReadConsistency, ReturnDocument, Warning, WriteConcern, WriteResult},
};

/// `If-Match` request header (optimistic concurrency on `_rev`).
pub const IF_MATCH: &str = "if-match";

fn invalid(field: &str, message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message.into()).with_detail("field", field)
}

/// A document from extended JSON; `field` names the request field in errors.
///
/// # Errors
/// The extended-JSON parser's RGN-1001/1003/1004.
pub(crate) fn document_in(raw: &RawValue, field: &str) -> Result<Document, Error> {
    parse_document(raw.get()).map_err(|e| Error::from(e).with_detail("field", field))
}

/// A value from extended JSON.
///
/// # Errors
/// As [`document_in`].
pub(crate) fn value_in(raw: &RawValue, field: &str) -> Result<Value, Error> {
    parse_value(raw.get()).map_err(|e| Error::from(e).with_detail("field", field))
}

fn raw(text: String) -> Result<Box<RawValue>, Error> {
    // The extended-JSON writer always produces valid JSON; failing here is a bug.
    RawValue::from_string(text)
        .map_err(|_| Error::new(ErrorCode::Internal, "document serialization failed"))
}

/// A document as canonical extended JSON.
///
/// # Errors
/// RGN-5001 only if the serializer produced invalid JSON.
pub(crate) fn document_out(d: &Document) -> Result<Box<RawValue>, Error> {
    raw(to_json(d, JsonMode::Canonical))
}

/// A value as canonical extended JSON (result rows of any type, ids).
///
/// # Errors
/// As [`document_out`].
pub(crate) fn value_out(v: &Value) -> Result<Box<RawValue>, Error> {
    raw(value_to_json(v, JsonMode::Canonical))
}

/// Query parameters: names `"1"`, `"2"`, … are the positional `$1`, `$2`, …, any other name a
/// named parameter (the rule of the gRPC `params` map).
///
/// # Errors
/// RGN-1001 for gaps, value parse errors.
pub(crate) fn params_in(map: &BTreeMap<String, Box<RawValue>>) -> Result<Params, Error> {
    let pairs = map
        .iter()
        .map(|(k, v)| Ok((k.clone(), value_in(v, "params")?)))
        .collect::<Result<Vec<_>, Error>>()?;
    params_from_values(pairs)
}

/// Options (`implicit_collection_creation`, …) from a JSON object of extended-JSON values,
/// sorted by name like the gRPC map.
///
/// # Errors
/// Value parse errors.
pub(crate) fn options_in(
    map: &BTreeMap<String, Box<RawValue>>,
) -> Result<Vec<(String, Value)>, Error> {
    map.iter()
        .map(|(k, v)| Ok((k.clone(), value_in(v, "options")?)))
        .collect()
}

/// Options as a JSON object of extended-JSON values.
///
/// # Errors
/// As [`value_out`].
pub(crate) fn options_out(
    options: &[(String, Value)],
) -> Result<BTreeMap<String, Box<RawValue>>, Error> {
    options
        .iter()
        .map(|(k, v)| Ok((k.clone(), value_out(v)?)))
        .collect()
}

/// A document id taken from a URL path segment (already percent-decoded by the router): the
/// segment is read as an extended-JSON value when it is one (`42` → `int64`,
/// `{"$oid":"…"}` → `objectId`, `"42"` → the string `42`), otherwise it is the string itself
/// (`/documents/alice` → `"alice"`). PD-055.
#[must_use]
pub(crate) fn id_from_path(segment: &str) -> Value {
    parse_value(segment).unwrap_or_else(|_| Value::String(segment.to_owned()))
}

/// The `_rev` of `doc`, if it has a string one.
#[must_use]
pub(crate) fn rev_of(doc: &Document) -> Option<&str> {
    match doc.get("_rev") {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// `ETag` value for a revision: the quoted `_rev` (a strong validator).
#[must_use]
pub(crate) fn etag(rev: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("\"{rev}\"")).ok()
}

/// Headers carrying `ETag` for `rev` (empty without one).
#[must_use]
pub(crate) fn etag_headers(rev: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(v) = rev.and_then(etag) {
        h.insert(http::header::ETAG, v);
    }
    h
}

/// The `_rev` precondition of an `If-Match` header: one strong entity tag (`"<rev>"`; a bare
/// `<rev>` is accepted for curl users). `*`, weak tags and lists are not supported (RGN-1001):
/// a precondition the server cannot evaluate exactly must not be ignored.
///
/// # Errors
/// RGN-1001 (detail `header` = `if-match`).
pub(crate) fn if_match(headers: &HeaderMap) -> Result<Option<String>, Error> {
    let Some(value) = single(headers, IF_MATCH)? else {
        return Ok(None);
    };
    let bad = |reason: &str| crate::services::invalid_header(IF_MATCH, reason);
    let value = value.trim_matches(' ');
    if value == "*" || value.starts_with("W/") || value.contains(',') {
        return Err(bad("expected one strong entity tag (\"<_rev>\")"));
    }
    let rev = match value.strip_prefix('"') {
        Some(rest) => rest
            .strip_suffix('"')
            .ok_or_else(|| bad("unterminated entity tag"))?,
        None => value,
    };
    if rev.is_empty() || rev.contains('"') {
        return Err(bad("empty or malformed entity tag"));
    }
    Ok(Some(rev.to_owned()))
}

/// A continuation token from its base64url text (no padding).
///
/// # Errors
/// RGN-1001 (detail `field` = `continuationToken`).
pub(crate) fn token_in(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| invalid("continuationToken", "continuation token is not base64url"))
}

/// A continuation token as base64url text (no padding).
#[must_use]
pub(crate) fn token_out(token: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(token)
}

/// Unix milliseconds of `t` (the `*_unix_ms` convention of protocol.md §3).
#[must_use]
pub(crate) fn unix_ms(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A duration as whole milliseconds (saturating).
#[must_use]
pub(crate) fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------------------------
// Enumerations and option objects
// ---------------------------------------------------------------------------------------------

/// Read consistency level (protocol.md §3 `ReadConsistencyLevel`; omitted = server default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    /// Linearizable read.
    Linearizable,
    /// Bounded staleness (needs `maxStalenessMs`).
    BoundedStaleness,
    /// Follower read.
    Follower,
}

/// Read consistency of a read outside transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consistency {
    /// Level.
    pub level: ConsistencyLevel,
    /// Staleness bound in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_staleness_ms: Option<u32>,
}

/// Query parameters selecting the read consistency of a `GET`.
#[derive(Debug, Clone, Copy, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ConsistencyQuery {
    /// Read consistency level (default: the server default, linearizable).
    pub consistency: Option<ConsistencyLevel>,
    /// Staleness bound in milliseconds for `bounded_staleness` / `follower`.
    pub max_staleness_ms: Option<u32>,
}

/// The service form of an optional consistency.
#[must_use]
pub(crate) fn consistency_in(c: Option<Consistency>) -> ReadConsistency {
    let Some(c) = c else {
        return ReadConsistency::Default;
    };
    let staleness = c
        .max_staleness_ms
        .map(|ms| Duration::from_millis(u64::from(ms)));
    match c.level {
        ConsistencyLevel::Linearizable => ReadConsistency::Linearizable,
        ConsistencyLevel::BoundedStaleness => ReadConsistency::BoundedStaleness {
            max_staleness: staleness.unwrap_or(Duration::ZERO),
        },
        ConsistencyLevel::Follower => ReadConsistency::Follower {
            max_staleness: staleness,
        },
    }
}

impl ConsistencyQuery {
    /// The service form.
    #[must_use]
    pub(crate) fn read_consistency(self) -> ReadConsistency {
        consistency_in(self.consistency.map(|level| Consistency {
            level,
            max_staleness_ms: self.max_staleness_ms,
        }))
    }
}

/// Write concern (protocol.md §3 `WriteConcern`; omitted = server default, majority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WriteConcernName {
    /// Majority of replicas.
    Majority,
    /// All replicas.
    All,
    /// Majority in the local datacenter.
    LocalDcMajority,
    /// Synchronous cross-datacenter.
    SyncCrossDc,
    /// Asynchronous cross-datacenter.
    AsyncCrossDc,
}

/// The service form of an optional write concern.
#[must_use]
pub(crate) fn write_concern_in(w: Option<WriteConcernName>) -> WriteConcern {
    match w {
        None => WriteConcern::Default,
        Some(WriteConcernName::Majority) => WriteConcern::Majority,
        Some(WriteConcernName::All) => WriteConcern::All,
        Some(WriteConcernName::LocalDcMajority) => WriteConcern::LocalDcMajority,
        Some(WriteConcernName::SyncCrossDc) => WriteConcern::SyncCrossDc,
        Some(WriteConcernName::AsyncCrossDc) => WriteConcern::AsyncCrossDc,
    }
}

/// Transaction isolation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IsolationName {
    /// SERIALIZABLE (default).
    Serializable,
    /// SNAPSHOT.
    Snapshot,
    /// READ COMMITTED.
    ReadCommitted,
}

/// The engine form.
#[must_use]
pub(crate) fn isolation_in(i: Option<IsolationName>) -> Option<Isolation> {
    i.map(|i| match i {
        IsolationName::Serializable => Isolation::Serializable,
        IsolationName::Snapshot => Isolation::Snapshot,
        IsolationName::ReadCommitted => Isolation::ReadCommitted,
    })
}

/// Transaction priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PriorityName {
    /// High.
    High,
    /// Normal (default).
    Normal,
    /// Low.
    Low,
}

/// The engine form.
#[must_use]
pub(crate) fn priority_in(p: Option<PriorityName>) -> Option<Priority> {
    p.map(|p| match p {
        PriorityName::High => Priority::High,
        PriorityName::Normal => Priority::Normal,
        PriorityName::Low => Priority::Low,
    })
}

/// Which version of a written document the response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReturnDocumentName {
    /// None (default).
    #[default]
    None,
    /// Before the write.
    Before,
    /// After the write.
    After,
}

/// The service form.
#[must_use]
pub(crate) fn return_document_in(r: Option<ReturnDocumentName>) -> ReturnDocument {
    match r.unwrap_or_default() {
        ReturnDocumentName::None => ReturnDocument::None,
        ReturnDocumentName::Before => ReturnDocument::Before,
        ReturnDocumentName::After => ReturnDocument::After,
    }
}

// ---------------------------------------------------------------------------------------------
// Shared response pieces
// ---------------------------------------------------------------------------------------------

/// A non-fatal condition reported with a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WarningJson {
    /// Stable kind, e.g. `EvaluationWarning`.
    pub kind: String,
    /// Message (no document contents).
    pub message: String,
    /// Details.
    pub details: BTreeMap<String, String>,
}

/// Warnings of a result.
#[must_use]
pub(crate) fn warnings_out(w: &[Warning]) -> Vec<WarningJson> {
    w.iter()
        .map(|w| WarningJson {
            kind: w.kind.clone(),
            message: w.message.clone(),
            details: w.details.clone(),
        })
        .collect()
}

/// Outcome of one written document.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WriteResultJson {
    /// Document id (extended-JSON value).
    #[schema(value_type = Value)]
    pub id: Box<RawValue>,
    /// New `_rev` (absent for deletes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

/// A write result.
///
/// # Errors
/// As [`value_out`].
pub(crate) fn write_result_out(r: &WriteResult) -> Result<WriteResultJson, Error> {
    Ok(WriteResultJson {
        id: value_out(&r.id)?,
        rev: r.rev.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use http::HeaderValue;

    use super::*;

    fn h(v: &'static str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(IF_MATCH, HeaderValue::from_static(v));
        m
    }

    #[test]
    fn fr_api_002_if_match_takes_one_strong_tag() {
        assert_eq!(if_match(&HeaderMap::new()).unwrap(), None);
        assert_eq!(if_match(&h("\"r1\"")).unwrap().as_deref(), Some("r1"));
        assert_eq!(if_match(&h("r1")).unwrap().as_deref(), Some("r1"));
        for bad in ["*", "W/\"r1\"", "\"a\", \"b\"", "\"r1", "\"\""] {
            let e = if_match(&h(bad)).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(e.details().get("header").unwrap(), IF_MATCH);
        }
    }

    #[test]
    fn fr_api_002_path_ids_are_extended_json_or_strings() {
        assert_eq!(id_from_path("42"), Value::Int64(42));
        assert_eq!(id_from_path("\"42\""), Value::String("42".into()));
        assert_eq!(id_from_path("alice"), Value::String("alice".into()));
        assert!(matches!(
            id_from_path("{\"$oid\":\"0123456789abcdef01234567\"}"),
            Value::ObjectId(_)
        ));
    }

    #[test]
    fn fr_api_002_documents_keep_order_and_reject_duplicates() {
        let raw = RawValue::from_string("{\"b\":1,\"a\":{\"$int64\":\"2\"}}".into()).unwrap();
        let d = document_in(&raw, "document").unwrap();
        assert_eq!(document_out(&d).unwrap().get(), "{\"b\":1,\"a\":2}");
        let dup = RawValue::from_string("{\"a\":1,\"a\":2}".into()).unwrap();
        let e = document_in(&dup, "document").unwrap_err();
        assert_eq!(e.details().get("field").unwrap(), "document");
        assert_eq!(token_in(&token_out(&[1, 2, 255])).unwrap(), vec![1, 2, 255]);
        assert!(token_in("not base64!").is_err());
    }
}
