// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! prost messages ↔ service-layer types for the data-plane adapters (protocol.md §3,
//! PD-045, PD-053): `RDoc` documents and values, parameters, enums (`*_UNSPECIFIED` = server
//! default, unknown values = RGN-1001), result batches.

use std::{collections::HashMap, time::Duration};

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, rdoc};
use rustegon_engine::{Isolation, Priority};
use rustegon_proto::v1 as pb;
use rustegon_query::Params;

use crate::services::{
    QueryOptions, QueryStats, ReadConsistency, ResultBatch, ReturnDocument, Warning, WriteConcern,
    WriteResult,
};

fn invalid(field: &str, message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message.into()).with_detail("field", field)
}

/// A `Value` (`RDoc` value encoding) as a value; `field` names the request field in errors.
///
/// # Errors
/// RGN-1001 (absent), the `RDoc` decoding errors (RGN-1001/1002/1003/1004).
pub fn value_from_proto(v: Option<&pb::Value>, field: &str) -> Result<Value, Error> {
    let v = v.ok_or_else(|| invalid(field, format!("{field} is required")))?;
    rdoc::decode_value(&v.rdoc_value).map_err(|e| Error::from(e).with_detail("field", field))
}

/// A value in the `RDoc` value encoding.
///
/// # Errors
/// `RDoc` limits (never for values read from the store).
pub fn value_to_proto(v: &Value) -> Result<pb::Value, Error> {
    Ok(pb::Value {
        rdoc_value: rdoc::encode_value(v)?,
    })
}

/// A `Document` (`RDoc` bytes) as a document.
///
/// # Errors
/// RGN-1001 (absent), the `RDoc` decoding errors.
pub fn document_from_proto(d: Option<&pb::Document>, field: &str) -> Result<Document, Error> {
    let d = d.ok_or_else(|| invalid(field, format!("{field} is required")))?;
    rdoc::decode(&d.rdoc).map_err(|e| Error::from(e).with_detail("field", field))
}

/// A document as `RDoc` bytes.
///
/// # Errors
/// `RDoc` limits.
pub fn document_to_proto(d: &Document) -> Result<pb::Document, Error> {
    Ok(pb::Document {
        rdoc: rdoc::encode(d)?,
    })
}

/// A result row as a document: objects as they are, any other value wrapped as
/// `{"value": row}` (`ResultBatch.docs` carries documents only; PD-053).
///
/// # Errors
/// `RDoc` limits.
pub fn row_to_proto(row: &Value) -> Result<pb::Document, Error> {
    match row {
        Value::Object(d) => document_to_proto(d),
        other => document_to_proto(&Document::try_from_fields(vec![(
            "value".to_owned(),
            other.clone(),
        )])?),
    }
}

/// Query parameters: `"1"`, `"2"`, … are the positional `$1`, `$2`, … (they must be
/// contiguous from 1), any other key a named parameter.
///
/// # Errors
/// RGN-1001 for gaps in positional parameters, value decoding errors.
pub fn params_from_proto<S: std::hash::BuildHasher>(
    map: &HashMap<String, pb::Value, S>,
) -> Result<Params, Error> {
    let pairs = map
        .iter()
        .map(|(name, v)| Ok((name.clone(), value_from_proto(Some(v), "params")?)))
        .collect::<Result<Vec<_>, Error>>()?;
    params_from_values(pairs)
}

/// Named and positional parameters from `(name, value)` pairs, by the rule of
/// [`params_from_proto`]; shared with the REST front end so both channels bind alike.
///
/// # Errors
/// RGN-1001 for gaps in positional parameters.
pub fn params_from_values(pairs: Vec<(String, Value)>) -> Result<Params, Error> {
    let mut params = Params::new();
    let mut positional: Vec<(usize, Value)> = Vec::new();
    for (name, value) in pairs {
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = name
                .parse()
                .map_err(|_| invalid("params", "positional parameter out of range"))?;
            positional.push((n, value));
        } else {
            params.set(name, value);
        }
    }
    positional.sort_by_key(|(n, _)| *n);
    for (i, (n, value)) in positional.into_iter().enumerate() {
        if n != i + 1 {
            return Err(invalid(
                "params",
                "positional parameters must be numbered 1, 2, … without gaps",
            ));
        }
        params.push(value);
    }
    Ok(params)
}

fn enum_value<E: TryFrom<i32>>(raw: i32, field: &str) -> Result<E, Error> {
    E::try_from(raw).map_err(|_| invalid(field, format!("unknown {field} value {raw}")))
}

/// Read consistency.
///
/// # Errors
/// RGN-1001 for unknown levels.
pub fn consistency_from_proto(c: Option<&pb::ReadConsistency>) -> Result<ReadConsistency, Error> {
    let Some(c) = c else {
        return Ok(ReadConsistency::Default);
    };
    let staleness = c
        .max_staleness_ms
        .map(|ms| Duration::from_millis(u64::from(ms)));
    Ok(
        match enum_value::<pb::ReadConsistencyLevel>(c.level, "consistency")? {
            pb::ReadConsistencyLevel::Unspecified => ReadConsistency::Default,
            pb::ReadConsistencyLevel::Linearizable => ReadConsistency::Linearizable,
            pb::ReadConsistencyLevel::BoundedStaleness => ReadConsistency::BoundedStaleness {
                max_staleness: staleness.unwrap_or(Duration::ZERO),
            },
            pb::ReadConsistencyLevel::Follower => ReadConsistency::Follower {
                max_staleness: staleness,
            },
        },
    )
}

/// Write concern.
///
/// # Errors
/// RGN-1001 for unknown values.
pub fn write_concern_from_proto(raw: i32) -> Result<WriteConcern, Error> {
    Ok(
        match enum_value::<pb::WriteConcern>(raw, "write_concern")? {
            pb::WriteConcern::Unspecified => WriteConcern::Default,
            pb::WriteConcern::Majority => WriteConcern::Majority,
            pb::WriteConcern::All => WriteConcern::All,
            pb::WriteConcern::LocalDcMajority => WriteConcern::LocalDcMajority,
            pb::WriteConcern::SyncCrossDc => WriteConcern::SyncCrossDc,
            pb::WriteConcern::AsyncCrossDc => WriteConcern::AsyncCrossDc,
        },
    )
}

/// Write concern of optional `WriteOptions`.
///
/// # Errors
/// As [`write_concern_from_proto`].
pub fn write_options_from_proto(o: Option<&pb::WriteOptions>) -> Result<WriteConcern, Error> {
    o.map_or(Ok(WriteConcern::Default), |o| {
        write_concern_from_proto(o.write_concern)
    })
}

/// Isolation (`None` = default).
///
/// # Errors
/// RGN-1001 for unknown values.
pub fn isolation_from_proto(raw: i32) -> Result<Option<Isolation>, Error> {
    Ok(match enum_value::<pb::AstIsolation>(raw, "isolation")? {
        pb::AstIsolation::Unspecified => None,
        pb::AstIsolation::Serializable => Some(Isolation::Serializable),
        pb::AstIsolation::Snapshot => Some(Isolation::Snapshot),
        pb::AstIsolation::ReadCommitted => Some(Isolation::ReadCommitted),
    })
}

/// Priority (`None` = default).
///
/// # Errors
/// RGN-1001 for unknown values.
pub fn priority_from_proto(raw: i32) -> Result<Option<Priority>, Error> {
    Ok(match enum_value::<pb::AstPriority>(raw, "priority")? {
        pb::AstPriority::Unspecified => None,
        pb::AstPriority::High => Some(Priority::High),
        pb::AstPriority::Normal => Some(Priority::Normal),
        pb::AstPriority::Low => Some(Priority::Low),
    })
}

/// Which document a write returns.
///
/// # Errors
/// RGN-1001 for unknown values.
pub fn return_document_from_proto(raw: i32) -> Result<ReturnDocument, Error> {
    Ok(
        match enum_value::<pb::ReturnDocument>(raw, "return_document")? {
            pb::ReturnDocument::Unspecified => ReturnDocument::None,
            pb::ReturnDocument::Before => ReturnDocument::Before,
            pb::ReturnDocument::After => ReturnDocument::After,
        },
    )
}

/// Execution options.
///
/// # Errors
/// RGN-1001 for unknown enum values.
pub fn query_options_from_proto(o: Option<&pb::ExecOptions>) -> Result<QueryOptions, Error> {
    let Some(o) = o else {
        return Ok(QueryOptions::default());
    };
    Ok(QueryOptions {
        batch_size: o.batch_size,
        max_time: o.max_time_ms.map(Duration::from_millis),
        consistency: consistency_from_proto(o.consistency.as_ref())?,
        allow_disk_use: o.allow_disk_use,
        max_batches: o.max_batches,
        continuation_token: o.continuation_token.clone(),
        write_concern: write_concern_from_proto(o.write_concern)?,
    })
}

/// A warning.
#[must_use]
pub fn warning_to_proto(w: &Warning) -> pb::Warning {
    pb::Warning {
        kind: w.kind.clone(),
        message: w.message.clone(),
        details: w.details.clone().into_iter().collect(),
    }
}

/// A result batch.
///
/// # Errors
/// `RDoc` limits.
pub fn batch_to_proto(b: ResultBatch) -> Result<pb::ResultBatch, Error> {
    Ok(pb::ResultBatch {
        docs: b.rows.iter().map(row_to_proto).collect::<Result<_, _>>()?,
        includes: HashMap::new(),
        cursor_id: b.cursor_id,
        continuation_token: b.continuation_token,
        stats: b.stats.as_ref().map(stats_to_proto),
        warnings: b.warnings.iter().map(warning_to_proto).collect(),
        staleness: None,
    })
}

fn stats_to_proto(s: &QueryStats) -> pb::QueryStats {
    pb::QueryStats {
        docs_examined: 0,
        keys_examined: 0,
        docs_returned: s.docs_returned,
        docs_affected: s.docs_affected,
        execution_time_us: s.execution_time_us,
        indexes_used: Vec::new(),
    }
}

/// A write result.
///
/// # Errors
/// `RDoc` limits.
pub fn write_result_to_proto(r: &WriteResult) -> Result<pb::WriteResult, Error> {
    Ok(pb::WriteResult {
        id: Some(value_to_proto(&r.id)?),
        rev: r.rev.clone(),
    })
}

/// An optional document.
///
/// # Errors
/// `RDoc` limits.
pub fn opt_document_to_proto(d: Option<&Document>) -> Result<Option<pb::Document>, Error> {
    d.map(document_to_proto).transpose()
}
