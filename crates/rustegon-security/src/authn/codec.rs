// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Strict `RDoc` field accessors shared by the record codecs of this module.
//!
//! Records are canonical `RDoc`s (data-model.md §4) with a per-record format field. Decoding is
//! strict like the catalog's: unknown fields and wrong types are corruption, because a new
//! field means a new format version (implementation-rules.md §6) and silently dropping it on a
//! rewrite would lose security metadata.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustegon_doc::{Document, Value, rdoc, value::BINARY_GENERIC};

use crate::authn::error::{AuthnError, AuthnResult};

/// A decoded record plus the name of its kind, for error messages.
pub(crate) struct Fields<'a> {
    pub(crate) doc: &'a Document,
    pub(crate) what: &'static str,
}

impl Fields<'_> {
    fn err(&self, msg: impl std::fmt::Display) -> AuthnError {
        AuthnError::corrupt(self.what, msg)
    }

    /// Fails on any field outside `allowed`.
    pub(crate) fn only(&self, allowed: &[&str]) -> AuthnResult<()> {
        match self.doc.iter().find(|(n, _)| !allowed.contains(n)) {
            Some((n, _)) => Err(self.err(format!("unknown field {n:?}"))),
            None => Ok(()),
        }
    }

    /// Checks the format field `name` equals `version` and the `type` field equals `ty`.
    pub(crate) fn header(&self, name: &str, version: i64, ty: &str) -> AuthnResult<()> {
        match self.doc.get(name) {
            Some(Value::Int64(v)) if *v == version => {}
            Some(Value::Int64(v)) => return Err(self.err(format!("unsupported {name} {v}"))),
            _ => return Err(self.err(format!("missing {name}"))),
        }
        match self.doc.get("type") {
            Some(Value::String(t)) if t == ty => Ok(()),
            _ => Err(self.err(format!("type is not {ty:?}"))),
        }
    }

    pub(crate) fn i64(&self, name: &str) -> AuthnResult<i64> {
        match self.doc.get(name) {
            Some(Value::Int64(v)) => Ok(*v),
            _ => Err(self.err(format!("{name} missing or not an int64"))),
        }
    }

    pub(crate) fn u32(&self, name: &str) -> AuthnResult<u32> {
        u32::try_from(self.i64(name)?).map_err(|_| self.err(format!("{name} not a u32")))
    }

    pub(crate) fn u64(&self, name: &str) -> AuthnResult<u64> {
        u64::try_from(self.i64(name)?).map_err(|_| self.err(format!("{name} negative")))
    }

    pub(crate) fn bool(&self, name: &str) -> AuthnResult<bool> {
        match self.doc.get(name) {
            Some(Value::Bool(v)) => Ok(*v),
            _ => Err(self.err(format!("{name} missing or not a bool"))),
        }
    }

    pub(crate) fn str(&self, name: &str) -> AuthnResult<String> {
        match self.doc.get(name) {
            Some(Value::String(v)) => Ok(v.clone()),
            _ => Err(self.err(format!("{name} missing or not a string"))),
        }
    }

    pub(crate) fn bin(&self, name: &str) -> AuthnResult<Vec<u8>> {
        bin_of(self.doc.get(name)).ok_or_else(|| self.err(format!("{name} not generic binary")))
    }

    pub(crate) fn bin_n<const N: usize>(&self, name: &str) -> AuthnResult<[u8; N]> {
        <[u8; N]>::try_from(self.bin(name)?)
            .map_err(|_| self.err(format!("{name} is not {N} bytes")))
    }

    pub(crate) fn time(&self, name: &str) -> AuthnResult<SystemTime> {
        match self.doc.get(name) {
            Some(Value::DateTime(ms)) => from_millis(*ms).ok_or_else(|| self.err("time < 0")),
            _ => Err(self.err(format!("{name} missing or not a datetime"))),
        }
    }

    pub(crate) fn opt_time(&self, name: &str) -> AuthnResult<Option<SystemTime>> {
        match self.doc.get(name) {
            None => Ok(None),
            Some(_) => self.time(name).map(Some),
        }
    }

    pub(crate) fn str_array(&self, name: &str) -> AuthnResult<Vec<String>> {
        match self.doc.get(name) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s.clone()),
                    _ => Err(self.err(format!("{name} has a non-string element"))),
                })
                .collect(),
            _ => Err(self.err(format!("{name} missing or not an array"))),
        }
    }

    pub(crate) fn object(&self, name: &str) -> AuthnResult<Option<&Document>> {
        match self.doc.get(name) {
            None => Ok(None),
            Some(Value::Object(d)) => Ok(Some(d)),
            Some(_) => Err(self.err(format!("{name} not an object"))),
        }
    }
}

fn bin_of(v: Option<&Value>) -> Option<Vec<u8>> {
    match v {
        Some(Value::Binary {
            subtype: BINARY_GENERIC,
            data,
        }) => Some(data.clone()),
        _ => None,
    }
}

/// Decodes `bytes` as an `RDoc`, mapping errors to corruption of `what`.
pub(crate) fn decode(bytes: &[u8], what: &'static str) -> AuthnResult<Document> {
    rdoc::decode(bytes).map_err(|e| AuthnError::corrupt(what, e))
}

/// Encodes a record document.
pub(crate) fn encode(doc: &Document) -> AuthnResult<Vec<u8>> {
    rdoc::encode(doc).map_err(|e| AuthnError::Store(e.into()))
}

pub(crate) fn bin(data: &[u8]) -> Value {
    Value::Binary {
        subtype: BINARY_GENERIC,
        data: data.to_vec(),
    }
}

pub(crate) fn string(s: &str) -> Value {
    Value::String(s.to_owned())
}

pub(crate) fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
}

/// Milliseconds since the Unix epoch, saturating (times before 1970 never occur: they come from
/// [`rustegon_sim_api::Clock::wall`]).
#[must_use]
pub(crate) fn millis(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

pub(crate) fn time(t: SystemTime) -> Value {
    Value::DateTime(millis(t))
}

pub(crate) fn from_millis(ms: i64) -> Option<SystemTime> {
    let ms = u64::try_from(ms).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_millis(ms))
}

/// Truncates `t` to whole milliseconds, the resolution of persisted times, so that a record
/// built in memory equals its decoded form.
#[must_use]
pub(crate) fn trunc_millis(t: SystemTime) -> SystemTime {
    from_millis(millis(t)).unwrap_or(UNIX_EPOCH)
}
