// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Document model: `Value`, `RDoc` codec, JSON and extended JSON, key encoding and update operators.
//!
//! Specified by data-model.md §2 (types, order, field paths), §3.1–3.2 (key encoding, keyspace)
//! and §4 (`RDoc` v1); update operators by query-language.md §3 and data-model.md §2.3.
//! Requirements FR-DOC-001…006; tests TC-DOC-001…012.

pub mod compare;
pub mod decimal;
pub mod error;
mod hex;
pub mod json;
pub mod keyenc;
pub mod keyspace;
pub mod limits;
mod numeric;
pub mod oid;
pub mod path;
pub mod rdoc;
pub mod update;
pub mod value;

pub use crate::{
    decimal::Decimal128,
    error::{DocError, DocResult},
    oid::{ObjectId, ObjectIdGenerator},
    value::{Document, Timestamp, Value},
};
