// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Collection validators: a JSON Schema 2020-12 subset with Rustegon type names (FR-SCH-002,
//! FR-SCH-003; data-model.md §5, database-engine.md §2.5).
//!
//! A validator is stored verbatim as JSON text in the collection descriptor (PD-027) in the
//! form `{"$jsonSchema": <schema>}`. [`Validator::compile`] turns it into an evaluable schema
//! once; [`Validator::validate`] checks a value and reports violations as
//! [`ValidationError`]s (JSON pointer + keyword + message), at most [`MAX_REPORTED_ERRORS`].
//! [`check_write`] applies `validationLevel` / `validationAction` to one write, as a pure
//! function of the old and new documents, and [`ValidatorCache`] is the write path's
//! per-descriptor-version cache of compiled validators.
//!
//! Supported keywords: `type`, `required`, `properties`, `additionalProperties`, `enum`,
//! `const`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `minLength`,
//! `maxLength`, `pattern`, `items`, `minItems`, `maxItems`, `uniqueItems`, `allOf`, `anyOf`,
//! `oneOf`, `not`, plus boolean schemas; annotations are ignored, every other keyword is
//! rejected at compile time (an unknown keyword silently ignored would look enforced).

mod compile;
mod eval;
mod write;

use rustegon_doc::Value;
use serde_json::Value as Json;

pub use self::{
    compile::{MAX_REGEX_SIZE, MAX_SCHEMA_DEPTH},
    write::{SERVER_MAINTAINED_FIELDS, ValidationFailure, ValidatorCache, WriteCheck, check_write},
};
use self::{
    compile::{Schema, compile_schema},
    eval::{Sink, evaluate, is_valid},
};
use crate::error::{CatalogError, CatalogResult};

/// The single top-level key of a validator definition (data-model.md §5).
pub const JSON_SCHEMA_KEY: &str = "$jsonSchema";
/// Maximum size of a validator's JSON text (provisional, PD pending): it lives in the
/// collection descriptor, which every node caches.
pub const MAX_VALIDATOR_BYTES: usize = 256 * 1024;
/// Maximum number of violations reported for one document; the total is still counted.
pub const MAX_REPORTED_ERRORS: usize = 16;

/// One violation of a validator (FR-SCH-003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// RFC 6901 JSON pointer to the failing value in the document (`""` = the document
    /// itself). For `required`, it points at the missing property.
    pub path: String,
    /// The failing keyword (`type`, `required`, `pattern`, …; `false` for a `false` schema).
    pub keyword: &'static str,
    /// Human-readable explanation. Never contains values of the document.
    pub message: String,
}

/// Result of validating one value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    /// The first violations found, at most the requested limit, in evaluation order.
    pub errors: Vec<ValidationError>,
    /// Number of violations found (`>= errors.len()`).
    pub total: usize,
}

impl ValidationReport {
    /// Whether the value satisfies the validator.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.total == 0
    }
}

/// A compiled validator.
#[derive(Debug)]
pub struct Validator {
    schema: Schema,
}

impl Validator {
    /// Compiles a validator definition `{"$jsonSchema": <schema>}`.
    ///
    /// # Errors
    /// [`CatalogError::InvalidArgument`] (`RGN-1001`) for text that is not JSON, larger than
    /// [`MAX_VALIDATOR_BYTES`], not of the form above, or a schema using an unsupported or
    /// malformed keyword, an unknown type name, an invalid regex or nesting deeper than
    /// [`MAX_SCHEMA_DEPTH`].
    pub fn compile(text: &str) -> CatalogResult<Self> {
        if text.len() > MAX_VALIDATOR_BYTES {
            return Err(CatalogError::InvalidArgument(format!(
                "validator exceeds {MAX_VALIDATOR_BYTES} bytes"
            )));
        }
        let json: Json = serde_json::from_str(text).map_err(|e| {
            CatalogError::InvalidArgument(format!("validator is not valid JSON: {e}"))
        })?;
        let schema = match &json {
            Json::Object(map) if map.len() == 1 => match map.get(JSON_SCHEMA_KEY) {
                Some(s) => s,
                None => return Err(wrong_shape()),
            },
            _ => return Err(wrong_shape()),
        };
        Ok(Self {
            schema: compile_schema(schema, &format!("/{JSON_SCHEMA_KEY}"), 0)?,
        })
    }

    /// Validates `value`, reporting at most [`MAX_REPORTED_ERRORS`] violations.
    #[must_use]
    pub fn validate(&self, value: &Value) -> ValidationReport {
        self.validate_with_limit(value, MAX_REPORTED_ERRORS)
    }

    /// Validates `value`, keeping at most `limit` violations (`0` behaves as `1`); `total`
    /// still counts all of them.
    #[must_use]
    pub fn validate_with_limit(&self, value: &Value, limit: usize) -> ValidationReport {
        let mut sink = Sink::report(limit.max(1));
        evaluate(&self.schema, value, &mut sink);
        let (errors, total) = sink.into_parts();
        ValidationReport { errors, total }
    }

    /// Whether `value` satisfies the validator (stops at the first violation).
    #[must_use]
    pub fn is_valid(&self, value: &Value) -> bool {
        is_valid(&self.schema, value)
    }
}

fn wrong_shape() -> CatalogError {
    CatalogError::InvalidArgument(format!(
        "validator must be an object with the single key `{JSON_SCHEMA_KEY}`"
    ))
}
