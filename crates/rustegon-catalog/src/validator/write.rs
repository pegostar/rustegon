// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `validationLevel` / `validationAction` on the write path (FR-SCH-002, data-model.md §5,
//! database-engine.md §3 step 3: validation runs before intents are written).
//!
//! [`check_write`] is pure — old document, new document, options in; decision out — so every
//! write path (embedded API now, the server's document service from M4) applies the same
//! semantics, and the semantics are testable without a store.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};

use super::{ValidationReport, Validator};
use crate::{
    descriptor::{CollectionDescriptor, CollectionOptions, ValidationAction, ValidationLevel},
    error::{CatalogError, CatalogResult},
};

/// Top-level fields the server maintains (FR-DOC-005, data-model.md §2.2). Validators do not see
/// them: users cannot write them, so a schema with `additionalProperties: false` must not have
/// to list them (provisional, PD pending). `_id` and `_expiresAt` are user-writable and are
/// validated.
pub const SERVER_MAINTAINED_FIELDS: [&str; 5] =
    ["_rev", "_createdAt", "_updatedAt", "_conflict", "_origin"];

/// Upper bound of cached compiled validators; the cache is cleared when it is reached (old
/// descriptor versions are never needed again, so precise eviction is not worth a dependency).
const MAX_CACHED_VALIDATORS: usize = 1024;

/// Outcome of [`check_write`] for an accepted write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCheck {
    /// No validator, or `validationLevel: off`.
    Unchecked,
    /// The new document satisfies the validator.
    Valid,
    /// `moderate`: the new document fails, but it updates a document that already failed, so
    /// the update is not validated (data-model.md §5).
    Exempt,
    /// `validationAction: warn`: the new document fails and the write is accepted; the
    /// violations are returned to the client and logged.
    Warned(ValidationReport),
}

/// A write rejected by `validationAction: error` (`RGN-1006 SchemaValidationFailed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    /// The violations of the new document.
    pub report: ValidationReport,
}

impl From<ValidationFailure> for Error {
    /// `RGN-1006` with details `path`, `keyword`, `message` of the first violation (the
    /// `{path, keyword, message}` of data-model.md §5), `violations` (total count) and `errors`
    /// (a JSON array of all reported violations).
    fn from(f: ValidationFailure) -> Self {
        let r = f.report;
        let Some(first) = r.errors.first() else {
            return Error::new(
                ErrorCode::SchemaValidationFailed,
                "document fails the collection validator",
            );
        };
        let more = r.total.saturating_sub(1);
        let suffix = if more > 0 {
            format!(" (+{more} more)")
        } else {
            String::new()
        };
        let pointer = if first.path.is_empty() {
            "/"
        } else {
            &first.path
        };
        let list = serde_json::Value::Array(
            r.errors
                .iter()
                .map(|e| {
                    serde_json::json!({ "path": e.path, "keyword": e.keyword, "message": e.message })
                })
                .collect(),
        );
        Error::new(
            ErrorCode::SchemaValidationFailed,
            format!(
                "document fails the collection validator at {pointer} ({}): {}{suffix}",
                first.keyword, first.message
            ),
        )
        .with_detail("path", first.path.clone())
        .with_detail("keyword", first.keyword)
        .with_detail("message", first.message.clone())
        .with_detail("violations", r.total.to_string())
        .with_detail("errors", list.to_string())
    }
}

/// Applies `options` to one write (module docs). `old` is the document being replaced or
/// updated (`None` for an insert), `new` the document to store; both may carry the
/// server-maintained fields, which are hidden from the validator
/// ([`SERVER_MAINTAINED_FIELDS`]).
///
/// - `off` or no validator → [`WriteCheck::Unchecked`];
/// - `new` valid → [`WriteCheck::Valid`];
/// - `moderate`, an update, and `old` invalid → [`WriteCheck::Exempt`] (inserts are always
///   validated);
/// - otherwise `warn` → [`WriteCheck::Warned`], `error` → `Err` ([`ValidationFailure`]).
///
/// # Errors
/// [`ValidationFailure`] when the write must be rejected.
pub fn check_write(
    options: &CollectionOptions,
    validator: Option<&Validator>,
    old: Option<&Document>,
    new: &Document,
) -> Result<WriteCheck, ValidationFailure> {
    let Some(validator) = validator else {
        return Ok(WriteCheck::Unchecked);
    };
    if options.validation_level == ValidationLevel::Off {
        return Ok(WriteCheck::Unchecked);
    }
    let report = validator.validate(&user_view(new));
    if report.is_valid() {
        return Ok(WriteCheck::Valid);
    }
    // `old` is evaluated only when `new` fails: a valid `new` is accepted at every level.
    if options.validation_level == ValidationLevel::Moderate
        && old.is_some_and(|o| !validator.is_valid(&user_view(o)))
    {
        return Ok(WriteCheck::Exempt);
    }
    match options.validation_action {
        ValidationAction::Warn => Ok(WriteCheck::Warned(report)),
        ValidationAction::Error => Err(ValidationFailure { report }),
    }
}

/// The document as validators see it: without the server-maintained fields. Copies the
/// document because the evaluator works on [`Value`]s; validation is linear in the document
/// anyway.
fn user_view(doc: &Document) -> Value {
    let fields = doc
        .iter()
        .filter(|(n, _)| !SERVER_MAINTAINED_FIELDS.contains(n))
        .map(|(n, v)| (n.to_owned(), v.clone()))
        .collect();
    // Names of a valid document are unique, so this cannot fail; an empty object is never
    // reached in practice and would only make the check stricter.
    Value::Object(Document::try_from_fields(fields).unwrap_or_default())
}

/// Compiled validators by (collection id, descriptor version), plus the count of writes
/// accepted with warnings.
///
/// A descriptor change bumps the version, so an entry is never stale: a new version simply
/// misses and compiles. The lock protects only the map; compilation runs outside it, so two
/// writers may compile the same validator once each — harmless, and cheaper than holding the
/// lock during compilation.
#[derive(Debug, Default)]
pub struct ValidatorCache {
    compiled: Mutex<HashMap<(u32, u64), Arc<Validator>>>,
    warnings: AtomicU64,
}

impl ValidatorCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The compiled validator of `coll`, `None` if it has none or `validationLevel` is `off`.
    ///
    /// # Errors
    /// [`CatalogError::InvalidArgument`] if the stored validator does not compile (it is
    /// checked at creation, so this means a descriptor written by another tool or version).
    pub fn get(&self, coll: &CollectionDescriptor) -> CatalogResult<Option<Arc<Validator>>> {
        let Some(text) = &coll.options.validator else {
            return Ok(None);
        };
        if coll.options.validation_level == ValidationLevel::Off {
            return Ok(None);
        }
        let key = (coll.id, coll.version);
        if let Some(v) = self.lock().get(&key) {
            return Ok(Some(Arc::clone(v)));
        }
        let compiled = Arc::new(Validator::compile(text).map_err(|e| match e {
            CatalogError::InvalidArgument(m) => {
                CatalogError::InvalidArgument(format!("collection {}: {m}", coll.name))
            }
            other => other,
        })?);
        let mut map = self.lock();
        if map.len() >= MAX_CACHED_VALIDATORS {
            map.clear();
        }
        map.insert(key, Arc::clone(&compiled));
        Ok(Some(compiled))
    }

    /// [`check_write`] for a write to `coll`, with the compiled validator taken from the cache.
    /// A [`WriteCheck::Warned`] outcome is logged (`warn`, `main` channel) and counted.
    ///
    /// # Errors
    /// `RGN-1006` when the write is rejected; `RGN-1001` for an uncompilable stored validator.
    pub fn check(
        &self,
        coll: &CollectionDescriptor,
        old: Option<&Document>,
        new: &Document,
    ) -> Result<WriteCheck, Error> {
        let validator = self.get(coll)?;
        let outcome = check_write(&coll.options, validator.as_deref(), old, new)?;
        if let WriteCheck::Warned(report) = &outcome {
            self.warnings.fetch_add(1, Ordering::Relaxed);
            // Only schema-side facts are logged: the pointer contains document field names,
            // which are document contents (coding-standards.md §3.6); the client gets the full
            // report in the response.
            tracing::warn!(
                collection_id = coll.id,
                keyword = report.errors.first().map_or("", |e| e.keyword),
                violations = report.total,
                "write accepted despite validator violations (validationAction=warn)"
            );
        }
        Ok(outcome)
    }

    /// Number of writes accepted with validator warnings since the cache was created (a
    /// process-local counter; exported as a metric once the metrics registry exists).
    #[must_use]
    pub fn warnings(&self) -> u64 {
        self.warnings.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(u32, u64), Arc<Validator>>> {
        // The map holds only immutable compiled validators: a panic while holding the lock
        // cannot leave it inconsistent, so a poisoned lock is still usable.
        self.compiled.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
