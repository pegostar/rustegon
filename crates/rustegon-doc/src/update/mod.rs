// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Field-level update operators (FR-DOC-006; tests TC-DOC-009…012, AC-DOC-005).
//!
//! The engine works on an in-memory [`Document`](crate::Document) and knows nothing about the query engine: RGQL
//! (`query-language.md` §3 `update_ops`) is lowered by `rustegon-query` into a list of
//! [`UpdateOp`]s, and the only expression-dependent pieces — `PULL … WHERE expr` and array filters
//! — are caller-supplied [`ElementPredicate`]s.
//!
//! # Semantics
//! [`apply_updates`] applies a list of operators **atomically**: it works on a copy and returns
//! either the fully updated document or the first error, leaving the input untouched. Errors are
//! reported in a fixed order so that every implementation (and the reference interpreter of the
//! tests) reports the same one:
//! 1. per operator, in list order: field names of its paths (§2.2, `RGN-1004`), server-maintained
//!    top-level fields `_rev`, `_createdAt`, `_updatedAt`, `_conflict`, `_origin` (`RGN-1004`),
//!    `_id` (immutable, `RGN-1001`; `SET _id = v` with `v` equal to the current `_id` is a no-op),
//!    operand checks (values to store: valid field names and no `counter`, `RGN-1004`; `INC`/`MUL`
//!    operands numeric, `RGN-1011`; `RENAME` paths without positional segments, `RGN-1001`);
//! 2. conflicting paths: two targets where one is equal to or a prefix of the other (positional
//!    segments match any element) — `RGN-1001`;
//! 3. application, in list order (see [`UpdateOp`] for each operator and [`UpdatePath`] for path
//!    resolution).
//!
//! Size and depth limits (`RGN-1002`/`RGN-1003`) are enforced when the result is encoded.
//!
//! *Provisional (PD pending)*: the specification names the operators but not their edge-case
//! semantics; the choices here follow MongoDB where it is safe and are stricter where MongoDB
//! silently pads or promotes (writing past the end of an array is an error, integer overflow is
//! an error). They are listed in data-model.md §2.3.

mod apply;
mod arith;

use std::{fmt, sync::Arc};

use rustegon_common::{Error, ErrorCode};

pub use self::apply::apply_updates;
use crate::{error::DocError, keyenc::Direction, path::FieldPath, path::Segment, value::Value};

/// A predicate over one array element, evaluated by `PULL … WHERE` and array filters.
///
/// The query layer implements it with its expression evaluator; an evaluation error aborts the
/// whole update.
#[derive(Clone)]
pub struct ElementPredicate(Arc<PredicateFn>);

/// The closure type behind [`ElementPredicate`].
type PredicateFn = dyn Fn(&Value) -> Result<bool, Error> + Send + Sync;

impl ElementPredicate {
    /// Wraps a closure.
    pub fn new(f: impl Fn(&Value) -> Result<bool, Error> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Evaluates the predicate on `element`.
    ///
    /// # Errors
    /// Whatever the predicate returns.
    pub fn matches(&self, element: &Value) -> Result<bool, Error> {
        (self.0)(element)
    }
}

impl fmt::Debug for ElementPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElementPredicate(..)")
    }
}

/// One segment of an update target path.
#[derive(Debug, Clone)]
pub enum UpdateSegment {
    /// A field name, or an array index when it is a canonical decimal number (as in
    /// [`FieldPath`]).
    Field(Segment),
    /// Every element of an array (MongoDB `$[]`).
    AllElements,
    /// Every element of an array that matches the predicate (MongoDB `$[<id>]` with an array
    /// filter); the predicate sees the element before the update.
    Filtered(ElementPredicate),
}

/// The target path of an update operator.
///
/// Resolution, segment by segment, starting at the document root:
/// - a field segment on an object selects that field; when it is missing, operators that create
///   (`SET`, `INC`, `MUL`, `MIN`, `MAX`, `CURRENT DATE`, `PUSH`, `ADD TO SET`) insert an empty
///   object for an intermediate segment, the others do nothing;
/// - an index segment on an array selects that element; an index past the end, or a non-index
///   segment, is `RGN-1001` / `RGN-1011` for creating operators and a no-op for the others;
/// - a field segment on a scalar is `RGN-1011` for creating operators, a no-op otherwise;
/// - a positional segment ([`UpdateSegment::AllElements`], [`UpdateSegment::Filtered`]) on
///   anything but an existing array is `RGN-1011`; it applies the rest of the path to every
///   (matching) element.
///
/// Removing an array element by path (`UNSET a.0`) sets it to `null`, so that indexes of the
/// other elements do not shift.
#[derive(Debug, Clone)]
pub struct UpdatePath {
    segments: Vec<UpdateSegment>,
}

impl UpdatePath {
    /// Parses dot notation as [`FieldPath::parse`] (positional segments are built with
    /// [`UpdatePath::new`]).
    ///
    /// # Errors
    /// As [`FieldPath::parse`] (`RGN-1004`).
    pub fn parse(path: &str) -> Result<Self, DocError> {
        Ok(FieldPath::parse(path)?.into())
    }

    /// Builds a path from segments.
    #[must_use]
    pub fn new(segments: Vec<UpdateSegment>) -> Self {
        Self { segments }
    }

    /// The segments.
    #[must_use]
    pub fn segments(&self) -> &[UpdateSegment] {
        &self.segments
    }

    /// Renders the path for error messages (field names only, never values).
    fn display(&self) -> String {
        self.segments
            .iter()
            .map(|s| match s {
                UpdateSegment::Field(f) => f.name.as_str(),
                UpdateSegment::AllElements => "$[]",
                UpdateSegment::Filtered(_) => "$[filter]",
            })
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl From<FieldPath> for UpdatePath {
    fn from(p: FieldPath) -> Self {
        Self {
            segments: p
                .segments()
                .iter()
                .cloned()
                .map(UpdateSegment::Field)
                .collect(),
        }
    }
}

/// End of the array that `POP` removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopEnd {
    /// The first element.
    First,
    /// The last element.
    Last,
}

/// Sort modifier of `PUSH`: the whole array is stably re-sorted after the insertion.
#[derive(Debug, Clone)]
pub enum PushSort {
    /// By element value in the §2.1 total order.
    Elements(Direction),
    /// By fields of the elements (lexicographic over the keys); a non-object element, or one
    /// without the field, sorts as `missing`.
    Fields(Vec<(FieldPath, Direction)>),
}

/// `PUSH path VALUE v [push_mods]`: inserts `values` (MongoDB `$each`; a single value is a
/// one-element list) and then applies the modifiers in MongoDB order: position, sort, slice.
#[derive(Debug, Clone)]
pub struct Push {
    /// Target array (created when missing).
    pub path: UpdatePath,
    /// Values to insert, in order.
    pub values: Vec<Value>,
    /// Insertion index: `None` appends; `n ≥ 0` inserts before element `n` (clamped to the
    /// length); `n < 0` counts from the end (`-1` = before the last element, clamped to 0).
    pub position: Option<i64>,
    /// Re-sort after insertion.
    pub sort: Option<PushSort>,
    /// Then keep the first `n` elements (`n ≥ 0`) or the last `|n|` (`n < 0`).
    pub slice: Option<i64>,
}

/// One field-level update operator (FR-DOC-006, query-language.md §3 `update_ops`).
#[derive(Debug, Clone)]
pub enum UpdateOp {
    /// `SET path = value`: replaces or creates the target.
    Set {
        /// Target.
        path: UpdatePath,
        /// New value.
        value: Value,
    },
    /// `UNSET path`: removes the target (sets an array element to `null`); missing is a no-op.
    Unset {
        /// Target.
        path: UpdatePath,
    },
    /// `INC path BY n`: adds `n`; a missing target is created as `n`. Numeric rules in the
    /// `arith` module docs (`int64` overflow is `RGN-1001`; non-numeric target is `RGN-1011`).
    Inc {
        /// Target.
        path: UpdatePath,
        /// Increment (`int64`, `float64` or `decimal128`).
        by: Value,
    },
    /// `MUL path BY n`: multiplies by `n`; a missing target is created as zero of `n`'s type.
    Mul {
        /// Target.
        path: UpdatePath,
        /// Factor (`int64`, `float64` or `decimal128`).
        by: Value,
    },
    /// `MIN path WITH v`: sets the target to `v` when missing or when `v` sorts before it (§2.1).
    Min {
        /// Target.
        path: UpdatePath,
        /// Candidate.
        value: Value,
    },
    /// `MAX path WITH v`: sets the target to `v` when missing or when `v` sorts after it (§2.1).
    Max {
        /// Target.
        path: UpdatePath,
        /// Candidate.
        value: Value,
    },
    /// `RENAME from TO to`: moves a field (no positional segments; arrays may not be traversed,
    /// `RGN-1011`); a missing `from` is a no-op; an existing `to` is overwritten in place.
    Rename {
        /// Source field.
        from: UpdatePath,
        /// Destination field.
        to: UpdatePath,
    },
    /// `CURRENT DATE path`: sets the target to [`UpdateContext::now_ms`] as a `datetime`.
    CurrentDate {
        /// Target.
        path: UpdatePath,
    },
    /// `PUSH`, see [`Push`]. A non-array target is `RGN-1011`.
    Push(Push),
    /// `PULL path WHERE pred`: removes the elements matching the predicate; missing is a no-op,
    /// a non-array target is `RGN-1011`.
    Pull {
        /// Target array.
        path: UpdatePath,
        /// Elements to remove.
        predicate: ElementPredicate,
    },
    /// `pullAll`: removes the elements equal (§2.1 `=`) to any of `values`.
    PullAll {
        /// Target array.
        path: UpdatePath,
        /// Values to remove.
        values: Vec<Value>,
    },
    /// `ADD TO SET path VALUE v`: appends each value not already present (§2.1 `=`); creates the
    /// array when missing; a non-array target is `RGN-1011`.
    AddToSet {
        /// Target array.
        path: UpdatePath,
        /// Values to add, in order.
        values: Vec<Value>,
    },
    /// `POP path FIRST|LAST`: removes one end element; missing or empty is a no-op.
    Pop {
        /// Target array.
        path: UpdatePath,
        /// Which end.
        end: PopEnd,
    },
}

/// Inputs of an update that come from the statement rather than the operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateContext {
    /// `CURRENT DATE` value: milliseconds since the Unix epoch, taken from the transaction
    /// timestamp so that every operator of a statement (and every replica applying the
    /// evaluated batch) sees the same instant.
    pub now_ms: i64,
}

/// Error of [`apply_updates`].
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// `_id` would change (FR-DOC-002, AC-DOC-003; `RGN-1001`).
    #[error("_id is immutable and cannot be changed")]
    ImmutableId,
    /// Server-maintained or invalid field name, or a value that cannot be stored (`RGN-1004`).
    #[error(transparent)]
    InvalidField(#[from] DocError),
    /// Two operators target the same path or one targets a prefix of the other (`RGN-1001`).
    #[error("conflicting update paths '{0}' and '{1}'")]
    ConflictingPaths(String, String),
    /// Malformed operator: positional segment in `RENAME`, array index past the end (`RGN-1001`).
    #[error("invalid update: {0}")]
    InvalidOperator(String),
    /// Result out of range of its numeric type (`RGN-1001`).
    #[error("numeric overflow in update of '{0}'")]
    NumericOverflow(String),
    /// Operator applied to a value of the wrong type (`RGN-1011`).
    #[error("type mismatch in update of '{0}': {1}")]
    TypeMismatch(String, &'static str),
    /// A caller-supplied predicate failed.
    #[error("predicate failed: {0}")]
    Predicate(Error),
}

impl UpdateError {
    /// The catalog code (proto/errors.yaml).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::ImmutableId
            | Self::ConflictingPaths(..)
            | Self::InvalidOperator(_)
            | Self::NumericOverflow(_) => ErrorCode::InvalidArgument,
            Self::InvalidField(e) => e.code(),
            Self::TypeMismatch(..) => ErrorCode::QueryTypeError,
            Self::Predicate(e) => e.code(),
        }
    }
}

impl From<UpdateError> for Error {
    fn from(e: UpdateError) -> Self {
        match e {
            UpdateError::Predicate(inner) => inner,
            other => Error::new(other.code(), other.to_string()),
        }
    }
}

/// Result alias of the update engine.
pub type UpdateResult<T> = Result<T, UpdateError>;
