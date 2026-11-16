// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-operation options and the awaitable operation builder (rust-driver.md §4).
//!
//! Every I/O method returns an [`Action`]: set options by chaining, then `.await` it —
//! `coll.update_one(Filter::id(42), upd).if_rev(rev).timeout(d).await?`. The option set is shared
//! by all operations, as in the other drivers; an option that does not apply to an operation is
//! ignored.

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    time::Duration,
};

use crate::{
    error::Result,
    session::Session,
    settings::{ReadConsistency, WriteConcern},
};

/// A boxed, `Send` future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Validation level of a collection validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// No validation.
    Off,
    /// Every write is validated.
    Strict,
    /// Only documents that were valid stay valid.
    Moderate,
}

/// What a failed validation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationAction {
    /// Refuse the write (RGN-1006).
    Error,
    /// Accept it with a warning.
    Warn,
}

/// A collection validator: a JSON Schema (text) with optional level and action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    /// The `$jsonSchema` document as JSON text.
    pub json_schema: String,
    /// Level (server default when `None`).
    pub level: Option<ValidationLevel>,
    /// Action (server default when `None`).
    pub action: Option<ValidationAction>,
}

/// Options of one operation (see the module docs).
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct OpOptions {
    pub session: Option<Session>,
    pub timeout: Option<Duration>,
    pub if_rev: Option<String>,
    pub upsert: bool,
    pub unordered: bool,
    pub if_exists: bool,
    pub if_not_exists: bool,
    pub unique: bool,
    pub batch_size: Option<u32>,
    pub read_consistency: Option<(ReadConsistency, Option<Duration>)>,
    pub write_concern: Option<WriteConcern>,
    pub validator: Option<Validator>,
}

/// The option setters shared by [`Action`] and [`crate::Find`].
macro_rules! option_setters {
    () => {
        /// Runs the operation in a causal-consistency session.
        pub fn session(mut self, session: &$crate::Session) -> Self {
            self.opts.session = Some(session.clone());
            self
        }
        /// Deadline of this operation (all attempts included), instead of the client's.
        pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
            self.opts.timeout = Some(timeout);
            self
        }
        /// Optimistic concurrency: write only if the document's `_rev` is `rev` (id filters).
        pub fn if_rev(mut self, rev: impl Into<String>) -> Self {
            self.opts.if_rev = Some(rev.into());
            self
        }
        /// `replace_one`: insert when no document has the id.
        pub fn upsert(mut self, on: bool) -> Self {
            self.opts.upsert = on;
            self
        }
        /// `bulk_write`: stop at the first failure (`true`, default) or run every operation.
        pub fn ordered(mut self, on: bool) -> Self {
            self.opts.unordered = !on;
            self
        }
        /// Drops: no error when the object does not exist.
        pub fn if_exists(mut self, on: bool) -> Self {
            self.opts.if_exists = on;
            self
        }
        /// Creates: no error when the object exists.
        pub fn if_not_exists(mut self, on: bool) -> Self {
            self.opts.if_not_exists = on;
            self
        }
        /// `create_index`: a unique index.
        pub fn unique(mut self, on: bool) -> Self {
            self.opts.unique = on;
            self
        }
        /// Documents per batch of a query or cursor.
        pub fn batch_size(mut self, n: u32) -> Self {
            self.opts.batch_size = Some(n);
            self
        }
        /// Read consistency of this read (the bound is separate from the level, PD-095).
        pub fn read_consistency(
            mut self,
            level: $crate::ReadConsistency,
            max_staleness: Option<std::time::Duration>,
        ) -> Self {
            self.opts.read_consistency = Some((level, max_staleness));
            self
        }
        /// Write concern of this write.
        pub fn write_concern(mut self, wc: $crate::WriteConcern) -> Self {
            self.opts.write_concern = Some(wc);
            self
        }
        /// `create_collection`: the validator.
        pub fn validator(mut self, v: $crate::Validator) -> Self {
            self.opts.validator = Some(v);
            self
        }
    };
}
pub(crate) use option_setters;

type Runner<'a, T> = Box<dyn FnOnce(OpOptions) -> BoxFuture<'a, Result<T>> + Send + 'a>;

/// An operation with its options; `.await` runs it.
#[must_use = "an Action does nothing until awaited"]
pub struct Action<'a, T> {
    opts: OpOptions,
    run: Runner<'a, T>,
}

impl<'a, T: 'a> Action<'a, T> {
    pub(crate) fn new<F, Fut>(f: F) -> Self
    where
        F: FnOnce(OpOptions) -> Fut + Send + 'a,
        Fut: Future<Output = Result<T>> + Send + 'a,
    {
        Self {
            opts: OpOptions::default(),
            run: Box::new(move |o| Box::pin(f(o))),
        }
    }

    option_setters!();
}

impl<T> std::fmt::Debug for Action<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Action")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

impl<'a, T: 'a> IntoFuture for Action<'a, T> {
    type Output = Result<T>;
    type IntoFuture = BoxFuture<'a, Result<T>>;

    fn into_future(self) -> Self::IntoFuture {
        (self.run)(self.opts)
    }
}
