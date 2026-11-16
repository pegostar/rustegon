// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Statement parameters (FR-QL-003, query-language.md §2): `$name` and positional `$1`.
//!
//! Parameters are values, never text: the binder substitutes them into the bound expression
//! tree as constants after parsing, so no parameter value can change the statement's structure
//! (injection-proof by construction, AC-QL-004).

use std::collections::BTreeMap;

use rustegon_common::Error;
use rustegon_doc::{Document, Value};

use crate::error::type_error;

/// Parameter values of one execution.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Params {
    named: BTreeMap<String, Value>,
    positional: Vec<Value>,
}

impl Params {
    /// No parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Positional parameters: `values[0]` is `$1`.
    #[must_use]
    pub fn positional(values: Vec<Value>) -> Self {
        Self {
            named: BTreeMap::new(),
            positional: values,
        }
    }

    /// Adds (or replaces) the named parameter `$name`.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: Value) -> Self {
        self.named.insert(name.into(), value);
        self
    }

    /// Sets the named parameter `$name`.
    pub fn set(&mut self, name: impl Into<String>, value: Value) {
        self.named.insert(name.into(), value);
    }

    /// Appends the next positional parameter.
    pub fn push(&mut self, value: Value) {
        self.positional.push(value);
    }

    /// Every parameter as one document `{named: [[name, value], …], positional: […]}` (stable
    /// order; the fingerprint of continuation tokens).
    #[must_use]
    pub(crate) fn to_document(&self) -> Document {
        let mut d = Document::new();
        d.insert(
            "named",
            Value::Array(
                self.named
                    .iter()
                    .map(|(n, v)| Value::Array(vec![Value::String(n.clone()), v.clone()]))
                    .collect(),
            ),
        );
        d.insert("positional", Value::Array(self.positional.clone()));
        d
    }

    /// The value of the parameter written `$name` in the statement (`name` is the AST's
    /// parameter name: an identifier or a 1-based decimal position).
    ///
    /// # Errors
    /// `RGN-1011` when the parameter is not supplied.
    pub fn resolve(&self, name: &str) -> Result<&Value, Error> {
        let found = if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            name.parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| self.positional.get(i))
        } else {
            self.named.get(name)
        };
        found.ok_or_else(|| {
            type_error(format!("parameter ${name} is not bound")).with_detail("parameter", name)
        })
    }
}
