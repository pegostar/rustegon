// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The RGQL abstract syntax tree and its structured (JSON) form (query-language.md §13).
//!
//! The AST is the single representation shared by the text parser ([`crate::parse`]), the
//! canonical printer ([`crate::print`](mod@crate::print)) and the structured form drivers send (FR-QL-002):
//! `serde` derives give the JSON mirror with a `"kind"` discriminator, and
//! `proto/rustegon/v1/query_ast.proto` mirrors the same shape field for field.
//!
//! **Canonical ASTs.** Every AST the parser produces is canonical: `parse(print(ast)) == ast`
//! (TC-QL-003). An AST built elsewhere (JSON from a driver) may be non-canonical — e.g. an
//! `access` whose base is a `path`, which the text syntax cannot distinguish from a longer
//! path. [`Statement::from_json`] therefore accepts a structured statement only if it survives
//! the round trip unchanged, which also enforces the parser's limits (nesting depth, size) on
//! structured input: text and structured requests are accepted under exactly the same rules.

pub mod expr;
pub mod literal;
pub mod query;
pub mod stmt;

pub use self::{
    expr::{BinaryOp, Expr, IsTest, ObjectField, Path, Quantifier, Segment, WhenThen},
    literal::Literal,
    query::{
        AggItem, Facet, FromClause, GroupKey, GroupSpec, IndexName, LookupClause, MergeMatched,
        MergeNotMatched, OptionItem, OrderItem, Projection, QualifiedName, Query, Select, SetItem,
        Source, Stage,
    },
    stmt::{
        AlterCollectionAction, Begin, ColumnDef, CreateIndex, CreateTable, CreateTimeseries,
        Delete, Duration, Image, IndexKey, IndexType, Insert, InsertSource, Isolation, KillTarget,
        OnConflict, PopEnd, Priority, Returning, ShowTarget, Statement, Update, UpdateOp, Upsert,
    },
};
use crate::parse::{ParseError, parse_statement};

/// `serde` helper: omit `false` booleans so the JSON form stays minimal and canonical.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes fields by reference.
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

/// Error decoding a structured (JSON) statement.
#[derive(Debug, thiserror::Error)]
pub enum AstError {
    /// The JSON does not match the AST schema.
    #[error("malformed structured query: {0}")]
    Malformed(String),
    /// The JSON nests deeper than the JSON decoder allows (128 levels).
    #[error("structured query too complex: {0}")]
    TooComplex(String),
    /// The AST is well-formed but not canonical: it has no text form that parses back to it.
    #[error("non-canonical structured query: {0}")]
    NonCanonical(String),
    /// The canonical text of the AST violates a parser rule (e.g. nesting too deep).
    #[error(transparent)]
    Parse(#[from] ParseError),
}

impl AstError {
    /// The public error code: `RGN-1013` when a limit was exceeded, `RGN-1010` otherwise.
    #[must_use]
    pub fn code(&self) -> rustegon_common::ErrorCode {
        match self {
            Self::Parse(e) => e.code(),
            Self::TooComplex(_) => rustegon_common::ErrorCode::QueryTooComplex,
            Self::Malformed(_) | Self::NonCanonical(_) => {
                rustegon_common::ErrorCode::QuerySyntaxError
            }
        }
    }
}

impl Statement {
    /// The structured JSON form (§13).
    ///
    /// # Errors
    /// Fails only if a value cannot be represented in JSON (never for parser output).
    pub fn to_json(&self) -> Result<String, AstError> {
        serde_json::to_string(self).map_err(|e| AstError::Malformed(e.to_string()))
    }

    /// Decodes and validates a structured JSON statement (module docs: the AST must be
    /// canonical).
    ///
    /// # Errors
    /// [`AstError::Malformed`] on schema errors, [`AstError::TooComplex`] beyond the JSON
    /// decoder's nesting limit, [`AstError::NonCanonical`] if the AST is not the parse of its
    /// own canonical text, [`AstError::Parse`] if that text violates a parser limit.
    pub fn from_json(json: &str) -> Result<Self, AstError> {
        let stmt: Self = serde_json::from_str(json).map_err(|e| {
            // serde_json reports its recursion guard only through the message text.
            let text = e.to_string();
            if text.contains("recursion limit exceeded") {
                AstError::TooComplex(text)
            } else {
                AstError::Malformed(text)
            }
        })?;
        stmt.validate()?;
        Ok(stmt)
    }

    /// Checks that this AST is canonical (see the module docs).
    ///
    /// # Errors
    /// As [`Statement::from_json`] minus the schema errors.
    pub fn validate(&self) -> Result<(), AstError> {
        let text = crate::print::print_statement(self);
        let reparsed = parse_statement(&text)?;
        if &reparsed == self {
            Ok(())
        } else {
            Err(AstError::NonCanonical(format!(
                "its canonical text `{text}` denotes a different AST"
            )))
        }
    }
}
