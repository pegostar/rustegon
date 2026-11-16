// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Document limits (FR-DOC-004) and field-name rules (data-model.md §2.2, FR-DOC-005).

use crate::{
    error::{DocError, DocResult},
    value::Document,
};

/// Maximum encoded document size: 16 MiB, counted over the whole `RDoc` (header included).
pub const MAX_DOCUMENT_SIZE: usize = 16 * 1024 * 1024;
/// Maximum nesting depth; the root object is depth 1 and every nested object or array adds 1.
pub const MAX_DEPTH: usize = 100;
/// Maximum field-name length in bytes of UTF-8 (§2.2).
pub const MAX_FIELD_NAME_LEN: usize = 1024;

/// Top-level names maintained by the server and rejected as user input (§2.2, FR-DOC-005).
/// `_id` (user-settable on insert) and `_expiresAt` (writable TTL, AC-DOC-004) are reserved but
/// writable and therefore not listed.
pub const SERVER_MAINTAINED_FIELDS: [&str; 5] =
    ["_rev", "_createdAt", "_updatedAt", "_conflict", "_origin"];

/// Checks the syntax rules every stored field name obeys at any level: 1–1024 bytes, no NUL,
/// not starting with `$` (§2.2).
///
/// # Errors
/// [`DocError::InvalidFieldName`] (`RGN-1004`).
pub fn validate_field_name(name: &str) -> DocResult<()> {
    let reason = if name.is_empty() {
        "empty field name"
    } else if name.len() > MAX_FIELD_NAME_LEN {
        "field name longer than 1024 bytes"
    } else if name.as_bytes().contains(&0) {
        "field name contains NUL"
    } else if name.starts_with('$') {
        "field name starts with '$'"
    } else {
        return Ok(());
    };
    Err(DocError::InvalidFieldName(reason.into()))
}

/// Checks a document written by a user (insert/replace input): top-level names that the server
/// maintains are rejected (FR-DOC-005, AC-DOC-004). Syntax and limits are already enforced by
/// the JSON parser and the `RDoc` codec.
///
/// # Errors
/// [`DocError::InvalidFieldName`] (`RGN-1004`) naming the reserved field.
pub fn validate_user_document(doc: &Document) -> DocResult<()> {
    match doc
        .iter()
        .find(|(name, _)| SERVER_MAINTAINED_FIELDS.contains(name))
    {
        Some((name, _)) => Err(DocError::InvalidFieldName(format!(
            "{name} is maintained by the server"
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    #[test]
    fn user_document_reserved_names() {
        for name in SERVER_MAINTAINED_FIELDS {
            let mut d = Document::new();
            d.insert(name, Value::Null);
            assert!(validate_user_document(&d).is_err(), "{name}");
        }
        let mut d = Document::new();
        d.insert("_id", Value::Int64(1));
        d.insert("_expiresAt", Value::DateTime(0));
        d.insert("_other", Value::Null);
        assert!(validate_user_document(&d).is_ok());
    }
}
