// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Name rules of databases and collections (system-overview.md §9).
//!
//! Both alphabets are printable ASCII without NUL, which the name-index key layout relies on
//! (the name bytes are the last key component, see [`crate::keys`]).

use crate::error::{CatalogError, CatalogResult, ObjectKind};

/// Maximum database name length in characters (= bytes, the alphabet is ASCII).
pub const MAX_DATABASE_NAME_LEN: usize = 64;
/// Maximum collection name length in characters (= bytes, the alphabet is ASCII).
pub const MAX_COLLECTION_NAME_LEN: usize = 120;
/// Collection names with this prefix are reserved for system collections.
pub const RESERVED_COLLECTION_PREFIX: &str = "system.";

/// Checks a database name: 1–64 chars `[a-z0-9_-]`, not starting with `_` (reserved for system).
///
/// # Errors
/// [`CatalogError::InvalidName`] (`RGN-1001`).
pub fn validate_database_name(name: &str) -> CatalogResult<()> {
    let reason = if name.is_empty() {
        Some("empty")
    } else if name.len() > MAX_DATABASE_NAME_LEN {
        Some("longer than 64 characters")
    } else if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        Some("allowed characters are [a-z0-9_-]")
    } else if name.starts_with('_') {
        Some("names starting with '_' are reserved for the system")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(CatalogError::InvalidName {
            kind: ObjectKind::Database,
            reason,
        })
    })
}

/// Checks a collection name: 1–120 chars `[A-Za-z0-9_.-]`, not starting with `system.`.
///
/// # Errors
/// [`CatalogError::InvalidName`] (`RGN-1001`).
pub fn validate_collection_name(name: &str) -> CatalogResult<()> {
    let reason = if name.is_empty() {
        Some("empty")
    } else if name.len() > MAX_COLLECTION_NAME_LEN {
        Some("longer than 120 characters")
    } else if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        Some("allowed characters are [A-Za-z0-9_.-]")
    } else if name.starts_with(RESERVED_COLLECTION_PREFIX) {
        Some("names starting with 'system.' are reserved")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(CatalogError::InvalidName {
            kind: ObjectKind::Collection,
            reason,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_names() {
        for ok in ["a", "shop", "my-db_2", &"x".repeat(64)] {
            assert!(validate_database_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "_sys", "Shop", "a.b", "a b", "é", &"x".repeat(65)] {
            let err = validate_database_name(bad).err();
            assert!(
                matches!(err, Some(CatalogError::InvalidName { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn collection_names() {
        for ok in [
            "a",
            "Orders",
            "orders.archive",
            "x-y_z.1",
            "systemx",
            &"c".repeat(120),
        ] {
            assert!(validate_collection_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "system.users", "a b", "a/b", "a\0b", &"c".repeat(121)] {
            assert!(validate_collection_name(bad).is_err(), "{bad:?}");
        }
    }
}
