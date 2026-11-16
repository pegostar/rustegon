// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Error constructors of the reference interpreter.

use rustegon_common::{Error, ErrorCode};

/// Detail key marking a feature the reference interpreter does not implement (aggregation,
/// joins, search… — M7). The differential harness skips statements failing this way on either
/// side instead of reporting a mismatch.
pub const UNSUPPORTED_DETAIL: &str = "unsupported";

/// `true` if `e` reports a feature outside the implemented scope (see [`UNSUPPORTED_DETAIL`]).
#[must_use]
pub fn is_unsupported(e: &Error) -> bool {
    e.details().contains_key(UNSUPPORTED_DETAIL)
}

/// An "outside the reference scope" error.
pub(crate) fn unsupported(what: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, format!("not supported: {what}"))
        .with_detail(UNSUPPORTED_DETAIL, what)
}

/// `RGN-1011 QueryTypeError`.
pub(crate) fn type_error(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::QueryTypeError, msg)
}

/// `RGN-1001 InvalidArgument`.
pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
}
