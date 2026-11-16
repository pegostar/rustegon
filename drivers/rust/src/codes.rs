// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The error catalog as the driver sees it: code → name and class (proto/errors.yaml joined with
//! `drivers/conformance/errors-map.yaml`, PD-075). The table mirrors
//! `drivers/conformance/generated/errors.json`; the conformance runner's `checkErrorMapping`
//! (TC-DRV-RS-004) fails when they differ, so a new catalog code cannot be forgotten here.

use crate::error::ErrorClass;

/// `(code, name, class)` of every catalog code.
pub(crate) const CATALOG: &[(u32, &str, ErrorClass)] = &[
    (1001, "InvalidArgument", ErrorClass::Client),
    (1002, "DocumentTooLarge", ErrorClass::Client),
    (1003, "NestingTooDeep", ErrorClass::Client),
    (1004, "InvalidFieldName", ErrorClass::Client),
    (1005, "DuplicateKey", ErrorClass::DuplicateKey),
    (
        1006,
        "SchemaValidationFailed",
        ErrorClass::DocumentValidation,
    ),
    (1007, "PartitionTooLarge", ErrorClass::Client),
    (1008, "IndexKeyTooLarge", ErrorClass::Client),
    (1009, "CounterOverflow", ErrorClass::Client),
    (1010, "QuerySyntaxError", ErrorClass::QuerySyntax),
    (1011, "QueryTypeError", ErrorClass::QuerySyntax),
    (1012, "UnknownFunction", ErrorClass::QuerySyntax),
    (1013, "QueryTooComplex", ErrorClass::Client),
    (1020, "IndexAlreadyExists", ErrorClass::Client),
    (1021, "IndexNotFound", ErrorClass::Client),
    (1022, "IndexBuildFailed", ErrorClass::Client),
    (1023, "IndexLimitExceeded", ErrorClass::Client),
    (1024, "IndexStaleTimeout", ErrorClass::Timeout),
    (1025, "MultikeyCompoundArrays", ErrorClass::Client),
    (1030, "NotFound", ErrorClass::Client),
    (1031, "AlreadyExists", ErrorClass::Client),
    (1032, "ResumeTokenExpired", ErrorClass::Client),
    (1033, "SchemaChangeInProgress", ErrorClass::Client),
    (1034, "DescriptorVersionMismatch", ErrorClass::Server),
    (1040, "InvalidVector", ErrorClass::Client),
    (1041, "InvalidGeometry", ErrorClass::Client),
    (2001, "TransactionConflict", ErrorClass::TransactionConflict),
    (2002, "TransactionAborted", ErrorClass::TransactionAborted),
    (2003, "TransactionTimeout", ErrorClass::Timeout),
    (2004, "TransactionTooLarge", ErrorClass::Client),
    (2005, "DeadlockDetected", ErrorClass::TransactionConflict),
    (
        2006,
        "CommitOutcomeUnknown",
        ErrorClass::CommitOutcomeUnknown,
    ),
    (2007, "ReadTimestampTooOld", ErrorClass::TransactionConflict),
    (2008, "WriteTooOld", ErrorClass::TransactionConflict),
    (2009, "PreconditionFailed", ErrorClass::Client),
    (3001, "NotLeaseholder", ErrorClass::Unavailable),
    (3002, "Unavailable", ErrorClass::Unavailable),
    (3003, "RangeKeyMismatch", ErrorClass::Unavailable),
    (3004, "NodeDraining", ErrorClass::Unavailable),
    (3005, "ClockOffsetExceeded", ErrorClass::Unavailable),
    (3006, "WriteConcernTimeout", ErrorClass::Timeout),
    (3007, "StaleReadUnavailable", ErrorClass::Unavailable),
    (4001, "Unauthenticated", ErrorClass::Authentication),
    (4002, "PermissionDenied", ErrorClass::Authorization),
    (4003, "RateLimited", ErrorClass::RateLimited),
    (4004, "TlsRequired", ErrorClass::Authentication),
    (4005, "SessionExpired", ErrorClass::Authentication),
    (4006, "KeyUnavailable", ErrorClass::Server),
    (4007, "AccountLocked", ErrorClass::Authentication),
    (5001, "Internal", ErrorClass::Server),
    (5002, "StorageCorruption", ErrorClass::Server),
    (5003, "DiskFull", ErrorClass::Server),
    (5004, "ResourceExhausted", ErrorClass::Server),
    (5005, "Cancelled", ErrorClass::Server),
    (5006, "DeadlineExceeded", ErrorClass::Timeout),
    (5007, "VersionIncompatible", ErrorClass::Client),
];

/// Codes the driver itself refers to.
pub(crate) const UNAUTHENTICATED: u32 = 4001;
pub(crate) const PERMISSION_DENIED: u32 = 4002;
pub(crate) const SESSION_EXPIRED: u32 = 4005;
pub(crate) const TRANSACTION_ABORTED: u32 = 2002;
pub(crate) const COMMIT_OUTCOME_UNKNOWN: u32 = 2006;

/// The name of a code, `RGN-<code>` when unknown (newer server).
pub(crate) fn name_of(code: u32) -> String {
    CATALOG
        .iter()
        .find(|(c, _, _)| *c == code)
        .map_or_else(|| format!("RGN-{code}"), |(_, n, _)| (*n).to_owned())
}

/// The class of a code; unknown codes map to [`ErrorClass::Base`] (errors-map.yaml `unknown`).
pub(crate) fn class_of(code: u32) -> ErrorClass {
    CATALOG
        .iter()
        .find(|(c, _, _)| *c == code)
        .map_or(ErrorClass::Base, |(_, _, k)| *k)
}

/// errors-map.yaml `transport`: `(class, code, retryable)` of a status without `ErrorDetail`.
pub(crate) fn transport_fallback(code: tonic::Code) -> (ErrorClass, u32, bool) {
    match code {
        tonic::Code::Unavailable => (ErrorClass::Unavailable, 3002, true),
        tonic::Code::DeadlineExceeded => (ErrorClass::Timeout, 5006, false),
        tonic::Code::ResourceExhausted => (ErrorClass::Server, 5004, true),
        tonic::Code::Unauthenticated => (ErrorClass::Authentication, 4001, false),
        tonic::Code::PermissionDenied => (ErrorClass::Authorization, 4002, false),
        // INTERNAL, UNKNOWN and every other status: the `default` row.
        _ => (ErrorClass::Server, 5001, false),
    }
}
