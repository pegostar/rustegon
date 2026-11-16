// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Mapping of [`rustegon_common::Error`] onto the gRPC error model (protocol.md §3, §7).

use prost::Message as _;
use rustegon_common::{Error, GrpcCode};

use crate::v1::ErrorDetail;

/// `type_url` of a packed [`ErrorDetail`] inside `google.rpc.Status.details`.
pub const ERROR_DETAIL_TYPE_URL: &str = "type.googleapis.com/rustegon.v1.ErrorDetail";

/// `google.rpc.Status` (google/rpc/status.proto), the payload of the `grpc-status-details-bin`
/// trailer.
///
/// Declared here instead of importing `googleapis` protos: it has three stable fields, and the
/// standard gRPC error-details convention (used by every official gRPC client library to expose
/// rich errors) needs exactly this shape, so drivers can unpack [`ErrorDetail`] without any
/// Rustegon-specific trailer.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcStatus {
    /// The `google.rpc.Code` number (same as the gRPC status code).
    #[prost(int32, tag = "1")]
    pub code: i32,
    /// Developer-facing message (same as the gRPC status message).
    #[prost(string, tag = "2")]
    pub message: String,
    /// Packed detail messages; Rustegon sends exactly one [`ErrorDetail`].
    #[prost(message, repeated, tag = "3")]
    pub details: Vec<prost_types::Any>,
}

/// The `tonic` status code of a catalog gRPC code.
///
/// `GrpcCode` discriminants are the `google.rpc.Code` numbers, so the conversion is exact;
/// TC-API-005 checks it against the protocol.md §7 table for every catalog entry.
#[must_use]
pub fn tonic_code(code: GrpcCode) -> tonic::Code {
    tonic::Code::from_i32(i32::from(code as u8))
}

/// Builds the `ErrorDetail` carried in `google.rpc.Status.details` for an error.
///
/// `committed` is set only for codes whose outcome is known to be committed
/// (`WriteConcernTimeout`, protocol.md §7); `CommitOutcomeUnknown` leaves it unset on purpose,
/// because the client must not assume either outcome.
#[must_use]
pub fn error_detail(error: &Error, trace_id: &str) -> ErrorDetail {
    let code = error.code();
    ErrorDetail {
        code: u32::from(code.code()),
        name: code.name().to_owned(),
        retryable: error.retryable(),
        committed: (code.retry_note() == Some("committed=true")).then_some(true),
        details: error
            .details()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        trace_id: trace_id.to_owned(),
        retry_after_ms: None,
    }
}

/// Converts an error into the `tonic::Status` returned by every Rustegon RPC (protocol.md §7).
///
/// The status carries the catalog gRPC code, the error message, and a `google.rpc.Status` with
/// one packed [`ErrorDetail`] in its details, so clients read the stable Rustegon code, name,
/// retry and commit flags without parsing the message text. `retry_after_ms` is set by callers
/// that know it (rate limiting) through [`to_status_with_detail`].
#[must_use]
pub fn to_status(error: &Error, trace_id: &str) -> tonic::Status {
    to_status_with_detail(error, &error_detail(error, trace_id))
}

/// Like [`to_status`] with a prepared [`ErrorDetail`] (for example with `retry_after_ms` set).
#[must_use]
pub fn to_status_with_detail(error: &Error, detail: &ErrorDetail) -> tonic::Status {
    let code = tonic_code(error.code().grpc_code());
    let rpc = RpcStatus {
        code: code as i32,
        message: error.message().to_owned(),
        details: vec![prost_types::Any {
            type_url: ERROR_DETAIL_TYPE_URL.to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    tonic::Status::with_details(code, error.message(), rpc.encode_to_vec().into())
}

/// Extracts the [`ErrorDetail`] from a status built by [`to_status`]; `None` when the status
/// carries no (or a foreign/corrupt) Rustegon detail. Used by the Rust client side and tests.
#[must_use]
pub fn error_detail_of(status: &tonic::Status) -> Option<ErrorDetail> {
    let rpc = RpcStatus::decode(status.details()).ok()?;
    rpc.details
        .iter()
        .find(|any| any.type_url == ERROR_DETAIL_TYPE_URL)
        .and_then(|any| ErrorDetail::decode(any.value.as_slice()).ok())
}
