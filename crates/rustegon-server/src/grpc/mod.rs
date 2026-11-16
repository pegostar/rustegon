// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC front end (`rustegon.v1`, protocol.md §2–§3, §5, §7): tonic adapters over
//! [`crate::services`], metadata extraction, response trailers and the client listener.
//!
//! Adapter pattern for wave 2b services (see [`SessionGrpc`], [`AdminGrpc`]): extract the context
//! with [`context_from_request`] (it carries the principal the gate authenticated), convert the
//! prost request into the service's Rust input, call the service, map errors with
//! [`status_of`] and the context's trace id, and return the response through [`respond`] with
//! the [`ResponseTrailers`] to send. Register the generated `*Server` in `server::routes` and
//! its service name in `gate::WITH_SECURITY`; the gate then enforces the service's rules from
//! [`crate::security::RPC_ACCESS`] before the handler runs (PD-051).

mod admin;
pub mod ast;
mod auth;
mod backup;
pub mod convert;
mod data;
mod document;
mod gate;
pub mod metadata;
mod query;
mod schema;
mod server;
mod session;
mod transaction;

pub use admin::{AdminGrpc, grant_to_role_ref, role_ref_to_grant};
pub use auth::AuthGrpc;
pub use backup::{BackupGrpc, DumpResponses, backup_info, hlc_to_proto};
pub use document::DocumentGrpc;
pub use gate::served_rpcs;
pub use metadata::{
    ResponseTrailers, context_from_metadata, context_from_request, respond, status_of,
};
pub use query::{ExecuteResponses, QueryGrpc};
pub use schema::SchemaGrpc;
pub use server::{
    ConnectionInfo, GrpcServer, GrpcServerOptions, ListenerSecurity, ServerError, TrailerBody,
};
pub use session::SessionGrpc;
pub use transaction::TransactionGrpc;
