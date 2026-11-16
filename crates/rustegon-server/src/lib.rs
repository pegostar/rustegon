// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Client-facing services: gRPC (tonic), REST (axum), WebSocket and GUI embedding.
//!
//! M4 wave 2a (FR-API-001, PD-050) provides the skeleton every front end builds on:
//! - [`services`]: the transport-independent service layer called by both gRPC and REST
//!   (protocol.md §1), with the per-request [`services::RequestContext`];
//! - [`Executor`]: runs synchronous `rustegon-engine` calls on the blocking pool with bounded
//!   concurrency and deadline/cancellation propagation;
//! - [`grpc`]: tonic adapters, metadata parsing, response trailers and the TLS client listener
//!   ([`grpc::GrpcServer`]).
//!
//! M4 wave 2b lane I (FR-API-002/003, PD-052) adds [`rest`]: the axum REST front end over the
//! same services, its `OpenAPI` document and the REST listener ([`rest::RestServer`], port 7780).
//! Both listeners share the accept loop and TLS policy ([`ListenerSecurity`],
//! [`ConnectionInfo`]).
//!
//! M4 wave 2b lane H (FR-SEC-001…006, PD-051) adds [`security`]: authentication of every
//! request (the [`services::PrincipalResolver`] of both front ends), RBAC per RPC, audit, rate
//! limiting, lockout, the system store over the engine and runtime settings; `AuthService` and
//! `AdminService` are served when it is installed ([`services::Services::with_security`]).
//!
//! M4 wave 3 lane O (FR-OPS-001/003, PD-059) adds [`metrics`] (`GET /metrics`, `OpenMetrics`)
//! and [`health`] (readiness for `GET /api/v1/health/ready`).

mod executor;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod grpc;
pub mod health;
mod listener;
pub mod metrics;
pub mod rest;
pub mod security;
pub mod services;

pub use executor::{CancelToken, Completion, DEFAULT_MAX_IN_FLIGHT, Executor};
pub use listener::{ConnectionInfo, ListenerSecurity, ServerError};
