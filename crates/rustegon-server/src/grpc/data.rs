// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared plumbing of the data-plane gRPC adapters (Query, Document, Transaction, Schema).

use std::time::Duration;

use tonic::Status;

use super::metadata::ResponseTrailers;
use crate::services::{DataServices, RequestContext, Services};

/// The services behind a data-plane adapter.
#[derive(Debug, Clone)]
pub(crate) struct DataGrpc {
    pub(crate) services: Services,
}

impl DataGrpc {
    /// The data services (always present when the adapters are registered).
    #[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
    pub(crate) fn data(&self) -> Result<&DataServices, Status> {
        self.services
            .data()
            .ok_or_else(|| Status::unimplemented("this node serves no data plane"))
    }

    /// Data calls do not issue causality tokens yet (consistency.md: HLC tokens come with
    /// replication); the client's token is echoed so it keeps the newest one it was given.
    #[allow(clippy::unused_self)] // Kept on the adapter: tokens will come from the services.
    pub(crate) fn trailers(&self, ctx: &RequestContext) -> ResponseTrailers {
        ResponseTrailers {
            causality_token: ctx.causality_token().map(str::to_owned),
        }
    }
}

/// A duration as whole milliseconds in a `uint32` field (saturating).
pub(crate) fn millis_u32(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}
