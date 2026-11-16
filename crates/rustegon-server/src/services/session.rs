// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `SessionService`: liveness and version/feature negotiation (protocol.md §2, §9).

use std::sync::Arc;

use rustegon_common::Error;

use super::{NodeIdentity, RequestContext, ServiceDeps};

/// Wire protocol major version (`rustegon.v1`, `/api/v1`).
pub const PROTOCOL_MAJOR: u32 = 1;
/// Wire protocol minor version. Bumped by every additive change to `proto/rustegon/v1` or
/// `/api/v1` (protocol.md §9); drivers gate behaviour on [`ServerInfo::features`], not on it.
pub const PROTOCOL_MINOR: u32 = 0;

/// `GetServerInfo` result, transport-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// Server version (semver of the `rustegon-server` crate, i.e. the release).
    pub server_version: String,
    /// `"1.<minor>"`.
    pub protocol_version: String,
    /// Capability flags of this node (protocol.md §9).
    pub features: Vec<String>,
    /// Client endpoints of the cluster nodes known to this node (topology hint, §5.3).
    pub node_addresses: Vec<String>,
}

/// Session-level operations; usable without authentication.
#[derive(Debug, Clone)]
pub struct SessionService {
    deps: ServiceDeps,
    node: Arc<NodeIdentity>,
}

impl SessionService {
    /// Creates the service.
    #[must_use]
    pub fn new(deps: ServiceDeps, node: Arc<NodeIdentity>) -> Self {
        Self { deps, node }
    }

    /// Liveness round trip. Honors the deadline like every other call so that clients can
    /// probe deadline handling end to end.
    ///
    /// # Errors
    /// RGN-5006 when the request deadline has already passed.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // Same async shape as every service method (PD-050).
    pub async fn ping(&self, ctx: &RequestContext) -> Result<(), Error> {
        ctx.check_deadline(self.deps.clock.as_ref())
    }

    /// Versions, capability flags and the topology hint.
    ///
    /// # Errors
    /// RGN-5006 when the request deadline has already passed.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // Same async shape as every service method (PD-050).
    pub async fn server_info(&self, ctx: &RequestContext) -> Result<ServerInfo, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        Ok(ServerInfo {
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: format!("{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"),
            features: self.node.features.clone(),
            node_addresses: self.node.client_addresses.clone(),
        })
    }
}
