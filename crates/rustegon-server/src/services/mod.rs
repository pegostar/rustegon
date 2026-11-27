// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transport-independent service layer (protocol.md §1, PD-050).
//!
//! gRPC (`crate::grpc`) and REST (wave 2b) are thin adapters: they decode the wire request,
//! build a [`RequestContext`] from their headers, call a method here and encode the result or
//! map the [`rustegon_common::Error`] onto their error model. Behaviour therefore lives in one
//! place and TC-API-006 (REST/gRPC parity) holds by construction.
//!
//! Conventions for every service (wave 2b adds Auth, Query, Document, Transaction, Schema,
//! Admin following the same shape):
//! - a concrete struct, cheap to clone, built from [`ServiceDeps`];
//! - `async fn op(&self, ctx: &RequestContext, request: <plain Rust input>) -> Result<<plain
//!   Rust output>, Error>`; inputs and outputs are Rust types, not prost messages, so REST can
//!   use them without protobuf;
//! - engine calls go through [`ServiceDeps::executor`] ([`crate::Executor::run`]) with
//!   [`crate::Completion::Abandon`] for reads and [`crate::Completion::Await`] for writes;
//!   work outside the executor calls [`RequestContext::check_deadline`] first.

pub mod admin;
pub mod auth;
pub mod backup;
pub mod backup_engine;
pub mod backup_logical;
pub mod context;
mod cursors;
mod data;
mod document;
mod idempotency;
mod identity;
mod principal;
pub mod privileges;
mod query;
mod schema;
mod session;
pub(crate) mod token;
mod transactions;

use std::sync::Arc;

pub use context::{
    ConnectionInfo, Deadline, Principal, RawRequestHeaders, RequestContext, RequestId,
    TraceContext, TraceId, cancelled, deadline_exceeded, invalid_header,
};
pub use data::{DataPlaneConfig, ReadConsistency, WriteConcern};
pub use document::{
    BulkError, BulkOp, BulkWriteOutput, DeleteOutput, DocumentService, InsertOutput, ReadOptions,
    ReturnDocument, Target, WriteOptions, WriteOutput, WriteResult,
};
pub use identity::unauthenticated;
pub use principal::{Anonymous, PrincipalResolver};
pub use query::{
    ExecuteInput, ExecuteStream, ExplainInput, QueryOptions, QueryService, QueryStats, QueryText,
    ResultBatch, Warning,
};
use rustegon_engine::EmbeddedDb;
use rustegon_sim_api::{Clock, Rng};
pub use schema::{
    CollectionInfo, DatabaseInfo, IMPLICIT_COLLECTION_CREATION, IndexInfo, IndexProgress,
    IndexStatus, SchemaService, ValidatorDef,
};
pub use session::{PROTOCOL_MAJOR, PROTOCOL_MINOR, ServerInfo, SessionService};
pub use transactions::{BeginInput, BeginOutput, TransactionService, TxnState};

pub use self::{
    admin::AdminService,
    auth::AuthService,
    backup::{BackupBackend, BackupService},
};
use crate::{Executor, health::Readiness, metrics::ServerMetrics, security::Security};

/// Shared dependencies of every service.
#[derive(Clone)]
pub struct ServiceDeps {
    /// Time source (deadlines, generated request ids, `rgn-server-time`).
    pub clock: Arc<dyn Clock>,
    /// Randomness (generated request and trace ids).
    pub rng: Arc<dyn Rng>,
    /// Bridge to the synchronous engine.
    pub executor: Executor,
}

impl std::fmt::Debug for ServiceDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceDeps")
            .field("executor", &self.executor)
            .finish_non_exhaustive()
    }
}

/// What this node reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeIdentity {
    /// Node id, sent in the `rgn-node-id` response trailer.
    pub node_id: u64,
    /// Capability flags returned by `GetServerInfo` (protocol.md §9). Only features whose
    /// services are actually served may be listed.
    pub features: Vec<String>,
    /// Client endpoints (`host:port`) of the cluster nodes, for topology-aware drivers.
    pub client_addresses: Vec<String>,
}

/// All services of a node, shared by the gRPC and REST front ends.
#[derive(Debug, Clone)]
pub struct Services {
    deps: ServiceDeps,
    node: Arc<NodeIdentity>,
    principals: Arc<dyn PrincipalResolver>,
    session: SessionService,
    security: Option<Arc<Security>>,
    auth: AuthService,
    admin: AdminService,
    backup: BackupService,
    data: Option<DataServices>,
    metrics: Arc<ServerMetrics>,
    readiness: Arc<Readiness>,
}

/// The data-plane services over one engine (M4 wave 2b lane G, PD-053). They share the
/// transaction and cursor registries, the idempotency store and the token sealer.
#[derive(Debug, Clone)]
pub struct DataServices {
    /// `TransactionService`.
    pub transaction: TransactionService,
    /// `QueryService`.
    pub query: QueryService,
    /// `DocumentService`.
    pub document: DocumentService,
    /// `SchemaService`.
    pub schema: SchemaService,
    plane: Arc<data::DataPlane>,
}

impl DataServices {
    /// The engine the services run on.
    #[must_use]
    pub fn engine(&self) -> &Arc<EmbeddedDb> {
        &self.plane.db
    }

    /// Open query cursors (`/metrics`).
    #[must_use]
    pub fn open_cursors(&self) -> usize {
        self.plane.cursors.len()
    }

    /// Runs one sweep of the registries now (expired cursors and transactions, old
    /// idempotency records); normally done by the background task every `sweep_interval`.
    /// Blocking.
    pub fn sweep_now(&self) {
        self.plane.sweep_blocking();
    }

    /// Graceful-shutdown step (PD-054): rolls back every open interactive transaction and
    /// closes every open cursor, so their snapshots and locks are released before the engine
    /// closes. Call it after the listeners stopped. Blocking.
    #[must_use = "the summary is what shutdown logs"]
    pub fn shutdown_blocking(&self) -> ShutdownSummary {
        ShutdownSummary {
            cursors_closed: self.plane.cursors.close_all_blocking(),
            transactions_rolled_back: self.plane.txns.rollback_all_blocking(),
        }
    }
}

/// What [`DataServices::shutdown_blocking`] released.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShutdownSummary {
    /// Open cursors closed.
    pub cursors_closed: usize,
    /// Active interactive transactions rolled back.
    pub transactions_rolled_back: usize,
}

impl Services {
    /// Builds every service over the same dependencies. Callers are anonymous until a
    /// [`PrincipalResolver`] is installed with [`Services::with_principal_resolver`].
    #[must_use]
    pub fn new(deps: ServiceDeps, node: NodeIdentity) -> Self {
        let node = Arc::new(node);
        Self {
            session: SessionService::new(deps.clone(), Arc::clone(&node)),
            backup: BackupService::new(deps.clone()),
            deps,
            node,
            principals: Arc::new(Anonymous),
            security: None,
            auth: AuthService::new(None),
            admin: AdminService::new(None),
            data: None,
            metrics: Arc::new(ServerMetrics::default()),
            readiness: Arc::new(Readiness::default()),
        }
    }

    /// The node's request metrics and registered metric sources (`GET /metrics`, PD-059).
    #[must_use]
    pub fn metrics(&self) -> &Arc<ServerMetrics> {
        &self.metrics
    }

    /// The node lifecycle behind the readiness probe (`GET /api/v1/health/ready`): starting
    /// until the binary marks it serving (FR-OPS-003, PD-059).
    #[must_use]
    pub fn readiness(&self) -> &Arc<Readiness> {
        &self.readiness
    }

    /// Adds the data-plane services (Query, Document, Transaction, Schema) over `engine`
    /// (PD-053). They are served over gRPC only together with the security layer
    /// ([`Services::with_security`], in either order), which authenticates every call; their
    /// database and collection privileges are checked by the services. Inside a Tokio runtime
    /// this also starts the registries' background sweep (it ends when the last clone of these
    /// services is dropped).
    #[must_use]
    pub fn with_engine(mut self, engine: Arc<EmbeddedDb>, config: DataPlaneConfig) -> Self {
        let plane = data::DataPlane::new(&self.deps, engine, config);
        if let Some(security) = &self.security {
            plane.set_security(Arc::clone(security));
        }
        self.data = Some(DataServices {
            transaction: TransactionService::new(self.deps.clone(), Arc::clone(&plane)),
            query: QueryService::new(self.deps.clone(), Arc::clone(&plane)),
            document: DocumentService::new(self.deps.clone(), Arc::clone(&plane)),
            schema: SchemaService::new(self.deps.clone(), Arc::clone(&plane)),
            plane,
        });
        self
    }

    /// The data-plane services; `None` for a node built without an engine
    /// ([`Services::with_engine`]).
    #[must_use]
    pub fn data(&self) -> Option<&DataServices> {
        self.data.as_ref()
    }

    /// Installs the resolver the front ends use to authenticate callers (PD-052 extension
    /// point for the authentication layer).
    #[must_use]
    pub fn with_principal_resolver(mut self, resolver: Arc<dyn PrincipalResolver>) -> Self {
        self.principals = resolver;
        self
    }

    /// The installed principal resolver.
    #[must_use]
    pub fn principal_resolver(&self) -> &dyn PrincipalResolver {
        self.principals.as_ref()
    }

    /// Installs the security layer (PD-051): it becomes the [`PrincipalResolver`] of both front
    /// ends (session token, API key, client certificate), the gRPC gate enforces the RPC access
    /// rules, and `AuthService`/`AdminService` are served. Without it only anonymous RPCs
    /// (`SessionService`) are served over gRPC and everything else fails with RGN-4001.
    #[must_use]
    pub fn with_security(mut self, security: Arc<Security>) -> Self {
        self.auth = AuthService::new(Some(Arc::clone(&security)));
        self.admin = AdminService::new(Some(Arc::clone(&security)));
        self.backup = self.backup.clone().with_security(Arc::clone(&security));
        self.principals = Arc::clone(&security) as Arc<dyn PrincipalResolver>;
        if let Some(data) = &self.data {
            data.plane.set_security(Arc::clone(&security));
        }
        self.security = Some(security);
        self
    }

    /// The security layer, if installed.
    #[must_use]
    pub fn security(&self) -> Option<&Arc<Security>> {
        self.security.as_ref()
    }

    /// `AuthService`.
    #[must_use]
    pub fn auth(&self) -> &AuthService {
        &self.auth
    }

    /// `AdminService`.
    #[must_use]
    pub fn admin(&self) -> &AdminService {
        &self.admin
    }

    /// Installs the engine side of `BackupService` (M13a wave 2, PD-077). `BackupService` is
    /// served with the security layer; without a backend its engine operations (create backup,
    /// snapshots, dump, logical restore) fail with RGN-5007 `not_implemented`, while listing,
    /// describing and verifying backups work.
    #[must_use]
    pub fn with_backup_backend(mut self, backend: Arc<dyn BackupBackend>) -> Self {
        self.backup = self.backup.clone().with_backend(backend);
        self
    }

    /// Installs the destination allowlist of `BackupService` (`backup.allowed_destinations`,
    /// PD-082). Without one every server-side destination is refused with RGN-4002.
    #[must_use]
    pub fn with_backup_destinations(mut self, policy: rustegon_backup::DestinationPolicy) -> Self {
        self.backup = self.backup.clone().with_policy(policy);
        self
    }

    /// Installs the spool directory of the dumps the server writes to a destination
    /// (`POST /api/v1/dumps`, PD-226); default: a directory under the system temporary one.
    #[must_use]
    pub fn with_dump_spool(mut self, dir: std::path::PathBuf) -> Self {
        self.backup = self.backup.clone().with_spool(dir);
        self
    }

    /// Installs the `[backup.s3]` settings `BackupService` opens `s3://` destinations with
    /// (lane BS3, PD-065); default: `S3Settings::default()` (environment credentials).
    #[must_use]
    pub fn with_backup_s3(mut self, s3: rustegon_backup::S3Settings) -> Self {
        self.backup = self.backup.clone().with_s3(s3);
        self
    }

    /// Installs the online restore of the process (`rustegond`, ADR-037): without one
    /// `RestoreBackup` and `GetRestoreStatus` fail with RGN-5007 `not_implemented`.
    #[must_use]
    pub fn with_restore_scheduler(mut self, scheduler: Arc<dyn backup::RestoreScheduler>) -> Self {
        self.backup = self.backup.clone().with_scheduler(scheduler);
        self
    }

    /// Installs the node restart of the process (`rustegond`, PD-230): without one
    /// `POST /node/restart` fails with RGN-5007 `not_implemented`. Call it after
    /// [`Self::with_security`].
    #[must_use]
    pub fn with_node_control(mut self, control: Arc<dyn admin::NodeControl>) -> Self {
        self.admin = self.admin.clone().with_control(control);
        self
    }

    /// `BackupService`.
    #[must_use]
    pub fn backup(&self) -> &BackupService {
        &self.backup
    }

    /// Shared dependencies.
    #[must_use]
    pub fn deps(&self) -> &ServiceDeps {
        &self.deps
    }

    /// This node's identity.
    #[must_use]
    pub fn node(&self) -> &NodeIdentity {
        &self.node
    }

    /// `SessionService`.
    #[must_use]
    pub fn session(&self) -> &SessionService {
        &self.session
    }
}
