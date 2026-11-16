// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Every REST endpoint and the RPC whose access rule and service operation it shares
//! (protocol.md §4; PD-055).
//!
//! [`REST_ENDPOINTS`] is the REST counterpart of [`crate::security::RPC_ACCESS`]: handlers
//! admit requests with the rule of the RPC listed here (`super::gate`), the REST privilege
//! matrix (TC-SEC-001, `tests/privilege_matrix.rs`) is generated from it, and
//! `tc_api_002_every_documented_route_is_in_the_endpoint_table` pins it to the router, so an
//! endpoint cannot be added without declaring which rule protects it.

/// One REST endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestEndpoint {
    /// HTTP method (upper case).
    pub method: &'static str,
    /// Path template as documented in the `OpenAPI` document (`/api/v1/…/{name}`).
    pub path: &'static str,
    /// The gRPC method whose access rule and service operation the endpoint uses, or the
    /// pseudo-method of an HTTP-only endpoint with a rule in
    /// [`crate::security::HTTP_ACCESS`] (`GET /metrics`); `None` for the liveness and
    /// readiness probes, which authenticate nobody.
    pub rpc: Option<&'static str>,
}

/// RPC method paths used by the REST handlers.
pub mod rpc {
    #![allow(missing_docs)] // Each constant is the gRPC method path it is named after.

    pub const AUTHENTICATE: &str = "/rustegon.v1.AuthService/Authenticate";
    pub const LOGOUT: &str = "/rustegon.v1.AuthService/Logout";
    pub const WHO_AM_I: &str = "/rustegon.v1.AuthService/WhoAmI";
    pub const PING: &str = "/rustegon.v1.SessionService/Ping";
    pub const GET_SERVER_INFO: &str = "/rustegon.v1.SessionService/GetServerInfo";

    pub const EXECUTE: &str = "/rustegon.v1.QueryService/Execute";
    pub const GET_MORE: &str = "/rustegon.v1.QueryService/GetMore";
    pub const KILL_CURSOR: &str = "/rustegon.v1.QueryService/KillCursor";
    pub const EXPLAIN: &str = "/rustegon.v1.QueryService/Explain";

    pub const DOC_GET: &str = "/rustegon.v1.DocumentService/Get";
    pub const DOC_GET_MANY: &str = "/rustegon.v1.DocumentService/GetMany";
    pub const DOC_INSERT: &str = "/rustegon.v1.DocumentService/Insert";
    pub const DOC_REPLACE: &str = "/rustegon.v1.DocumentService/Replace";
    pub const DOC_UPDATE: &str = "/rustegon.v1.DocumentService/Update";
    pub const DOC_UPSERT: &str = "/rustegon.v1.DocumentService/Upsert";
    pub const DOC_DELETE: &str = "/rustegon.v1.DocumentService/Delete";
    pub const DOC_BULK_WRITE: &str = "/rustegon.v1.DocumentService/BulkWrite";

    pub const TXN_BEGIN: &str = "/rustegon.v1.TransactionService/Begin";
    pub const TXN_COMMIT: &str = "/rustegon.v1.TransactionService/Commit";
    pub const TXN_ROLLBACK: &str = "/rustegon.v1.TransactionService/Rollback";
    pub const TXN_STATUS: &str = "/rustegon.v1.TransactionService/Status";
    pub const TXN_HEARTBEAT: &str = "/rustegon.v1.TransactionService/Heartbeat";

    pub const CREATE_DATABASE: &str = "/rustegon.v1.SchemaService/CreateDatabase";
    pub const DROP_DATABASE: &str = "/rustegon.v1.SchemaService/DropDatabase";
    pub const LIST_DATABASES: &str = "/rustegon.v1.SchemaService/ListDatabases";
    pub const CREATE_COLLECTION: &str = "/rustegon.v1.SchemaService/CreateCollection";
    pub const DROP_COLLECTION: &str = "/rustegon.v1.SchemaService/DropCollection";
    pub const ALTER_COLLECTION: &str = "/rustegon.v1.SchemaService/AlterCollection";
    pub const GET_COLLECTION: &str = "/rustegon.v1.SchemaService/GetCollection";
    pub const LIST_COLLECTIONS: &str = "/rustegon.v1.SchemaService/ListCollections";
    pub const CREATE_INDEX: &str = "/rustegon.v1.SchemaService/CreateIndex";
    pub const DROP_INDEX: &str = "/rustegon.v1.SchemaService/DropIndex";
    pub const LIST_INDEXES: &str = "/rustegon.v1.SchemaService/ListIndexes";
    pub const INDEX_BUILD_PROGRESS: &str = "/rustegon.v1.SchemaService/IndexBuildProgress";
    pub const GET_VALIDATOR: &str = "/rustegon.v1.SchemaService/GetValidator";
    pub const SET_VALIDATOR: &str = "/rustegon.v1.SchemaService/SetValidator";
    pub const REMOVE_VALIDATOR: &str = "/rustegon.v1.SchemaService/RemoveValidator";

    pub const CREATE_USER: &str = "/rustegon.v1.AdminService/CreateUser";
    pub const GET_USER: &str = "/rustegon.v1.AdminService/GetUser";
    pub const LIST_USERS: &str = "/rustegon.v1.AdminService/ListUsers";
    pub const UPDATE_USER: &str = "/rustegon.v1.AdminService/UpdateUser";
    pub const DROP_USER: &str = "/rustegon.v1.AdminService/DropUser";
    pub const CHANGE_PASSWORD: &str = "/rustegon.v1.AdminService/ChangePassword";
    pub const CREATE_ROLE: &str = "/rustegon.v1.AdminService/CreateRole";
    pub const GET_ROLE: &str = "/rustegon.v1.AdminService/GetRole";
    pub const LIST_ROLES: &str = "/rustegon.v1.AdminService/ListRoles";
    pub const UPDATE_ROLE: &str = "/rustegon.v1.AdminService/UpdateRole";
    pub const DROP_ROLE: &str = "/rustegon.v1.AdminService/DropRole";
    pub const CREATE_API_KEY: &str = "/rustegon.v1.AdminService/CreateApiKey";
    pub const LIST_API_KEYS: &str = "/rustegon.v1.AdminService/ListApiKeys";
    pub const REVOKE_API_KEY: &str = "/rustegon.v1.AdminService/RevokeApiKey";
    pub const GET_SETTINGS: &str = "/rustegon.v1.AdminService/GetSettings";
    pub const UPDATE_SETTINGS: &str = "/rustegon.v1.AdminService/UpdateSettings";

    pub const CREATE_BACKUP: &str = "/rustegon.v1.BackupService/CreateBackup";
    pub const LIST_BACKUPS: &str = "/rustegon.v1.BackupService/ListBackups";
    pub const GET_BACKUP: &str = "/rustegon.v1.BackupService/GetBackup";
    pub const VERIFY_BACKUP: &str = "/rustegon.v1.BackupService/VerifyBackup";
    pub const CREATE_SNAPSHOT: &str = "/rustegon.v1.BackupService/CreateSnapshot";
    pub const LIST_SNAPSHOTS: &str = "/rustegon.v1.BackupService/ListSnapshots";
    pub const DELETE_SNAPSHOT: &str = "/rustegon.v1.BackupService/DeleteSnapshot";

    /// HTTP-only: the Prometheus scrape (`crate::security::HTTP_ACCESS`, PD-059).
    pub const METRICS: &str = crate::security::METRICS_ENDPOINT;
}

const fn ep(method: &'static str, path: &'static str, rpc: &'static str) -> RestEndpoint {
    RestEndpoint {
        method,
        path,
        rpc: Some(rpc),
    }
}

const DB: &str = "/api/v1/databases/{db}";

/// Every REST endpoint (module docs), grouped by service.
pub const REST_ENDPOINTS: &[RestEndpoint] = &[
    // Session and health (PD-052).
    ep("GET", "/api/v1/ping", rpc::PING),
    ep("GET", "/api/v1/server-info", rpc::GET_SERVER_INFO),
    RestEndpoint {
        method: "GET",
        path: "/api/v1/health/live",
        rpc: None,
    },
    // Readiness and metrics (PD-059).
    RestEndpoint {
        method: "GET",
        path: "/api/v1/health/ready",
        rpc: None,
    },
    ep("GET", "/metrics", rpc::METRICS),
    // Authentication.
    ep("POST", "/api/v1/auth/scram/start", rpc::AUTHENTICATE),
    ep("POST", "/api/v1/auth/scram/finish", rpc::AUTHENTICATE),
    ep("POST", "/api/v1/auth/login", rpc::AUTHENTICATE),
    ep("POST", "/api/v1/auth/logout", rpc::LOGOUT),
    ep("GET", "/api/v1/auth/me", rpc::WHO_AM_I),
    ep("POST", "/api/v1/auth/password", rpc::CHANGE_PASSWORD),
    // Administration.
    ep("GET", "/api/v1/users", rpc::LIST_USERS),
    ep("POST", "/api/v1/users", rpc::CREATE_USER),
    ep("GET", "/api/v1/users/{name}", rpc::GET_USER),
    ep("PATCH", "/api/v1/users/{name}", rpc::UPDATE_USER),
    ep("DELETE", "/api/v1/users/{name}", rpc::DROP_USER),
    ep("GET", "/api/v1/roles", rpc::LIST_ROLES),
    ep("POST", "/api/v1/roles", rpc::CREATE_ROLE),
    ep("GET", "/api/v1/roles/{name}", rpc::GET_ROLE),
    ep("PATCH", "/api/v1/roles/{name}", rpc::UPDATE_ROLE),
    ep("DELETE", "/api/v1/roles/{name}", rpc::DROP_ROLE),
    ep("GET", "/api/v1/api-keys", rpc::LIST_API_KEYS),
    ep("POST", "/api/v1/api-keys", rpc::CREATE_API_KEY),
    ep("DELETE", "/api/v1/api-keys/{key_id}", rpc::REVOKE_API_KEY),
    ep("GET", "/api/v1/settings", rpc::GET_SETTINGS),
    ep("PATCH", "/api/v1/settings", rpc::UPDATE_SETTINGS),
    // Backups and snapshots (PD-062, PD-077; `Dump`/`LogicalRestore` are gRPC only).
    ep("GET", "/api/v1/backups", rpc::LIST_BACKUPS),
    ep("POST", "/api/v1/backups", rpc::CREATE_BACKUP),
    ep("GET", "/api/v1/backups/{backup_id}", rpc::GET_BACKUP),
    ep(
        "POST",
        "/api/v1/backups/{backup_id}/verify",
        rpc::VERIFY_BACKUP,
    ),
    ep("GET", "/api/v1/snapshots", rpc::LIST_SNAPSHOTS),
    ep("POST", "/api/v1/snapshots", rpc::CREATE_SNAPSHOT),
    ep("DELETE", "/api/v1/snapshots/{name}", rpc::DELETE_SNAPSHOT),
    // Transactions.
    ep("POST", "/api/v1/transactions", rpc::TXN_BEGIN),
    ep("GET", "/api/v1/transactions/{txn_id}", rpc::TXN_STATUS),
    ep(
        "POST",
        "/api/v1/transactions/{txn_id}/commit",
        rpc::TXN_COMMIT,
    ),
    ep(
        "POST",
        "/api/v1/transactions/{txn_id}/rollback",
        rpc::TXN_ROLLBACK,
    ),
    ep(
        "POST",
        "/api/v1/transactions/{txn_id}/heartbeat",
        rpc::TXN_HEARTBEAT,
    ),
    // Queries and cursors.
    ep("POST", "/api/v1/databases/{db}/query", rpc::EXECUTE),
    ep("POST", "/api/v1/databases/{db}/explain", rpc::EXPLAIN),
    ep("POST", "/api/v1/cursors/{cursor_id}/next", rpc::GET_MORE),
    ep("DELETE", "/api/v1/cursors/{cursor_id}", rpc::KILL_CURSOR),
    // Schema.
    ep("GET", "/api/v1/databases", rpc::LIST_DATABASES),
    ep("POST", "/api/v1/databases", rpc::CREATE_DATABASE),
    ep("GET", DB, rpc::LIST_DATABASES),
    ep("DELETE", DB, rpc::DROP_DATABASE),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections",
        rpc::LIST_COLLECTIONS,
    ),
    ep(
        "POST",
        "/api/v1/databases/{db}/collections",
        rpc::CREATE_COLLECTION,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}",
        rpc::GET_COLLECTION,
    ),
    ep(
        "PATCH",
        "/api/v1/databases/{db}/collections/{coll}",
        rpc::ALTER_COLLECTION,
    ),
    ep(
        "DELETE",
        "/api/v1/databases/{db}/collections/{coll}",
        rpc::DROP_COLLECTION,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/indexes",
        rpc::LIST_INDEXES,
    ),
    ep(
        "POST",
        "/api/v1/databases/{db}/collections/{coll}/indexes",
        rpc::CREATE_INDEX,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/indexes/{name}",
        rpc::LIST_INDEXES,
    ),
    ep(
        "DELETE",
        "/api/v1/databases/{db}/collections/{coll}/indexes/{name}",
        rpc::DROP_INDEX,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/indexes/{name}/progress",
        rpc::INDEX_BUILD_PROGRESS,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/validator",
        rpc::GET_VALIDATOR,
    ),
    ep(
        "PUT",
        "/api/v1/databases/{db}/collections/{coll}/validator",
        rpc::SET_VALIDATOR,
    ),
    ep(
        "DELETE",
        "/api/v1/databases/{db}/collections/{coll}/validator",
        rpc::REMOVE_VALIDATOR,
    ),
    // Documents.
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/documents",
        rpc::EXECUTE,
    ),
    ep(
        "POST",
        "/api/v1/databases/{db}/collections/{coll}/documents",
        rpc::DOC_INSERT,
    ),
    ep(
        "GET",
        "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
        rpc::DOC_GET,
    ),
    ep(
        "PUT",
        "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
        rpc::DOC_REPLACE,
    ),
    ep(
        "PATCH",
        "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
        rpc::DOC_UPDATE,
    ),
    ep(
        "DELETE",
        "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
        rpc::DOC_DELETE,
    ),
    ep(
        "POST",
        "/api/v1/databases/{db}/collections/{coll}/get-many",
        rpc::DOC_GET_MANY,
    ),
    ep(
        "POST",
        "/api/v1/databases/{db}/collections/{coll}/bulk",
        rpc::DOC_BULK_WRITE,
    ),
];

/// The endpoint for `method` and documented `path`, if any.
#[must_use]
pub fn endpoint(method: &str, path: &str) -> Option<&'static RestEndpoint> {
    REST_ENDPOINTS
        .iter()
        .find(|e| e.method == method && e.path == path)
}
