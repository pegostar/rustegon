// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The client: long-lived, cheap to clone, safe to share between tasks (rust-driver.md §3).

use std::{future::Future, sync::Arc};

use crate::{
    database::{DataContext, Database},
    error::{Error, Result},
    options::Action,
    pb::{
        ChangePasswordRequest, CreateDatabaseRequest, DropDatabaseRequest, GetServerInfoRequest,
        ListDatabasesRequest, PingRequest,
    },
    session::Session,
    settings::Settings,
    transaction::{self, Transaction, TransactionOptions},
    transport::{CallSpec, Executor, OpKind, unary},
};

/// What `get_server_info` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// Server version.
    pub server_version: String,
    /// Protocol version (`major.minor`).
    pub protocol_version: String,
    /// Optional features the server serves (PD-069).
    pub features: Vec<String>,
    /// Known node addresses.
    pub node_addresses: Vec<String>,
}

/// A Rustegon client. Creating it performs no I/O (connections open on first use); it must be
/// used from a Tokio runtime. Clones share connections and the login session.
#[derive(Clone)]
pub struct Client {
    exec: Arc<Executor>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("settings", &self.exec.settings)
            .finish()
    }
}

impl Client {
    /// A client for validated `settings`; invalid settings are an [`Error::Argument`].
    pub fn new(mut settings: Settings) -> Result<Self> {
        settings.validate()?;
        Ok(Self {
            exec: Executor::new(settings)?,
        })
    }

    /// A client for a connection string (`rustegon://user:pwd@host:port/db?…`).
    pub fn from_connection_string(uri: &str) -> Result<Self> {
        Self::new(Settings::from_connection_string(uri)?)
    }

    /// The settings in use.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.exec.settings
    }

    /// Logs in now (otherwise the first operation does), surfacing credential errors early.
    pub async fn connect(&self) -> Result<()> {
        self.exec.check_open()?;
        self.exec
            .auth
            .authorization(&self.exec.pool.first())
            .await
            .map(|_| ())
    }

    /// Closes the client: logs the session out (best effort) and refuses later operations with
    /// [`Error::InvalidState`]. Idempotent.
    pub async fn close(&self) {
        if self.exec.mark_closed() {
            self.exec.auth.logout(self.exec.pool.first()).await;
        }
    }

    /// A database handle (no I/O).
    #[must_use]
    pub fn database(&self, name: &str) -> Database {
        Database {
            ctx: DataContext {
                exec: Arc::clone(&self.exec),
                database: name.to_owned(),
                txn: None,
            },
        }
    }

    /// The default database of the settings (empty name when none: operations then fail with
    /// an argument error).
    #[must_use]
    pub fn default_database(&self) -> Database {
        self.database(self.exec.settings.default_database.as_deref().unwrap_or(""))
    }

    /// `SessionService.Ping`.
    pub fn ping(&self) -> Action<'_, ()> {
        Action::new(move |o| async move {
            let spec = CallSpec {
                kind: OpKind::Read,
                timeout: o.timeout,
                session: None,
            };
            unary!(
                self.exec,
                spec,
                session_service_client::SessionServiceClient,
                ping,
                PingRequest {}
            )
            .map(|_| ())
        })
    }

    /// Server version, protocol version and features.
    pub fn server_info(&self) -> Action<'_, ServerInfo> {
        Action::new(move |o| async move {
            let spec = CallSpec {
                kind: OpKind::Read,
                timeout: o.timeout,
                session: None,
            };
            let r = unary!(
                self.exec,
                spec,
                session_service_client::SessionServiceClient,
                get_server_info,
                GetServerInfoRequest {}
            )?;
            Ok(ServerInfo {
                server_version: r.server_version,
                protocol_version: r.protocol_version,
                features: r.features,
                node_addresses: r.node_addresses,
            })
        })
    }

    /// Database names, sorted.
    pub fn list_database_names(&self) -> Action<'_, Vec<String>> {
        Action::new(move |o| async move {
            let spec = CallSpec {
                kind: OpKind::Read,
                timeout: o.timeout,
                session: None,
            };
            let r = unary!(
                self.exec,
                spec,
                schema_service_client::SchemaServiceClient,
                list_databases,
                ListDatabasesRequest {}
            )?;
            let mut names: Vec<String> = r.databases.into_iter().map(|d| d.name).collect();
            names.sort();
            Ok(names)
        })
    }

    /// Creates a database (`if_not_exists` option); `true` when created.
    pub fn create_database(&self, name: &str) -> Action<'_, bool> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty database name"));
            }
            let spec = CallSpec {
                kind: OpKind::NoRetry,
                timeout: o.timeout,
                session: None,
            };
            let req = CreateDatabaseRequest {
                name,
                options: std::collections::HashMap::new(),
                if_not_exists: o.if_not_exists,
            };
            Ok(unary!(
                self.exec,
                spec,
                schema_service_client::SchemaServiceClient,
                create_database,
                req
            )?
            .created)
        })
    }

    /// Drops a database (`if_exists` option); `true` when dropped.
    pub fn drop_database(&self, name: &str) -> Action<'_, bool> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty database name"));
            }
            let spec = CallSpec {
                kind: OpKind::NoRetry,
                timeout: o.timeout,
                session: None,
            };
            let req = DropDatabaseRequest {
                name,
                if_exists: o.if_exists,
            };
            Ok(unary!(
                self.exec,
                spec,
                schema_service_client::SchemaServiceClient,
                drop_database,
                req
            )?
            .dropped)
        })
    }

    /// A causal-consistency session (no I/O); `causal = false` disables token propagation.
    pub fn start_session(&self, causal: bool) -> Result<Session> {
        self.exec.check_open()?;
        Ok(Session::new(causal))
    }

    /// Begins a transaction (manual mode).
    pub async fn begin_transaction(&self, options: TransactionOptions) -> Result<Transaction> {
        Transaction::begin(
            &self.exec,
            self.exec
                .settings
                .default_database
                .clone()
                .unwrap_or_default(),
            &options,
        )
        .await
    }

    /// Runs `f` in a transaction and commits, re-running it on retryable errors until
    /// `max_retry_time` (transactions.md §5). Errors that are not retryable — including
    /// [`Error::Application`] returned by `f` — roll back and are returned unchanged.
    ///
    /// ```no_run
    /// # async fn demo(client: rustegon::Client) -> rustegon::Result<()> {
    /// use rustegon::{Filter, TransactionOptions, Update};
    /// client
    ///     .with_transaction(TransactionOptions::new(), |tx| async move {
    ///         let acct = tx.collection("accounts");
    ///         acct.update_one(Filter::id("a1"), Update::new().inc("balance", -10)).await?;
    ///         acct.update_one(Filter::id("a2"), Update::new().inc("balance", 10)).await?;
    ///         Ok(())
    ///     })
    ///     .await
    /// # }
    /// ```
    pub async fn with_transaction<T, F, Fut>(&self, options: TransactionOptions, f: F) -> Result<T>
    where
        F: FnMut(Transaction) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let db = self
            .exec
            .settings
            .default_database
            .clone()
            .unwrap_or_default();
        transaction::with_transaction(&self.exec, &db, options, f).await
    }

    /// Changes the logged-in user's password.
    pub fn change_password(&self, current: &str, new: &str) -> Action<'_, ()> {
        let req = ChangePasswordRequest {
            current_password: current.to_owned(),
            new_password: new.to_owned(),
        };
        Action::new(move |o| async move {
            if req.current_password.is_empty() || req.new_password.is_empty() {
                return Err(Error::argument("empty password"));
            }
            let spec = CallSpec {
                kind: OpKind::Write,
                timeout: o.timeout,
                session: None,
            };
            unary!(
                self.exec,
                spec,
                admin_service_client::AdminServiceClient,
                change_password,
                req
            )
            .map(|_| ())
        })
    }

    /// Runs one admin-service call with the client's authentication (fixtures and tools; not
    /// part of the Driver Conceptual Model, PD-069).
    #[doc(hidden)]
    pub async fn admin<T, F, Fut>(&self, call: F) -> Result<T>
    where
        F: Fn(tonic::transport::Channel, tonic::metadata::MetadataMap) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        let call = &call;
        self.exec
            .run(CallSpec::of(OpKind::NoRetry), |a| async move {
                let r = a.request(());
                let md = r.metadata().clone();
                call(a.channel.clone(), md).await.map_err(Into::into)
            })
            .await
    }
}
