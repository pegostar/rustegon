// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `SchemaService`: databases, collections, indexes (with build progress) and validators
//! (FR-SCH-001/002/003, FR-IDX-001/003, protocol.md §2, schema.proto; PD-027, PD-053).
//!
//! Every call maps onto one engine catalog operation (its own transaction). Notes
//! (*Provisional (PD-053)*):
//! - **Options.** Database option `implicit_collection_creation` (bool, default true,
//!   FR-SCH-001) is the only `WITH` option in M4; collections have no options besides their
//!   validator (its own message), so any other option name is RGN-1001 and `AlterCollection`
//!   accepts only an empty change.
//! - **Drops** free the names at once; the data is reclaimed by a later GC job
//!   (`rustegon_engine` `schema.rs`).
//! - **Indexes** are built by the online job in the background: `CreateIndex` runs the DDL
//!   transaction, returns `BUILDING`, and a task drives the job's steps (each one engine
//!   transaction on the blocking pool, waiting the job's throttling pauses on the sim-api
//!   clock). `IndexBuildProgress` reports the descriptor state plus the progress this node's
//!   task recorded (`docs_processed`; `docs_total` and `eta_ms` are not estimated yet). A
//!   failed build leaves the index dropped (`rustegon-index`); its failure stays visible to
//!   `IndexBuildProgress` (`FAILED`, message) until the node restarts. Builds interrupted by a
//!   restart resume when the server calls `EmbeddedDb::resume_index_builds` at startup
//!   (`rustegond` wiring, wave 2c).
//! - `if_not_exists` on `CreateIndex` succeeds without change when an index of that name with
//!   the same keys, uniqueness and options exists; any other same-name index is RGN-1020.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use rustegon_catalog::{
    CollectionDescriptor, CollectionOptions, CollectionSpec, DatabaseOptions, IndexDescriptor,
    IndexOrder, IndexState, ValidationAction, ValidationLevel,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::Value;
use rustegon_engine::EmbeddedDb;
use rustegon_index::{BuildConfig, BuildStep, IndexBuild};
use rustegon_query::{
    Params, Statement,
    ast::{
        CreateIndex, Expr, IndexKey, IndexType, Literal, OptionItem, Path, QualifiedName, Segment,
    },
    parse_statement, print_statement,
};
use rustegon_security::rbac::{Action, Resource};

use super::{RequestContext, ServiceDeps, data::DataPlane};
use crate::Completion;

/// The database option of FR-SCH-001.
pub const IMPLICIT_COLLECTION_CREATION: &str = "implicit_collection_creation";
/// Attempts of one failing build step before the build is reported failed.
const STEP_ATTEMPTS: u32 = 16;

/// A database as listed.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseInfo {
    /// Name.
    pub name: String,
    /// Options (`implicit_collection_creation`).
    pub options: Vec<(String, Value)>,
}

/// A collection validator (data-model.md §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorDef {
    /// `{"$jsonSchema": …}` as JSON text (stored verbatim, PD-027).
    pub definition_json: String,
    /// Level.
    pub level: ValidationLevel,
    /// Action.
    pub action: ValidationAction,
}

/// A collection as described.
#[derive(Debug, Clone, PartialEq)]
pub struct CollectionInfo {
    /// Name.
    pub name: String,
    /// Options (none in M4).
    pub options: Vec<(String, Value)>,
    /// Validator.
    pub validator: Option<ValidatorDef>,
}

/// Client-visible index state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexStatus {
    /// Being built.
    Building,
    /// Usable.
    Ready,
    /// Build failed.
    Failed,
    /// Maintained but hidden from the planner.
    Hidden,
}

/// An index as described.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexInfo {
    /// Definition (structured `CREATE INDEX`).
    pub definition: CreateIndex,
    /// State.
    pub state: IndexStatus,
    /// Failure message when failed.
    pub error: Option<String>,
}

/// `IndexBuildProgress` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexProgress {
    /// State.
    pub state: IndexStatus,
    /// Documents processed by the backfill (this node's build task).
    pub docs_processed: u64,
    /// Estimated total (0: not estimated).
    pub docs_total: u64,
}

#[derive(Debug, Clone)]
struct Tracked {
    state: IndexStatus,
    docs_processed: u64,
    error: Option<String>,
}

/// Progress of the index builds started on this node, by (database, collection, index).
#[derive(Default)]
pub(crate) struct BuildTracker {
    map: Mutex<HashMap<(String, String, String), Tracked>>,
}

impl BuildTracker {
    fn lock(&self) -> MutexGuard<'_, HashMap<(String, String, String), Tracked>> {
        // Entries are replaced whole; a panic cannot leave one torn.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, key: &(String, String, String), tracked: Tracked) {
        self.lock().insert(key.clone(), tracked);
    }

    fn get(&self, key: &(String, String, String)) -> Option<Tracked> {
        self.lock().get(key).cloned()
    }
}

fn status_of(d: &IndexDescriptor) -> IndexStatus {
    match d.state {
        IndexState::Public if d.hidden => IndexStatus::Hidden,
        IndexState::Public => IndexStatus::Ready,
        IndexState::Dropping => IndexStatus::Failed,
        _ => IndexStatus::Building,
    }
}

/// An index key path as stored (`a.b`, `a.0`, `` `x.y`.z ``, `a.**`) back as AST segments
/// (the inverse of the engine's DDL key rendering).
fn key_path(text: &str) -> Path {
    if text == "**" || text.ends_with(".**") {
        return Path(vec![Segment::Field(text.to_owned())]);
    }
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let flush = |current: &mut String, was_quoted: bool, segments: &mut Vec<Segment>| {
        let seg = std::mem::take(current);
        match seg.parse::<u32>() {
            Ok(p) if !was_quoted && !segments.is_empty() => segments.push(Segment::Position(p)),
            _ => segments.push(Segment::Field(seg)),
        }
    };
    for c in text.chars() {
        match c {
            '`' => {
                quoted = !quoted;
                was_quoted = true;
            }
            '.' if !quoted => {
                flush(&mut current, was_quoted, &mut segments);
                was_quoted = false;
            }
            c => current.push(c),
        }
    }
    flush(&mut current, was_quoted, &mut segments);
    Path(segments)
}

/// The structured definition of a stored index, in canonical form.
fn definition_of(
    d: &IndexDescriptor,
    database: &str,
    collection: &str,
) -> Result<CreateIndex, Error> {
    let lit = |l: Literal| Expr::Literal(l);
    let mut options = Vec::new();
    if d.sparse {
        options.push(OptionItem {
            name: "sparse".to_owned(),
            value: lit(Literal::Bool(true)),
        });
    }
    if d.hidden {
        options.push(OptionItem {
            name: "hidden".to_owned(),
            value: lit(Literal::Bool(true)),
        });
    }
    if let Some(p) = &d.partial {
        options.push(OptionItem {
            name: "partial".to_owned(),
            value: lit(Literal::String(p.clone())),
        });
    }
    if !d.include.is_empty() {
        options.push(OptionItem {
            name: "include".to_owned(),
            value: Expr::Array {
                elements: d
                    .include
                    .iter()
                    .map(|s| lit(Literal::String(s.clone())))
                    .collect(),
            },
        });
    }
    let ci = CreateIndex {
        index_type: if d.unique {
            IndexType::Unique
        } else {
            IndexType::Standard
        },
        name: d.name.clone(),
        on: QualifiedName {
            database: Some(database.to_owned()),
            name: collection.to_owned(),
        },
        keys: d
            .fields
            .iter()
            .map(|f| IndexKey {
                path: key_path(&f.path),
                descending: f.order == IndexOrder::Desc,
                analyzer: None,
                boost: None,
            })
            .collect(),
        expire_after: None,
        options,
    };
    // Canonical form: the AST the parser produces for its own printed text.
    let text = print_statement(&Statement::CreateIndex(ci));
    match parse_statement(&text) {
        Ok(Statement::CreateIndex(ci)) => Ok(ci),
        _ => Err(Error::new(
            ErrorCode::Internal,
            format!("stored index {} has no canonical definition", d.name),
        )),
    }
}

fn database_options(options: Vec<(String, Value)>) -> Result<DatabaseOptions, Error> {
    let mut out = DatabaseOptions::default();
    for (name, value) in options {
        match (name.as_str(), value) {
            (IMPLICIT_COLLECTION_CREATION, Value::Bool(b)) => out.implicit_collection_creation = b,
            (IMPLICIT_COLLECTION_CREATION, _) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("{IMPLICIT_COLLECTION_CREATION} must be a boolean"),
                ));
            }
            (other, _) => return Err(unknown_option(other)),
        }
    }
    Ok(out)
}

fn unknown_option(name: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, format!("unknown option {name}"))
        .with_detail("option", name)
}

fn validator_of(c: &CollectionDescriptor) -> Option<ValidatorDef> {
    c.options.validator.as_ref().map(|v| ValidatorDef {
        definition_json: v.clone(),
        level: c.options.validation_level,
        action: c.options.validation_action,
    })
}

fn collection_info(c: &CollectionDescriptor) -> CollectionInfo {
    CollectionInfo {
        name: c.name.clone(),
        options: Vec::new(),
        validator: validator_of(c),
    }
}

fn collection_not_found(name: &str) -> Error {
    Error::new(ErrorCode::NotFound, format!("collection {name} not found"))
        .with_detail("kind", "collection")
}

/// `SchemaService` (module docs).
#[derive(Debug, Clone)]
pub struct SchemaService {
    deps: ServiceDeps,
    plane: Arc<DataPlane>,
}

impl SchemaService {
    pub(crate) fn new(deps: ServiceDeps, plane: Arc<DataPlane>) -> Self {
        Self { deps, plane }
    }

    /// Requires `action` on `resource` (PD-051 rule of the RPC, checked here because it names
    /// the resource).
    async fn require(
        &self,
        ctx: &RequestContext,
        resource: Resource,
        action: Action,
    ) -> Result<(), Error> {
        self.plane.authorize(ctx, &[(resource, action)]).await
    }

    /// Runs a DDL or catalog call on the blocking pool (DDL with `Await`: its outcome is
    /// always reported).
    async fn call<T: Send + 'static>(
        &self,
        ctx: &RequestContext,
        completion: Completion,
        f: impl FnOnce(&EmbeddedDb) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let db = Arc::clone(&self.plane.db);
        self.deps
            .executor
            .run(ctx, completion, move |_| f(&db))
            .await
    }

    /// Creates a database; `false` when `if_not_exists` found it.
    ///
    /// # Errors
    /// RGN-1031 (exists), RGN-1001 (name, options), RGN-5006.
    pub async fn create_database(
        &self,
        ctx: &RequestContext,
        name: String,
        options: Vec<(String, Value)>,
        if_not_exists: bool,
    ) -> Result<bool, Error> {
        self.require(
            ctx,
            Resource::Database(name.clone()),
            Action::CreateDatabase,
        )
        .await?;
        let options = database_options(options)?;
        self.call(ctx, Completion::Await, move |db| {
            match db.create_database(&name, &options) {
                Ok(_) => Ok(true),
                Err(e) if if_not_exists && e.code() == ErrorCode::AlreadyExists => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
    }

    /// Drops a database and its collections; `false` when `if_exists` found nothing.
    ///
    /// # Errors
    /// RGN-1030 (missing, without `if_exists`), RGN-5006.
    pub async fn drop_database(
        &self,
        ctx: &RequestContext,
        name: String,
        if_exists: bool,
    ) -> Result<bool, Error> {
        self.require(ctx, Resource::Database(name.clone()), Action::DropDatabase)
            .await?;
        self.call(ctx, Completion::Await, move |db| {
            match db.drop_database(&name)? {
                true => Ok(true),
                false if if_exists => Ok(false),
                false => Err(
                    Error::new(ErrorCode::NotFound, format!("database {name} not found"))
                        .with_detail("kind", "database"),
                ),
            }
        })
        .await
    }

    /// The databases, by name.
    ///
    /// # Errors
    /// RGN-5006, transaction errors.
    pub async fn list_databases(&self, ctx: &RequestContext) -> Result<Vec<DatabaseInfo>, Error> {
        self.plane.authenticated(ctx)?;
        let (plane, ctx_owned) = (Arc::clone(&self.plane), ctx.clone());
        self.call(ctx, Completion::Abandon, move |db| {
            Ok(db
                .list_databases()?
                .into_iter()
                .filter(|d| plane.visible(&ctx_owned, &Resource::Database(d.name.clone())))
                .map(|d| DatabaseInfo {
                    name: d.name,
                    options: vec![(
                        IMPLICIT_COLLECTION_CREATION.to_owned(),
                        Value::Bool(d.options.implicit_collection_creation),
                    )],
                })
                .collect())
        })
        .await
    }

    /// Creates a collection (optionally with a validator); `false` when `if_not_exists`
    /// found it.
    ///
    /// # Errors
    /// RGN-1030 (database), RGN-1031, RGN-1001 (name, options, invalid validator), RGN-5006.
    pub async fn create_collection(
        &self,
        ctx: &RequestContext,
        database: String,
        name: String,
        options: Vec<(String, Value)>,
        validator: Option<ValidatorDef>,
        if_not_exists: bool,
    ) -> Result<bool, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), name.clone()),
            Action::CreateCollection,
        )
        .await?;
        if let Some((n, _)) = options.first() {
            return Err(unknown_option(n));
        }
        let mut spec = CollectionSpec::document(name);
        if let Some(v) = validator {
            spec.options = CollectionOptions {
                validator: Some(v.definition_json),
                validation_level: v.level,
                validation_action: v.action,
            };
        }
        self.call(ctx, Completion::Await, move |db| {
            match db.create_collection(&database, &spec) {
                Ok(_) => Ok(true),
                Err(e) if if_not_exists && e.code() == ErrorCode::AlreadyExists => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
    }

    /// Drops a collection; `false` when `if_exists` found nothing.
    ///
    /// # Errors
    /// RGN-1030, RGN-5006.
    pub async fn drop_collection(
        &self,
        ctx: &RequestContext,
        database: String,
        name: String,
        if_exists: bool,
    ) -> Result<bool, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), name.clone()),
            Action::DropCollection,
        )
        .await?;
        self.call(ctx, Completion::Await, move |db| {
            match db.drop_collection(&database, &name)? {
                true => Ok(true),
                false if if_exists => Ok(false),
                false => Err(collection_not_found(&name)),
            }
        })
        .await
    }

    /// Changes collection options (none are alterable in M4: module docs).
    ///
    /// # Errors
    /// RGN-1001 for any option, RGN-1030 for a missing collection.
    pub async fn alter_collection(
        &self,
        ctx: &RequestContext,
        database: String,
        name: String,
        set_options: Vec<(String, Value)>,
        unset_options: Vec<String>,
    ) -> Result<(), Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), name.clone()),
            Action::AlterCollection,
        )
        .await?;
        if let Some((n, _)) = set_options.first() {
            return Err(unknown_option(n));
        }
        if let Some(n) = unset_options.first() {
            return Err(unknown_option(n));
        }
        // Only the existence check (the caller holds `alter_collection`, not necessarily `find`).
        self.call(ctx, Completion::Abandon, move |db| {
            db.collection(&database, &name)?
                .map(|_| ())
                .ok_or_else(|| collection_not_found(&name))
        })
        .await
    }

    /// Describes one collection.
    ///
    /// # Errors
    /// RGN-1030.
    pub async fn get_collection(
        &self,
        ctx: &RequestContext,
        database: String,
        name: String,
    ) -> Result<CollectionInfo, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), name.clone()),
            Action::Find,
        )
        .await?;
        self.call(ctx, Completion::Abandon, move |db| {
            db.collection(&database, &name)?
                .map(|c| collection_info(&c))
                .ok_or_else(|| collection_not_found(&name))
        })
        .await
    }

    /// The collections of a database, by name.
    ///
    /// # Errors
    /// RGN-1030 (database).
    pub async fn list_collections(
        &self,
        ctx: &RequestContext,
        database: String,
    ) -> Result<Vec<CollectionInfo>, Error> {
        self.plane.authenticated(ctx)?;
        let (plane, ctx_owned) = (Arc::clone(&self.plane), ctx.clone());
        self.call(ctx, Completion::Abandon, move |db| {
            Ok(db
                .list_collections(&database)?
                .iter()
                .filter(|c| {
                    plane.visible(
                        &ctx_owned,
                        &Resource::collection(database.clone(), c.name.clone()),
                    )
                })
                .map(collection_info)
                .collect())
        })
        .await
    }

    /// Creates an index and starts its background build (module docs).
    ///
    /// # Errors
    /// RGN-1001 (unsupported type/options), RGN-1020 (exists), RGN-1023, RGN-1030, RGN-5006.
    pub async fn create_index(
        &self,
        ctx: &RequestContext,
        database: String,
        mut definition: CreateIndex,
        if_not_exists: bool,
    ) -> Result<IndexInfo, Error> {
        let database = definition.on.database.clone().unwrap_or(database);
        definition.on.database = Some(database.clone());
        let collection = definition.on.name.clone();
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::CreateIndex,
        )
        .await?;
        let spec = EmbeddedDb::index_spec(&definition, &Params::new())?;
        let (db_name, coll_name, def) = (database.clone(), collection.clone(), definition.clone());
        let started = self
            .call(ctx, Completion::Await, move |db| {
                match db.start_index_build(&db_name, &coll_name, &spec, &BuildConfig::default()) {
                    Ok(build) => Ok(Ok(build)),
                    Err(e) if if_not_exists && e.code() == ErrorCode::IndexAlreadyExists => {
                        let same = db
                            .list_indexes(&db_name, &coll_name)?
                            .into_iter()
                            .find(|d| d.name == def.name)
                            .filter(|d| {
                                definition_of(d, &db_name, &coll_name)
                                    .is_ok_and(|existing| same_index(&existing, &def))
                            });
                        match same {
                            Some(d) => Ok(Err(d)),
                            None => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .await?;
        match started {
            Ok(build) => {
                let key = (database, collection, definition.name.clone());
                self.plane.builds.set(
                    &key,
                    Tracked {
                        state: IndexStatus::Building,
                        docs_processed: 0,
                        error: None,
                    },
                );
                self.spawn_build(key, build);
                Ok(IndexInfo {
                    definition,
                    state: IndexStatus::Building,
                    error: None,
                })
            }
            Err(existing) => Ok(IndexInfo {
                definition: definition_of(&existing, &database, &collection)?,
                state: status_of(&existing),
                error: None,
            }),
        }
    }

    /// Drives a build job to its end in the background (module docs).
    fn spawn_build(&self, key: (String, String, String), build: IndexBuild) {
        let plane = Arc::clone(&self.plane);
        let clock = Arc::clone(&self.deps.clock);
        let run = async move {
            let mut build = Some(build);
            let mut failures = 0;
            while let Some(mut job) = build.take() {
                let db = Arc::clone(&plane.db);
                let stepped = tokio::task::spawn_blocking(move || {
                    let step = db.step_index_build(&mut job);
                    (job, step)
                })
                .await;
                let Ok((job, step)) = stepped else {
                    tracing::error!(index = %key.2, "index build step panicked");
                    plane.builds.set(&key, failed("build step panicked"));
                    return;
                };
                match step {
                    Ok(BuildStep::Continue { progress, pause }) => {
                        failures = 0;
                        plane.builds.set(
                            &key,
                            Tracked {
                                state: IndexStatus::Building,
                                docs_processed: progress.docs_scanned,
                                error: None,
                            },
                        );
                        if !pause.is_zero() {
                            clock.sleep(pause).await;
                        }
                        build = Some(job);
                    }
                    Ok(BuildStep::Public(_)) => {
                        let docs = plane.builds.get(&key).map_or(0, |t| t.docs_processed);
                        plane.builds.set(
                            &key,
                            Tracked {
                                state: IndexStatus::Ready,
                                docs_processed: docs,
                                error: None,
                            },
                        );
                        return;
                    }
                    Ok(BuildStep::Abandoned(e)) => {
                        plane.builds.set(&key, failed(e.message()));
                        return;
                    }
                    Err(e) if failures + 1 < STEP_ATTEMPTS => {
                        // Steps are transactions on the persisted job record: retrying one
                        // after a conflict or I/O error is safe (rustegon-index).
                        failures += 1;
                        // Code only (PD-057): a build error can quote an indexed value.
                        tracing::debug!(index = %key.2, code = %e.code(), "index build step failed; retrying");
                        clock.sleep(std::time::Duration::from_millis(100)).await;
                        build = Some(job);
                    }
                    Err(e) => {
                        // The message (which may quote a duplicate value) goes to the build
                        // status the caller is authorised to read, not to the log.
                        tracing::warn!(index = %key.2, code = %e.code(), "index build stopped");
                        plane.builds.set(&key, failed(e.message()));
                        return;
                    }
                }
            }
        };
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            drop(rt.spawn(run));
        } else {
            tracing::error!("no runtime to drive an index build");
        }
    }

    /// Drops an index; `false` when `if_exists` found nothing.
    ///
    /// # Errors
    /// RGN-1021 (without `if_exists`), RGN-1030, RGN-5006.
    pub async fn drop_index(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
        name: String,
        if_exists: bool,
    ) -> Result<bool, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::DropIndex,
        )
        .await?;
        self.call(ctx, Completion::Await, move |db| {
            match db.drop_index(&database, &collection, &name) {
                Ok(()) => Ok(true),
                Err(e) if if_exists && e.code() == ErrorCode::IndexNotFound => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
    }

    /// The indexes of a collection, by name.
    ///
    /// # Errors
    /// RGN-1030 (database).
    pub async fn list_indexes(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
    ) -> Result<Vec<IndexInfo>, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::Find,
        )
        .await?;
        self.call(ctx, Completion::Abandon, move |db| {
            let mut out = Vec::new();
            for d in db.list_indexes(&database, &collection)? {
                out.push(IndexInfo {
                    definition: definition_of(&d, &database, &collection)?,
                    state: status_of(&d),
                    error: None,
                });
            }
            out.sort_by(|a, b| a.definition.name.cmp(&b.definition.name));
            Ok(out)
        })
        .await
    }

    /// Progress of an index build.
    ///
    /// # Errors
    /// RGN-1021 (unknown index), RGN-1030.
    pub async fn index_build_progress(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
        name: String,
    ) -> Result<IndexProgress, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::Find,
        )
        .await?;
        let key = (database.clone(), collection.clone(), name.clone());
        let tracked = self.plane.builds.get(&key);
        let found = self
            .call(ctx, Completion::Abandon, move |db| {
                Ok(db
                    .list_indexes(&database, &collection)?
                    .into_iter()
                    .find(|d| d.name == name))
            })
            .await?;
        match (found, tracked) {
            (Some(d), t) => Ok(IndexProgress {
                state: status_of(&d),
                docs_processed: t.map_or(0, |t| t.docs_processed),
                docs_total: 0,
            }),
            (None, Some(t)) if t.state == IndexStatus::Failed => Ok(IndexProgress {
                state: IndexStatus::Failed,
                docs_processed: t.docs_processed,
                docs_total: 0,
            }),
            _ => Err(Error::new(
                ErrorCode::IndexNotFound,
                format!("index {} not found", key.2),
            )),
        }
    }

    /// The failure message of a build of this node (for `IndexInfo.error`).
    #[must_use]
    pub fn build_error(&self, database: &str, collection: &str, name: &str) -> Option<String> {
        self.plane
            .builds
            .get(&(database.to_owned(), collection.to_owned(), name.to_owned()))
            .and_then(|t| t.error)
    }

    /// The validator of a collection.
    ///
    /// # Errors
    /// RGN-1030.
    pub async fn get_validator(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
    ) -> Result<Option<ValidatorDef>, Error> {
        Ok(self
            .get_collection(ctx, database, collection)
            .await?
            .validator)
    }

    /// Sets or replaces the validator (existing documents are not checked, PD-031).
    ///
    /// # Errors
    /// RGN-1001 (invalid validator), RGN-1030, RGN-5006.
    pub async fn set_validator(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
        validator: ValidatorDef,
    ) -> Result<(), Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::AlterCollection,
        )
        .await?;
        let options = CollectionOptions {
            validator: Some(validator.definition_json),
            validation_level: validator.level,
            validation_action: validator.action,
        };
        self.call(ctx, Completion::Await, move |db| {
            db.set_collection_options(&database, &collection, &options)
                .map(|_| ())
        })
        .await
    }

    /// Removes the validator; `false` when there was none.
    ///
    /// # Errors
    /// RGN-1030, RGN-5006.
    pub async fn remove_validator(
        &self,
        ctx: &RequestContext,
        database: String,
        collection: String,
    ) -> Result<bool, Error> {
        self.require(
            ctx,
            Resource::collection(database.clone(), collection.clone()),
            Action::AlterCollection,
        )
        .await?;
        self.call(ctx, Completion::Await, move |db| {
            let current = db
                .collection(&database, &collection)?
                .ok_or_else(|| collection_not_found(&collection))?;
            if current.options.validator.is_none() {
                return Ok(false);
            }
            db.set_collection_options(&database, &collection, &CollectionOptions::default())?;
            Ok(true)
        })
        .await
    }
}

fn failed(message: &str) -> Tracked {
    Tracked {
        state: IndexStatus::Failed,
        docs_processed: 0,
        error: Some(message.to_owned()),
    }
}

/// Same name, type, keys and options (the collection is the same by construction).
fn same_index(a: &CreateIndex, b: &CreateIndex) -> bool {
    let canonical = |ci: &CreateIndex| {
        let mut ci = ci.clone();
        ci.on = QualifiedName {
            database: None,
            name: String::new(),
        };
        ci.options.sort_by(|x, y| x.name.cmp(&y.name));
        print_statement(&Statement::CreateIndex(ci))
    };
    canonical(a) == canonical(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_idx_001_key_paths_round_trip_the_ddl_rendering() {
        assert_eq!(
            key_path("a.b"),
            Path(vec![Segment::Field("a".into()), Segment::Field("b".into())])
        );
        assert_eq!(
            key_path("items.0.sku"),
            Path(vec![
                Segment::Field("items".into()),
                Segment::Position(0),
                Segment::Field("sku".into())
            ])
        );
        assert_eq!(
            key_path("`x.y`.z"),
            Path(vec![
                Segment::Field("x.y".into()),
                Segment::Field("z".into())
            ])
        );
        assert_eq!(key_path("a.**"), Path(vec![Segment::Field("a.**".into())]));
    }
}
