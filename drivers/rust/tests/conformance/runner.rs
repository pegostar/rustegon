// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The conformance runner (README §5–§7): operations, matching and the normalised observations
//! of README §6, ported from the .NET/Go runners so the observations are identical (AC-DRV-003).
//!
//! State lives behind `RefCell`s and every method takes `&self`, so a `with_transaction`
//! callback can borrow the run while it executes nested operations. No borrow is held across an
//! `.await`.

use std::{
    cell::RefCell, collections::HashMap, future::Future, pin::Pin, sync::Mutex, time::Duration,
};

use rustegon::{
    BulkOperation, Client, Collection, Cursor, Database, Document, Error, ErrorClass, Filter,
    Isolation, Session, Transaction, TransactionOptions, Update, UpdateResult, ValidationAction,
    ValidationLevel, Validator, Value,
    codec::json::{self, JsonMode},
};

use crate::{
    dsl::{dsl_filter, dsl_update, keys_of, projection_of, sort_of},
    yaml::{Y, Yaml, is_wrapper, json_string, to_json, to_value},
};

/// Fields the server maintains: dropped from observations, ignored by matching unless named.
const SYSTEM_FIELDS: [&str; 3] = ["_rev", "_createdAt", "_updatedAt"];

/// A failed expectation (never an observed driver error).
#[derive(Debug)]
pub struct Fail(pub String);

pub type Res<T> = Result<T, Outcome>;

/// Why an operation did not produce a value.
#[derive(Debug)]
pub enum Outcome {
    /// A driver error (observed, maybe expected).
    Driver(Error),
    /// A failed expectation: the test fails.
    Fail(Fail),
}

impl From<Error> for Outcome {
    fn from(e: Error) -> Self {
        Self::Driver(e)
    }
}

pub fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(Outcome::Fail(Fail(msg.into())))
}

/// The error of `runner.throwApplicationError`.
#[derive(Debug)]
pub struct ApplicationError;

impl std::fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("application error raised by the conformance callback")
    }
}

impl std::error::Error for ApplicationError {}

fn is_application(e: &Error) -> bool {
    matches!(e, Error::Application(a) if a.is::<ApplicationError>())
}

/// A saved object (`saveAs`).
pub enum Saved {
    Value(Value),
    Client(Client),
    Session(Session),
    Cursor(Box<Cursor>),
    Txn(Transaction),
}

/// Result of one operation.
pub enum Out {
    Value(Value),
    Handle(Saved),
}

type OpenClient<'a> = Box<dyn Fn(&Yaml) -> Res<Client> + 'a>;
type RunnerExt<'a> = Box<dyn Fn(&str, &Yaml) -> Option<Result<(), String>> + 'a>;
type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// One test's run.
pub struct Run<'a> {
    pub client: Client,
    pub database: String,
    pub default_collection: String,
    pub substitute: &'a dyn Fn(&str) -> String,
    normalizer: RefCell<Normalizer>,
    saved: RefCell<HashMap<String, Saved>>,
    opened: RefCell<Vec<Client>>,
    txn: RefCell<Option<Transaction>>,
    last_error: RefCell<Option<String>>,
    pub observations: RefCell<Vec<String>>,
    pub open_client: Option<OpenClient<'a>>,
    pub runner_ext: Option<RunnerExt<'a>>,
}

impl<'a> Run<'a> {
    pub fn new(
        client: Client,
        database: &str,
        default_collection: &str,
        substitute: &'a dyn Fn(&str) -> String,
        test_text: &str,
    ) -> Self {
        Self {
            client,
            database: database.to_owned(),
            default_collection: default_collection.to_owned(),
            substitute,
            normalizer: RefCell::new(Normalizer::new(test_text)),
            saved: RefCell::new(HashMap::new()),
            opened: RefCell::new(Vec::new()),
            txn: RefCell::new(None),
            last_error: RefCell::new(None),
            observations: RefCell::new(Vec::new()),
            open_client: None,
            runner_ext: None,
        }
    }

    /// Closes what the run opened.
    pub async fn close(&self) {
        let saved: Vec<Saved> = self.saved.borrow_mut().drain().map(|(_, v)| v).collect();
        for s in saved {
            match s {
                Saved::Cursor(mut c) => {
                    let _ = c.close().await;
                }
                Saved::Txn(t) => {
                    let _ = t.close().await;
                }
                _ => {}
            }
        }
        let opened: Vec<Client> = self.opened.borrow_mut().drain(..).collect();
        for c in opened {
            c.close().await;
        }
    }

    /// Runs operations; `top_level` records observations (README §6).
    pub fn run_ops<'s>(
        &'s self,
        ops: &'s [Yaml],
        top_level: bool,
    ) -> LocalFuture<'s, Result<(), Outcome>> {
        Box::pin(async move {
            for (i, op) in ops.iter().enumerate() {
                self.run_one(op, top_level.then_some(i)).await?;
            }
            Ok(())
        })
    }

    async fn run_one(&self, op: &Yaml, index: Option<usize>) -> Result<(), Outcome> {
        let (target, name) = (op.str_("object"), op.str_("name"));
        let label = format!("{target}.{name}");
        let expect = op.get("expect");
        let result = self.dispatch(target, name, op).await;
        let out = match result {
            Err(Outcome::Fail(f)) => return Err(Outcome::Fail(f)),
            Err(Outcome::Driver(e)) => {
                *self.last_error.borrow_mut() =
                    Some(e.rustegon().map(|r| r.trace_id.clone()).unwrap_or_default());
                if let Some(i) = index {
                    self.observations
                        .borrow_mut()
                        .push(format!("{{\"error\":{},\"op\":{i}}}", error_json(&e)));
                }
                if !expect.has("error") {
                    if index.is_none() {
                        // Inside a callback or a step: the error belongs to the enclosing operation.
                        return Err(Outcome::Driver(e));
                    }
                    return fail(format!("{label} failed: {e}"));
                }
                return check_error(&label, expect.get("error"), &e)
                    .map_err(|m| Outcome::Fail(Fail(m)));
            }
            Ok(o) => o,
        };
        if let Some(i) = index {
            let observed = match &out {
                Out::Handle(_) => "\"<handle>\"".to_owned(),
                Out::Value(v) => self.normalizer.borrow_mut().json(&self.volatile(name, v)),
            };
            self.observations
                .borrow_mut()
                .push(format!("{{\"op\":{i},\"result\":{observed}}}"));
        }
        let saved_value = match &out {
            Out::Value(v) => Some(v.clone()),
            Out::Handle(_) => None,
        };
        let save_as = op.str_("saveAs");
        if !save_as.is_empty() {
            let s = match out {
                Out::Value(v) => Saved::Value(v),
                Out::Handle(h) => h,
            };
            self.saved.borrow_mut().insert(save_as.to_owned(), s);
        }
        if expect.is_badvalue() {
            return Ok(());
        }
        if expect.has("error") {
            return fail(format!("{label} succeeded but an error was expected"));
        }
        if expect.has("result") {
            let mode = Mode {
                subset: op.str_("match") == "subset",
                ordered: op.get("ordered").as_bool() != Some(false),
                field_order: op.is_true("fieldOrder"),
            };
            let actual = saved_value.unwrap_or(Value::Null);
            if let Err(why) = self.result(expect.get("result"), &actual, mode) {
                return fail(format!("{label}: {why}"));
            }
        }
        Ok(())
    }

    fn volatile(&self, name: &str, v: &Value) -> Value {
        match (name, v) {
            ("causalityToken", Value::String(_)) => Value::String("<volatile>".into()),
            ("listDatabaseNames", Value::Array(a)) => Value::Array(
                a.iter()
                    .filter_map(|n| match n {
                        Value::String(s) if s.starts_with(&self.database) => Some(Value::String(
                            format!("<database>{}", &s[self.database.len()..]),
                        )),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => v.clone(),
        }
    }

    // --------------------------------------------------------------------------- dispatch

    async fn dispatch(&self, target: &str, name: &str, op: &Yaml) -> Res<Out> {
        let args = op.get("args");
        match target {
            "runner" => {
                return self
                    .runner(name, args)
                    .await
                    .map(|()| Out::Value(Value::Null));
            }
            "client" => return self.client_op(&self.client, name, op, args).await,
            "database" => {
                return self
                    .database_op(&self.client.database(&self.database), name, args)
                    .await;
            }
            "collection" => {
                let c = self
                    .client
                    .database(&self.database)
                    .collection(&self.coll_name(op)?);
                return self.collection_op(&c, name, op, args).await;
            }
            "transaction" => {
                let tx = self.txn.borrow().clone();
                let Some(tx) = tx else {
                    return fail("object: transaction outside a callback");
                };
                return self.transaction_op(&tx, name, op, args).await;
            }
            _ => {}
        }
        enum H {
            Client(Client),
            Txn(Transaction),
            Session(Session),
            Cursor,
        }
        let h = match self.saved.borrow().get(target) {
            Some(Saved::Client(c)) => H::Client(c.clone()),
            Some(Saved::Txn(t)) => H::Txn(t.clone()),
            Some(Saved::Session(s)) => H::Session(s.clone()),
            Some(Saved::Cursor(_)) => H::Cursor,
            _ => return fail(format!("unknown object {target}")),
        };
        match h {
            H::Client(c) => self.client_op(&c, name, op, args).await,
            H::Txn(t) => self.transaction_op(&t, name, op, args).await,
            H::Session(s) => match name {
                "causalityToken" => Ok(Out::Value(
                    s.causality_token().map_or(Value::Null, Value::String),
                )),
                "close" => {
                    s.close();
                    Ok(Out::Value(Value::Null))
                }
                _ => fail(format!("unknown session operation {name}")),
            },
            H::Cursor => {
                // Take the cursor out while it is awaited (no RefCell borrow across .await).
                let Some(Saved::Cursor(mut c)) = self.saved.borrow_mut().remove(target) else {
                    return fail("cursor vanished");
                };
                let r = match name {
                    "next" => c
                        .next()
                        .await
                        .map(|d| Out::Value(d.map_or(Value::Null, Value::Object))),
                    "close" => c.close().await.map(|()| Out::Value(Value::Null)),
                    _ => {
                        self.saved
                            .borrow_mut()
                            .insert(target.to_owned(), Saved::Cursor(c));
                        return fail(format!("unknown cursor operation {name}"));
                    }
                };
                self.saved
                    .borrow_mut()
                    .insert(target.to_owned(), Saved::Cursor(c));
                Ok(r?)
            }
        }
    }

    fn coll_name(&self, op: &Yaml) -> Res<String> {
        let c = op.str_("collection");
        if !c.is_empty() {
            return Ok(c.to_owned());
        }
        if !self.default_collection.is_empty() {
            return Ok(self.default_collection.clone());
        }
        fail("no collection")
    }

    async fn client_op(&self, c: &Client, name: &str, op: &Yaml, args: &Yaml) -> Res<Out> {
        let v = |x: Value| Ok(Out::Value(x));
        match name {
            "open" => {
                let Some(open) = &self.open_client else {
                    return fail("client.open is not available here");
                };
                let nc = open(args)?;
                self.connect(nc).await
            }
            "openFromConnectionString" => {
                let nc = Client::from_connection_string(&(self.substitute)(args.str_("uri")))?;
                self.connect(nc).await
            }
            "getServerInfo" => {
                let i = c.server_info().await?;
                v(Value::Object(rustegon::doc! {
                    "serverVersion" => i.server_version,
                    "protocolVersion" => i.protocol_version,
                    "features" => i.features,
                }))
            }
            "listDatabaseNames" => v(c.list_database_names().await?.into()),
            "createDatabase" => {
                let ok = c
                    .create_database(&(self.substitute)(args.str_("name")))
                    .if_not_exists(args.is_true("ifNotExists"))
                    .await?;
                v(Value::Object(rustegon::doc! { "created" => ok }))
            }
            "dropDatabase" => {
                let ok = c
                    .drop_database(&(self.substitute)(args.str_("name")))
                    .if_exists(args.is_true("ifExists"))
                    .await?;
                v(Value::Object(rustegon::doc! { "dropped" => ok }))
            }
            "startSession" => Ok(Out::Handle(Saved::Session(
                c.start_session(args.get("causalConsistency").as_bool() != Some(false))?,
            ))),
            "beginTransaction" => Ok(Out::Handle(Saved::Txn(
                c.begin_transaction(txn_options(args)).await?,
            ))),
            "withTransaction" => {
                let callback = args.list("callback");
                let this = self;
                let r = c
                    .with_transaction(txn_options(args), |tx| async move {
                        this.in_transaction(tx, callback).await
                    })
                    .await;
                match r {
                    Ok(()) => v(Value::Null),
                    Err(e) => match self.take_failure(&e) {
                        Some(f) => Err(Outcome::Fail(f)),
                        None => Err(Outcome::Driver(e)),
                    },
                }
            }
            "manualTransaction" => {
                let tx = c.begin_transaction(txn_options(args)).await?;
                let r = self.in_transaction(tx.clone(), args.list("steps")).await;
                let _ = tx.close().await;
                match r {
                    Ok(()) => v(Value::Null),
                    Err(e) => match self.take_failure(&e) {
                        Some(f) => Err(Outcome::Fail(f)),
                        None => Err(Outcome::Driver(e)),
                    },
                }
            }
            "changePassword" => {
                c.change_password(args.str_("currentPassword"), args.str_("newPassword"))
                    .await?;
                v(Value::Null)
            }
            "close" => {
                c.close().await;
                v(Value::Null)
            }
            _ => {
                // README §5: collection operations are also available on a saved client.
                let coll = c.database(&self.database).collection(&self.coll_name(op)?);
                self.collection_op(&coll, name, op, args).await
            }
        }
    }

    async fn connect(&self, c: Client) -> Res<Out> {
        if let Err(e) = c.connect().await {
            c.close().await;
            return Err(e.into());
        }
        self.opened.borrow_mut().push(c.clone());
        Ok(Out::Handle(Saved::Client(c)))
    }

    /// Runs steps/callback operations with `object: transaction` bound to `tx`. A failed
    /// expectation inside is carried out as an application error and recovered by the caller.
    async fn in_transaction(&self, tx: Transaction, ops: &[Yaml]) -> rustegon::Result<()> {
        let outer = self.txn.replace(Some(tx));
        let r = self.run_ops(ops, false).await;
        *self.txn.borrow_mut() = outer;
        match r {
            Ok(()) => Ok(()),
            Err(Outcome::Driver(e)) => Err(e),
            Err(Outcome::Fail(f)) => Err(Error::application(FailCarrier(Mutex::new(Some(f))))),
        }
    }

    fn take_failure(&self, e: &Error) -> Option<Fail> {
        match e {
            Error::Application(a) => a
                .downcast_ref::<FailCarrier>()
                .and_then(|c| c.0.lock().ok().and_then(|mut f| f.take())),
            _ => None,
        }
    }

    async fn transaction_op(
        &self,
        tx: &Transaction,
        name: &str,
        op: &Yaml,
        args: &Yaml,
    ) -> Res<Out> {
        match name {
            "query" => {
                let mut a = tx.query(args.str_("rgql"), self.params(args));
                if let Some(b) = args.int("batchSize") {
                    a = a.batch_size(u32::try_from(b).unwrap_or(0));
                }
                drain(a.await?).await
            }
            "commit" => tx
                .commit()
                .await
                .map(|()| Out::Value(Value::Null))
                .map_err(Into::into),
            "rollback" => tx
                .rollback()
                .await
                .map(|()| Out::Value(Value::Null))
                .map_err(Into::into),
            "close" => tx
                .close()
                .await
                .map(|()| Out::Value(Value::Null))
                .map_err(Into::into),
            "resolve" => Ok(Out::Value(Value::String(
                tx.resolve().await?.as_str().into(),
            ))),
            _ => {
                let coll = tx.collection(&self.coll_name(op)?);
                self.collection_op(&coll, name, op, args).await
            }
        }
    }

    fn params(&self, args: &Yaml) -> Document {
        if args.has("params") {
            self.document(args.get("params"))
        } else {
            Document::new()
        }
    }

    async fn database_op(&self, db: &Database, name: &str, args: &Yaml) -> Res<Out> {
        let v = |x: Value| Ok(Out::Value(x));
        match name {
            "query" => {
                let mut a = db.query(args.str_("rgql"), self.params(args));
                if let Some(b) = args.int("batchSize") {
                    a = a.batch_size(u32::try_from(b).unwrap_or(0));
                }
                drain(a.await?).await
            }
            "createCollection" => {
                let mut a = db
                    .create_collection(args.str_("name"))
                    .if_not_exists(args.is_true("ifNotExists"));
                if args.has("validator") {
                    a = a.validator(validator_of(args.get("validator")));
                }
                v(Value::Object(rustegon::doc! { "created" => a.await? }))
            }
            "dropCollection" => {
                let ok = db
                    .drop_collection(args.str_("name"))
                    .if_exists(args.is_true("ifExists"))
                    .await?;
                v(Value::Object(rustegon::doc! { "dropped" => ok }))
            }
            "listCollectionNames" => v(db.list_collection_names().await?.into()),
            _ => fail(format!("unknown database operation {name}")),
        }
    }

    async fn collection_op(&self, c: &Collection, name: &str, op: &Yaml, args: &Yaml) -> Res<Out> {
        let session = {
            let s = op.str_("session");
            match self.saved.borrow().get(s) {
                Some(Saved::Session(x)) if !s.is_empty() => Some(x.clone()),
                _ => None,
            }
        };
        let opts = args.get("options");
        let if_rev = match opts.get("ifRev") {
            Yaml::String(s) => match self.resolve_string(s) {
                Some(Value::String(r)) => Some(r),
                _ => None,
            },
            _ => None,
        };
        // Applies the shared options to any Action.
        macro_rules! with_opts {
            ($a:expr) => {{
                let mut a = $a;
                if let Some(s) = &session {
                    a = a.session(s);
                }
                if let Some(r) = &if_rev {
                    a = a.if_rev(r.clone());
                }
                a
            }};
        }
        let v = |x: Value| Ok(Out::Value(x));
        match name {
            "insertOne" => {
                let r = with_opts!(c.insert_one(self.document(args.get("document")))).await?;
                v(Value::Object(
                    rustegon::doc! { "insertedId" => r.inserted_id },
                ))
            }
            "insertMany" => {
                let docs = args
                    .list("documents")
                    .iter()
                    .map(|d| self.document(d))
                    .collect();
                let r = with_opts!(c.insert_many(docs)).await?;
                v(Value::Object(
                    rustegon::doc! { "insertedIds" => r.inserted_ids },
                ))
            }
            "findById" => {
                let d = with_opts!(c.find_by_id(self.value(args.get("id")))).await?;
                v(d.map_or(Value::Null, Value::Object))
            }
            "find" => {
                let mut q = c.find(self.filter(args.get("filter"))?);
                if let Some(s) = &session {
                    q = q.session(s);
                }
                if let Some(l) = args.get("sort").as_vec() {
                    q = q.sort(sort_of(l));
                }
                if let Some(n) = args.int("limit") {
                    q = q.limit(n);
                }
                if let Some(n) = args.int("skip") {
                    q = q.skip(n);
                }
                if args.has("projection") {
                    q = q.project(projection_of(args.get("projection")));
                }
                if let Some(n) = args.int("batchSize") {
                    q = q.batch_size(u32::try_from(n).unwrap_or(0));
                }
                match op.str_("then") {
                    "first" => v(q.first().await?.map_or(Value::Null, Value::Object)),
                    "cursor" => Ok(Out::Handle(Saved::Cursor(Box::new(q.cursor().await?)))),
                    _ => v(Value::Array(
                        q.to_list().await?.into_iter().map(Value::Object).collect(),
                    )),
                }
            }
            "updateOne" | "updateMany" => {
                let f = self.filter(args.get("filter"))?;
                let u = self.update_of(args.list("update"))?;
                let r = if name == "updateOne" {
                    with_opts!(c.update_one(f, u)).await?
                } else {
                    with_opts!(c.update_many(f, u)).await?
                };
                v(counts(&r))
            }
            "replaceOne" => {
                let f = self.filter(args.get("filter"))?;
                let r = with_opts!(c.replace_one(f, self.document(args.get("replacement"))))
                    .upsert(opts.is_true("upsert"))
                    .await?;
                v(counts(&r))
            }
            "deleteOne" | "deleteMany" => {
                let f = self.filter(args.get("filter"))?;
                let r = if name == "deleteOne" {
                    with_opts!(c.delete_one(f)).await?
                } else {
                    with_opts!(c.delete_many(f)).await?
                };
                v(Value::Object(
                    rustegon::doc! { "deletedCount" => count(r.deleted_count) },
                ))
            }
            "bulkWrite" => {
                let ops = args
                    .list("operations")
                    .iter()
                    .map(|b| self.bulk_of(b))
                    .collect::<Res<Vec<_>>>()?;
                let r = with_opts!(c.bulk_write(ops))
                    .ordered(args.get("ordered").as_bool() != Some(false))
                    .await?;
                let errors: Vec<Value> = r
                    .errors
                    .iter()
                    .map(|e| {
                        Value::Object(rustegon::doc! {
                            "index" => i64::try_from(e.index).unwrap_or(-1),
                            "code" => i64::from(e.error.code().unwrap_or(0)),
                        })
                    })
                    .collect();
                v(Value::Object(rustegon::doc! {
                    "insertedCount" => count(r.inserted_count),
                    "matchedCount" => count(r.matched_count),
                    "modifiedCount" => count(r.modified_count),
                    "deletedCount" => count(r.deleted_count),
                    "errors" => errors,
                }))
            }
            "createIndex" => {
                let d = c
                    .create_index(args.str_("name"), keys_of(args.list("keys")))
                    .unique(args.is_true("unique"))
                    .await?;
                v(Value::Object(
                    rustegon::doc! { "name" => d.name, "state" => d.state.as_str() },
                ))
            }
            "dropIndex" => {
                let ok = c
                    .drop_index(args.str_("name"))
                    .if_exists(args.is_true("ifExists"))
                    .await?;
                v(Value::Object(rustegon::doc! { "dropped" => ok }))
            }
            "listIndexes" => {
                let list = c.list_indexes().await?;
                v(Value::Array(
                    list.into_iter()
                        .map(|i| {
                            let keys: Vec<Value> = i
                                .keys
                                .iter()
                                .map(|k| Value::Object(rustegon::doc! { "path" => k.path.clone(), "descending" => k.descending }))
                                .collect();
                            Value::Object(rustegon::doc! {
                                "name" => i.name, "keys" => keys, "unique" => i.unique, "state" => i.state.as_str(),
                            })
                        })
                        .collect(),
                ))
            }
            _ => fail(format!("unknown collection operation {name}")),
        }
    }

    async fn runner(&self, name: &str, args: &Yaml) -> Res<()> {
        match name {
            "sleep" => {
                let ms = u64::try_from(args.int("ms").unwrap_or(0)).unwrap_or(0);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(())
            }
            "throwApplicationError" => Err(Outcome::Driver(Error::application(ApplicationError))),
            "assertLastErrorHasTraceId" => match self.last_error.borrow().as_deref() {
                Some(t) if !t.is_empty() => Ok(()),
                _ => fail("the last error has no trace id"),
            },
            _ => match self.runner_ext.as_ref().and_then(|ext| ext(name, args)) {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => fail(format!("runner {name}: {e}")),
                None => fail(format!("unknown runner operation {name}")),
            },
        }
    }

    // ------------------------------------------------------------------------ values, DSL

    /// A string with substitutions, or the value of a `$$ref` (`None` = missing).
    pub fn resolve_string(&self, s: &str) -> Option<Value> {
        let Some(r) = s.strip_prefix("$$ref:") else {
            return Some(Value::String((self.substitute)(s)));
        };
        let mut parts = r.split('.');
        let first = parts.next().unwrap_or("");
        let mut v = match self.saved.borrow().get(first) {
            Some(Saved::Value(v)) => v.clone(),
            _ => return None,
        };
        for p in parts {
            v = match v {
                Value::Object(d) => d.get(p)?.clone(),
                _ => return None,
            };
        }
        Some(v)
    }

    pub fn value(&self, y: &Yaml) -> Value {
        to_value(y, &|s| self.resolve_string(s).unwrap_or(Value::MinKey))
    }

    pub fn document(&self, y: &Yaml) -> Document {
        match self.value(y) {
            Value::Object(d) => d,
            _ => Document::new(),
        }
    }

    fn filter(&self, y: &Yaml) -> Res<Filter> {
        dsl_filter(y, &|x| self.value(x)).or_else(fail)
    }

    fn update_of(&self, ops: &[Yaml]) -> Res<Update> {
        dsl_update(ops, &|x| self.value(x)).or_else(fail)
    }

    fn bulk_of(&self, b: &Yaml) -> Res<BulkOperation> {
        let Some((kind, a)) = b.single() else {
            return fail("a bulk operation has one key");
        };
        let if_rev = match a.get("ifRev") {
            Yaml::String(s) => match self.resolve_string(s) {
                Some(Value::String(r)) => Some(r),
                _ => None,
            },
            _ => None,
        };
        Ok(match kind {
            "insert" => BulkOperation::Insert(self.document(a.get("document"))),
            "upsert" => BulkOperation::Upsert(self.document(a.get("document"))),
            "replace" => BulkOperation::Replace {
                id: self.value(a.get("id")),
                document: self.document(a.get("document")),
                if_rev,
            },
            "update" => BulkOperation::Update {
                id: self.value(a.get("id")),
                update: self.update_of(a.list("update"))?,
                if_rev,
            },
            "delete" => BulkOperation::Delete {
                id: self.value(a.get("id")),
                if_rev,
            },
            _ => return fail(format!("unknown bulk operation {kind}")),
        })
    }

    // --------------------------------------------------------------------------- matching

    /// Compares an expected YAML result with an actual value (README §5 "Values and matching").
    pub fn result(&self, expected: &Yaml, actual: &Value, mode: Mode) -> Result<(), String> {
        if let (Some(list), false) = (expected.as_vec(), mode.ordered) {
            let Value::Array(items) = actual else {
                return Err(format!("expected an array, got {}", value_json(actual)));
            };
            if (mode.subset && items.len() < list.len())
                || (!mode.subset && items.len() != list.len())
            {
                return Err(format!(
                    "expected {} rows, got {}: {}",
                    list.len(),
                    items.len(),
                    value_json(actual)
                ));
            }
            let mut left: Vec<&Value> = items.iter().collect();
            for e in list {
                let Some(i) = left
                    .iter()
                    .position(|a| self.why(e, Some(a), mode, "").is_ok())
                else {
                    return Err(format!(
                        "no row matches {} in {}",
                        to_json(e),
                        value_json(actual)
                    ));
                };
                left.remove(i);
            }
            return Ok(());
        }
        self.why(expected, Some(actual), mode, "$")
    }

    fn why(&self, e: &Yaml, a: Option<&Value>, mode: Mode, at: &str) -> Result<(), String> {
        let fail = |what: String| -> Result<(), String> {
            Err(match a {
                None => format!("{at}: {what} (actual missing)"),
                Some(v) => format!("{at}: {what} (actual {})", value_json(v)),
            })
        };
        match e {
            Yaml::String(x) if x == "$$any" => Ok(()),
            Yaml::String(x) if x.starts_with("$$ref:") => match (self.resolve_string(x), a) {
                (Some(want), Some(got)) if &want == got => Ok(()),
                (want, _) => fail(format!(
                    "expected {}",
                    want.map_or("missing".into(), |w| value_json(&w))
                )),
            },
            Yaml::String(x) => {
                let want = (self.substitute)(x);
                match a {
                    Some(Value::String(s)) if *s == want => Ok(()),
                    _ => fail(format!("expected {want:?}")),
                }
            }
            Yaml::Null => match a {
                Some(Value::Null) => Ok(()),
                _ => fail("expected null".into()),
            },
            Yaml::Boolean(b) => match a {
                Some(Value::Bool(x)) if x == b => Ok(()),
                _ => fail(format!("expected {b}")),
            },
            Yaml::Integer(i) => match a {
                Some(Value::Int64(x)) if x == i => Ok(()),
                _ => fail(format!("expected int64 {i}")),
            },
            Yaml::Real(r) => {
                let want: f64 = r.parse().unwrap_or(f64::NAN);
                match a {
                    Some(Value::Float64(x))
                        if (x.is_nan() && want.is_nan()) || x.to_bits() == want.to_bits() =>
                    {
                        Ok(())
                    }
                    _ => fail(format!("expected float64 {r}")),
                }
            }
            Yaml::Array(list) => {
                let Some(Value::Array(arr)) = a else {
                    return fail(format!("expected an array of {}", list.len()));
                };
                if arr.len() != list.len() {
                    return fail(format!("expected an array of {}", list.len()));
                }
                for (i, (x, y)) in list.iter().zip(arr).enumerate() {
                    self.why(x, Some(y), mode, &format!("{at}[{i}]"))?;
                }
                Ok(())
            }
            Yaml::Hash(h) => {
                if h.len() == 1 && e.has("$$type") {
                    let want = e.str_("$$type");
                    return if a.is_some_and(|v| type_name(v) == want) {
                        Ok(())
                    } else {
                        fail(format!("expected type {want}"))
                    };
                }
                if is_wrapper(e) {
                    let want = to_value(e, &|s| Value::String(s.to_owned()));
                    return if a == Some(&want) {
                        Ok(())
                    } else {
                        fail(format!("expected {}", value_json(&want)))
                    };
                }
                let Some(Value::Object(d)) = a else {
                    return fail("expected a document".into());
                };
                let keys = e.keys();
                let names: Vec<&str> = d
                    .iter()
                    .map(|(n, _)| n)
                    .filter(|n| !SYSTEM_FIELDS.contains(n) || keys.contains(n))
                    .collect();
                for k in &keys {
                    let Some(av) = d.get(k) else {
                        return fail(format!("missing field '{k}'"));
                    };
                    self.why(e.get(k), Some(av), mode, &format!("{at}.{k}"))?;
                }
                if !mode.subset && names.len() != keys.len() {
                    return fail("unexpected fields".into());
                }
                if mode.field_order && !mode.subset && names != keys {
                    return fail(format!(
                        "field order {} instead of {}",
                        names.join(","),
                        keys.join(",")
                    ));
                }
                Ok(())
            }
            _ => Err(format!("{at}: unsupported expectation {e:?}")),
        }
    }
}

/// Carries a failed expectation out of a transaction callback (an application error the
/// driver propagates unchanged).
struct FailCarrier(Mutex<Option<Fail>>);

impl std::fmt::Debug for FailCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FailCarrier")
    }
}

impl std::fmt::Display for FailCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.lock().ok().as_deref().and_then(Option::as_ref) {
            Some(x) => f.write_str(&x.0),
            None => f.write_str("failed expectation"),
        }
    }
}

impl std::error::Error for FailCarrier {}

#[derive(Clone, Copy)]
pub struct Mode {
    pub subset: bool,
    pub ordered: bool,
    pub field_order: bool,
}

fn count(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn counts(u: &UpdateResult) -> Value {
    let mut d = rustegon::doc! { "matchedCount" => count(u.matched_count), "modifiedCount" => count(u.modified_count) };
    if let Some(id) = &u.upserted_id {
        d.insert("upsertedId", id.clone());
    }
    Value::Object(d)
}

async fn drain(mut c: Cursor) -> Res<Out> {
    let rows = c.to_list().await;
    let _ = c.close().await;
    Ok(Out::Value(Value::Array(
        rows?.into_iter().map(Value::Object).collect(),
    )))
}

pub fn txn_options(args: &Yaml) -> TransactionOptions {
    let o = args.get("options");
    let mut t = TransactionOptions::new().read_only(o.is_true("readOnly"));
    match o.str_("isolation") {
        "serializable" => t = t.isolation(Isolation::Serializable),
        "snapshot" => t = t.isolation(Isolation::Snapshot),
        "read_committed" => t = t.isolation(Isolation::ReadCommitted),
        _ => {}
    }
    if let Some(ms) = o.int("maxRetryTimeMs") {
        t = t.max_retry_time(Duration::from_millis(u64::try_from(ms).unwrap_or(0)));
    }
    t
}

pub fn validator_of(v: &Yaml) -> Validator {
    Validator {
        json_schema: to_json(v.get("jsonSchema")),
        level: match v.str_("level") {
            "off" => Some(ValidationLevel::Off),
            "strict" => Some(ValidationLevel::Strict),
            "moderate" => Some(ValidationLevel::Moderate),
            _ => None,
        },
        action: match v.str_("action") {
            "error" => Some(ValidationAction::Error),
            "warn" => Some(ValidationAction::Warn),
            _ => None,
        },
    }
}

/// The class id of an error (errors-map.yaml, plus `Argument` / `InvalidState`).
fn class_id(e: &Error) -> &'static str {
    match e {
        Error::Rustegon(r) => r.class.id(),
        Error::Argument(_) => "Argument",
        Error::InvalidState(_) => "InvalidState",
        Error::Application(_) => "ApplicationError",
        _ => "Unknown",
    }
}

fn error_json(e: &Error) -> String {
    if is_application(e) {
        return "{\"applicationError\":true}".into();
    }
    match e.rustegon() {
        Some(r) => format!(
            "{{\"code\":{},\"exception\":\"{}\",\"retryable\":{}}}",
            r.code,
            r.class.id(),
            r.retryable
        ),
        None => format!("{{\"exception\":\"{}\"}}", class_id(e)),
    }
}

fn check_error(label: &str, expected: &Yaml, e: &Error) -> Result<(), String> {
    let require = |ok: bool, what: String| -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            Err(format!("{label}: {what}; got {e}"))
        }
    };
    if expected.is_true("applicationError") {
        return require(
            is_application(e),
            "expected the application's error unchanged".into(),
        );
    }
    let cls = expected.str_("exception");
    if !cls.is_empty() {
        let ok = match cls {
            "Argument" => matches!(e, Error::Argument(_)),
            "InvalidState" => matches!(e, Error::InvalidState(_)),
            _ => {
                let Some(c) = ErrorClass::ALL.iter().find(|c| c.id() == cls) else {
                    return Err(format!("unknown exception class id {cls}"));
                };
                e.is(*c)
            }
        };
        require(ok, format!("expected an instance of {cls}"))?;
    }
    let r = e.rustegon();
    if let Some(code) = expected.int("code") {
        require(
            r.is_some_and(|r| i64::from(r.code) == code),
            format!("expected code {code}"),
        )?;
    }
    let n = expected.str_("name");
    if !n.is_empty() {
        require(r.is_some_and(|r| r.name == n), format!("expected name {n}"))?;
    }
    if let Some(b) = expected.get("retryable").as_bool() {
        require(
            r.is_some_and(|r| r.retryable == b),
            format!("expected retryable {b}"),
        )?;
    }
    if let Some(b) = expected.get("committed").as_bool() {
        require(
            r.is_some_and(|r| r.committed == Some(b)),
            format!("expected committed {b}"),
        )?;
    }
    Ok(())
}

/// data-model §2 type names.
fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Int64(_) => "int64",
        Value::Float64(_) => "float64",
        Value::Decimal(_) => "decimal128",
        Value::String(_) => "string",
        Value::Binary { .. } => "binary",
        Value::DateTime(_) => "datetime",
        Value::Timestamp(_) => "timestamp",
        Value::ObjectId(_) => "objectId",
        Value::Uuid(_) => "uuid",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::VectorF32(_) => "vector_f32",
        Value::Counter(_) => "counter",
        Value::MinKey => "minKey",
        Value::MaxKey => "maxKey",
    }
}

pub fn value_json(v: &Value) -> String {
    json::value_to_json(v, JsonMode::Canonical)
}

// ------------------------------------------------------------------------- normalisation (§6)

pub struct Normalizer {
    test_text: String,
    oids: HashMap<String, String>,
}

impl Normalizer {
    pub fn new(text: &str) -> Self {
        Self {
            test_text: text.to_lowercase(),
            oids: HashMap::new(),
        }
    }

    pub fn json(&mut self, v: &Value) -> String {
        let n = self.normalize(v);
        value_json(&n)
    }

    fn normalize(&mut self, v: &Value) -> Value {
        match v {
            Value::ObjectId(o) => {
                let hex = o.to_string();
                if self.test_text.contains(&hex) {
                    return v.clone();
                }
                let next = self.oids.len() + 1;
                Value::String(
                    self.oids
                        .entry(hex)
                        .or_insert_with(|| format!("<oid:{next}>"))
                        .clone(),
                )
            }
            Value::DateTime(_) => {
                let text = value_json(v);
                // {"$date":"<iso>"} → <iso>
                let iso = text
                    .split_once(":\"")
                    .map(|(_, r)| r.trim_end_matches("\"}"))
                    .unwrap_or("")
                    .to_lowercase();
                if !iso.is_empty() && self.test_text.contains(&iso) {
                    v.clone()
                } else {
                    Value::String("<datetime>".into())
                }
            }
            Value::Array(a) => Value::Array(a.iter().map(|e| self.normalize(e)).collect()),
            Value::Object(d) => {
                let mut fields: Vec<(&str, &Value)> = d.iter().collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = Document::new();
                for (n, x) in fields {
                    // System fields are always removed from observations (README §6).
                    if !SYSTEM_FIELDS.contains(&n) {
                        let nv = self.normalize(x);
                        out.insert(n, nv);
                    }
                }
                Value::Object(out)
            }
            _ => v.clone(),
        }
    }
}

/// `{"<coll>": [...], …}` with sorted keys from already-normalised parts.
pub fn outcome_json(parts: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = parts.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let body: Vec<String> = sorted
        .iter()
        .map(|(k, v)| format!("{}:{v}", json_string(k)))
        .collect();
    format!("{{{}}}", body.join(","))
}
