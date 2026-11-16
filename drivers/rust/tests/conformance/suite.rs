// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The shared conformance suite (TC-DRV-RS-020, FR-DRV-003/005, AC-DRV-003/005): every test of
//! `drivers/conformance/<category>/*.yaml`, with the fixture lifecycle of README §5 (PD-072), and
//! the results file of README §6 (`RUSTEGON_CONFORMANCE_RESULTS`, default
//! `drivers/rust/conformance-results.json`).

use std::{collections::BTreeMap, path::PathBuf};

use rustegon::{
    Client, Credential, Document, Filter, Settings, Sort, TlsSettings, Value,
    pb::{self, admin_service_client::AdminServiceClient, auth_service_client::AuthServiceClient},
};

use crate::{
    checks,
    dsl::keys_of,
    fake,
    fixture::{self, ADMIN_USER, CLIENT_CERT_USER, Server},
    runner::{Mode, Normalizer, Outcome, Run, outcome_json, validator_of},
    yaml::{self, Y, Yaml, conformance_dir, json_string, plain, to_document},
};

const CATEGORIES: [&str; 9] = [
    "crud", "query", "cursor", "bulk", "txn", "errors", "schema", "auth", "client",
];

struct Entry {
    status: &'static str,
    reason: Option<String>,
    observations: Vec<String>,
    outcome: Option<String>,
}

pub struct Results {
    entries: BTreeMap<String, Entry>,
    server_version: String,
}

impl Results {
    fn path() -> PathBuf {
        std::env::var_os("RUSTEGON_CONFORMANCE_RESULTS").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-results.json"),
            PathBuf::from,
        )
    }

    fn write(&self) {
        let mut out = String::new();
        out.push_str(&format!(
            "{{\"driver\":\"rust\",\"driverVersion\":{},\"serverVersion\":{},\"results\":[",
            json_string(rustegon::VERSION),
            json_string(&self.server_version)
        ));
        for (i, (id, e)) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "\n  {{\"id\":{},\"status\":\"{}\"",
                json_string(id),
                e.status
            ));
            if let Some(r) = &e.reason {
                out.push_str(&format!(",\"reason\":{}", json_string(r)));
            }
            out.push_str(&format!(",\"observations\":[{}]", e.observations.join(",")));
            if let Some(o) = &e.outcome {
                out.push_str(&format!(",\"outcome\":{o}"));
            }
            out.push('}');
        }
        out.push_str("\n]}\n");
        // Pretty enough for review; the comparison re-serializes it (driver_results.rs).
        if let Err(e) = std::fs::write(Self::path(), out) {
            eprintln!("cannot write the results file: {e}");
        }
    }
}

/// Per file: a fresh database and an admin client (README §5 lifecycle).
struct FileContext {
    database: String,
    client: Client,
}

fn admin_settings(s: &Server, database: &str) -> Settings {
    let mut b = Settings::builder()
        .endpoints([s.grpc.clone()])
        .credential(Credential::scram(ADMIN_USER, s.admin_password.clone()))
        .application_name("rustegon-rust-tests")
        .default_database(database);
    if s.tls() {
        b = b.tls(TlsSettings {
            enabled: true,
            ca_file: Some(s.ca_file()),
            ..TlsSettings::default()
        });
    }
    b.build().expect("admin settings")
}

/// An admin-service call with the client's authentication.
macro_rules! admin {
    ($client:expr, $svc:ident, $method:ident, $req:expr) => {{
        let req = $req;
        $client
            .admin(|ch, md| {
                let mut r = tonic::Request::new(req.clone());
                *r.metadata_mut() = md;
                async move { $svc::new(ch).$method(r).await }
            })
            .await
    }};
}

fn grant(r: &str) -> pb::RoleGrant {
    match r.split_once('@') {
        None => pb::RoleGrant {
            role: r.to_owned(),
            resource: String::new(),
        },
        Some((role, scope)) => pb::RoleGrant {
            role: role.to_owned(),
            resource: format!(
                "{}{scope}",
                if scope.contains('.') {
                    "collection:"
                } else {
                    "database:"
                }
            ),
        },
    }
}

/// `encodeURIComponent`-style escaping (RFC 3986 unreserved kept), as .NET `EscapeDataString`.
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// TC-DRV-RS-020: runs the whole suite; returns `(passed, failed, skipped, failures)`.
pub async fn run_suite() -> (usize, usize, usize, Vec<String>) {
    let mut results = Results {
        entries: BTreeMap::new(),
        server_version: String::new(),
    };
    let node = fixture::shared_tls();
    let server = node.as_deref().map_err(Clone::clone);
    let mut contexts: BTreeMap<String, FileContext> = BTreeMap::new();
    let mut api_key: Option<String> = None;
    let mut failures = Vec::new();
    for category in CATEGORIES {
        let mut files: Vec<PathBuf> = std::fs::read_dir(conformance_dir().join(category))
            .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        files.retain(|p| p.extension().is_some_and(|e| e == "yaml"));
        files.sort();
        for path in files {
            let file = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let relative = format!("{category}/{file}");
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let root = yaml::parse(&text).unwrap_or_else(|e| panic!("{relative}: {e}"));
            for test in root.list("tests") {
                let id = test.str_("id").to_owned();
                let entry = run_test(
                    &relative,
                    &root,
                    test,
                    &text,
                    server.clone(),
                    &mut contexts,
                    &mut api_key,
                    &mut results.server_version,
                )
                .await;
                if entry.status == "failed" {
                    failures.push(format!(
                        "{id}: {}",
                        entry.reason.clone().unwrap_or_default()
                    ));
                }
                results.entries.insert(id, entry);
                results.write();
            }
        }
    }
    for (_, f) in contexts {
        let _ = f.client.drop_database(&f.database).if_exists(true).await;
        f.client.close().await;
    }
    let count = |s: &str| results.entries.values().filter(|e| e.status == s).count();
    (count("passed"), count("failed"), count("skipped"), failures)
}

#[allow(clippy::too_many_arguments)]
async fn run_test(
    relative: &str,
    root: &Yaml,
    test: &Yaml,
    text: &str,
    server: Result<&Server, String>,
    contexts: &mut BTreeMap<String, FileContext>,
    api_key: &mut Option<String>,
    server_version: &mut String,
) -> Entry {
    let setup = if test.has("setup") {
        test.get("setup")
    } else {
        root.get("setup")
    };
    let ops = test.list("operations");
    let unit_level = setup.is_badvalue() && ops.iter().all(|o| o.str_("object") == "runner");
    let skipped = |reason: String| Entry {
        status: "skipped",
        reason: Some(reason),
        observations: Vec::new(),
        outcome: None,
    };
    let r = if unit_level {
        run_unit_level(ops, text).await.map(|o| (o, None))
    } else {
        let s = match server {
            Ok(s) => s,
            Err(reason) => {
                fixture::skip_or_fail(&reason);
                return skipped(format!("no server binaries (RUSTEGON_BIN_DIR): {reason}"));
            }
        };
        run_with_server(
            relative,
            test,
            setup,
            ops,
            text,
            s,
            contexts,
            api_key,
            server_version,
        )
        .await
    };
    match r {
        Ok((observations, outcome)) => Entry {
            status: "passed",
            reason: None,
            observations,
            outcome,
        },
        Err(reason) => Entry {
            status: "failed",
            reason: Some(reason),
            observations: Vec::new(),
            outcome: None,
        },
    }
}

/// Runner operations that need no server (README §7).
pub fn runner_checks(name: &str, args: &Yaml) -> Option<Result<(), String>> {
    let file = args.str_("file");
    Some(match name {
        "checkErrorMapping" => checks::error_mapping(file),
        "checkValueVectors" | "checkDocumentVectors" | "checkInvalidVectors" => {
            checks::codec_vectors(file)
        }
        "checkAstVectors" => checks::ast_vectors(file),
        "checkConnectionStrings" => checks::connection_strings(file),
        "checkScramVectors" => checks::scram_vectors(file),
        // Needs its own async context: run on a helper thread with its own runtime.
        "runRetryScenarios" => {
            let file = file.to_owned();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(fake::retry_scenarios(&file, None))
            })
            .join()
            .unwrap_or_else(|_| Err("retry scenarios panicked".into()))
        }
        _ => return None,
    })
}

async fn run_unit_level(ops: &[Yaml], text: &str) -> Result<Vec<String>, String> {
    // Runner operations need no server; the run still needs a client object, never used.
    let client = Client::new(
        Settings::builder()
            .endpoints(["unused.invalid:7700"])
            .build()
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let identity = |s: &str| s.to_owned();
    let mut run = Run::new(client, "unused", "", &identity, text);
    run.runner_ext = Some(Box::new(runner_checks));
    let r = run.run_ops(ops, true).await;
    run.close().await;
    r.map_err(describe)?;
    Ok(run.observations.take())
}

fn describe(o: Outcome) -> String {
    match o {
        Outcome::Fail(f) => f.0,
        Outcome::Driver(e) => format!("unexpected error: {e}"),
    }
}

async fn file_context<'c>(
    relative: &str,
    s: &Server,
    contexts: &'c mut BTreeMap<String, FileContext>,
) -> Result<&'c FileContext, String> {
    if !contexts.contains_key(relative) {
        let (category, file) = relative.split_once('/').unwrap_or(("x", relative));
        let stem = file.trim_end_matches(".yaml").replace('-', "_");
        let mut tag = [0u8; 4];
        getrandom::fill(&mut tag).map_err(|e| e.to_string())?;
        let database = format!("conf_{category}_{stem}_{}", rustegon::codec::to_hex(&tag));
        let client = Client::new(admin_settings(s, &database)).map_err(|e| e.to_string())?;
        client
            .create_database(&database)
            .await
            .map_err(|e| format!("create database: {e}"))?;
        contexts.insert(relative.to_owned(), FileContext { database, client });
    }
    contexts.get(relative).ok_or_else(|| "no context".into())
}

async fn fixture_api_key(c: &Client, api_key: &mut Option<String>) -> Result<String, String> {
    if let Some(k) = api_key {
        return Ok(k.clone());
    }
    let who =
        admin!(c, AuthServiceClient, who_am_i, pb::WhoAmIRequest {}).map_err(|e| e.to_string())?;
    let created = admin!(
        c,
        AdminServiceClient,
        create_api_key,
        pb::CreateApiKeyRequest {
            description: "rust conformance runner".into(),
            roles: who.roles,
            ..Default::default()
        }
    )
    .map_err(|e| e.to_string())?;
    *api_key = Some(created.secret.clone());
    Ok(created.secret)
}

#[allow(clippy::too_many_arguments)]
async fn run_with_server(
    relative: &str,
    test: &Yaml,
    setup: &Yaml,
    ops: &[Yaml],
    text: &str,
    s: &Server,
    contexts: &mut BTreeMap<String, FileContext>,
    api_key: &mut Option<String>,
    server_version: &mut String,
) -> Result<(Vec<String>, Option<String>), String> {
    let requires: Vec<&str> = test
        .list("requires")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    let key = {
        let f = file_context(relative, s, contexts).await?;
        if server_version.is_empty()
            && let Ok(i) = f.client.server_info().await
        {
            *server_version = i.server_version;
        }
        if requires.contains(&"api-key") {
            fixture_api_key(&f.client, api_key).await?
        } else {
            String::new()
        }
    };
    let f = contexts.get(relative).ok_or("no context")?;
    let (host, port) = s.grpc.rsplit_once(':').unwrap_or((&s.grpc, "7700"));
    let ca = s.ca_file().to_string_lossy().into_owned();
    let subs: Vec<(&str, String)> = vec![
        ("${database}", f.database.clone()),
        ("${host}", host.to_owned()),
        ("${port}", port.to_owned()),
        ("${adminUserEncoded}", escape(ADMIN_USER)),
        ("${adminPasswordEncoded}", escape(&s.admin_password)),
        ("${adminUser}", ADMIN_USER.to_owned()),
        ("${adminPassword}", s.admin_password.clone()),
        ("${caFileEncoded}", escape(&ca)),
        ("${caFile}", ca),
        ("${apiKey}", key),
        (
            "${clientCertFile}",
            s.client_cert_file().to_string_lossy().into_owned(),
        ),
        (
            "${clientKeyFile}",
            s.client_key_file().to_string_lossy().into_owned(),
        ),
    ];
    let substitute = move |x: &str| {
        let mut out = x.to_owned();
        for (k, v) in &subs {
            out = out.replace(k, v);
        }
        out
    };
    let mut users = Vec::new();
    let first = setup_test(
        f,
        setup,
        &mut users,
        requires.contains(&"x509-client-cert"),
        &substitute,
    )
    .await;
    let result = match first {
        Err(e) => Err(format!("setup: {e}")),
        Ok(first) => {
            let mut run = Run::new(f.client.clone(), &f.database, &first, &substitute, text);
            run.runner_ext = Some(Box::new(runner_checks));
            let database = f.database.clone();
            let sub = &substitute;
            run.open_client = Some(Box::new(move |args: &Yaml| {
                open_fixture_client(s, &database, args, sub).map_err(Outcome::Driver)
            }));
            let r = run.run_ops(ops, true).await;
            let out = match r {
                Err(o) => Err(describe(o)),
                Ok(()) if test.has("outcome") => check_outcome(f, &run, test.get("outcome"), text)
                    .await
                    .map(Some),
                Ok(()) => Ok(None),
            };
            run.close().await;
            out.map(|o| (run.observations.take(), o))
        }
    };
    for u in users {
        let _ = admin!(
            f.client,
            AdminServiceClient,
            drop_user,
            pb::DropUserRequest { name: u }
        );
    }
    result
}

async fn setup_test(
    f: &FileContext,
    setup: &Yaml,
    users: &mut Vec<String>,
    x509: bool,
    substitute: &dyn Fn(&str) -> String,
) -> Result<String, String> {
    let db = f.client.database(&f.database);
    for n in db
        .list_collection_names()
        .await
        .map_err(|e| e.to_string())?
    {
        db.drop_collection(&n)
            .if_exists(true)
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut first = String::new();
    for c in setup.list("collections") {
        if first.is_empty() {
            first = c.str_("name").to_owned();
        }
        let mut a = db.create_collection(c.str_("name"));
        if c.has("validator") {
            a = a.validator(validator_of(c.get("validator")));
        }
        a.await.map_err(|e| e.to_string())?;
    }
    for i in setup.list("indexes") {
        let d = db
            .collection(i.str_("collection"))
            .create_index(i.str_("name"), keys_of(i.list("keys")))
            .unique(i.is_true("unique"))
            .await
            .map_err(|e| e.to_string())?;
        if d.state != rustegon::IndexState::Ready {
            return Err(format!("index {} is {}", d.name, d.state.as_str()));
        }
    }
    let data = setup.get("data");
    for coll in data.keys() {
        let docs: Vec<Document> = data
            .list(coll)
            .iter()
            .map(|d| to_document(d, &plain))
            .collect();
        if !docs.is_empty() {
            db.collection(coll)
                .insert_many(docs)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    for u in setup.list("users") {
        let req = pb::CreateUserRequest {
            name: u.str_("name").to_owned(),
            password: Some(u.str_("password").to_owned()),
            roles: u
                .list("roles")
                .iter()
                .filter_map(Yaml::as_str)
                .map(|r| grant(&substitute(r)))
                .collect(),
            must_change_password: u.is_true("mustChangePassword"),
            x509_subject: None,
        };
        admin!(f.client, AdminServiceClient, create_user, req).map_err(|e| e.to_string())?;
        users.push(u.str_("name").to_owned());
    }
    if x509 {
        // README §5: the init client certificate maps to a user with read_write@${database}.
        let name = format!("x509:CN={CLIENT_CERT_USER}");
        let req = pb::CreateUserRequest {
            name: name.clone(),
            password: None,
            roles: vec![grant(&format!("read_write@{}", f.database))],
            must_change_password: false,
            x509_subject: None,
        };
        admin!(f.client, AdminServiceClient, create_user, req).map_err(|e| e.to_string())?;
        users.push(name);
    }
    Ok(first)
}

fn open_fixture_client(
    s: &Server,
    database: &str,
    args: &Yaml,
    substitute: &dyn Fn(&str) -> String,
) -> rustegon::Result<Client> {
    let cred = args.get("credential");
    let mut tls = TlsSettings {
        enabled: s.tls(),
        ca_file: s.tls().then(|| s.ca_file()),
        ..TlsSettings::default()
    };
    let credential = if cred.has("scram") {
        let sc = cred.get("scram");
        Credential::scram(substitute(sc.str_("user")), substitute(sc.str_("password")))
    } else if cred.has("apiKey") {
        Credential::api_key(substitute(cred.str_("apiKey")))
    } else {
        let x = cred.get("x509");
        tls.certificate_file = Some(substitute(x.str_("certificateFile")).into());
        tls.key_file = Some(substitute(x.str_("keyFile")).into());
        Credential::x509()
    };
    Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .default_database(database)
            .application_name("rustegon-rust-tests")
            .allow_password_change_only(args.is_true("allowPasswordChangeOnly"))
            .credential(credential)
            .tls(tls)
            .build()?,
    )
}

async fn check_outcome(
    f: &FileContext,
    run: &Run<'_>,
    expected: &Yaml,
    text: &str,
) -> Result<String, String> {
    // A fresh normaliser for the outcome (as the .NET and Go runners): tokens restart at 1.
    let mut n = Normalizer::new(text);
    let mut parts = Vec::new();
    for coll in expected.keys() {
        let docs = f
            .client
            .database(&f.database)
            .collection(coll)
            .find(Filter::empty())
            .sort(Sort::asc("_id"))
            .to_list()
            .await
            .map_err(|e| e.to_string())?;
        let arr = Value::Array(docs.into_iter().map(Value::Object).collect());
        let mode = Mode {
            subset: false,
            ordered: true,
            field_order: false,
        };
        run.result(expected.get(coll), &arr, mode)
            .map_err(|w| format!("outcome of {coll}: {w}"))?;
        parts.push((coll.to_owned(), n.json(&arr)));
    }
    Ok(outcome_json(&parts))
}
