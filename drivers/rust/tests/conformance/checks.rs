// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Runner operations that need no server (README §7): codec, SCRAM, connection-string,
//! error-mapping and AST vectors.

use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage};
use rustegon::{
    __conformance::{
        ParamSink, catalog, delete_statement, error_from_detail, error_from_transport,
        find_statement, name_of, update_statement,
    },
    Error, ErrorClass, Projection, Settings, Sort, Update,
    codec::{
        from_hex,
        json::{self, JsonMode},
        rdoc, to_hex,
    },
    pb,
    scram::{ScramClient, saslprep},
};

use crate::{
    dsl::{dsl_filter, dsl_update, projection_of, sort_of},
    yaml::{Y, Yaml, load, plain, to_document, to_json},
};

type R = Result<(), String>;

fn hex_of(s: &str) -> Vec<u8> {
    from_hex(s).unwrap_or_else(|| b"<bad hex in vector file>".to_vec())
}

fn eq(what: &str, want: &str, got: &str) -> R {
    if want == got {
        Ok(())
    } else {
        Err(format!("{what}: want {want}, got {got}"))
    }
}

// ------------------------------------------------------------------------- codec (TC-DRV-RS-001)

/// `checkValueVectors` / `checkDocumentVectors` / `checkInvalidVectors`.
pub fn codec_vectors(file: &str) -> R {
    let f = load(file);
    let mut n = 0;
    let base = file.rsplit('/').next().unwrap_or(file);
    let tag = |section: &str, e: &Yaml, r: R| {
        r.map_err(|m| format!("{file}#{section}/{}: {m}", e.str_("name")))
    };
    match base {
        "values.yaml" => {
            for e in f.list("values") {
                tag("values", e, value_vector(e))?;
                n += 1;
            }
            for e in f.list("noncanonical") {
                tag("noncanonical", e, noncanonical(e, false))?;
                n += 1;
            }
        }
        "documents.yaml" => {
            for e in f.list("documents") {
                tag("documents", e, document_vector(e))?;
                n += 1;
            }
            for e in f.list("noncanonical") {
                tag("noncanonical", e, noncanonical(e, true))?;
                n += 1;
            }
        }
        "invalid.yaml" => {
            for e in f.list("documents") {
                tag(
                    "documents",
                    e,
                    rejected(e, rdoc::decode(&hex_of(e.str_("hex"))).err()),
                )?;
                n += 1;
            }
            for e in f.list("values") {
                tag(
                    "values",
                    e,
                    rejected(e, rdoc::decode_value(&hex_of(e.str_("hex"))).err()),
                )?;
                n += 1;
            }
            for e in f.list("json") {
                let err = match e.str_("kind") {
                    "document" => json::parse_document(e.str_("json")).err(),
                    _ => json::parse_value(e.str_("json")).err(),
                };
                tag("json", e, rejected(e, err))?;
                n += 1;
            }
        }
        _ => return Err(format!("no codec check for {file}")),
    }
    if n == 0 {
        return Err(format!("{file}: no vectors"));
    }
    Ok(())
}

fn rejected(e: &Yaml, err: Option<rustegon::codec::DocError>) -> R {
    let Some(err) = err else {
        return Err("accepted".into());
    };
    let want = e.int("code").unwrap_or(0);
    if i64::from(err.code()) != want {
        return Err(format!("code {} instead of {want}", err.code()));
    }
    Ok(())
}

fn value_vector(e: &Yaml) -> R {
    if !e.is_true("decode_only") {
        let input = json::parse_value(e.str_("input")).map_err(|x| format!("parse input: {x}"))?;
        let ext =
            json::parse_value(e.str_("ext_json")).map_err(|x| format!("parse ext_json: {x}"))?;
        if input != ext {
            return Err("input and ext_json parse to different values".into());
        }
        for text in [e.str_("input"), e.str_("ext_json"), e.str_("extended_json")] {
            let v = json::parse_value(text).map_err(|x| format!("parse {text}: {x}"))?;
            let b = rdoc::encode_value(&v).map_err(|x| format!("encode {text}: {x}"))?;
            eq(&format!("encode {text}"), e.str_("hex"), &to_hex(&b))?;
        }
    }
    let v = rdoc::decode_value(&hex_of(e.str_("hex"))).map_err(|x| format!("decode: {x}"))?;
    eq(
        "ext_json",
        e.str_("ext_json"),
        &json::value_to_json(&v, JsonMode::Canonical),
    )?;
    eq(
        "extended_json",
        e.str_("extended_json"),
        &json::value_to_json(&v, JsonMode::Extended),
    )
}

fn document_vector(e: &Yaml) -> R {
    if !e.is_true("decode_only") {
        let d = json::parse_document(e.str_("ext_json")).map_err(|x| format!("parse: {x}"))?;
        let b = rdoc::encode(&d).map_err(|x| format!("encode: {x}"))?;
        eq("encode", e.str_("hex"), &to_hex(&b))?;
    }
    let d = rdoc::decode(&hex_of(e.str_("hex"))).map_err(|x| format!("decode: {x}"))?;
    eq(
        "ext_json",
        e.str_("ext_json"),
        &json::to_json(&d, JsonMode::Canonical),
    )?;
    for h in e.list("name_hash16") {
        let got = format!("{:04x}", rdoc::name_hash16(h.str_("name").as_bytes()));
        eq(
            &format!("name_hash16({})", h.str_("name")),
            h.str_("hash"),
            &got,
        )?;
    }
    Ok(())
}

fn noncanonical(e: &Yaml, document: bool) -> R {
    let bytes = hex_of(e.str_("hex"));
    let (json_text, again) = if document {
        let d = rdoc::decode(&bytes).map_err(|x| format!("decode: {x}"))?;
        (json::to_json(&d, JsonMode::Canonical), rdoc::encode(&d))
    } else {
        let v = rdoc::decode_value(&bytes).map_err(|x| format!("decode: {x}"))?;
        (
            json::value_to_json(&v, JsonMode::Canonical),
            rdoc::encode_value(&v),
        )
    };
    eq("ext_json", e.str_("ext_json"), &json_text)?;
    let again = again.map_err(|x| format!("re-encode: {x}"))?;
    eq("canonical_hex", e.str_("canonical_hex"), &to_hex(&again))
}

// -------------------------------------------------------------------------- SCRAM (TC-DRV-RS-003)

/// `checkScramVectors`.
pub fn scram_vectors(file: &str) -> R {
    let f = load(file);
    for c in f.list("saslprep") {
        let got = saslprep(c.str_("input"));
        match (c.is_true("error"), got) {
            (true, Ok(o)) => return Err(format!("saslprep {}: accepted as {o:?}", c.str_("name"))),
            (false, Err(_)) => return Err(format!("saslprep {}: refused", c.str_("name"))),
            (false, Ok(o)) => eq(
                &format!("saslprep {}", c.str_("name")),
                c.str_("output"),
                &o,
            )?,
            (true, Err(_)) => {}
        }
    }
    for x in f.list("exchanges") {
        let name = x.str_("name");
        let (c, first) =
            ScramClient::with_nonce(x.str_("user"), x.str_("password"), x.str_("clientNonce"))
                .map_err(|e| format!("{name}: {e:?}"))?;
        eq(
            &format!("{name} clientFirst"),
            x.str_("clientFirst"),
            &first,
        )?;
        let (fin, client_final) = c
            .server_first(x.str_("serverFirst"))
            .map_err(|e| format!("{name}: {e:?}"))?;
        eq(
            &format!("{name} clientFinal"),
            x.str_("clientFinal"),
            &client_final,
        )?;
        let server_final = x.str_("serverFinal");
        // A copy with one character changed must be rejected (the exchange is re-run because
        // the final state is consumed).
        let mut tampered: Vec<char> = server_final.chars().collect();
        if let Some(ch) = tampered.get_mut(4) {
            *ch = if *ch == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = tampered.into_iter().collect();
        fin.server_final(server_final)
            .map_err(|e| format!("{name}: serverFinal refused: {e:?}"))?;
        let (c2, _) =
            ScramClient::with_nonce(x.str_("user"), x.str_("password"), x.str_("clientNonce"))
                .map_err(|e| format!("{name}: {e:?}"))?;
        let (fin2, _) = c2
            .server_first(x.str_("serverFirst"))
            .map_err(|e| format!("{e:?}"))?;
        if fin2.server_final(&tampered).is_ok() {
            return Err(format!("{name}: a tampered serverFinal was accepted"));
        }
    }
    Ok(())
}

// -------------------------------------------------------------- connection strings (TC-DRV-RS-005)

fn settings_model(s: &Settings) -> serde_json::Value {
    use serde_json::{Value as J, json};
    let opt = |v: Option<&str>| v.map_or(J::Null, |s| J::String(s.to_owned()));
    let path = |p: &Option<std::path::PathBuf>| {
        p.as_ref()
            .map_or(J::Null, |p| J::String(p.to_string_lossy().into_owned()))
    };
    let hosts: Vec<J> = s
        .endpoints
        .iter()
        .map(|e| {
            let (h, p) = e.rsplit_once(':').unwrap_or((e, "7700"));
            json!({"host": h.trim_start_matches('[').trim_end_matches(']'), "port": p.parse::<i64>().unwrap_or(0)})
        })
        .collect();
    let (user, password) = match &s.credential {
        Some(c) => (
            opt(c.user()),
            if c.mechanism() == rustegon::AuthMechanism::ScramSha256 {
                opt(c.secret())
            } else {
                J::Null
            },
        ),
        None => (J::Null, J::Null),
    };
    json!({
        "hosts": hosts, "user": user, "password": password,
        "database": opt(s.default_database.as_deref()),
        "tls": s.tls_enabled(), "tlsCaFile": path(&s.tls.ca_file),
        "tlsServerName": opt(s.tls.server_name.as_deref()),
        "tlsCertificateFile": path(&s.tls.certificate_file), "tlsKeyFile": path(&s.tls.key_file),
        "authMechanism": s.auth_mechanism().map_or(J::Null, |m| J::String(m.name().into())),
        "applicationName": opt(s.application_name.as_deref()),
        "connectTimeoutMs": i64::try_from(s.connect_timeout.as_millis()).unwrap_or(0),
        "operationTimeoutMs": i64::try_from(s.operation_timeout.as_millis()).unwrap_or(0),
        "readConsistency": s.read_consistency.map_or(J::Null, |r| J::String(match r {
            rustegon::ReadConsistency::Linearizable => "linearizable",
            rustegon::ReadConsistency::BoundedStaleness => "bounded_staleness",
            rustegon::ReadConsistency::Follower => "follower",
        }.into())),
        "maxStalenessMs": s.max_staleness.map_or(J::Null, |d| json!(i64::try_from(d.as_millis()).unwrap_or(0))),
        "writeConcern": s.write_concern.map_or(J::Null, |w| J::String(match w {
            rustegon::WriteConcern::Majority => "majority",
            rustegon::WriteConcern::All => "all",
        }.into())),
        "retryReads": s.retry_reads, "retryWrites": s.retry_writes,
        "maxRetries": s.max_retries, "connectionsPerEndpoint": s.connections_per_endpoint,
    })
}

/// `checkConnectionStrings`.
pub fn connection_strings(file: &str) -> R {
    let f = load(file);
    let defaults: serde_json::Value =
        serde_json::from_str(&to_json(f.get("defaults"))).map_err(|e| e.to_string())?;
    for c in f.list("cases") {
        let (name, uri) = (c.str_("name"), c.str_("uri"));
        let parsed = Settings::from_connection_string(uri);
        if !c.is_true("valid") {
            let err = match parsed {
                Ok(_) => return Err(format!("{name}: accepted an invalid string")),
                Err(e) => e,
            };
            if !matches!(err, Error::Argument(_)) {
                return Err(format!("{name}: not an argument error: {err}"));
            }
            if let Some((_, after)) = uri.split_once("://")
                && let Some(at) = after.rfind('@')
                && let Some((_, pw)) = after[..at].split_once(':')
                && pw.len() >= 4
                && err.to_string().contains(pw)
            {
                return Err(format!("{name}: the message quotes the password"));
            }
            continue;
        }
        let s = parsed.map_err(|e| format!("{name}: {e}"))?;
        let got = settings_model(&s);
        let mut want = defaults.clone();
        let expect: serde_json::Value =
            serde_json::from_str(&to_json(c.get("expect"))).map_err(|e| e.to_string())?;
        if let (Some(w), Some(x)) = (want.as_object_mut(), expect.as_object()) {
            for (k, v) in x {
                w.insert(k.clone(), v.clone());
            }
        }
        for (k, w) in want.as_object().into_iter().flatten() {
            if got.get(k) != Some(w) {
                return Err(format!("{name}: {k} = {:?}, expected {w}", got.get(k)));
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ error mapping (TC-DRV-RS-004)

fn grpc_code(name: &str) -> Option<tonic::Code> {
    use tonic::Code as C;
    Some(match name {
        "OK" => C::Ok,
        "CANCELLED" => C::Cancelled,
        "UNKNOWN" => C::Unknown,
        "INVALID_ARGUMENT" => C::InvalidArgument,
        "DEADLINE_EXCEEDED" => C::DeadlineExceeded,
        "NOT_FOUND" => C::NotFound,
        "ALREADY_EXISTS" => C::AlreadyExists,
        "PERMISSION_DENIED" => C::PermissionDenied,
        "RESOURCE_EXHAUSTED" => C::ResourceExhausted,
        "FAILED_PRECONDITION" => C::FailedPrecondition,
        "ABORTED" => C::Aborted,
        "OUT_OF_RANGE" => C::OutOfRange,
        "UNIMPLEMENTED" => C::Unimplemented,
        "INTERNAL" => C::Internal,
        "UNAVAILABLE" => C::Unavailable,
        "DATA_LOSS" => C::DataLoss,
        "UNAUTHENTICATED" => C::Unauthenticated,
        // `default`: a status no row names.
        _ => return None,
    })
}

/// The gRPC status code of a catalog code name (`grpc` column), for the fake server.
pub fn grpc_code_of(name: &str) -> tonic::Code {
    grpc_code(name).unwrap_or(tonic::Code::Unknown)
}

/// `checkErrorMapping` (`generated/errors.json`).
pub fn error_mapping(file: &str) -> R {
    let f = load(file);
    let codes = f.list("codes");
    if codes.len() != catalog().len() {
        return Err(format!(
            "the driver's catalog has {} codes, {file} {}",
            catalog().len(),
            codes.len()
        ));
    }
    for c in codes {
        let code = u32::try_from(c.int("code").unwrap_or(0)).unwrap_or(0);
        let d = pb::ErrorDetail {
            code,
            name: c.str_("name").into(),
            retryable: true,
            ..pb::ErrorDetail::default()
        };
        let e = error_from_detail(&d);
        let want = c.get("exception").str_("id");
        let got = e.class().map(ErrorClass::id).unwrap_or("");
        if got != want || e.code() != Some(code) || !e.is_retryable() {
            return Err(format!("code {code} maps to {got}, expected {want}"));
        }
        if name_of(code) != c.str_("name") {
            return Err(format!(
                "code {code} is named {}, expected {}",
                name_of(code),
                c.str_("name")
            ));
        }
    }
    let unknown = error_from_detail(&pb::ErrorDetail {
        code: 9999,
        ..pb::ErrorDetail::default()
    });
    if unknown.class().map(ErrorClass::id) != Some(f.get("unknown").str_("id"))
        || unknown.code() != Some(9999)
    {
        return Err("unknown code mapping".into());
    }
    for t in f.list("transport") {
        let code = grpc_code(t.str_("grpc")).unwrap_or(tonic::Code::DataLoss);
        let e = error_from_transport(code);
        let ok = e.code() == u32::try_from(t.int("code").unwrap_or(0)).ok()
            && e.is_retryable() == t.is_true("retryable")
            && e.class().map(ErrorClass::id) == Some(t.get("exception").str_("id"));
        if !ok {
            return Err(format!("transport {} maps to {e}", t.str_("grpc")));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------- AST (TC-DRV-RS-006)

fn pool() -> DescriptorPool {
    DescriptorPool::decode(pb::FILE_DESCRIPTOR_SET)
        .unwrap_or_else(|e| panic!("descriptor set: {e}"))
}

/// Protobuf JSON → message of type `name` → prost type `M`.
fn parse_pb<M: prost::Message + Default>(
    pool: &DescriptorPool,
    name: &str,
    y: &Yaml,
) -> Result<M, String> {
    let desc = pool
        .get_message_by_name(name)
        .ok_or_else(|| format!("no message {name}"))?;
    let text = to_json(y);
    let mut de = serde_json::Deserializer::from_str(&text);
    let dynamic = DynamicMessage::deserialize(desc, &mut de).map_err(|e| format!("{name}: {e}"))?;
    M::decode(dynamic.encode_to_vec().as_slice()).map_err(|e| e.to_string())
}

fn check_params(c: &Yaml, s: &ParamSink) -> R {
    let want = c.get("params");
    let mut want_keys: Vec<&str> = want.keys();
    let mut got_keys: Vec<&str> = s.params.keys().map(String::as_str).collect();
    want_keys.sort_unstable();
    got_keys.sort_unstable();
    if want_keys != got_keys {
        return Err(format!("params {got_keys:?}, expected {want_keys:?}"));
    }
    for k in want_keys {
        let got = to_hex(&s.params[k].rdoc_value);
        eq(&format!("param {k}"), want.get(k).str_("hex"), &got)?;
    }
    Ok(())
}

/// `checkAstVectors`.
pub fn ast_vectors(file: &str) -> R {
    let f = load(file);
    let pool = pool();
    let coll = f.str_("collection");
    let coll = if coll.is_empty() { "c" } else { coll };
    let val = |y: &Yaml| crate::yaml::to_value(y, &plain);
    for c in f.list("cases") {
        let name = c.str_("name");
        let fail = |m: String| format!("{name}: {m}");
        let mut s = ParamSink::new();
        if file.ends_with("filters.json") {
            let filter = dsl_filter(c.get("filter"), &val).map_err(&fail)?;
            let r#where = filter.to_ast(&mut s).map_err(|e| fail(e.to_string()))?;
            let want: Option<pb::AstExpr> = if c.has("where") {
                Some(parse_pb(&pool, "rustegon.v1.AstExpr", c.get("where")).map_err(&fail)?)
            } else {
                None
            };
            if want != r#where {
                return Err(fail(format!("where {where:?}, expected {want:?}")));
            }
            check_params(c, &s).map_err(&fail)?;
            let mut s2 = ParamSink::new();
            let st = find_statement(coll, &filter, None, None, None, None, &mut s2)
                .map_err(|e| fail(e.to_string()))?;
            compare_statement(&pool, c, &st).map_err(&fail)?;
            check_params(c, &s2).map_err(&fail)?;
        } else if file.ends_with("updates.json") {
            let ops = c.list("update");
            let u = match ops.first().map(|o| o.get("replace")) {
                Some(r) if ops.len() == 1 && !r.is_badvalue() => {
                    Update::replacement(to_document(r, &plain))
                }
                _ => dsl_update(ops, &val).map_err(&fail)?,
            };
            let got = u.to_ast(&mut s).map_err(|e| fail(e.to_string()))?;
            let want: Vec<pb::AstUpdateOp> = c
                .list("operations")
                .iter()
                .map(|o| parse_pb(&pool, "rustegon.v1.AstUpdateOp", o))
                .collect::<Result<_, _>>()
                .map_err(&fail)?;
            if want != got {
                return Err(fail(format!("operations {got:?}, expected {want:?}")));
            }
            check_params(c, &s).map_err(&fail)?;
        } else if file.ends_with("statements.json") {
            let args = c.get("args");
            let filter = dsl_filter(args.get("filter"), &val).map_err(&fail)?;
            let st = match c.str_("op") {
                "find" => {
                    let sort: Option<Sort> = args
                        .as_hash()
                        .and(args.get("sort").as_vec())
                        .map(|l| sort_of(l));
                    let proj: Option<Projection> = (!args.get("projection").is_badvalue())
                        .then(|| projection_of(args.get("projection")));
                    find_statement(
                        coll,
                        &filter,
                        sort.as_ref(),
                        proj.as_ref(),
                        args.int("limit"),
                        args.int("skip"),
                        &mut s,
                    )
                }
                op @ ("updateOne" | "updateMany") => {
                    let u = dsl_update(args.list("update"), &val).map_err(&fail)?;
                    update_statement(coll, &filter, &u, op == "updateOne", &mut s)
                }
                "replaceOne" => update_statement(
                    coll,
                    &filter,
                    &Update::replacement(to_document(args.get("replacement"), &plain)),
                    true,
                    &mut s,
                ),
                op @ ("deleteOne" | "deleteMany") => {
                    delete_statement(coll, &filter, op == "deleteOne", &mut s)
                }
                op => return Err(fail(format!("unknown op {op}"))),
            }
            .map_err(|e| fail(e.to_string()))?;
            compare_statement(&pool, c, &st).map_err(&fail)?;
            check_params(c, &s).map_err(&fail)?;
        } else {
            return Err(format!("no AST check for {file}"));
        }
    }
    Ok(())
}

fn compare_statement(pool: &DescriptorPool, c: &Yaml, st: &pb::AstStatement) -> R {
    let want: pb::AstStatement = parse_pb(pool, "rustegon.v1.AstStatement", c.get("statement"))?;
    if &want != st {
        return Err(format!("statement {st:?}, expected {want:?}"));
    }
    Ok(())
}
