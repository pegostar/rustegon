// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Driver error tables (FR-DRV-001/002, java-driver.md §11, PD-075).
//!
//! `proto/errors.yaml` (codes, names, gRPC/HTTP mapping, retry class) joined with the
//! hand-written `drivers/conformance/errors-map.yaml` (code → exception class of each driver)
//! gives three checked-in files the driver builds include as they are:
//! - `drivers/conformance/generated/ErrorCodes.g.cs` (namespace `Rustegon.Driver.Errors`),
//! - `drivers/conformance/generated/ErrorCodes.java` (package `io.rustegon.driver.errors`),
//! - `drivers/conformance/generated/errors.json` (language-neutral, for runners and tooling).
//!
//! The test fails when a file is stale; re-bless with
//! `RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-common --test driver_tables` and
//! review the diff. It also fails when `errors-map.yaml` misses a catalog code, names an
//! unknown class, or declares a broken hierarchy.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "../build/codegen.rs"]
#[allow(dead_code, missing_docs)]
mod codegen;
mod drivers_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use drivers_support::{check_or_bless, conformance_dir, load_yaml};
use serde_json::{Value as Json, json};

const CATALOG: &str = include_str!("../../../proto/errors.yaml");
const BLESS_COMMAND: &str = "cargo nextest run -p rustegon-common --test driver_tables";
const HEADER_SOURCES: &str = "proto/errors.yaml and drivers/conformance/errors-map.yaml (PD-075)";

/// One exception class of the shared hierarchy.
struct Class {
    id: String,
    dotnet: String,
    java: String,
    parent: Option<String>,
}

/// A transport fallback (failure without `ErrorDetail`).
struct Transport {
    grpc: String,
    class: String,
    code: u16,
    retryable: bool,
}

/// `errors-map.yaml`, validated against the catalog.
struct ErrorMap {
    classes: Vec<Class>,
    codes: BTreeMap<u16, String>,
    unknown: String,
    transport: Vec<Transport>,
}

impl ErrorMap {
    fn class(&self, id: &str) -> &Class {
        self.classes
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("errors-map.yaml: unknown class `{id}`"))
    }
}

fn str_field<'a>(v: &'a Json, field: &str, ctx: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("errors-map.yaml: {ctx}: missing string `{field}`"))
}

fn load_map(entries: &[codegen::Entry]) -> ErrorMap {
    let doc = load_yaml(&conformance_dir().join("errors-map.yaml"));
    assert_eq!(doc["version"], 1, "errors-map.yaml: version must be 1");
    let mut classes = Vec::new();
    for c in doc["classes"]
        .as_array()
        .expect("errors-map.yaml: `classes` list")
    {
        let id = str_field(c, "id", "class").to_owned();
        classes.push(Class {
            dotnet: str_field(c, "dotnet", &id).to_owned(),
            java: str_field(c, "java", &id).to_owned(),
            parent: c["parent"].as_str().map(str::to_owned),
            id,
        });
    }
    let ids: BTreeSet<&str> = classes.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids.len(),
        classes.len(),
        "errors-map.yaml: duplicate class id"
    );
    let roots: Vec<&Class> = classes.iter().filter(|c| c.parent.is_none()).collect();
    assert_eq!(roots.len(), 1, "errors-map.yaml: exactly one root class");
    for c in &classes {
        // Every chain of parents ends at the root (no cycles, no dangling parent).
        let mut seen = BTreeSet::new();
        let mut at = c;
        while let Some(p) = &at.parent {
            assert!(
                seen.insert(p.clone()),
                "errors-map.yaml: cycle through `{p}`"
            );
            assert!(
                ids.contains(p.as_str()),
                "errors-map.yaml: `{}` has unknown parent `{p}`",
                at.id
            );
            at = classes.iter().find(|x| &x.id == p).unwrap();
        }
        for name in [&c.dotnet, &c.java] {
            assert!(
                name.ends_with("Exception") && name.chars().all(char::is_alphanumeric),
                "errors-map.yaml: class name `{name}`"
            );
        }
    }
    let mut codes = BTreeMap::new();
    for (k, v) in doc["codes"]
        .as_object()
        .expect("errors-map.yaml: `codes` mapping")
    {
        let code: u16 = k
            .parse()
            .unwrap_or_else(|_| panic!("errors-map.yaml: code `{k}`"));
        let class = v
            .as_str()
            .unwrap_or_else(|| panic!("errors-map.yaml: code {code}: class id"));
        assert!(
            ids.contains(class),
            "errors-map.yaml: code {code}: unknown class `{class}`"
        );
        codes.insert(code, class.to_owned());
    }
    let catalog: BTreeSet<u16> = entries.iter().map(|e| e.code).collect();
    let mapped: BTreeSet<u16> = codes.keys().copied().collect();
    let missing: Vec<_> = catalog.difference(&mapped).collect();
    let extra: Vec<_> = mapped.difference(&catalog).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "errors-map.yaml out of sync with proto/errors.yaml: missing {missing:?}, unknown {extra:?}"
    );
    let unknown = doc["unknown"]
        .as_str()
        .expect("errors-map.yaml: `unknown`")
        .to_owned();
    assert!(
        ids.contains(unknown.as_str()),
        "errors-map.yaml: unknown class `{unknown}`"
    );
    let mut transport = Vec::new();
    for (grpc, v) in doc["transport"]
        .as_object()
        .expect("errors-map.yaml: `transport`")
    {
        assert!(
            grpc == "default" || codegen::GRPC_CODES.contains(&grpc.as_str()),
            "errors-map.yaml: transport status `{grpc}`"
        );
        let class = str_field(v, "class", grpc).to_owned();
        assert!(
            ids.contains(class.as_str()),
            "errors-map.yaml: transport `{grpc}`: class `{class}`"
        );
        let code = v["code"]
            .as_u64()
            .and_then(|c| u16::try_from(c).ok())
            .unwrap();
        assert!(
            catalog.contains(&code),
            "errors-map.yaml: transport `{grpc}`: code {code}"
        );
        transport.push(Transport {
            grpc: grpc.clone(),
            class,
            code,
            retryable: v["retryable"].as_bool().unwrap(),
        });
    }
    assert!(
        transport.iter().any(|t| t.grpc == "default"),
        "errors-map.yaml: transport default"
    );
    // `default` last, the others in google.rpc.Code order, so the output is stable.
    transport.sort_by_key(|t| {
        codegen::GRPC_CODES
            .iter()
            .position(|g| *g == t.grpc)
            .unwrap_or(usize::MAX)
    });
    ErrorMap {
        classes,
        codes,
        unknown,
        transport,
    }
}

fn grpc_number(name: &str) -> usize {
    codegen::GRPC_CODES.iter().position(|g| *g == name).unwrap()
}

/// `InvalidArgument` → `INVALID_ARGUMENT`.
fn screaming(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
    }
    out
}

fn quoted(s: &str) -> String {
    // Catalog strings are plain ASCII words (validated by codegen); escaping is not needed,
    // but quotes and backslashes would break the generated code, so refuse them.
    assert!(!s.contains(['"', '\\']), "unexpected character in `{s}`");
    format!("\"{s}\"")
}

fn csharp(entries: &[codegen::Entry], map: &ErrorMap) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "// <auto-generated>\n// Generated by crates/rustegon-common/tests/driver_tables.rs from\n// {HEADER_SOURCES}.\n// Do not edit: re-bless with RGN_FIXTURES_BLESS=1 {BLESS_COMMAND}\n// </auto-generated>\n// SPDX-License-Identifier: Apache-2.0\n// Copyright The Rustegon Authors\n\n"
    );
    o.push_str("#nullable enable\n\nusing System;\nusing System.Collections.Generic;\n\nnamespace Rustegon.Driver.Errors;\n\n");
    o.push_str(
        "/// <summary>Retry class of an error code in the catalog (proto/errors.yaml).</summary>\npublic enum ErrorRetryable\n{\n    /// <summary>The operation must not be retried.</summary>\n    No,\n\n    /// <summary>The operation may be retried.</summary>\n    Yes,\n\n    /// <summary>Retryable depending on the error (see <see cref=\"ErrorCodeInfo.RetryNote\"/>); the response's <c>ErrorDetail.retryable</c> decides.</summary>\n    Conditional,\n}\n\n",
    );
    o.push_str(concat!(
        "/// <summary>One entry of the error catalog joined with the exception mapping.</summary>\n",
        "/// <param name=\"Code\">Numeric code (<c>RGN-&lt;code&gt;</c>).</param>\n",
        "/// <param name=\"Name\">Stable error name.</param>\n",
        "/// <param name=\"Aliases\">Alternative names of the same code.</param>\n",
        "/// <param name=\"Internal\">Never returned to clients by a healthy server.</param>\n",
        "/// <param name=\"GrpcStatusCode\">google.rpc.Code number of the gRPC status.</param>\n",
        "/// <param name=\"GrpcStatusName\">google.rpc.Code name of the gRPC status.</param>\n",
        "/// <param name=\"HttpStatus\">HTTP status of the REST API.</param>\n",
        "/// <param name=\"Retryable\">Catalog retry class (the response flag takes precedence).</param>\n",
        "/// <param name=\"RetryNote\">Qualifier of the retry class, if any.</param>\n",
        "/// <param name=\"ExceptionType\">Simple name of the exception class the driver throws.</param>\n",
        "public sealed record ErrorCodeInfo(\n    int Code,\n    string Name,\n    IReadOnlyList<string> Aliases,\n    bool Internal,\n    int GrpcStatusCode,\n    string GrpcStatusName,\n    int HttpStatus,\n    ErrorRetryable Retryable,\n    string? RetryNote,\n    string ExceptionType);\n\n",
        "/// <summary>Mapping of a failed call that carries no <c>ErrorDetail</c>.</summary>\n",
        "/// <param name=\"GrpcStatusName\">google.rpc.Code name, or <c>default</c> for any other status.</param>\n",
        "/// <param name=\"Code\">Error code the driver reports.</param>\n",
        "/// <param name=\"Retryable\">Retry flag the driver reports.</param>\n",
        "/// <param name=\"ExceptionType\">Simple name of the exception class the driver throws.</param>\n",
        "public sealed record TransportFallback(string GrpcStatusName, int Code, bool Retryable, string ExceptionType);\n\n",
    ));
    o.push_str("/// <summary>The error catalog of protocol.md section 7 with the exception mapping of drivers/conformance/errors-map.yaml.</summary>\npublic static class ErrorCodes\n{\n");
    for e in entries {
        let _ = writeln!(
            o,
            "    /// <summary>RGN-{} {}.</summary>\n    public const int {} = {};\n",
            e.code, e.name, e.name, e.code
        );
        for a in &e.aliases {
            let _ = writeln!(
                o,
                "    /// <summary>RGN-{} {a} (alias of {}).</summary>\n    public const int {a} = {};\n",
                e.code, e.name, e.code
            );
        }
    }
    let _ = writeln!(
        o,
        "    /// <summary>Exception class for a code missing from this table (newer server).</summary>\n    public const string UnknownCodeExceptionType = {};\n",
        quoted(&map.class(&map.unknown).dotnet)
    );
    o.push_str("    private static readonly ErrorCodeInfo[] Entries =\n    {\n");
    for e in entries {
        let aliases = if e.aliases.is_empty() {
            "Array.Empty<string>()".to_owned()
        } else {
            format!(
                "new[] {{ {} }}",
                e.aliases
                    .iter()
                    .map(|a| quoted(a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let retry = match e.retryable.as_str() {
            "yes" => "Yes",
            "no" => "No",
            _ => "Conditional",
        };
        let note = e
            .retry_note
            .as_deref()
            .map_or_else(|| "null".to_owned(), quoted);
        let _ = writeln!(
            o,
            "        new({}, {}, {aliases}, {}, {}, {}, {}, ErrorRetryable.{retry}, {note}, {}),",
            e.code,
            quoted(&e.name),
            e.internal,
            grpc_number(&e.grpc),
            quoted(&e.grpc),
            e.http,
            quoted(&map.class(&map.codes[&e.code]).dotnet)
        );
    }
    o.push_str("    };\n\n    private static readonly TransportFallback[] Fallbacks =\n    {\n");
    for t in &map.transport {
        let _ = writeln!(
            o,
            "        new({}, {}, {}, {}),",
            quoted(&t.grpc),
            t.code,
            t.retryable,
            quoted(&map.class(&t.class).dotnet)
        );
    }
    o.push_str(concat!(
        "    };\n\n",
        "    private static readonly Dictionary<int, ErrorCodeInfo> ByCode = BuildIndex();\n\n",
        "    /// <summary>All catalog entries in ascending code order.</summary>\n",
        "    public static IReadOnlyList<ErrorCodeInfo> All => Entries;\n\n",
        "    /// <summary>Transport fallbacks; the entry named <c>default</c> applies to any other status.</summary>\n",
        "    public static IReadOnlyList<TransportFallback> TransportFallbacks => Fallbacks;\n\n",
        "    /// <summary>The entry of <paramref name=\"code\"/>, or <c>null</c> for a code unknown to this driver version.</summary>\n",
        "    /// <param name=\"code\">Numeric error code.</param>\n",
        "    /// <returns>The catalog entry or <c>null</c>.</returns>\n",
        "    public static ErrorCodeInfo? Find(int code) => ByCode.TryGetValue(code, out var info) ? info : null;\n\n",
        "    private static Dictionary<int, ErrorCodeInfo> BuildIndex()\n    {\n",
        "        var index = new Dictionary<int, ErrorCodeInfo>(Entries.Length);\n",
        "        foreach (var entry in Entries)\n        {\n            index.Add(entry.Code, entry);\n        }\n\n",
        "        return index;\n    }\n}\n",
    ));
    o
}

fn java(entries: &[codegen::Entry], map: &ErrorMap) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "/*\n * Generated by crates/rustegon-common/tests/driver_tables.rs from\n * {HEADER_SOURCES}.\n * Do not edit: re-bless with RGN_FIXTURES_BLESS=1 {BLESS_COMMAND}\n *\n * SPDX-License-Identifier: Apache-2.0\n * Copyright The Rustegon Authors\n */\n"
    );
    o.push_str("package io.rustegon.driver.errors;\n\nimport java.util.Collections;\nimport java.util.HashMap;\nimport java.util.List;\nimport java.util.Map;\n\n");
    o.push_str(concat!(
        "/** The error catalog of protocol.md section 7 with the exception mapping of drivers/conformance/errors-map.yaml. */\n",
        "public final class ErrorCodes {\n",
        "  private ErrorCodes() {}\n\n",
        "  /** Retry class of an error code in the catalog (proto/errors.yaml). */\n",
        "  public enum Retryable {\n",
        "    /** The operation must not be retried. */\n    NO,\n",
        "    /** The operation may be retried. */\n    YES,\n",
        "    /** Retryable depending on the error; the response's {@code ErrorDetail.retryable} decides. */\n    CONDITIONAL\n  }\n\n",
        "  /**\n   * One entry of the error catalog joined with the exception mapping.\n   *\n",
        "   * @param code numeric code ({@code RGN-<code>})\n",
        "   * @param name stable error name\n",
        "   * @param aliases alternative names of the same code\n",
        "   * @param internal never returned to clients by a healthy server\n",
        "   * @param grpcStatusCode google.rpc.Code number of the gRPC status\n",
        "   * @param grpcStatusName google.rpc.Code name of the gRPC status\n",
        "   * @param httpStatus HTTP status of the REST API\n",
        "   * @param retryable catalog retry class (the response flag takes precedence)\n",
        "   * @param retryNote qualifier of the retry class, or {@code null}\n",
        "   * @param exceptionType simple name of the exception class the driver throws\n   */\n",
        "  public record Info(\n      int code,\n      String name,\n      List<String> aliases,\n      boolean internal,\n      int grpcStatusCode,\n      String grpcStatusName,\n      int httpStatus,\n      Retryable retryable,\n      String retryNote,\n      String exceptionType) {}\n\n",
        "  /**\n   * Mapping of a failed call that carries no {@code ErrorDetail}.\n   *\n",
        "   * @param grpcStatusName google.rpc.Code name, or {@code default} for any other status\n",
        "   * @param code error code the driver reports\n",
        "   * @param retryable retry flag the driver reports\n",
        "   * @param exceptionType simple name of the exception class the driver throws\n   */\n",
        "  public record TransportFallback(String grpcStatusName, int code, boolean retryable, String exceptionType) {}\n\n",
    ));
    for e in entries {
        let _ = writeln!(
            o,
            "  /** RGN-{} {}. */\n  public static final int {} = {};\n",
            e.code,
            e.name,
            screaming(&e.name),
            e.code
        );
        for a in &e.aliases {
            let _ = writeln!(
                o,
                "  /** RGN-{} {a} (alias of {}). */\n  public static final int {} = {};\n",
                e.code,
                e.name,
                screaming(a),
                e.code
            );
        }
    }
    let _ = writeln!(
        o,
        "  /** Exception class for a code missing from this table (newer server). */\n  public static final String UNKNOWN_CODE_EXCEPTION_TYPE = {};\n",
        quoted(&map.class(&map.unknown).java)
    );
    o.push_str("  private static final List<Info> ENTRIES =\n      List.of(\n");
    for (i, e) in entries.iter().enumerate() {
        let aliases = format!(
            "List.of({})",
            e.aliases
                .iter()
                .map(|a| quoted(a))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let retry = match e.retryable.as_str() {
            "yes" => "YES",
            "no" => "NO",
            _ => "CONDITIONAL",
        };
        let note = e
            .retry_note
            .as_deref()
            .map_or_else(|| "null".to_owned(), quoted);
        let sep = if i + 1 == entries.len() { "" } else { "," };
        let _ = writeln!(
            o,
            "          new Info({}, {}, {aliases}, {}, {}, {}, {}, Retryable.{retry}, {note}, {}){sep}",
            e.code,
            quoted(&e.name),
            e.internal,
            grpc_number(&e.grpc),
            quoted(&e.grpc),
            e.http,
            quoted(&map.class(&map.codes[&e.code]).java)
        );
    }
    o.push_str(
        "      );\n\n  private static final List<TransportFallback> FALLBACKS =\n      List.of(\n",
    );
    for (i, t) in map.transport.iter().enumerate() {
        let sep = if i + 1 == map.transport.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(
            o,
            "          new TransportFallback({}, {}, {}, {}){sep}",
            quoted(&t.grpc),
            t.code,
            t.retryable,
            quoted(&map.class(&t.class).java)
        );
    }
    o.push_str(concat!(
        "      );\n\n",
        "  private static final Map<Integer, Info> BY_CODE = buildIndex();\n\n",
        "  /**\n   * All catalog entries in ascending code order.\n   *\n   * @return the entries\n   */\n",
        "  public static List<Info> all() {\n    return ENTRIES;\n  }\n\n",
        "  /**\n   * Transport fallbacks; the entry named {@code default} applies to any other status.\n   *\n   * @return the fallbacks\n   */\n",
        "  public static List<TransportFallback> transportFallbacks() {\n    return FALLBACKS;\n  }\n\n",
        "  /**\n   * The entry of a code.\n   *\n   * @param code numeric error code\n   * @return the entry, or {@code null} for a code unknown to this driver version\n   */\n",
        "  public static Info find(int code) {\n    return BY_CODE.get(code);\n  }\n\n",
        "  private static Map<Integer, Info> buildIndex() {\n",
        "    Map<Integer, Info> index = new HashMap<>();\n",
        "    for (Info info : ENTRIES) {\n      index.put(info.code(), info);\n    }\n",
        "    return Collections.unmodifiableMap(index);\n  }\n}\n",
    ));
    o
}

fn json_table(entries: &[codegen::Entry], map: &ErrorMap) -> String {
    let codes: Vec<Json> = entries
        .iter()
        .map(|e| {
            let class = map.class(&map.codes[&e.code]);
            json!({
                "code": e.code,
                "name": e.name,
                "aliases": e.aliases,
                "internal": e.internal,
                "grpc": e.grpc,
                "grpcCode": grpc_number(&e.grpc),
                "http": e.http,
                "retryable": e.retryable,
                "retryNote": e.retry_note,
                "exception": {"id": class.id, "dotnet": class.dotnet, "java": class.java},
            })
        })
        .collect();
    let classes: Vec<Json> = map
        .classes
        .iter()
        .map(|c| json!({"id": c.id, "dotnet": c.dotnet, "java": c.java, "parent": c.parent}))
        .collect();
    let transport: Vec<Json> = map
        .transport
        .iter()
        .map(|t| {
            let class = map.class(&t.class);
            json!({"grpc": t.grpc, "code": t.code, "retryable": t.retryable,
                   "exception": {"id": class.id, "dotnet": class.dotnet, "java": class.java}})
        })
        .collect();
    let unknown = map.class(&map.unknown);
    let doc = json!({
        "description": format!("Generated by crates/rustegon-common/tests/driver_tables.rs from {HEADER_SOURCES}; do not edit."),
        "version": 1,
        "classes": classes,
        "codes": codes,
        "unknown": {"id": unknown.id, "dotnet": unknown.dotnet, "java": unknown.java},
        "transport": transport,
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

/// TC-DRV-CONF (PD-075): the generated driver tables match the catalog and the mapping.
#[test]
fn tc_drv_conf_error_tables_are_generated_from_the_catalog() {
    let entries = codegen::parse(CATALOG).expect("catalog must be valid");
    let map = load_map(&entries);
    let dir = conformance_dir().join("generated");
    check_or_bless(
        &dir.join("ErrorCodes.g.cs"),
        &csharp(&entries, &map),
        BLESS_COMMAND,
    );
    check_or_bless(
        &dir.join("ErrorCodes.java"),
        &java(&entries, &map),
        BLESS_COMMAND,
    );
    check_or_bless(
        &dir.join("errors.json"),
        &json_table(&entries, &map),
        BLESS_COMMAND,
    );
}

/// The mapping follows the driver specs where they are explicit (dotnet-driver.md §8,
/// java-driver.md §6, transactions.md §4).
#[test]
fn tc_drv_conf_error_map_follows_the_driver_specs() {
    let entries = codegen::parse(CATALOG).unwrap();
    let map = load_map(&entries);
    let class = |code: u16| map.codes[&code].as_str();
    assert_eq!(class(1005), "DuplicateKey");
    assert_eq!(class(1006), "DocumentValidation");
    assert_eq!(class(1010), "QuerySyntax");
    assert_eq!(class(2001), "TransactionConflict");
    assert_eq!(class(2002), "TransactionAborted");
    assert_eq!(class(2006), "CommitOutcomeUnknown");
    assert_eq!(class(4001), "Authentication");
    assert_eq!(class(4002), "Authorization");
    assert_eq!(class(4003), "RateLimited");
    // dotnet-driver.md §8: TimeoutException maps 5006 and 2003.
    assert_eq!(class(5006), "Timeout");
    assert_eq!(class(2003), "Timeout");
    // 5xxx are server exceptions except the timeout.
    for e in entries
        .iter()
        .filter(|e| e.code >= 5000 && e.code != 5006 && e.code != 5007)
    {
        assert_eq!(class(e.code), "Server", "RGN-{}", e.code);
    }
    for e in entries
        .iter()
        .filter(|e| (3000..4000).contains(&e.code) && e.code != 3006)
    {
        assert_eq!(class(e.code), "Unavailable", "RGN-{}", e.code);
    }
    assert_eq!(
        map.class("PasswordChangeRequired").parent.as_deref(),
        Some("Authentication")
    );
    assert_eq!(map.class("Timeout").java, "RustegonTimeoutException");
}
