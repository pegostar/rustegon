// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Parser, validator and Rust code generator for `proto/errors.yaml`.
//!
//! Shared by `build.rs` and by `tests/error_catalog.rs` (included with `#[path]`), so the
//! validation rules themselves are tested against invalid catalogs.

use std::{collections::HashSet, fmt::Write as _};

use yaml_rust2::{Yaml, YamlLoader};

/// gRPC status names accepted in the catalog (`google.rpc.Code`), in numeric order 0..=16.
pub const GRPC_CODES: [&str; 17] = [
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// One validated catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub code: u16,
    pub name: String,
    pub aliases: Vec<String>,
    pub internal: bool,
    pub grpc: String,
    pub http: u16,
    pub retryable: String,
    pub retry_note: Option<String>,
}

/// Parses and validates the catalog. Codes must be strictly ascending: the catalog is
/// append-only (protocol.md §7), so a new code always goes after the existing ones of its block.
pub fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| format!("invalid YAML: {e}"))?;
    let doc = docs.first().ok_or("empty catalog")?;
    if doc["version"].as_i64() != Some(1) {
        return Err("unsupported catalog version (expected 1)".into());
    }
    let items = doc["codes"].as_vec().ok_or("missing `codes` list")?;
    let mut entries = Vec::with_capacity(items.len());
    let mut names = HashSet::new();
    let mut last_code = 0u16;
    for item in items {
        let entry = parse_entry(item)?;
        if entry.code <= last_code {
            return Err(format!("code {} is not ascending/unique", entry.code));
        }
        last_code = entry.code;
        for name in std::iter::once(&entry.name).chain(&entry.aliases) {
            if !names.insert(name.clone()) {
                return Err(format!("duplicate name {name}"));
            }
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err("catalog has no codes".into());
    }
    Ok(entries)
}

fn parse_entry(item: &Yaml) -> Result<Entry, String> {
    let code = item["code"]
        .as_i64()
        .ok_or("entry without integer `code`")?;
    let code = u16::try_from(code)
        .ok()
        .filter(|c| (1000..=9999).contains(c))
        .ok_or_else(|| format!("code {code} outside 1000..=9999"))?;
    let ctx = |field: &str| format!("code {code}: invalid or missing `{field}`");
    let name = item["name"].as_str().ok_or_else(|| ctx("name"))?.to_owned();
    let aliases = match &item["aliases"] {
        Yaml::BadValue => Vec::new(),
        Yaml::Array(list) => list
            .iter()
            .map(|a| a.as_str().map(str::to_owned).ok_or_else(|| ctx("aliases")))
            .collect::<Result<_, _>>()?,
        _ => return Err(ctx("aliases")),
    };
    for n in std::iter::once(&name).chain(&aliases) {
        if !is_upper_camel(n) {
            return Err(format!("code {code}: name `{n}` is not UpperCamelCase"));
        }
    }
    let internal = match &item["internal"] {
        Yaml::BadValue => false,
        v => v.as_bool().ok_or_else(|| ctx("internal"))?,
    };
    let grpc = item["grpc"].as_str().ok_or_else(|| ctx("grpc"))?.to_owned();
    if grpc == "OK" || !GRPC_CODES.contains(&grpc.as_str()) {
        return Err(ctx("grpc"));
    }
    let http = item["http"]
        .as_i64()
        .and_then(|h| u16::try_from(h).ok())
        .filter(|h| (400..=599).contains(h))
        .ok_or_else(|| ctx("http"))?;
    let retryable = item["retryable"]
        .as_str()
        .ok_or_else(|| ctx("retryable"))?
        .to_owned();
    let retry_note = item["retry_note"].as_str().map(str::to_owned);
    match (retryable.as_str(), &retry_note) {
        ("yes" | "no", _) | ("conditional", Some(_)) => {}
        // A conditional code without a note would leave clients guessing when to retry.
        _ => return Err(ctx("retryable")),
    }
    Ok(Entry {
        code,
        name,
        aliases,
        internal,
        grpc,
        http,
        retryable,
        retry_note,
    })
}

fn is_upper_camel(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_uppercase()) && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// `INVALID_ARGUMENT` -> `InvalidArgument` (variant name of `GrpcCode`).
fn pascal_grpc(grpc: &str) -> String {
    grpc.split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map_or_else(String::new, |f| f.to_string() + &c.as_str().to_lowercase())
        })
        .collect()
}

/// Generates the `ErrorCode` enum, its metadata table and lookup functions.
pub fn generate(entries: &[Entry]) -> String {
    let mut out = String::from(
        "/// Stable, client-visible error codes (`RGN-<code>`), generated from `proto/errors.yaml`.\n\
         ///\n/// Append-only: codes and names never change (protocol.md §7).\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]\n\
         #[repr(u16)]\n#[non_exhaustive]\npub enum ErrorCode {\n",
    );
    for e in entries {
        let internal = if e.internal {
            " Internal: never returned to clients."
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "    /// `RGN-{}` (gRPC `{}`, HTTP {}).{internal}\n    {} = {},",
            e.code, e.grpc, e.http, e.name, e.code
        );
    }
    out.push_str("}\n\nconst INFO: &[ErrorCodeInfo] = &[\n");
    for e in entries {
        let aliases: Vec<String> = e.aliases.iter().map(|a| format!("{a:?}")).collect();
        let retryable = match e.retryable.as_str() {
            "yes" => "Retryable::Yes",
            "no" => "Retryable::No",
            _ => "Retryable::Conditional",
        };
        let _ = writeln!(
            out,
            "    ErrorCodeInfo {{ name: {name:?}, aliases: &[{aliases}], internal: {internal}, \
             grpc: GrpcCode::{grpc}, http: {http}, retryable: {retryable}, \
             retry_note: {note:?} }},",
            name = e.name,
            aliases = aliases.join(", "),
            internal = e.internal,
            grpc = pascal_grpc(&e.grpc),
            http = e.http,
            note = e.retry_note,
        );
    }
    out.push_str(
        "];\n\nimpl ErrorCode {\n    /// Every code, in catalog order.\n    \
         pub const ALL: &'static [ErrorCode] = &[\n",
    );
    for e in entries {
        let _ = writeln!(out, "        ErrorCode::{},", e.name);
    }
    out.push_str(
        "    ];\n\n    /// Looks up a code by its number.\n    #[must_use]\n    \
         pub const fn from_code(code: u16) -> Option<Self> {\n        match code {\n",
    );
    for e in entries {
        let _ = writeln!(
            out,
            "            {} => Some(ErrorCode::{}),",
            e.code, e.name
        );
    }
    out.push_str(
        "            _ => None,\n        }\n    }\n\n    \
         const fn index(self) -> usize {\n        match self {\n",
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = writeln!(out, "            ErrorCode::{} => {i},", e.name);
    }
    out.push_str("        }\n    }\n}\n");
    out
}
