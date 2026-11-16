// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! YAML/JSON access for the conformance files, and their values as driver values.
//!
//! README §5 "Values and matching": a YAML integer is `int64`, a float `float64`, a mapping whose
//! single key starts with `$` (not `$$`) is an extended-JSON wrapper, everything else maps
//! structurally. JSON files (`ast/*.json`, `generated/errors.json`) are read with the same loader
//! (JSON is YAML).

use std::path::PathBuf;

use rustegon::{Document, Value, codec::json};
pub use yaml_rust2::Yaml;
use yaml_rust2::YamlLoader;

/// `drivers/conformance`.
pub fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance")
}

/// Loads a file of the suite (path relative to `drivers/conformance`).
pub fn load(relative: &str) -> Yaml {
    let path = conformance_dir().join(relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse(&text).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// Parses one YAML document.
pub fn parse(text: &str) -> Result<Yaml, String> {
    let mut docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    if docs.is_empty() {
        return Err("empty YAML".into());
    }
    Ok(docs.swap_remove(0))
}

/// Accessors that tolerate missing keys.
pub trait Y {
    fn get(&self, key: &str) -> &Yaml;
    fn has(&self, key: &str) -> bool;
    fn str_(&self, key: &str) -> &str;
    fn list(&self, key: &str) -> &[Yaml];
    fn is_true(&self, key: &str) -> bool;
    fn int(&self, key: &str) -> Option<i64>;
    fn keys(&self) -> Vec<&str>;
    /// The single key and its value of a one-key mapping (DSL operators).
    fn single(&self) -> Option<(&str, &Yaml)>;
}

impl Y for Yaml {
    fn get(&self, key: &str) -> &Yaml {
        &self[key]
    }
    fn has(&self, key: &str) -> bool {
        !self[key].is_badvalue()
    }
    fn str_(&self, key: &str) -> &str {
        self[key].as_str().unwrap_or("")
    }
    fn list(&self, key: &str) -> &[Yaml] {
        self[key].as_vec().map_or(&[], Vec::as_slice)
    }
    fn is_true(&self, key: &str) -> bool {
        self[key].as_bool() == Some(true)
    }
    fn int(&self, key: &str) -> Option<i64> {
        self[key].as_i64()
    }
    fn keys(&self) -> Vec<&str> {
        self.as_hash()
            .map(|h| h.keys().filter_map(Yaml::as_str).collect())
            .unwrap_or_default()
    }
    fn single(&self) -> Option<(&str, &Yaml)> {
        let h = self.as_hash()?;
        if h.len() != 1 {
            return None;
        }
        h.iter()
            .next()
            .and_then(|(k, v)| k.as_str().map(|k| (k, v)))
    }
}

/// The extended-JSON wrappers (data-model.md §2 notes). Other `$` names are ordinary (invalid)
/// field names that the driver must refuse with RGN-1004.
const WRAPPERS: [&str; 12] = [
    "$int64", "$float", "$decimal", "$binary", "$date", "$ts", "$oid", "$uuid", "$vector",
    "$counter", "$minKey", "$maxKey",
];

/// A one-key wrapper `{"$int64": …}` (extended JSON).
pub fn is_wrapper(y: &Yaml) -> bool {
    y.as_hash().is_some_and(|h| {
        h.len() == 1
            && h.keys()
                .all(|k| k.as_str().is_some_and(|s| WRAPPERS.contains(&s)))
    })
}

/// JSON text of a YAML value (floats keep their text so `1.0` stays a float).
pub fn to_json(y: &Yaml) -> String {
    let mut out = String::new();
    write_json(&mut out, y);
    out
}

fn write_json(out: &mut String, y: &Yaml) {
    match y {
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => out.push_str("null"),
        Yaml::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        Yaml::Integer(i) => out.push_str(&i.to_string()),
        Yaml::Real(r) => out.push_str(r),
        Yaml::String(s) => out.push_str(&json_string(s)),
        Yaml::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(out, e);
            }
            out.push(']');
        }
        Yaml::Hash(h) => {
            out.push('{');
            for (i, (k, v)) in h.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k.as_str().unwrap_or("")));
                out.push(':');
                write_json(out, v);
            }
            out.push('}');
        }
    }
}

/// A JSON string literal.
pub fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// A YAML value as a driver value; `resolve` maps strings (substitutions, `$$ref`).
pub fn to_value(y: &Yaml, resolve: &dyn Fn(&str) -> Value) -> Value {
    match y {
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Value::Null,
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Integer(i) => Value::Int64(*i),
        Yaml::Real(r) => Value::Float64(r.parse().unwrap_or(f64::NAN)),
        Yaml::String(s) => resolve(s),
        Yaml::Array(a) => Value::Array(a.iter().map(|e| to_value(e, resolve)).collect()),
        Yaml::Hash(h) => {
            if is_wrapper(y) {
                return json::parse_value(&to_json(y))
                    .unwrap_or_else(|e| panic!("bad wrapper {}: {e}", to_json(y)));
            }
            let mut d = Document::new();
            for (k, v) in h {
                d.insert(k.as_str().unwrap_or(""), to_value(v, resolve));
            }
            Value::Object(d)
        }
    }
}

/// Plain string resolution (no substitutions).
pub fn plain(s: &str) -> Value {
    Value::String(s.to_owned())
}

/// A YAML mapping as a document.
pub fn to_document(y: &Yaml, resolve: &dyn Fn(&str) -> Value) -> Document {
    match to_value(y, resolve) {
        Value::Object(d) => d,
        _ => Document::new(),
    }
}
