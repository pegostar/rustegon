// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index key generation: document + descriptor → set of index entries (indexing.md §3,
//! data-model.md §3; FR-IDX-001).
//!
//! # Value extraction (per indexed path)
//! A path is resolved from the document root segment by segment:
//! - on an object, a segment selects the field (absent → `missing`);
//! - on an array, a canonical numeric segment (`a.0`) selects that element; any other segment
//!   **fans out** over the array's object elements (`a.b` with `a = [{b:1},{b:2}]` → 1, 2), as
//!   MongoDB does; non-object elements contribute nothing;
//! - on a scalar, any further segment yields `missing`;
//! - a terminal array value yields one value per element (**multikey**); an empty array is
//!   indexed as the value `[]` itself; nested arrays are indexed as whole values.
//!
//! The values found are deduplicated by their key encoding (one entry per *distinct* element);
//! `missing` is kept only when no value was found. A path "is array-valued" for this document
//! when it fanned out or ended on an array; at most one field of a compound index may be
//! array-valued per document (`RGN-1025 MultikeyCompoundArrays`).
//! *Provisional (PD pending)*: fan-out, empty arrays and `missing` mixed with values are not
//! specified by indexing.md §3; these are the MongoDB rules.
//!
//! # Entries
//! - compound: `enc(v1,dir1) ‖ … ‖ enc(vn,dirn)`, cartesian product over the (single)
//!   array-valued field; non-unique keys end with `enc(_id)`, unique ones do not (value =
//!   `_id`);
//! - `missing` is indexed as such (it orders before `null`), unless the index is **sparse**: then
//!   a document missing *every* indexed field has no entry (MongoDB's compound-sparse rule);
//! - **partial**: a document for which the caller-supplied [`PartialFilter`] returns false has no
//!   entry (the predicate text is evaluated by the query layer, not here);
//! - **wildcard** `path.**` / `**`: one entry per leaf below the path,
//!   `enc(leaf path string) ‖ enc(value, dir) ‖ enc(_id)`; arrays are traversed (multikey),
//!   empty objects and arrays are leaves; the root wildcard skips `_id` and the
//!   server-maintained fields; a missing prefix produces no entry;
//! - key part > 4 KiB: non-unique → truncated (see [`crate::entry`]), unique →
//!   `RGN-1008 IndexKeyTooLarge`;
//! - covered (`INCLUDE`) fields are stored in the value, resolved without fan-out.

use std::collections::BTreeMap;

use rustegon_catalog::{IndexDescriptor, IndexOrder};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
    keyenc::{Direction, decode_key, encode_element},
    keyspace::{index_entry_key, unique_index_key},
    limits::SERVER_MAINTAINED_FIELDS,
    path::{FieldPath, Segment, get_path},
};

use crate::entry::{EntryValue, MAX_KEY_PART, truncate_key_part};

/// Decides whether a document belongs to a partial index (indexing.md §3). Implemented by the
/// query layer's evaluator; tests use closures.
pub trait PartialFilter {
    /// Whether `doc` satisfies the partial predicate of `index` (`index.partial` is `Some`).
    ///
    /// # Errors
    /// Evaluation errors; they reject the write.
    fn matches(&self, index: &IndexDescriptor, doc: &Document) -> Result<bool, Error>;
}

impl<F> PartialFilter for F
where
    F: Fn(&IndexDescriptor, &Document) -> Result<bool, Error>,
{
    fn matches(&self, index: &IndexDescriptor, doc: &Document) -> Result<bool, Error> {
        self(index, doc)
    }
}

/// A [`PartialFilter`] for callers without a predicate evaluator: every partial index is an
/// error (`RGN-1001`), so no document is silently left out of (or put into) such an index.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPartialFilter;

impl PartialFilter for NoPartialFilter {
    fn matches(&self, index: &IndexDescriptor, _doc: &Document) -> Result<bool, Error> {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "partial index {} needs a predicate evaluator (not available yet)",
                index.name
            ),
        ))
    }
}

/// The entries of one document in one index: storage key → entry value bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocEntries {
    /// Entries in key order (keys are full storage keys).
    pub entries: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Whether some indexed path was array-valued (the index becomes multikey).
    pub saw_array: bool,
}

/// Directions of the key-part elements of `index` (wildcard: path string ascending, value).
#[must_use]
pub fn key_directions(index: &IndexDescriptor) -> Vec<Direction> {
    let dir = |o: IndexOrder| match o {
        IndexOrder::Asc => Direction::Ascending,
        IndexOrder::Desc => Direction::Descending,
    };
    if index.is_wildcard() {
        let order = index.fields.first().map_or(IndexOrder::Asc, |f| f.order);
        vec![Direction::Ascending, dir(order)]
    } else {
        index.fields.iter().map(|f| dir(f.order)).collect()
    }
}

/// Computes the entries of `doc` (whose `_id` is `id`) in `index`.
///
/// # Errors
/// `RGN-1025` (two array-valued fields), `RGN-1008` (unique key part > 4 KiB), `RGN-1004`
/// (unencodable values such as counters), partial-filter errors.
pub fn index_entries(
    index: &IndexDescriptor,
    id: &Value,
    doc: &Document,
    filter: &dyn PartialFilter,
) -> Result<DocEntries, Error> {
    let mut out = DocEntries::default();
    if index.partial.is_some() && !filter.matches(index, doc)? {
        return Ok(out);
    }
    let mut id_element = Vec::new();
    encode_element(&mut id_element, Some(id), Direction::Ascending)?;
    let value = EntryValue {
        truncated: false,
        id_element: index.unique.then(|| id_element.clone()),
        include: covered(index, doc)?,
    };
    let dirs = key_directions(index);
    for part in key_parts(index, doc, &dirs, &mut out.saw_array)? {
        let (part, truncated) = if part.len() <= MAX_KEY_PART {
            (part, false)
        } else if index.unique {
            return Err(Error::new(
                ErrorCode::IndexKeyTooLarge,
                format!(
                    "unique index {} key of {} bytes exceeds {MAX_KEY_PART}",
                    index.name,
                    part.len()
                ),
            )
            .with_detail("index", index.name.clone()));
        } else {
            (truncate_key_part(&part), true)
        };
        let key = if index.unique {
            unique_index_key(index.database_id, index.collection_id, index.id, &part)
        } else {
            index_entry_key(index.database_id, index.collection_id, index.id, &part, id)?
        };
        let v = EntryValue {
            truncated,
            ..value.clone()
        };
        out.entries.insert(key, v.encode()?);
    }
    Ok(out)
}

/// The covered-fields object (`None` if the index covers nothing).
fn covered(index: &IndexDescriptor, doc: &Document) -> Result<Option<Document>, Error> {
    if index.include.is_empty() {
        return Ok(None);
    }
    let mut inc = Document::new();
    for p in &index.include {
        let path = FieldPath::parse(p)?;
        if let Some(v) = get_path(doc, &path) {
            inc.insert(p.clone(), v.clone());
        }
    }
    Ok(Some(inc))
}

/// Every key part (without prefix and `_id`) of `doc` in `index`.
fn key_parts(
    index: &IndexDescriptor,
    doc: &Document,
    dirs: &[Direction],
    saw_array: &mut bool,
) -> Result<Vec<Vec<u8>>, Error> {
    if index.is_wildcard() {
        return wildcard_parts(index, doc, dirs, saw_array);
    }
    // Per field: its distinct encoded values.
    let mut per_field: Vec<Vec<Vec<u8>>> = Vec::with_capacity(index.fields.len());
    let mut array_fields = Vec::new();
    let mut all_missing = true;
    for (field, dir) in index.fields.iter().zip(dirs) {
        let path = FieldPath::parse(&field.path)?;
        let mut arr = false;
        let values = extract(doc, path.segments(), &mut arr);
        if arr {
            array_fields.push(field.path.as_str());
        }
        if values.iter().any(Option::is_some) {
            all_missing = false;
        }
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(values.len());
        for v in &values {
            let mut e = Vec::new();
            encode_element(&mut e, v.as_ref(), *dir)?;
            if !encoded.contains(&e) {
                encoded.push(e);
            }
        }
        per_field.push(encoded);
    }
    if array_fields.len() > 1 {
        return Err(Error::new(
            ErrorCode::MultikeyCompoundArrays,
            format!(
                "index {}: at most one array-valued field per document, found {}",
                index.name,
                array_fields.join(", ")
            ),
        )
        .with_detail("index", index.name.clone()));
    }
    *saw_array |= !array_fields.is_empty();
    if index.sparse && all_missing {
        return Ok(Vec::new());
    }
    // Cartesian product; at most one factor has more than one element.
    let mut parts = vec![Vec::new()];
    for values in per_field {
        let mut next = Vec::with_capacity(parts.len() * values.len());
        for p in &parts {
            for v in &values {
                let mut q = p.clone();
                q.extend_from_slice(v);
                next.push(q);
            }
        }
        parts = next;
    }
    Ok(parts)
}

/// Values of `segs` in `doc` (module docs). `None` = missing; never empty.
fn extract(doc: &Document, segs: &[Segment], arr: &mut bool) -> Vec<Option<Value>> {
    let mut out = Vec::new();
    if let Some((first, rest)) = segs.split_first() {
        match doc.get(&first.name) {
            Some(v) => collect(v, rest, &mut out, arr),
            None => out.push(None),
        }
    }
    let found: Vec<_> = out.iter().filter(|v| v.is_some()).cloned().collect();
    if found.is_empty() { vec![None] } else { found }
}

fn collect(v: &Value, segs: &[Segment], out: &mut Vec<Option<Value>>, arr: &mut bool) {
    let Some((seg, rest)) = segs.split_first() else {
        match v {
            Value::Array(items) if !items.is_empty() => {
                *arr = true;
                out.extend(items.iter().cloned().map(Some));
            }
            Value::Array(_) => {
                *arr = true;
                out.push(Some(v.clone()));
            }
            _ => out.push(Some(v.clone())),
        }
        return;
    };
    match v {
        Value::Object(d) => match d.get(&seg.name) {
            Some(c) => collect(c, rest, out, arr),
            None => out.push(None),
        },
        Value::Array(items) => {
            if let Some(i) = seg.index {
                match items.get(i) {
                    Some(c) => collect(c, rest, out, arr),
                    None => out.push(None),
                }
            } else {
                *arr = true;
                let mut any = false;
                for it in items {
                    if matches!(it, Value::Object(_)) {
                        any = true;
                        collect(it, segs, out, arr);
                    }
                }
                if !any {
                    out.push(None);
                }
            }
        }
        _ => out.push(None),
    }
}

/// Key parts of a wildcard index (module docs).
fn wildcard_parts(
    index: &IndexDescriptor,
    doc: &Document,
    dirs: &[Direction],
    saw_array: &mut bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let value_dir = dirs.get(1).copied().unwrap_or(Direction::Ascending);
    let mut leaves: Vec<(String, Value)> = Vec::new();
    match index.fields.first().and_then(|f| f.wildcard_prefix()) {
        None => {
            for (name, v) in doc.iter() {
                if name == "_id" || SERVER_MAINTAINED_FIELDS.contains(&name) {
                    continue;
                }
                let mut path = String::new();
                push_segment(&mut path, name);
                walk(v, &mut path, &mut leaves, saw_array);
            }
        }
        Some(prefix) => {
            let p = FieldPath::parse(prefix)?;
            if let Some(v) = get_path(doc, &p) {
                let mut path = prefix.to_owned();
                walk(v, &mut path, &mut leaves, saw_array);
            }
        }
    }
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(leaves.len());
    for (path, v) in leaves {
        let mut part = Vec::new();
        encode_element(&mut part, Some(&Value::String(path)), Direction::Ascending)?;
        encode_element(&mut part, Some(&v), value_dir)?;
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    Ok(parts)
}

/// Appends a path segment, backtick-quoted when it contains a dot (data-model.md §2.2).
fn push_segment(path: &mut String, name: &str) {
    if !path.is_empty() {
        path.push('.');
    }
    if name.contains('.') {
        path.push('`');
        path.push_str(name);
        path.push('`');
    } else {
        path.push_str(name);
    }
}

fn walk(v: &Value, path: &mut String, leaves: &mut Vec<(String, Value)>, saw_array: &mut bool) {
    match v {
        Value::Object(d) if !d.is_empty() => {
            for (name, c) in d.iter() {
                let len = path.len();
                push_segment(path, name);
                walk(c, path, leaves, saw_array);
                path.truncate(len);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            *saw_array = true;
            for it in items {
                if matches!(it, Value::Array(_)) {
                    leaves.push((path.clone(), it.clone()));
                } else {
                    walk(it, path, leaves, saw_array);
                }
            }
        }
        _ => leaves.push((path.clone(), v.clone())),
    }
}

/// Human-readable form of a key part for error details (`[v1, v2]`, `missing` for absent
/// values), or a placeholder for undecodable (truncated) parts.
#[must_use]
pub fn display_key_part(index: &IndexDescriptor, part: &[u8]) -> String {
    match decode_key(part, &key_directions(index)) {
        Ok(values) => {
            let items: Vec<String> = values
                .iter()
                .map(|v| {
                    v.as_ref().map_or_else(
                        || "missing".to_owned(),
                        |v| value_to_json(v, JsonMode::Canonical),
                    )
                })
                .collect();
            format!("[{}]", items.join(", "))
        }
        Err(_) => "<truncated key>".to_owned(),
    }
}
