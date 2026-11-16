// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The DDL subset of RGQL (query-language.md §11) the embedded API executes through its
//! catalog methods: `CREATE DATABASE`, `CREATE COLLECTION`, `CREATE [UNIQUE] INDEX` (options
//! `sparse`, `partial`, `hidden`, `include`) and `DROP INDEX`. Database and collection options,
//! TTL / full-text / vector / geo / local indexes and the other DDL statements belong to later
//! milestones and are rejected as unsupported.

use rustegon_catalog::{CollectionSpec, DatabaseOptions, IndexField, IndexSpec};
use rustegon_common::Error;
use rustegon_doc::Value;
use rustegon_query::{
    Params, QueryResult, Statement,
    ast::{CreateIndex, IndexType, OptionItem, Path, Segment},
    bind::ExprBinder,
    error::{invalid, unsupported},
    plan::rewrite::fold_constant,
};

use super::EmbeddedDb;

/// Whether `stmt` is DDL handled here.
pub(super) fn is_ddl(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::CreateDatabase { .. }
            | Statement::CreateCollection { .. }
            | Statement::CreateIndex(_)
            | Statement::DropIndex { .. }
    )
}

/// Executes a DDL statement (each in its own transaction).
pub(super) fn run(
    db: &EmbeddedDb,
    session_db: &str,
    stmt: &Statement,
    params: &Params,
) -> Result<QueryResult, Error> {
    match stmt {
        Statement::CreateDatabase { name, options } => {
            no_options(options, "database options")?;
            db.create_database(name, &DatabaseOptions::default())?;
        }
        Statement::CreateCollection { name, options } => {
            no_options(options, "collection options")?;
            let database = name.database.as_deref().unwrap_or(session_db);
            db.create_collection(database, &CollectionSpec::document(name.name.clone()))?;
        }
        Statement::CreateIndex(ci) => {
            let database = ci.on.database.as_deref().unwrap_or(session_db);
            db.create_index(database, &ci.on.name, &index_spec(ci, params)?)?;
        }
        Statement::DropIndex { name } => {
            let database = name.collection.database.as_deref().unwrap_or(session_db);
            db.drop_index(database, &name.collection.name, &name.index)?;
        }
        _ => return Err(unsupported("this DDL statement", "a later milestone")),
    }
    Ok(QueryResult::default())
}

fn no_options(options: &[OptionItem], what: &str) -> Result<(), Error> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(unsupported(what, "a later milestone"))
    }
}

/// The dotted path of an index key (wildcard keys `a.**` / `**` are written as one quoted
/// segment, `` `a.**` ``, and kept verbatim).
fn key_path(path: &Path) -> Result<String, Error> {
    let mut out = String::new();
    for seg in &path.0 {
        if !out.is_empty() {
            out.push('.');
        }
        match seg {
            Segment::Field(n) if n == "**" || n.ends_with(".**") || !n.contains('.') => {
                out.push_str(n);
            }
            Segment::Field(n) => {
                out.push('`');
                out.push_str(n);
                out.push('`');
            }
            Segment::Position(p) => out.push_str(&p.to_string()),
            Segment::Index(_) | Segment::Each => {
                return Err(invalid("an index key must be a field path"));
            }
        }
    }
    Ok(out)
}

pub(super) fn index_spec(ci: &CreateIndex, params: &Params) -> Result<IndexSpec, Error> {
    let unique = match ci.index_type {
        IndexType::Standard => false,
        IndexType::Unique => true,
        IndexType::Ttl => return Err(unsupported("TTL indexes", "M8")),
        IndexType::Fulltext => return Err(unsupported("full-text indexes", "M7")),
        IndexType::Vector => return Err(unsupported("vector indexes", "M9")),
        IndexType::Geo => return Err(unsupported("geospatial indexes", "M7")),
        IndexType::Local => return Err(unsupported("local (table) indexes", "M8")),
    };
    if ci.expire_after.is_some() {
        return Err(unsupported("EXPIRE AFTER", "M8"));
    }
    let mut fields = Vec::with_capacity(ci.keys.len());
    for k in &ci.keys {
        if k.analyzer.is_some() || k.boost.is_some() {
            return Err(unsupported("full-text key options", "M7"));
        }
        let p = key_path(&k.path)?;
        fields.push(if k.descending {
            IndexField::desc(p)
        } else {
            IndexField::asc(p)
        });
    }
    let mut spec = IndexSpec::new(ci.name.clone(), fields);
    spec.unique = unique;
    for item in &ci.options {
        let mut eb = ExprBinder::new(params, None);
        let v = fold_constant(eb.bind(&item.value)?);
        let bad = || invalid(format!("invalid value for index option {}", item.name));
        match (item.name.to_ascii_lowercase().as_str(), v) {
            ("sparse", Some(Value::Bool(b))) => spec.sparse = b,
            ("hidden", Some(Value::Bool(b))) => spec.hidden = b,
            ("unique", Some(Value::Bool(b))) => spec.unique = b,
            ("partial", Some(Value::String(s))) => spec.partial = Some(s),
            ("include", Some(Value::Array(items))) => {
                spec.include = items
                    .into_iter()
                    .map(|v| match v {
                        Value::String(s) => Ok(s),
                        _ => Err(bad()),
                    })
                    .collect::<Result<_, _>>()?;
            }
            ("sparse" | "hidden" | "unique" | "partial" | "include", _) => return Err(bad()),
            (other, _) => return Err(invalid(format!("unknown index option {other}"))),
        }
    }
    Ok(spec)
}
