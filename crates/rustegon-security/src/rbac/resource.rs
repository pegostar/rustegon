// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Resources (what a request touches) and resource patterns (what a privilege names).
//!
//! Text forms (security.md §3.1): `cluster`, `database:<db>`, `collection:<db>.<coll>`, where a
//! pattern may replace `<db>` or `<coll>` by `*`. Semantics (*Provisional (PD-048)*):
//! - `*` stands for a **whole** name component (any database / any collection); there is no
//!   prefix globbing (`logs_*` is an invalid name, not a pattern).
//! - Patterns are hierarchical: `cluster` covers every resource, `database:<db>` covers the
//!   database and all of its collections, `collection:<db>.<coll>` covers that collection only.
//!   So `root` is simply "every action on `cluster`", and `cluster_admin`'s `query_kill` on
//!   `cluster` kills queries in any database.
//! - Database names never contain `.` (catalog name rules), so `<db>.<coll>` splits at the
//!   first dot even when the collection name contains dots.

use std::fmt;

use rustegon_catalog::name::{validate_collection_name, validate_database_name};

use super::RbacError;

/// Wildcard component of a pattern.
pub const WILDCARD: &str = "*";
const CLUSTER: &str = "cluster";
const DATABASE_PREFIX: &str = "database:";
const COLLECTION_PREFIX: &str = "collection:";

/// Level of a resource in the hierarchy cluster ⊃ database ⊃ collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceKind {
    /// A collection (finest).
    Collection,
    /// A database.
    Database,
    /// The cluster (coarsest).
    Cluster,
}

/// A concrete resource a request acts on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    /// Cluster-wide operations (settings, nodes, backups, …).
    Cluster,
    /// A database (DDL on the database, database-wide operations).
    Database(String),
    /// A collection.
    Collection {
        /// Database name.
        db: String,
        /// Collection name.
        coll: String,
    },
}

impl Resource {
    /// A collection resource.
    #[must_use]
    pub fn collection(db: impl Into<String>, coll: impl Into<String>) -> Self {
        Self::Collection {
            db: db.into(),
            coll: coll.into(),
        }
    }

    /// A database resource.
    #[must_use]
    pub fn database(db: impl Into<String>) -> Self {
        Self::Database(db.into())
    }

    /// The level of the resource.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Cluster => ResourceKind::Cluster,
            Self::Database(_) => ResourceKind::Database,
            Self::Collection { .. } => ResourceKind::Collection,
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cluster => f.write_str(CLUSTER),
            Self::Database(db) => write!(f, "{DATABASE_PREFIX}{db}"),
            Self::Collection { db, coll } => write!(f, "{COLLECTION_PREFIX}{db}.{coll}"),
        }
    }
}

/// One name component of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NamePattern {
    /// `*`: any name.
    Any,
    /// Exactly this name.
    Exact(String),
}

impl NamePattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(n) => n == name,
        }
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str(WILDCARD),
            Self::Exact(n) => f.write_str(n),
        }
    }
}

/// The resource part of a privilege (module docs for the semantics).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourcePattern {
    /// `cluster`: every resource.
    Cluster,
    /// `database:<db>`: the database(s) and their collections.
    Database(NamePattern),
    /// `collection:<db>.<coll>`.
    Collection(NamePattern, NamePattern),
}

impl ResourcePattern {
    /// `database:<db>` for one database.
    #[must_use]
    pub fn database(db: impl Into<String>) -> Self {
        Self::Database(NamePattern::Exact(db.into()))
    }

    /// `collection:<db>.<coll>` for one collection.
    #[must_use]
    pub fn collection(db: impl Into<String>, coll: impl Into<String>) -> Self {
        Self::Collection(
            NamePattern::Exact(db.into()),
            NamePattern::Exact(coll.into()),
        )
    }

    /// The level of the pattern.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Cluster => ResourceKind::Cluster,
            Self::Database(_) => ResourceKind::Database,
            Self::Collection(..) => ResourceKind::Collection,
        }
    }

    /// Whether the pattern covers `resource` (hierarchically, module docs).
    #[must_use]
    pub fn covers(&self, resource: &Resource) -> bool {
        match (self, resource) {
            (Self::Cluster, _) => true,
            (Self::Database(p), Resource::Database(db) | Resource::Collection { db, .. }) => {
                p.matches(db)
            }
            (Self::Collection(pdb, pcoll), Resource::Collection { db, coll }) => {
                pdb.matches(db) && pcoll.matches(coll)
            }
            _ => false,
        }
    }

    /// Parses the text form (module docs).
    ///
    /// # Errors
    /// [`RbacError::InvalidResource`] for anything else, including invalid names.
    pub fn parse(text: &str) -> Result<Self, RbacError> {
        let invalid = |reason: &str| RbacError::InvalidResource {
            resource: text.to_owned(),
            reason: reason.to_owned(),
        };
        if text == CLUSTER {
            return Ok(Self::Cluster);
        }
        if let Some(db) = text.strip_prefix(DATABASE_PREFIX) {
            return Ok(Self::Database(db_pattern(db).map_err(|r| invalid(&r))?));
        }
        if let Some(rest) = text.strip_prefix(COLLECTION_PREFIX) {
            let (db, coll) = rest
                .split_once('.')
                .ok_or_else(|| invalid("expected collection:<db>.<coll>"))?;
            return Ok(Self::Collection(
                db_pattern(db).map_err(|r| invalid(&r))?,
                coll_pattern(coll).map_err(|r| invalid(&r))?,
            ));
        }
        Err(invalid(
            "expected cluster, database:<db> or collection:<db>.<coll>",
        ))
    }
}

fn db_pattern(name: &str) -> Result<NamePattern, String> {
    if name == WILDCARD {
        return Ok(NamePattern::Any);
    }
    validate_database_name(name).map_err(|e| e.to_string())?;
    Ok(NamePattern::Exact(name.to_owned()))
}

fn coll_pattern(name: &str) -> Result<NamePattern, String> {
    if name == WILDCARD {
        return Ok(NamePattern::Any);
    }
    validate_collection_name(name).map_err(|e| e.to_string())?;
    Ok(NamePattern::Exact(name.to_owned()))
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cluster => f.write_str(CLUSTER),
            Self::Database(db) => write!(f, "{DATABASE_PREFIX}{db}"),
            Self::Collection(db, coll) => write!(f, "{COLLECTION_PREFIX}{db}.{coll}"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        for text in [
            "cluster",
            "database:shop",
            "database:*",
            "collection:shop.orders",
            "collection:shop.*",
            "collection:*.orders",
            "collection:*.*",
            "collection:shop.orders.2026",
        ] {
            assert_eq!(ResourcePattern::parse(text).unwrap().to_string(), text);
        }
        for bad in [
            "",
            "Cluster",
            "database:",
            "database:Shop",
            "database:logs_*",
            "collection:shop",
            "collection:shop.",
            "collection:sh*p.orders",
            "table:shop.orders",
        ] {
            assert!(ResourcePattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn patterns_are_hierarchical_and_wildcards_match_whole_names() {
        let orders = Resource::collection("shop", "orders");
        let shop = Resource::database("shop");
        let p = |t| ResourcePattern::parse(t).unwrap();
        assert!(p("cluster").covers(&orders) && p("cluster").covers(&Resource::Cluster));
        assert!(p("database:shop").covers(&orders) && p("database:shop").covers(&shop));
        assert!(!p("database:shop").covers(&Resource::Cluster));
        assert!(!p("database:shop").covers(&Resource::collection("shop2", "orders")));
        assert!(p("database:*").covers(&orders) && !p("database:*").covers(&Resource::Cluster));
        assert!(p("collection:shop.orders").covers(&orders));
        assert!(!p("collection:shop.orders").covers(&shop));
        assert!(!p("collection:shop.orders").covers(&Resource::collection("shop", "order")));
        assert!(p("collection:*.orders").covers(&Resource::collection("crm", "orders")));
        assert!(p("collection:shop.*").covers(&orders));
        assert!(!p("collection:shop.*").covers(&Resource::collection("crm", "orders")));
    }
}
