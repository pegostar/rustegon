// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Actions of security.md §3.2 and compact action sets.

use std::fmt;

use super::resource::ResourceKind;

/// Group of an action (security.md §3.2 table rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionGroup {
    /// Reads and writes of documents.
    Data,
    /// DDL.
    Schema,
    /// Transaction and query operations.
    TxnOps,
    /// Administration.
    Admin,
}

macro_rules! actions {
    ($( $variant:ident => $name:literal, $group:ident, $finest:ident; )*) => {
        /// One action of security.md §3.2. A privilege grants actions on a resource pattern.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Action {
            $(
                #[doc = concat!("`", $name, "`.")]
                $variant,
            )*
        }

        impl Action {
            /// Every action, in declaration order (the order of security.md §3.2).
            pub const ALL: &'static [Action] = &[$(Action::$variant),*];

            /// The snake-case name used in role records, APIs and audit events.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Action::$variant => $name,)*
                }
            }

            /// Parses a name produced by [`Action::as_str`].
            #[must_use]
            pub fn parse(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Action::$variant),)*
                    _ => None,
                }
            }

            /// The group of the action.
            #[must_use]
            pub const fn group(self) -> ActionGroup {
                match self {
                    $(Action::$variant => ActionGroup::$group,)*
                }
            }

            /// The finest resource level the action can be checked on: a privilege granting it
            /// must name a resource at this level or a coarser one (PD-048). `query_kill` on a
            /// database makes sense, `cluster_manage` on a database does not.
            #[must_use]
            pub const fn finest_scope(self) -> ResourceKind {
                match self {
                    $(Action::$variant => ResourceKind::$finest,)*
                }
            }
        }
    };
}

actions! {
    Find => "find", Data, Collection;
    Insert => "insert", Data, Collection;
    Update => "update", Data, Collection;
    Delete => "delete", Data, Collection;
    BulkWrite => "bulk_write", Data, Collection;
    AggregateWrite => "aggregate_write", Data, Collection;
    ChangeStream => "change_stream", Data, Collection;
    SubscriptionManage => "subscription_manage", Data, Collection;
    CreateCollection => "create_collection", Schema, Collection;
    DropCollection => "drop_collection", Schema, Collection;
    AlterCollection => "alter_collection", Schema, Collection;
    CreateIndex => "create_index", Schema, Collection;
    DropIndex => "drop_index", Schema, Collection;
    CreateDatabase => "create_database", Schema, Database;
    DropDatabase => "drop_database", Schema, Database;
    TxnKill => "txn_kill", TxnOps, Database;
    QueryKill => "query_kill", TxnOps, Database;
    QueryStatsView => "query_stats_view", TxnOps, Database;
    UserManage => "user_manage", Admin, Database;
    RoleManage => "role_manage", Admin, Database;
    ClusterView => "cluster_view", Admin, Cluster;
    ClusterManage => "cluster_manage", Admin, Cluster;
    Backup => "backup", Admin, Cluster;
    Restore => "restore", Admin, Cluster;
    AuditView => "audit_view", Admin, Cluster;
    Diagnostics => "diagnostics", Admin, Cluster;
    XdcManage => "xdc_manage", Admin, Cluster;
    KeyManage => "key_manage", Admin, Cluster;
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of actions as a bit set (one bit per [`Action`] discriminant): evaluation is a mask
/// test instead of a search, and the set is `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ActionSet(u32);

// The bit set must hold every action.
const _: () = assert!(Action::ALL.len() <= 32);

impl ActionSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// Every action.
    #[must_use]
    pub const fn all() -> Self {
        let mut bits = 0u32;
        let mut i = 0;
        while i < Action::ALL.len() {
            bits |= 1 << (Action::ALL[i] as u8);
            i += 1;
        }
        Self(bits)
    }

    /// The set of the given actions.
    #[must_use]
    pub const fn of(actions: &[Action]) -> Self {
        let mut bits = 0u32;
        let mut i = 0;
        while i < actions.len() {
            bits |= 1 << (actions[i] as u8);
            i += 1;
        }
        Self(bits)
    }

    /// Every action of `group`.
    #[must_use]
    pub fn group(group: ActionGroup) -> Self {
        Action::ALL
            .iter()
            .filter(|a| a.group() == group)
            .copied()
            .collect()
    }

    /// Whether `action` is in the set.
    #[must_use]
    pub const fn contains(self, action: Action) -> bool {
        self.0 & (1 << (action as u8)) != 0
    }

    /// Adds `action`.
    pub fn insert(&mut self, action: Action) {
        self.0 |= 1 << (action as u8);
    }

    /// Set union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set difference.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The actions of the set in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Action> {
        Action::ALL
            .iter()
            .copied()
            .filter(move |a| self.contains(*a))
    }
}

impl FromIterator<Action> for ActionSet {
    fn from_iter<I: IntoIterator<Item = Action>>(iter: I) -> Self {
        let mut set = Self::EMPTY;
        for a in iter {
            set.insert(a);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_of_security_md_3_2_round_trips_by_name() {
        assert_eq!(Action::ALL.len(), 28);
        for a in Action::ALL {
            assert_eq!(Action::parse(a.as_str()), Some(*a));
        }
        assert_eq!(Action::parse("FIND"), None);
        assert_eq!(ActionSet::group(ActionGroup::Data).iter().count(), 8);
        assert_eq!(ActionSet::group(ActionGroup::Schema).iter().count(), 7);
        assert_eq!(ActionSet::group(ActionGroup::TxnOps).iter().count(), 3);
        assert_eq!(ActionSet::group(ActionGroup::Admin).iter().count(), 10);
    }

    #[test]
    fn action_set_operations() {
        let s = ActionSet::of(&[Action::Find, Action::Insert]);
        assert!(s.contains(Action::Find) && !s.contains(Action::Delete));
        assert_eq!(s.union(ActionSet::of(&[Action::Delete])).iter().count(), 3);
        assert_eq!(
            s.without(ActionSet::of(&[Action::Find])),
            ActionSet::of(&[Action::Insert])
        );
        assert_eq!(ActionSet::all().iter().count(), Action::ALL.len());
        assert!(ActionSet::EMPTY.is_empty());
    }
}
