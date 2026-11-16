// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Role resolution and privilege evaluation (security.md §3.1): the effective privileges of a
//! principal are the union of the privileges of all its roles, inherited roles included;
//! anything not granted is denied; there are no negative privileges.

use std::collections::{BTreeMap, BTreeSet};

use rustegon_common::{Error, ErrorCode};

use super::{
    RbacError,
    action::Action,
    resource::Resource,
    role::{Privilege, Role, RoleRef},
};

/// In-memory snapshot of the custom roles (loaded from the system keyspace by
/// [`super::store::load_roles`]). Invariant: inheritance among custom roles is acyclic and only
/// names existing roles — the store enforces both on every write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleCatalog {
    roles: BTreeMap<String, Role>,
}

impl RoleCatalog {
    /// An empty catalog (built-in roles only).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The custom role `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    /// All custom roles in name order.
    pub fn roles(&self) -> impl Iterator<Item = &Role> {
        self.roles.values()
    }

    /// Number of custom roles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roles.len()
    }

    /// Whether there is no custom role.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    /// Inserts or replaces `role` after validating it against the catalog: name and privileges
    /// valid, every inherited role exists, and the inheritance graph stays acyclic (TC-SEC-015).
    /// On error the catalog is unchanged.
    ///
    /// # Errors
    /// [`RbacError::InvalidRoleName`], [`RbacError::InvalidPrivilege`],
    /// [`RbacError::UnknownRole`], [`RbacError::InheritanceCycle`].
    pub fn upsert(&mut self, role: Role) -> Result<(), RbacError> {
        role.validate()?;
        for parent in &role.inherits {
            let (name, builtin, _) = parent.split()?;
            if builtin.is_none() && name != role.name && !self.roles.contains_key(name) {
                return Err(RbacError::UnknownRole(parent.to_string()));
            }
        }
        let name = role.name.clone();
        let previous = self.roles.insert(name.clone(), role);
        if let Some(cycle) = self.find_cycle_from(&name) {
            // Restore the previous state: the catalog must stay acyclic.
            match previous {
                Some(p) => self.roles.insert(name, p),
                None => self.roles.remove(&name),
            };
            return Err(RbacError::InheritanceCycle(cycle.join(" -> ")));
        }
        Ok(())
    }

    /// Removes the custom role `name`.
    ///
    /// # Errors
    /// [`RbacError::UnknownRole`] if absent; [`RbacError::RoleInUse`] if another custom role
    /// inherits it (dropping it would silently shrink that role).
    pub fn remove(&mut self, name: &str) -> Result<Role, RbacError> {
        if let Some(heir) = self
            .roles
            .values()
            .find(|r| r.inherits.iter().any(|p| p.as_str() == name))
        {
            return Err(RbacError::RoleInUse {
                role: name.to_owned(),
                inherited_by: heir.name.clone(),
            });
        }
        self.roles
            .remove(name)
            .ok_or_else(|| RbacError::UnknownRole(name.to_owned()))
    }

    /// Depth-first search for a cycle reachable from `start` through custom-role inheritance
    /// (built-in roles inherit nothing, so they end every path). Returns the cycle's path.
    fn find_cycle_from(&self, start: &str) -> Option<Vec<String>> {
        fn visit<'a>(
            cat: &'a RoleCatalog,
            name: &'a str,
            path: &mut Vec<&'a str>,
            done: &mut BTreeSet<&'a str>,
        ) -> Option<Vec<String>> {
            if let Some(pos) = path.iter().position(|n| *n == name) {
                let mut cycle: Vec<String> = path[pos..].iter().map(|s| (*s).to_owned()).collect();
                cycle.push(name.to_owned());
                return Some(cycle);
            }
            if done.contains(name) {
                return None;
            }
            let role = cat.roles.get(name)?;
            path.push(name);
            for parent in &role.inherits {
                if let Some(c) = visit(cat, parent.name(), path, done) {
                    return Some(c);
                }
            }
            path.pop();
            done.insert(name);
            None
        }
        visit(self, start, &mut Vec::new(), &mut BTreeSet::new())
    }

    /// The effective privileges of a principal holding `roles` (security.md §3.1).
    ///
    /// Role names that do not resolve (a custom role dropped after it was granted, a malformed
    /// name in an old user record) grant nothing and are reported in
    /// [`EffectivePrivileges::unresolved`]: deny by default, without locking the user out of the
    /// privileges of their other roles.
    #[must_use]
    pub fn resolve<S: AsRef<str>>(&self, roles: &[S]) -> EffectivePrivileges {
        let mut out = EffectivePrivileges::default();
        let mut seen = BTreeSet::new();
        let mut stack: Vec<String> = roles.iter().rev().map(|r| r.as_ref().to_owned()).collect();
        while let Some(text) = stack.pop() {
            if !seen.insert(text.clone()) {
                continue;
            }
            let Ok(role_ref) = RoleRef::parse(&text) else {
                out.unresolved.push(text);
                continue;
            };
            let Ok((name, builtin, scope)) = role_ref.split() else {
                out.unresolved.push(text);
                continue;
            };
            if let Some(b) = builtin {
                out.privileges.push(b.privileges(scope.as_ref()));
            } else if let Some(role) = self.roles.get(name) {
                out.privileges.extend(role.privileges.iter().cloned());
                stack.extend(role.inherits.iter().rev().map(ToString::to_string));
            } else {
                out.unresolved.push(text);
                continue;
            }
            out.roles.push(text);
        }
        out
    }
}

/// The resolved privileges of a principal (user, or API key restricted to its scope).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectivePrivileges {
    roles: Vec<String>,
    privileges: Vec<Privilege>,
    unresolved: Vec<String>,
    /// API key scope: when set, an action must also be allowed by the scope (intersection).
    scope: Option<Box<EffectivePrivileges>>,
}

impl EffectivePrivileges {
    /// Every role that contributed privileges, inherited ones included (audit `roles` field).
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// The union of the privileges of [`EffectivePrivileges::roles`].
    #[must_use]
    pub fn privileges(&self) -> &[Privilege] {
        &self.privileges
    }

    /// Role names that granted nothing because they do not resolve.
    #[must_use]
    pub fn unresolved(&self) -> &[String] {
        &self.unresolved
    }

    /// Restricts these privileges to `scope` (security.md §2, API key "scope = roles subset"):
    /// an action is then allowed only if both the owner's roles and the key's scope allow it, so
    /// a key can never exceed its owner even if the owner loses roles after the key was issued.
    #[must_use]
    pub fn restrict_to(mut self, scope: EffectivePrivileges) -> Self {
        self.scope = Some(Box::new(match self.scope.take() {
            // Nested restriction: both scopes apply.
            Some(existing) => existing.restrict_to(scope),
            None => scope,
        }));
        self
    }

    /// Whether `action` on `resource` is allowed (deny by default).
    #[must_use]
    pub fn allows(&self, resource: &Resource, action: Action) -> bool {
        self.privileges
            .iter()
            .any(|p| p.actions.contains(action) && p.resource.covers(resource))
            && self
                .scope
                .as_ref()
                .is_none_or(|s| s.allows(resource, action))
    }

    /// [`EffectivePrivileges::allows`] as a result.
    ///
    /// # Errors
    /// `RGN-4002 PermissionDenied` with details `action` and `resource`.
    pub fn authorize(&self, resource: &Resource, action: Action) -> Result<(), Error> {
        if self.allows(resource, action) {
            Ok(())
        } else {
            Err(permission_denied(resource, action))
        }
    }
}

/// Checks that the principal may perform `action` on `resource` — the entry point of the
/// binder and of every service handler.
///
/// # Errors
/// `RGN-4002 PermissionDenied`.
pub fn authorize(
    effective: &EffectivePrivileges,
    resource: &Resource,
    action: Action,
) -> Result<(), Error> {
    effective.authorize(resource, action)
}

/// The `RGN-4002` error for a denied check. Names of databases and collections are not secret;
/// the user is not included (the caller's audit event carries it).
#[must_use]
pub fn permission_denied(resource: &Resource, action: Action) -> Error {
    Error::new(
        ErrorCode::PermissionDenied,
        format!("permission denied: {action} on {resource}"),
    )
    .with_detail("action", action.as_str())
    .with_detail("resource", resource.to_string())
}

/// Checks an API key scope at key creation: every scope role must be one of the owner's roles
/// (security.md §2 "scope = roles subset"). Evaluation additionally intersects at request time
/// ([`EffectivePrivileges::restrict_to`]).
///
/// # Errors
/// [`RbacError::ScopeNotSubset`] naming the first offending role; [`RbacError::InvalidRoleName`]
/// for a malformed scope role.
pub fn check_api_key_scope<S: AsRef<str>, T: AsRef<str>>(
    owner_roles: &[S],
    scope: &[T],
) -> Result<(), RbacError> {
    for role in scope {
        RoleRef::parse(role.as_ref())?;
        if !owner_roles.iter().any(|o| o.as_ref() == role.as_ref()) {
            return Err(RbacError::ScopeNotSubset(role.as_ref().to_owned()));
        }
    }
    Ok(())
}
