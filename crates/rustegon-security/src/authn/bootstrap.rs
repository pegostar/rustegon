// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! First administrator without default credentials (security.md §2.2, FR-SEC-003,
//! TC-SEC-003; PD-047).
//!
//! A fresh cluster has no user, no API key and no realm record, so no credential can
//! authenticate: every SCRAM handshake takes the unknown-user path, every API key lookup
//! misses and every certificate user is unknown. [`bootstrap_admin`] is the only way in. It
//! runs once — it refuses when any user exists — and in one transaction creates the realm
//! secret ([`crate::authn::realm`]) and the admin user with the `root` role and either:
//!
//! - the operator's password ([`AdminPassword::Provided`]: interactive prompt,
//!   `--admin-password-file`, `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`), which must pass the
//!   password policy, or
//! - a generated [`crate::authn::password::GENERATED_LENGTH`]-character password
//!   ([`AdminPassword::Generate`], non-interactive init without a password), returned to the
//!   caller and flagged `must_change_password`, or
//! - the turnkey packages' local bootstrap password `admin` ([`AdminPassword::Turnkey`],
//!   ADR-036: `rustegon init --turnkey`, used by the MSI, DEB and RPM): the only password that
//!   skips the policy, always flagged `must_change_password`. The server additionally refuses to
//!   start while it is unchanged and a listener is not on loopback ([`has_turnkey_password`]).
//!
//! Writing the generated password to `<data_dir>/initial-admin-password` (0600) and printing
//! it once are the `rustegon init` command's job (M4 wave 3); this module never logs it.

use std::time::SystemTime;

use rustegon_catalog::CatalogRead;
use rustegon_sim_api::Rng;

use crate::authn::{
    PasswordChange, SecretString,
    error::{AuthnError, AuthnResult},
    password::generate_password,
    realm,
    scram::ScramCredentials,
    settings::AuthnSettings,
    store::{SystemTxn, user_prefix},
    users::{NewUser, PreparedUser, UserRecord, insert_user, prepare_user},
};

/// Name of the bootstrap administrator when the operator does not choose one.
pub const DEFAULT_ADMIN_USER: &str = "admin";
/// Role of the bootstrap administrator (security.md §3.3).
pub const ADMIN_ROLE: &str = "root";
/// Password of the turnkey bootstrap account (ADR-036). Known to everybody by design: it is
/// accepted only until the first password change and only while every listener is on
/// loopback.
pub const TURNKEY_ADMIN_PASSWORD: &str = "admin";

/// Where the first admin's password comes from.
#[derive(Debug)]
pub enum AdminPassword {
    /// Chosen by the operator; must pass the password policy.
    Provided(SecretString),
    /// Generated; the admin must change it at first login.
    Generate,
    /// The turnkey packages' [`TURNKEY_ADMIN_PASSWORD`] (ADR-036): bypasses the password
    /// policy; the admin must change it at first login.
    Turnkey,
}

/// Result of a bootstrap.
#[derive(Debug)]
pub struct Bootstrapped {
    /// The created admin.
    pub admin: UserRecord,
    /// The generated password, when [`AdminPassword::Generate`] was used.
    pub generated_password: Option<SecretString>,
}

/// Whether the cluster has been bootstrapped (any user exists).
///
/// # Errors
/// Store errors.
pub fn is_bootstrapped(txn: &dyn CatalogRead) -> AuthnResult<bool> {
    Ok(!txn.scan_prefix(&user_prefix())?.is_empty())
}

/// Creates the first administrator (module docs): [`prepare_bootstrap`] then
/// [`insert_bootstrap`] in one transaction (services prepare outside it).
///
/// # Errors
/// `PreconditionFailed` when a user exists already; `InvalidArgument` for an invalid name or a
/// weak provided password; store errors.
pub fn bootstrap_admin(
    txn: &mut dyn SystemTxn,
    admin: &str,
    password: AdminPassword,
    settings: &AuthnSettings,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<Bootstrapped> {
    // Checked first so that a bootstrapped store reports it whatever the password.
    if is_bootstrapped(txn)? {
        return Err(already_bootstrapped());
    }
    let prepared = prepare_bootstrap(admin, password, settings, rng)?;
    insert_bootstrap(txn, &prepared, now, rng)
}

/// The first administrator with its password chosen (provided or generated) and turned into
/// SCRAM credentials ([`prepare_bootstrap`]).
#[derive(Debug, Clone)]
pub struct PreparedBootstrap {
    user: PreparedUser,
    generated_password: Option<SecretString>,
}

/// Chooses the first administrator's password and derives its credentials — the PBKDF2 half
/// of the bootstrap, run before the transaction (see [`crate::authn::users::prepare_user`]).
///
/// # Errors
/// `InvalidArgument` for an invalid name or a weak provided password.
pub fn prepare_bootstrap(
    admin: &str,
    password: AdminPassword,
    settings: &AuthnSettings,
    rng: &dyn Rng,
) -> AuthnResult<PreparedBootstrap> {
    let (pw, change, generated) = match password {
        AdminPassword::Provided(pw) => (pw, PasswordChange::NotRequired, false),
        AdminPassword::Generate => (generate_password(rng), PasswordChange::Required, true),
        AdminPassword::Turnkey => {
            // The one policy bypass (ADR-036): credentials derived directly, never through
            // `prepare_password`, so no other path can store a weak password.
            let user = prepare_user(
                &NewUser {
                    name: admin,
                    password: None,
                    roles: vec![ADMIN_ROLE.to_owned()],
                    password_change: PasswordChange::Required,
                },
                settings,
                rng,
            )?
            .with_scram(ScramCredentials::generate(
                TURNKEY_ADMIN_PASSWORD,
                settings.scram_iterations,
                rng,
            )?);
            return Ok(PreparedBootstrap {
                user,
                generated_password: None,
            });
        }
    };
    let user = prepare_user(
        &NewUser {
            name: admin,
            password: Some(&pw),
            roles: vec![ADMIN_ROLE.to_owned()],
            password_change: change,
        },
        settings,
        rng,
    )?;
    Ok(PreparedBootstrap {
        user,
        generated_password: generated.then_some(pw),
    })
}

/// Writes a [`prepare_bootstrap`] result: the authentication realm and the administrator.
///
/// # Errors
/// `PreconditionFailed` when a user exists already; store errors.
pub fn insert_bootstrap(
    txn: &mut dyn SystemTxn,
    prepared: &PreparedBootstrap,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<Bootstrapped> {
    // The scan also makes two concurrent bootstraps conflict in the transaction layer.
    if is_bootstrapped(txn)? {
        return Err(already_bootstrapped());
    }
    realm::ensure(txn, now, rng)?;
    let admin = insert_user(txn, &prepared.user, now)?;
    Ok(Bootstrapped {
        admin,
        generated_password: prepared.generated_password.clone(),
    })
}

/// Whether `user` still has the turnkey bootstrap password (ADR-036): flagged
/// `must_change_password` and its credentials verify [`TURNKEY_ADMIN_PASSWORD`]. Runs PBKDF2
/// when the flag is set, so call it outside a transaction.
#[must_use]
pub fn has_turnkey_password(user: &UserRecord) -> bool {
    user.password_change == PasswordChange::Required
        && user
            .scram
            .as_ref()
            .is_some_and(|s| s.verify_password(TURNKEY_ADMIN_PASSWORD))
}

fn already_bootstrapped() -> AuthnError {
    AuthnError::PreconditionFailed("the cluster already has users; bootstrap runs only once".into())
}

#[cfg(test)]
mod tests;
