// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Server-side first-admin bootstrap (security.md §2.2, FR-SEC-003, TC-SEC-003; PD-051).
//!
//! [`Security::bootstrap_if_needed`] creates the first administrator when the store has no
//! user, and does nothing otherwise, so `rustegond` can call it on every start: the credentials
//! are derived ([`rustegon_security::authn::bootstrap::prepare_bootstrap`]) outside the system
//! transaction that writes them (`insert_bootstrap`, which re-checks that no user exists). A generated password is returned to the caller, which writes it
//! with [`write_initial_password`] to `<data_dir>/initial-admin-password` and prints it once
//! (wiring in `rustegond` / `rustegon init` is wave 2c). The password is never logged.
//!
//! The file is created with [`FileSystem::create_new_private`] (0600 on Unix, directory ACL on
//! Windows) and never overwritten: an existing file means an earlier bootstrap already handed a
//! password out, and replacing it could hide which one is valid.

use std::path::{Path, PathBuf};

use rustegon_common::{Error, ErrorCode};
use rustegon_security::authn::{
    SecretString,
    bootstrap::{
        AdminPassword, Bootstrapped, insert_bootstrap, is_bootstrapped, prepare_bootstrap,
    },
};
use rustegon_sim_api::FileSystem;

use super::Security;

/// Name of the file holding a generated first-admin password, under the data directory.
pub const INITIAL_ADMIN_PASSWORD_FILE: &str = "initial-admin-password";

/// What [`Security::bootstrap_if_needed`] did.
#[derive(Debug)]
pub enum BootstrapOutcome {
    /// Users exist already; nothing changed.
    AlreadyBootstrapped,
    /// The first admin was created. Boxed because `Bootstrapped` is large and the other
    /// variant is empty (`clippy::large_enum_variant` fires on Linux, where the layout differs).
    Created(Box<Bootstrapped>),
}

impl Security {
    /// Creates the first administrator `admin` when no user exists (module docs). Blocking:
    /// call it at startup or from a blocking thread.
    ///
    /// # Errors
    /// `RGN-1001` for an invalid name or a weak provided password; store errors.
    pub fn bootstrap_if_needed(
        &self,
        admin: &str,
        password: AdminPassword,
    ) -> Result<BootstrapOutcome, Error> {
        let settings = self.authn_settings();
        let now = self.clock.wall();
        let rng = std::sync::Arc::clone(&self.rng);
        // Three steps so that the PBKDF2 does not run inside a transaction (see
        // `Security::compute`): is the store bootstrapped, derive the credentials, write them
        // (the write re-checks, so a concurrent bootstrap conflicts instead of doubling).
        let bootstrapped = self.engine.system_transaction(|h| {
            is_bootstrapped(&super::store::EngineTxn(h)).map_err(Error::from)
        })?;
        if bootstrapped {
            return Ok(BootstrapOutcome::AlreadyBootstrapped);
        }
        let prepared = prepare_bootstrap(admin, password, &settings, rng.as_ref())?;
        self.engine.system_transaction(|h| {
            let mut txn = super::store::EngineTxn(h);
            if is_bootstrapped(&txn).map_err(Error::from)? {
                return Ok(BootstrapOutcome::AlreadyBootstrapped);
            }
            let done = insert_bootstrap(&mut txn, &prepared, now, rng.as_ref())?;
            Ok(BootstrapOutcome::Created(Box::new(done)))
        })
    }
}

/// Writes a generated first-admin password to `<data_dir>/initial-admin-password` as a new
/// owner-only file, synced with its directory, and returns the path.
///
/// # Errors
/// `RGN-1031 AlreadyExists` when the file exists; `RGN-5001` for other I/O errors.
pub fn write_initial_password(
    fs: &dyn FileSystem,
    data_dir: &Path,
    password: &SecretString,
) -> Result<PathBuf, Error> {
    let path = data_dir.join(INITIAL_ADMIN_PASSWORD_FILE);
    let io = |e: std::io::Error| {
        let code = if e.kind() == std::io::ErrorKind::AlreadyExists {
            ErrorCode::AlreadyExists
        } else {
            ErrorCode::Internal
        };
        // The path is not secret; the password never appears in the error.
        Error::new(code, format!("{}: {e}", path.display()))
    };
    fs.create_dir_all(data_dir).map_err(io)?;
    let mut file = fs.create_new_private(&path).map_err(io)?;
    let mut content = password.expose().as_bytes().to_vec();
    content.push(b'\n');
    let written = file.append(&content).and_then(|()| file.sync_data());
    // Overwrite the temporary copy of the secret before reporting the outcome.
    content.fill(0);
    written.map_err(io)?;
    fs.sync_dir(data_dir).map_err(io)?;
    Ok(path)
}
