// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Where the CLI takes secrets from (PD-058, security.md §2.2).
//!
//! Passwords and API keys are never accepted as command-line arguments: argv is visible to
//! every local user (`ps`, `/proc/<pid>/cmdline`, Windows process listings) and ends up in shell
//! history. The sources, in order:
//! 1. a file named by a flag (content minus one trailing line ending, like `rustegond
//!    --admin-password-file`);
//! 2. an environment variable (for scripts and containers);
//! 3. an interactive prompt without echo, only when stdin is a terminal.
//!
//! Secrets stay in [`SecretString`] (redacted `Debug`/`Display`, zeroized on drop) until they
//! are handed to the SCRAM client or a protobuf request.

use std::{
    io::{self, IsTerminal as _},
    path::Path,
};

use rustegon_security::authn::{SecretString, secret};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};
use zeroize::Zeroizing;

use crate::output::{CliResult, fail, io_err};

/// Largest accepted secret file (a password or an API key is at most a few hundred bytes).
const MAX_SECRET_FILE: u64 = 4096;

/// Reads a small file through the sim-api file system.
///
/// # Errors
/// I/O errors, a file larger than `max`.
pub fn read_file(path: &Path, max: u64) -> CliResult<Zeroizing<Vec<u8>>> {
    let file = StdFileSystem
        .open(path, OpenMode::Read)
        .map_err(|e| io_err(path.display(), &e))?;
    let size = file.size().map_err(|e| io_err(path.display(), &e))?;
    if size > max {
        return fail(format!(
            "{}: file too large ({size} bytes, at most {max})",
            path.display()
        ));
    }
    let len = usize::try_from(size)
        .map_err(|_| io_err(path.display(), &io::Error::from(io::ErrorKind::InvalidData)))?;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    file.read_exact_at(&mut buf, 0)
        .map_err(|e| io_err(path.display(), &e))?;
    Ok(buf)
}

/// Reads a secret file: UTF-8, one trailing line ending removed, not empty.
///
/// # Errors
/// I/O errors, a file that is too large, not UTF-8 or empty.
pub fn read_secret_file(path: &Path) -> CliResult<SecretString> {
    let raw = read_file(path, MAX_SECRET_FILE)?;
    let Ok(text) = std::str::from_utf8(&raw) else {
        return fail(format!("{}: not UTF-8", path.display()));
    };
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.is_empty() {
        return fail(format!("{}: empty", path.display()));
    }
    Ok(secret(text))
}

/// Writes a secret into a new owner-only file (`FileSystem::create_new_private`: 0600 on Unix,
/// directory ACL on Windows; never overwrites), with one trailing newline, and syncs it.
///
/// # Errors
/// I/O errors, including `AlreadyExists`.
pub fn write_private(path: &Path, value: &SecretString) -> CliResult<()> {
    let mut content = Zeroizing::new(value.expose().as_bytes().to_vec());
    content.push(b'\n');
    write_private_bytes(path, &content)
}

/// Writes `content` into a new owner-only file (see [`write_private`]) and syncs it and its
/// directory.
///
/// # Errors
/// I/O errors, including `AlreadyExists`.
pub fn write_private_bytes(path: &Path, content: &[u8]) -> CliResult<()> {
    let fs = StdFileSystem;
    let mut file = fs
        .create_new_private(path)
        .map_err(|e| io_err(path.display(), &e))?;
    file.append(content)
        .and_then(|()| file.sync_data())
        .map_err(|e| io_err(path.display(), &e))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs.sync_dir(dir).map_err(|e| io_err(dir.display(), &e))?;
    }
    Ok(())
}

/// Whether an interactive prompt is possible.
pub fn interactive() -> bool {
    io::stdin().is_terminal()
}

/// Prompts without echo. With `confirm`, asks twice and requires both to match.
///
/// # Errors
/// Terminal errors, a mismatch, an empty answer.
pub fn prompt(label: &str, confirm: bool) -> CliResult<SecretString> {
    let first =
        Zeroizing::new(rpassword::prompt_password(label).map_err(|e| io_err("terminal", &e))?);
    if first.is_empty() {
        return fail("empty password");
    }
    if confirm {
        let again = Zeroizing::new(
            rpassword::prompt_password("Repeat: ").map_err(|e| io_err("terminal", &e))?,
        );
        if *again != *first {
            return fail("the passwords do not match");
        }
    }
    Ok(secret(first.as_str()))
}

/// A secret from `file`, else the environment variable `env`, else a prompt (terminal only).
/// `what` names the secret in messages and the prompt.
///
/// # Errors
/// Source errors; no source available.
pub fn obtain(
    what: &str,
    file: Option<&Path>,
    env: &str,
    file_flag: &str,
    confirm: bool,
) -> CliResult<SecretString> {
    if let Some(path) = file {
        return read_secret_file(path);
    }
    if let Some(value) = std::env::var_os(env) {
        let Ok(value) = value.into_string() else {
            return fail(format!("{env} is not UTF-8"));
        };
        let value = Zeroizing::new(value);
        if value.is_empty() {
            return fail(format!("{env} is empty"));
        }
        return Ok(secret(value.as_str()));
    }
    if interactive() {
        return prompt(&format!("{what}: "), confirm);
    }
    fail(format!(
        "no {what}: use {file_flag}, the {env} environment variable or a terminal prompt"
    ))
}
