// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Error type and terminal output of the CLI.
//!
//! Results go to stdout (one line each, so they can be piped), status and diagnostics to
//! stderr. Nothing written here may contain a secret: callers pass only names, paths and
//! server messages (which never carry document contents or credentials, protocol.md §7).

use std::{
    fmt,
    io::{self, Write as _},
};

use rustegon_proto::{status::error_detail_of, v1::ErrorDetail};

/// A failed command: the message printed on stderr, exit code 1.
#[derive(Debug)]
pub struct CliError(pub String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<tonic::Status> for CliError {
    fn from(status: tonic::Status) -> Self {
        Self(status_text(&status))
    }
}

/// Result of a CLI step.
pub type CliResult<T> = Result<T, CliError>;

/// Builds a [`CliError`].
pub fn fail<T>(message: impl Into<String>) -> CliResult<T> {
    Err(CliError(message.into()))
}

/// Maps an I/O error on `what` (a path or a stream name).
pub fn io_err(what: impl fmt::Display, e: &io::Error) -> CliError {
    CliError(format!("{what}: {e}"))
}

/// `RGN-<code> <Name>: message` for a server error, the plain status otherwise.
pub fn status_text(status: &tonic::Status) -> String {
    match error_detail_of(status) {
        Some(ErrorDetail { code, name, .. }) => {
            format!("RGN-{code} {name}: {}", status.message())
        }
        None => format!("{:?}: {}", status.code(), status.message()),
    }
}

/// Writes one line to stdout.
///
/// # Errors
/// The stdout write error (e.g. a closed pipe).
pub fn out(line: &str) -> CliResult<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{line}")
        .and_then(|()| stdout.flush())
        .map_err(|e| io_err("stdout", &e))
}

/// Writes one line to stderr (best effort: there is nowhere else to report a failure).
pub fn err(line: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}
