// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Audit log (FR-SEC-004, security.md §4): tamper-evident JSON lines per node.
//!
//! - [`event`]: event kinds, outcomes and the caller-built [`AuditEvent`] with secret redaction;
//! - [`record`]: audit record format 1 and the BLAKE3 hash chain;
//! - [`log`]: the file sink [`AuditLog`] (rotation, retention, recovery of the chain tail);
//! - [`verify`]: offline chain verification ([`verify_dir`]);
//! - [`settings`]: the `[audit]` configuration section.
//!
//! The sink is synchronous (all I/O through [`rustegon_sim_api::FileSystem`], which is blocking
//! by contract): async callers run [`AuditLog::record`] on the blocking I/O pool, never on an
//! executor thread (coding-standards.md §3.3).

pub mod event;
pub mod log;
pub mod record;
pub mod settings;
pub mod verify;

use std::path::PathBuf;

use rustegon_common::{Error, ErrorCode};

pub use self::{
    event::{AuditEvent, AuditEventKind, AuditOutcome, DetailValue, is_secret_key},
    log::{AuditLog, AuditLogConfig},
    record::{AUDIT_FORMAT, AuditRecord, GENESIS_HASH, line_hash},
    settings::AuditSettings,
    verify::{VerifyReport, verify_dir},
};

/// How the hash chain or the record stream is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainFault {
    /// The line is not a valid format-1 record.
    Malformed(String),
    /// `seq` is not the successor of the previous record (deleted, duplicated or moved line).
    SeqMismatch {
        /// Expected sequence number.
        expected: u64,
        /// Sequence number found.
        found: u64,
    },
    /// `prev_hash` does not match the hash of the previous line (edited or reordered line).
    HashMismatch,
    /// The file name does not match the sequence number of its first record.
    NameMismatch,
    /// A newline-less tail in a file other than the newest one.
    TornTail,
}

/// Errors of the audit log.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// File system error.
    #[error("audit I/O error on {path}: {source}")]
    Io {
        /// File or directory.
        path: PathBuf,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
    /// Chain or record corruption.
    #[error("audit chain broken in {path} line {line}: {fault:?}")]
    Corrupt {
        /// File.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        fault: ChainFault,
    },
    /// A previous write or sync failed; the durable state of the file is unknown and the log
    /// refuses further records until reopened (fs.rs `sync_data` contract).
    #[error("audit log failed earlier and must be reopened")]
    Failed,
}

impl From<AuditError> for Error {
    fn from(e: AuditError) -> Self {
        let code = match &e {
            AuditError::Corrupt { .. } => ErrorCode::StorageCorruption,
            AuditError::Io { .. } | AuditError::Failed => ErrorCode::Internal,
        };
        Error::new(code, e.to_string()).with_source(e)
    }
}

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> AuditError {
    let path = path.into();
    move |source| AuditError::Io { path, source }
}
