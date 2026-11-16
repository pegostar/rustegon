// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the TLS layer.
//!
//! Messages never contain key material: PEM and key parsing errors carry only the file path and
//! the parser's reason, never the bytes (coding-standards.md §3.6).

use std::{io, path::PathBuf};

/// Errors raised while building TLS configurations, loading or generating certificates.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A certificate, key or CA file could not be read or written.
    #[error("TLS file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A PEM file could not be parsed.
    #[error("invalid PEM in {path}: {reason}")]
    Pem {
        /// The file (or a label for in-memory PEM).
        path: PathBuf,
        /// Parser reason (never the content).
        reason: String,
    },
    /// The certificate file holds no certificate.
    #[error("no certificate found in {0}")]
    NoCertificate(PathBuf),
    /// The key file holds no private key.
    #[error("no private key found in {0}")]
    NoPrivateKey(PathBuf),
    /// A certificate could not be parsed as X.509.
    #[error("invalid X.509 certificate: {0}")]
    Certificate(String),
    /// The leaf certificate is outside its validity period.
    #[error("certificate not valid now (not_after = {not_after_unix} s since the Unix epoch)")]
    Expired {
        /// The certificate's `notAfter`, seconds since the Unix epoch.
        not_after_unix: i64,
    },
    /// rustls rejected the certificate/key pair (unsupported key type, key does not match the
    /// certificate, ...).
    #[error("TLS: {0}")]
    Rustls(#[from] rustls::Error),
    /// The client-certificate verifier could not be built (e.g. empty CA bundle).
    #[error("client certificate verifier: {0}")]
    ClientVerifier(#[from] rustls::server::VerifierBuilderError),
    /// Certificate generation failed.
    #[error("certificate generation: {0}")]
    Generate(#[from] rcgen::Error),
    /// Plain-text transport was requested where it is not allowed (security.md §5).
    #[error("plain-text transport refused: {0}")]
    InsecureRefused(&'static str),
    /// Invalid TLS settings.
    #[error("invalid TLS settings: {0}")]
    Config(String),
}

impl TlsError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
