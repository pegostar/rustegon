// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Reading and parsing PEM certificates, keys and CA bundles through the sim-api
//! [`FileSystem`] (ADR-029).

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_common::Redacted;
use rustegon_sim_api::{FileSystem, OpenMode};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};

use crate::TlsError;

/// Upper bound for a certificate, key or CA bundle file. Real files are a few KiB (a CA bundle
/// of a few hundred roots stays below 1 MiB); the bound stops a misconfigured path (a device, a
/// huge log) from being read whole into memory.
const MAX_PEM_FILE: u64 = 4 << 20;

/// Reads a whole PEM file.
///
/// # Errors
/// [`TlsError::Io`] when the file cannot be read or exceeds 4 MiB.
pub(crate) fn read_file(fs: &dyn FileSystem, path: &Path) -> Result<Vec<u8>, TlsError> {
    let file = fs
        .open(path, OpenMode::Read)
        .map_err(|e| TlsError::io(path, e))?;
    let size = file.size().map_err(|e| TlsError::io(path, e))?;
    if size > MAX_PEM_FILE {
        return Err(TlsError::io(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "file larger than 4 MiB"),
        ));
    }
    let len = usize::try_from(size).map_err(|_| {
        TlsError::io(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "file too large"),
        )
    })?;
    let mut buf = vec![0u8; len];
    file.read_exact_at(&mut buf, 0)
        .map_err(|e| TlsError::io(path, e))?;
    Ok(buf)
}

/// Parses every `CERTIFICATE` block of a PEM file, in order (leaf first for a chain).
///
/// # Errors
/// [`TlsError::Pem`] on malformed PEM, [`TlsError::NoCertificate`] when there is none.
pub fn parse_certificates(
    pem: &[u8],
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate(path.to_path_buf()));
    }
    Ok(certs)
}

/// Parses the first private key (PKCS#8, SEC1 or PKCS#1) of a PEM file.
///
/// # Errors
/// [`TlsError::NoPrivateKey`] when the file holds no key, [`TlsError::Pem`] when it is
/// malformed. The error never contains key bytes.
pub fn parse_private_key(
    pem: &[u8],
    path: &Path,
) -> Result<Redacted<PrivateKeyDer<'static>>, TlsError> {
    match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => Ok(Redacted::new(key)),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            Err(TlsError::NoPrivateKey(path.to_path_buf()))
        }
        Err(e) => Err(TlsError::Pem {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

/// `notAfter` of a DER certificate, in seconds since the Unix epoch.
///
/// # Errors
/// [`TlsError::Certificate`] when the DER is not an X.509 certificate.
pub fn not_after_unix(cert: &CertificateDer<'_>) -> Result<i64, TlsError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| TlsError::Certificate(e.to_string()))?;
    Ok(parsed.validity().not_after.timestamp())
}

/// A set of trusted CA certificates (cluster CA for peers, client CA for X.509 client auth).
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    roots: Arc<RootCertStore>,
    source: PathBuf,
}

impl TrustAnchors {
    /// Parses a PEM CA bundle held in memory; `label` names it in errors.
    ///
    /// # Errors
    /// [`TlsError::Pem`]/[`TlsError::NoCertificate`] on bad PEM, [`TlsError::Rustls`] when a
    /// certificate is not a usable trust anchor.
    pub fn from_pem(pem: &[u8], label: impl Into<PathBuf>) -> Result<Self, TlsError> {
        let source = label.into();
        let certs = parse_certificates(pem, &source)?;
        let mut roots = RootCertStore::empty();
        for cert in certs {
            // `add` (not `add_parsable_certificates`): a bundle with one bad entry is a
            // configuration error to report, not something to skip silently.
            roots.add(cert)?;
        }
        Ok(Self {
            roots: Arc::new(roots),
            source,
        })
    }

    /// Reads and parses a PEM CA bundle file.
    ///
    /// # Errors
    /// As [`TrustAnchors::from_pem`], plus [`TlsError::Io`].
    pub fn load(fs: &dyn FileSystem, path: &Path) -> Result<Self, TlsError> {
        let pem = read_file(fs, path)?;
        Self::from_pem(&pem, path)
    }

    /// The root store for rustls verifiers.
    #[must_use]
    pub fn roots(&self) -> Arc<RootCertStore> {
        Arc::clone(&self.roots)
    }

    /// Where the anchors were loaded from (for diagnostics).
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }
}
