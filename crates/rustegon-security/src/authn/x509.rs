// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! X.509 client certificate → principal mapping (security.md §2, FR-SEC-001, TC-SEC-012;
//! PD-047).
//!
//! The TLS layer (`rustegon-net`) has already verified the chain against the configured client
//! CA, the validity period and the `clientAuth` usage; this module only maps the verified leaf
//! certificate to an identity:
//!
//! 1. **Node**: a subject alternative name is the URI [`NODE_ROLE_URI`] (what `rustegon-net`
//!    writes into node certificates, format 2) or, legacy format 1, the extended key usage
//!    contains [`NODE_ROLE_OID`] (ADR-035) → principal `node:<CN>` with the single role
//!    [`NODE_ROLE`]. No user record is involved; the CN is the node name. The marker is trusted
//!    exactly as far as the CA the TLS layer verified the chain against.
//! 2. **User**: otherwise the subject CN maps to the user `x509:CN=<CN>`; without a CN, the
//!    first subject alternative name of type DNS, e-mail or URI maps to `x509:DNS=<name>`,
//!    `x509:email=<address>` or `x509:URI=<uri>`. The user record must exist (created by an
//!    administrator, without password) and be enabled.
//!
//! A subject with more than one CN, or more than one EKU or SAN extension (RFC 5280 §4.2
//! forbids duplicates), is rejected rather than guessing which one counts. The EKU is parsed by
//! hand (a SEQUENCE OF OBJECT IDENTIFIER compared by DER content bytes) because the legacy node
//! role OID lives under the UUID arc `2.25`, whose 128-bit arc the `const-oid` type cannot
//! represent.
//! Every failure is the generic `RGN-4001`.

use rustegon_catalog::CatalogRead;
use rustegon_common::pki::{NODE_ROLE_OID, NODE_ROLE_URI};
use x509_cert::{
    Certificate,
    der::{Any, Decode, Tag, Tagged},
    ext::pkix::{SubjectAltName, name::GeneralName},
    name::Name,
    spki::ObjectIdentifier,
};

use crate::authn::{
    AuthMethod, PasswordChange, Principal,
    error::{AuthnError, AuthnResult, FailureReason},
    users::{NODE_PREFIX, UserState, X509_PREFIX, get_user, validate_user_name},
};

/// Role of cluster node principals.
pub const NODE_ROLE: &str = "node";
/// `id-at-commonName` (RFC 4519 §2.3).
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `id-ce-extKeyUsage` (RFC 5280 §4.2.1.12).
const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// The identity a certificate maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertIdentity {
    /// A cluster node named by its CN.
    Node(String),
    /// The user name `x509:…` (module docs).
    User(String),
}

fn malformed() -> AuthnError {
    AuthnError::failed(FailureReason::Malformed)
}

/// DER content octets of a dotted OID with arcs up to 128 bits (X.690 §8.19); `None` when it
/// is not a valid OID.
pub(crate) fn oid_content(dotted: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u128> = dotted
        .split('.')
        .map(|a| a.parse().ok())
        .collect::<Option<_>>()?;
    let (&a0, &a1) = (arcs.first()?, arcs.get(1)?);
    if a0 > 2 || (a0 < 2 && a1 >= 40) {
        return None;
    }
    let first = a0.checked_mul(40)?.checked_add(a1)?;
    let mut out = Vec::new();
    for mut arc in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        // Base-128, most significant group first, continuation bit on all but the last.
        let mut groups = [0u8; 19];
        let mut i = groups.len();
        loop {
            i -= 1;
            groups[i] = (arc & 0x7F) as u8;
            arc >>= 7;
            if arc == 0 {
                break;
            }
        }
        let last = groups.len() - 1;
        for g in &mut groups[i..last] {
            *g |= 0x80;
        }
        out.extend_from_slice(&groups[i..]);
    }
    Some(out)
}

/// Whether `cert` carries the node role: the URI SAN [`NODE_ROLE_URI`] or the legacy EKU
/// purpose [`NODE_ROLE_OID`]. Both extensions are always parsed, so a malformed or repeated one
/// fails even when the other already marks a node.
fn has_node_role(cert: &Certificate) -> AuthnResult<bool> {
    let uri_role = subject_alt_names(cert)?.is_some_and(|san| {
        san.0.iter().any(|n| {
            matches!(n, GeneralName::UniformResourceIdentifier(u) if u.as_str() == NODE_ROLE_URI)
        })
    });
    Ok(has_node_role_oid(cert)? || uri_role)
}

/// The SAN extension of `cert`, if any; a repeated one is malformed.
fn subject_alt_names(cert: &Certificate) -> AuthnResult<Option<SubjectAltName>> {
    Ok(cert
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .map_err(|_| malformed())?
        .map(|(_, san)| san))
}

/// Whether the EKU extension of `cert` contains the legacy node role OID (format 1).
fn has_node_role_oid(cert: &Certificate) -> AuthnResult<bool> {
    let node_oid = oid_content(NODE_ROLE_OID).ok_or_else(malformed)?;
    let mut ekus = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|e| e.extn_id == OID_EKU);
    let Some(eku) = ekus.next() else {
        return Ok(false);
    };
    if ekus.next().is_some() {
        return Err(malformed());
    }
    let purposes = Vec::<Any>::from_der(eku.extn_value.as_bytes()).map_err(|_| malformed())?;
    Ok(purposes
        .iter()
        .any(|p| p.tag() == Tag::ObjectIdentifier && p.value() == node_oid.as_slice()))
}

/// The single CN of `name`, if any.
fn common_name(name: &Name) -> AuthnResult<Option<String>> {
    let mut cns = name.iter().filter(|atv| atv.oid == OID_CN);
    let Some(cn) = cns.next() else {
        return Ok(None);
    };
    if cns.next().is_some() {
        return Err(malformed());
    }
    let ds = x509_cert::ext::pkix::name::DirectoryString::try_from(&cn.value)
        .map_err(|_| malformed())?;
    Ok(Some(String::from(ds)))
}

/// The first DNS / e-mail / URI subject alternative name, as a user name.
fn san_user(cert: &Certificate) -> AuthnResult<Option<String>> {
    let Some(san) = subject_alt_names(cert)? else {
        return Ok(None);
    };
    Ok(san.0.iter().find_map(|n| match n {
        GeneralName::DnsName(s) => Some(format!("{X509_PREFIX}DNS={}", s.as_str())),
        GeneralName::Rfc822Name(s) => Some(format!("{X509_PREFIX}email={}", s.as_str())),
        GeneralName::UniformResourceIdentifier(s) => {
            Some(format!("{X509_PREFIX}URI={}", s.as_str()))
        }
        _ => None,
    }))
}

/// Maps a DER-encoded, already verified leaf certificate to its identity (module docs).
///
/// # Errors
/// Generic authentication failure for an unparsable certificate, several CNs or EKU
/// extensions, a node certificate without CN, or a subject that yields no valid user name.
pub fn identity_from_cert(der: &[u8]) -> AuthnResult<CertIdentity> {
    let cert = Certificate::from_der(der).map_err(|_| malformed())?;
    let cn = common_name(cert.tbs_certificate().subject())?;
    if has_node_role(&cert)? {
        let name = cn
            .filter(|n| validate_user_name(n).is_ok())
            .ok_or_else(malformed)?;
        return Ok(CertIdentity::Node(name));
    }
    let user = match cn {
        Some(cn) => format!("{X509_PREFIX}CN={cn}"),
        None => san_user(&cert)?.ok_or_else(malformed)?,
    };
    validate_user_name(&user).map_err(|_| malformed())?;
    Ok(CertIdentity::User(user))
}

/// Authenticates a verified client certificate: node principal, or the enabled `x509:` user.
///
/// # Errors
/// Generic authentication failure (see [`identity_from_cert`]; unknown or disabled user);
/// store errors.
pub fn authenticate_certificate(txn: &dyn CatalogRead, der: &[u8]) -> AuthnResult<Principal> {
    match identity_from_cert(der)? {
        CertIdentity::Node(name) => Ok(Principal {
            user: format!("{NODE_PREFIX}{name}"),
            roles: vec![NODE_ROLE.to_owned()],
            method: AuthMethod::Certificate,
            password_change: PasswordChange::NotRequired,
        }),
        CertIdentity::User(user) => get_user(txn, &user)?
            .filter(|u| u.state == UserState::Enabled)
            .map(|u| u.principal(AuthMethod::Certificate))
            .ok_or(AuthnError::failed(FailureReason::BadCredentials)),
    }
}

#[cfg(test)]
mod tests;
