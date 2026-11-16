// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! PKI identifiers shared by certificate issuance (`rustegon-net`) and certificate-to-principal
//! mapping (`rustegon-security`) (security.md §2: node certs carry the `node` role marker, ADR-035).
//!
//! Both sides must agree on the exact marker: a node certificate issued with one value and
//! checked against another would silently demote a cluster peer to an ordinary client. Keeping
//! the single definition here (the only crate both depend on) removes that drift.

/// Node certificate format (implementation-rules.md §6, ADR-035): 1 = node role as the extended
/// key usage [`NODE_ROLE_OID`] (PD-046, read-only now), 2 = node role as the URI SAN
/// [`NODE_ROLE_URI`] (what `CertAuthority::issue_node` writes). Fixtures live under
/// `crates/rustegon-net/tests/fixtures/formats/node_cert/<version>/`.
pub const NODE_CERT_FORMAT: u32 = 2;

/// URI subject alternative name marking a certificate as a Rustegon cluster node (node
/// certificate format 2, ADR-035). Compared byte for byte, case-sensitively.
pub const NODE_ROLE_URI: &str = "urn:rustegon:role:node";

/// Legacy (node certificate format 1) extended key usage OID marking a certificate as a Rustegon
/// cluster node. No longer issued (ADR-035): its 128-bit UUID arc makes Go's `crypto/x509` and
/// other parsers reject the whole certificate (PD-193). Still accepted on verification until
/// every format-1 node certificate has expired (they are valid 1 year; ADR-035 sets the removal).
///
/// The UUID is `95756968-d091-4359-9d27-d9059c1e52ac` under the UUID arc `2.25` (X.667).
pub const NODE_ROLE_OID: &str = "2.25.198664608061686819142413672999875924652";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_role_oid_is_the_uuid_arc_of_the_documented_uuid() {
        // 2.25.<UUID as an unsigned 128-bit integer> (X.667 §6.3).
        let uuid = 0x9575_6968_d091_4359_9d27_d905_9c1e_52ac_u128;
        assert_eq!(NODE_ROLE_OID, format!("2.25.{uuid}"));
    }
}
