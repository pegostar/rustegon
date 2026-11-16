// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Public gRPC contracts of Rustegon (`proto/rustegon/v1`, protocol.md §2–§3) compiled to Rust.
//!
//! The crate is separate from `rustegon-server` because the generated clients are also needed
//! by the `rustegon` CLI, the Rust driver and integration tests, and no crate may depend on
//! `rustegon-server` (repository-structure.md). Code generation runs in `build.rs` with the
//! pure-Rust `protox` compiler (PD-045).

pub mod status;

/// Generated messages, clients (`*_client`) and servers (`*_server`) of package `rustegon.v1`.
#[allow(
    missing_docs,
    clippy::pedantic,
    clippy::large_enum_variant,
    clippy::derive_partial_eq_without_eq,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/rustegon.v1.rs"));
}

/// Encoded `google.protobuf.FileDescriptorSet` of every `rustegon.v1` file (for descriptor
/// checks and gRPC server reflection).
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/rustegon_v1_descriptor.bin"));
