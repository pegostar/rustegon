// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Official Rust driver of Rustegon (FR-DRV-005, `docs/specifications/rust-driver.md`).
//!
//! The driver implements the Driver Conceptual Model shared with the .NET, Java, Node.js, Python
//! and Go drivers (dotnet-driver.md §1, DEC-014) over the public gRPC API (`proto/rustegon/v1`),
//! async on Tokio and tonic.
//!
//! ```no_run
//! use rustegon::{Client, Filter, Update, doc};
//!
//! # async fn demo() -> rustegon::Result<()> {
//! let client = Client::from_connection_string("rustegon://app:secret@localhost:7700/shop")?;
//! let orders = client.default_database().collection("orders");
//! orders.insert_one(doc! { "_id" => 42, "status" => "paid", "total" => 120 }).await?;
//! let paid = orders
//!     .find(Filter::and([Filter::eq("status", "paid"), Filter::gte("total", 100)]))
//!     .limit(50)
//!     .to_list()
//!     .await?;
//! orders.update_one(Filter::id(42), Update::new().set("status", "shipped")).await?;
//! # let _ = paid;
//! client.close().await;
//! # Ok(())
//! # }
//! ```

pub mod codec;
pub mod scram;

mod auth;
mod builders;
mod client;
mod codes;
mod collection;
mod connstring;
mod cursor;
mod database;
mod error;
mod options;
pub(crate) mod random;
mod session;
mod settings;
mod transaction;
mod transport;

pub use crate::{
    builders::{Filter, IndexKeys, Projection, Sort, SortKey, Update},
    client::{Client, ServerInfo},
    codec::{Document, Value},
    collection::{
        BulkOperation, BulkWriteError, BulkWriteResult, Collection, DeleteResult, Find,
        IndexDescription, IndexState, InsertManyResult, InsertOneResult, UpdateResult,
    },
    cursor::Cursor,
    database::Database,
    error::{Error, ErrorClass, Result, RustegonError},
    options::{Action, BoxFuture, ValidationAction, ValidationLevel, Validator},
    session::Session,
    settings::{
        AuthMechanism, Credential, DEFAULT_PORT, DRIVER_NAME, ReadConsistency, Settings,
        SettingsBuilder, TlsSettings, VERSION, WriteConcern,
    },
    transaction::{Isolation, Transaction, TransactionOptions, TransactionOutcome},
};

/// Hooks for the conformance runner (`drivers/conformance/`, TC-DRV-RS-004/006): the AST of the
/// builders and the error mapping, which the public API only exercises through I/O. Not part of
/// the API; may change without notice.
#[doc(hidden)]
pub mod __conformance {
    pub use crate::builders::{ParamSink, delete_statement, find_statement, update_statement};

    /// The error of an `ErrorDetail`.
    #[must_use]
    pub fn error_from_detail(d: &crate::pb::ErrorDetail) -> crate::Error {
        crate::Error::from_detail(d, "x")
    }

    /// The transport fallback of a gRPC status code.
    #[must_use]
    pub fn error_from_transport(code: tonic::Code) -> crate::Error {
        crate::Error::from_transport(code, "x")
    }

    /// The catalog name of a code.
    #[must_use]
    pub fn name_of(code: u32) -> String {
        crate::codes::name_of(code)
    }

    /// `(code, name, class id)` of the driver's catalog table.
    #[must_use]
    pub fn catalog() -> Vec<(u32, &'static str, &'static str)> {
        crate::codes::CATALOG
            .iter()
            .map(|(c, n, k)| (*c, *n, k.id()))
            .collect()
    }
}

/// Generated gRPC messages and client stubs of package `rustegon.v1` (internal: the driver's own
/// types are the API, as in the other drivers).
#[allow(
    missing_docs,
    unreachable_pub,
    clippy::pedantic,
    clippy::large_enum_variant,
    clippy::derive_partial_eq_without_eq,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags
)]
#[doc(hidden)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/rustegon.v1.rs"));

    /// Encoded `FileDescriptorSet` of `rustegon.v1` (tests: protobuf JSON, fake server).
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/rustegon_v1_descriptor.bin"));
}
