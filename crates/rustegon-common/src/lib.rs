// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared foundation: error model (`ErrorCode` generated from `proto/errors.yaml`), configuration
//! and settings registry, logging, secret redaction.

pub mod error;
pub mod logging;
pub mod pki;
pub mod redacted;
pub mod settings;

pub use error::{Error, ErrorCode, GrpcCode, Result, Retryable};
pub use redacted::Redacted;
