// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Generates `ErrorCode` from `proto/errors.yaml` (protocol.md §7).

use std::{env, error::Error, fs, path::PathBuf};

#[path = "build/codegen.rs"]
mod codegen;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let catalog = manifest.join("../../proto/errors.yaml");
    println!("cargo:rerun-if-changed={}", catalog.display());
    println!("cargo:rerun-if-changed=build/codegen.rs");
    let text = fs::read_to_string(&catalog)?;
    let entries = codegen::parse(&text).map_err(|e| format!("{}: {e}", catalog.display()))?;
    let out = PathBuf::from(env::var("OUT_DIR")?).join("error_codes.rs");
    fs::write(out, codegen::generate(&entries))?;
    Ok(())
}
