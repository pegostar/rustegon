// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compiles `proto/rustegon/v1/*.proto` into the driver's gRPC client stubs (PD-180), with the
//! pure-Rust `protox` compiler as `rustegon-proto` does (PD-045): no system `protoc` is needed and
//! the generated code cannot drift from the `.proto` files. Only clients are generated; the
//! descriptor set is kept for the tests (protobuf JSON of the AST vectors and the fake server).

use std::{env, error::Error, fs, path::PathBuf};

use prost::Message as _;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest.join("../../proto");
    let v1_dir = proto_root.join("rustegon/v1");
    println!("cargo:rerun-if-changed={}", v1_dir.display());
    let mut files = Vec::new();
    for entry in fs::read_dir(&v1_dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "proto") {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push(path);
        }
    }
    files.sort();
    let fds = protox::compile(&files, [&proto_root])?;
    let out = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out.join("rustegon_v1_descriptor.bin"), fds.encode_to_vec())?;
    tonic_prost_build::configure()
        .build_client(true)
        // The in-process fake server of the retry tests is generic over the descriptor set and
        // needs no generated server traits.
        .build_server(false)
        .compile_fds(fds)?;
    Ok(())
}
