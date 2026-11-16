// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compiles `proto/rustegon/v1/*.proto` into Rust (PD-045).
//!
//! Why `protox` instead of `protoc`: neither developer machines nor CI images ship a system
//! `protoc`, and vendoring a binary per platform is fragile. `protox` is a pure-Rust protobuf
//! compiler that yields the same `FileDescriptorSet`; `tonic-prost-build` then generates code
//! from that set without ever invoking `protoc`. Generated code is not checked in: it is a pure
//! function of the `.proto` files, so regenerating on every build cannot drift from them.

use std::{env, error::Error, fs, path::PathBuf};

use prost::Message as _;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest.join("../../proto");
    let v1_dir = proto_root.join("rustegon/v1");
    println!("cargo:rerun-if-changed={}", v1_dir.display());

    // Every file of the package is compiled, so a new .proto cannot be forgotten here.
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
    // Kept as bytes for descriptor tests and, later, gRPC server reflection.
    fs::write(out.join("rustegon_v1_descriptor.bin"), fds.encode_to_vec())?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)?;
    Ok(())
}
