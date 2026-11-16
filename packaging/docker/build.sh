#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Release build of rustegond and rustegon inside the image's build stage (docker.md §3,
# FR-INS-003, PD-150). Runs on the build platform and cross-compiles for the target platform
# (Debian cross gcc for ring/zstd and the link), so an arm64 image needs no emulated compiler.
# Expects gui/dist to be present (the Dockerfile's GUI stage).
# Usage: packaging/docker/build.sh <linux/amd64|linux/arm64> <output dir>
set -euo pipefail
platform="${1:?usage: build.sh <linux/amd64|linux/arm64> <output dir>}"
out="${2:?usage: build.sh <linux/amd64|linux/arm64> <output dir>}"
cd "$(dirname "$0")/../.."

case "$platform" in
  linux/amd64) target=x86_64-unknown-linux-gnu;  deb=amd64; gnu=x86-64; gcc=x86_64-linux-gnu-gcc ;;
  linux/arm64) target=aarch64-unknown-linux-gnu; deb=arm64; gnu=aarch64; gcc=aarch64-linux-gnu-gcc ;;
  *) echo "build.sh: unsupported platform $platform" >&2; exit 2 ;;
esac
[[ -f gui/dist/index.html ]] || { echo "build.sh: gui/dist missing (build the GUI first)" >&2; exit 2; }

# The toolchain of rust-toolchain.toml (rustup does not install it implicitly).
rustup toolchain install >/dev/null
rustup target add "$target" >/dev/null
host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "$host" != "$target" ]]; then
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "gcc-$gnu-linux-gnu" "libc6-dev-$deb-cross" >/dev/null
  env_target="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
  export "CARGO_TARGET_${env_target}_LINKER=$gcc" "CC_${target//-/_}=$gcc"
fi

# An empty CARGO_BUILD_JOBS build argument means cargo's default.
[[ -n "${CARGO_BUILD_JOBS:-}" ]] || unset CARGO_BUILD_JOBS
# cargo does not notice gui/dist changing under a cached target directory (PD-130).
touch bins/rustegond/src/gui.rs
CARGO_INCREMENTAL=0 cargo build --locked --release --target "$target" -p rustegond -p rustegon-cli
mkdir -p "$out/data"
cp "target/$target/release/rustegond" "target/$target/release/rustegon" "$out/"
