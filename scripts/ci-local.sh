#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Local stand-in for .github/workflows/ci.yml while no git remote exists (PD-021).
# Runs the host gates, then clippy + tests in Linux x64 and arm64 containers (arm64 via QEMU).
# Then the driver gates (.NET, Java, Node.js, Python, Go, Rust) and the AC-DRV-003 cross-driver comparison, in both modes,
# and the GUI gate (lint, unit tests, build, Playwright e2e against rustegond), then the host
# release archive and the TC-INS-009 walk-through from it, the dev-build MSI and TC-INS-011 on a
# Windows host, then the Docker image tests (scripts/docker-tests.sh: TC-INS-007, TC-INS-008)
# and the DEB/RPM package tests (scripts/package-tests.sh: TC-INS-004, TC-INS-005, TC-INS-013).
# Usage: scripts/ci-local.sh [--no-docker] [--no-drivers] [--no-gui] [--no-walkthrough]
set -euo pipefail
cd "$(dirname "$0")/.."

no_docker=""; no_drivers=""; no_gui=""; no_walkthrough=""
for arg in "$@"; do
  case "$arg" in
    --no-docker) no_docker=1 ;;
    --no-drivers) no_drivers=1 ;;
    --no-gui) no_gui=1 ;;
    --no-walkthrough) no_walkthrough=1 ;;
    *) echo "usage: scripts/ci-local.sh [--no-docker] [--no-drivers] [--no-gui] [--no-walkthrough]" >&2; exit 2 ;;
  esac
done

step() { printf '\n== %s\n' "$*"; }

# Same as .github/workflows/ci.yml: a gate always rebuilds after the code changed, so the
# incremental cache only costs disk (it reached tens of GB in target/debug/incremental).
export CARGO_INCREMENTAL=0

step "fmt";      cargo fmt --all --check
step "clippy";   cargo clippy --workspace --all-targets --all-features -- -D warnings
step "nextest";  cargo nextest run --workspace --all-features --profile ci
step "doctest";  cargo test --workspace --all-features --doc
step "rustdoc";  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
step "deny";     cargo deny check
step "audit";    cargo audit

# API contract gates (protocol.md §10, PD-060). The baseline of `buf breaking` (TC-API-001) and
# `oasdiff breaking` (TC-API-002) is the last released API: the tag `api-v1-alpha` (M4 exit)
# until a later release replaces it (`RGN_API_BASELINE=<tag>`). Before the tag exists both
# checks are skipped with a message; the stable `tc_api_001_wire_contract_matches_the_lock`
# test (proto/rustegon/v1.lock) and the OpenAPI golden test still guard every change.
API_BASELINE="${RGN_API_BASELINE:-api-v1-alpha}"
BUF_VERSION=1.75.0
run_buf() {
  if command -v buf >/dev/null 2>&1; then buf "$@"
  elif command -v npx >/dev/null 2>&1; then npx --yes "@bufbuild/buf@$BUF_VERSION" "$@"
  else return 127; fi
}
have_buf() { command -v buf >/dev/null 2>&1 || command -v npx >/dev/null 2>&1; }
baseline_dir=""
if git rev-parse -q --verify "refs/tags/$API_BASELINE" >/dev/null; then
  baseline_dir="$(mktemp -d)"
  trap 'rm -rf "$baseline_dir"' EXIT
  git archive "$API_BASELINE" proto api/openapi | tar -x -C "$baseline_dir"
fi

if have_buf; then
  step "buf lint (TC-API-001)"; (cd proto && run_buf lint)
  if [[ -n "$baseline_dir" ]]; then
    step "buf breaking vs $API_BASELINE (TC-API-001)"
    (cd proto && run_buf breaking --against "$baseline_dir/proto")
  else
    step "buf breaking: SKIPPED (no tag $API_BASELINE yet; take it at the M4 exit with 'git tag $API_BASELINE')"
  fi
else
  step "buf lint/breaking: SKIPPED (neither buf nor npx installed; https://buf.build/docs/installation)"
fi

if [[ -z "$baseline_dir" ]]; then
  step "oasdiff breaking: SKIPPED (no tag $API_BASELINE yet)"
elif command -v oasdiff >/dev/null 2>&1; then
  step "oasdiff breaking vs $API_BASELINE (TC-API-002)"
  oasdiff breaking --fail-on ERR \
    "$baseline_dir/api/openapi/rustegon-v1.yaml" api/openapi/rustegon-v1.yaml
elif command -v docker >/dev/null 2>&1; then
  step "oasdiff breaking vs $API_BASELINE (TC-API-002, docker tufin/oasdiff)"
  cp api/openapi/rustegon-v1.yaml "$baseline_dir/current.yaml"
  dir="$(cd "$baseline_dir" && (pwd -W 2>/dev/null || pwd))"
  MSYS_NO_PATHCONV=1 docker run --rm -v "$dir:/w" tufin/oasdiff breaking --fail-on ERR \
    /w/api/openapi/rustegon-v1.yaml /w/current.yaml
else
  step "oasdiff breaking: SKIPPED (neither oasdiff nor docker: 'go install github.com/oasdiff/oasdiff@latest')"
fi

# M11 drivers (AC-DRV-001…007): the .NET, Java, Node.js, Python, Go and Rust gates against release binaries of this tree
# (PD-072), then the comparison of their conformance-results files (conformance README §6).
# A missing toolchain skips its driver with a message; --no-drivers skips the whole step.
winpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
if [[ -n "$no_drivers" ]]; then
  step "drivers: SKIPPED (--no-drivers)"
else
  step "drivers: release binaries for RUSTEGON_BIN_DIR"
  cargo build --release -p rustegond -p rustegon-cli
  bin_dir="$(winpath target/release)"
  mkdir -p target/driver-results
  results=()
  if command -v dotnet >/dev/null 2>&1; then
    step "drivers: .NET build -warnaserror + tests (AC-DRV-001)"
    net_results="$(winpath target/driver-results)/dotnet.json"
    rm -f target/driver-results/dotnet.json
    (cd drivers/dotnet && dotnet build -c Release -warnaserror       && RUSTEGON_BIN_DIR="$bin_dir" RUSTEGON_CONFORMANCE_RESULTS="$net_results" dotnet test)
    results+=("$net_results")
  else
    step "drivers: .NET SKIPPED (dotnet not installed)"
  fi
  if command -v java >/dev/null 2>&1; then
    step "drivers: Java clean check, JDK 21 + 25 (AC-DRV-002)"
    (cd drivers/java && RUSTEGON_BIN_DIR="$bin_dir" ./gradlew clean check)
    java_build="$(winpath drivers/java/driver/build)"
    results+=("$java_build/conformance-results-jdk21.json" "$java_build/conformance-results-jdk25.json")
  else
    step "drivers: Java SKIPPED (java not installed)"
  fi
  # Node.js driver (FR-DRV-004, AC-DRV-004, node-driver.md §11): lint, typecheck, unit, conformance, integration.
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    step "drivers: Node.js lint + typecheck + tests (AC-DRV-004)"
    node_results="$(winpath target/driver-results)/node.json"
    rm -f target/driver-results/node.json
    (cd drivers/node && npm ci && npm run lint && npm run typecheck && npm test \
      && CI=true RUSTEGON_BIN_DIR="$bin_dir" RUSTEGON_CONFORMANCE_RESULTS="$node_results" npm run conformance \
      && CI=true RUSTEGON_BIN_DIR="$bin_dir" npm run test:integration)
    results+=("$node_results")
  else
    step "drivers: Node.js SKIPPED (node/npm not installed)"
  fi
  # Python (DEC-014, python-driver.md §11): the first interpreter >= 3.11 (Windows has a `python3`
  # stub that only opens the Store, so the version check also filters it out).
  py=""
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      py="$cand"; break
    fi
  done
  if [[ -n "$py" ]]; then
    step "drivers: Python venv, ruff, mypy --strict, pytest (AC-DRV-006)"
    py_results="$(winpath target/driver-results)/python.json"
    rm -f target/driver-results/python.json
    (cd drivers/python && "$py" -m venv .venv \
      && vpy=".venv/bin/python" && { [[ -x "$vpy" ]] || vpy=".venv/Scripts/python.exe"; } \
      && "$vpy" -m pip install -q -e . --group dev \
      && "$vpy" -m ruff check . && "$vpy" -m ruff format --check . && "$vpy" -m mypy \
      && CI=true RUSTEGON_BIN_DIR="$bin_dir" RUSTEGON_CONFORMANCE_RESULTS="$py_results" "$vpy" -m pytest -q)
    results+=("$py_results")
  else
    step "drivers: Python SKIPPED (no python >= 3.11)"
  fi
  # Go driver (FR-DRV-007, AC-DRV-007): gofmt, go vet, go test (with -race where cgo has a C
  # compiler, PD-192); the conformance runner writes its results for the AC-DRV-003 comparison.
  if command -v go >/dev/null 2>&1; then
    step "drivers: Go gofmt + vet + tests (AC-DRV-007)"
    go_results="$(winpath target/driver-results)/go.json"
    rm -f target/driver-results/go.json
    unformatted="$(cd drivers/go && gofmt -l .)"
    if [[ -n "$unformatted" ]]; then
      echo "gofmt: unformatted files:"; echo "$unformatted"; exit 1
    fi
    go_race=()
    if [[ "$(cd drivers/go && go env CGO_ENABLED)" == "1" ]] && command -v "$(cd drivers/go && go env CC)" >/dev/null 2>&1; then
      go_race=(-race)
    else
      echo "go test: -race SKIPPED (no cgo C compiler, PD-192)"
    fi
    (cd drivers/go && go vet ./...       && RUSTEGON_BIN_DIR="$bin_dir" RUSTEGON_CONFORMANCE_RESULTS="$go_results" go test -count=1 "${go_race[@]}" ./...)
    results+=("$go_results")
  else
    step "drivers: Go SKIPPED (go not installed)"
  fi
  # Rust driver (FR-DRV-005, AC-DRV-005): drivers/rust is a cargo workspace of its own (PD-180),
  # so the server gates above do not cover it; same checks here (nextest, as the server), deny
  # with the root deny.toml (run from the root, where cargo-deny looks for it). The conformance
  # runner writes its results for the AC-DRV-003 comparison.
  step "drivers: Rust fmt + clippy + nextest + doctest + deny (AC-DRV-005)"
  rust_results="$(winpath target/driver-results)/rust.json"
  rm -f target/driver-results/rust.json
  cargo fmt --manifest-path drivers/rust/Cargo.toml --all --check
  cargo clippy --manifest-path drivers/rust/Cargo.toml --all-targets -- -D warnings
  RUSTEGON_BIN_DIR="$bin_dir" RUSTEGON_CONFORMANCE_RESULTS="$rust_results"     cargo nextest run --manifest-path drivers/rust/Cargo.toml
  cargo test --manifest-path drivers/rust/Cargo.toml --doc
  cargo deny --manifest-path drivers/rust/Cargo.toml check
  results+=("$rust_results")
  if (( ${#results[@]} >= 2 )); then
    step "drivers: AC-DRV-003 cross-driver results (${#results[@]} files)"
    RGN_DRIVER_RESULTS="$(IFS=,; echo "${results[*]}")"       cargo nextest run -p rustegon-common --test driver_results --no-capture
  else
    step "drivers: AC-DRV-003 SKIPPED (fewer than two results files)"
  fi
fi

# M12 GUI (AC-GUI-002, TC-GUI-002): lint, unit tests, build with budgets, then Playwright
# against release binaries of this tree. Without node/npm the step is skipped with a message;
# --no-gui skips it.
if [[ -n "$no_gui" ]]; then
  step "gui: SKIPPED (--no-gui)"
elif ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  step "gui: SKIPPED (node/npm not installed)"
else
  step "gui: npm ci, lint, unit tests, build (M12)"
  (cd gui && npm ci && npm run lint && npm test && npm run build)
  step "gui: release binaries embedding gui/dist (PD-130)"
  # cargo does not track files added to gui/dist/ (PD-130): force the embed to be re-read.
  touch bins/rustegond/src/gui.rs
  cargo build --release -p rustegond -p rustegon-cli
  bin_dir="$(winpath target/release)"
  step "gui: Playwright e2e against rustegond serving /ui (TC-GUI-002, AC-GUI-002)"
  (cd gui && npx playwright install chromium     && RUSTEGON_BIN_DIR="$bin_dir" RGN_E2E_SERVE=rustegond npm run e2e)
fi

# M14a (FR-INS-003, NFR-USE-001, PD-154, PD-156): the host archive, then the first-run
# walk-through from it, timed (≤ 10 min). Needs the GUI step's npm ci and chromium. The Linux
# archives (containers, arm64 under QEMU) are built on demand: `cargo xtask dist`.
if [[ -n "$no_walkthrough" ]]; then
  step "TC-INS-009: SKIPPED (--no-walkthrough)"
elif [[ -n "$no_gui" ]] || ! command -v node >/dev/null 2>&1; then
  step "TC-INS-009: SKIPPED (needs the GUI step)"
else
  step "dist: host archive + SHA256SUMS (FR-INS-003, PD-154)"; cargo xtask dist --target host
  step "TC-INS-009: walk-through from the host archive (NFR-USE-001)"; scripts/walkthrough.sh
fi

# Dev-build MSI on a Windows host with the .NET SDK (FR-INS-001, PD-200): build, then TC-INS-011
# (ICE validation, tables, administrative image; nothing is installed). Reuses the host build.
if [[ -n "$no_walkthrough" || -n "$no_gui" ]] || ! command -v dotnet >/dev/null 2>&1 \
  || [[ "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* ]]; then
  step "TC-INS-011: SKIPPED (needs the GUI step, a Windows host and dotnet)"
else
  step "dist: MSI (FR-INS-001, PD-200)"; cargo xtask dist --target windows-x86_64 --packages
  step "TC-INS-011: MSI validation and administrative image"; scripts/package-tests.sh --msi
fi

if [[ -n "$no_docker" ]]; then exit 0; fi

# TC-BKP-006: the S3 destination against MinIO (pinned image, throw-away credentials, host
# build). Without these variables the test skips itself, so the nextest step above only ran the
# fake-server tests.
# MinIO no longer publishes community images (minio/minio pull access denied, quay.io 401):
# the last bitnami build, pinned by digest (minio DEVELOPMENT.2025-05-24T17-08-30Z), PD-093.
# Its entrypoint starts the server itself (no `server /data` arguments).
MINIO_IMAGE=bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c
step "TC-BKP-006: S3 destination against $MINIO_IMAGE"
minio_user="rustegon-ci"
minio_pass="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
minio_id="$(MSYS_NO_PATHCONV=1 docker run -d --rm -p 127.0.0.1::9000 \
  -e MINIO_ROOT_USER="$minio_user" -e MINIO_ROOT_PASSWORD="$minio_pass" "$MINIO_IMAGE")"
minio_port="$(docker port "$minio_id" 9000/tcp | head -n1 | sed 's/.*://')"
minio_ok=""
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$minio_port/minio/health/live" >/dev/null; then minio_ok=1; break; fi
  sleep 1
done
minio_status=0
if [[ -n "$minio_ok" ]]; then
  RUSTEGON_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" RUSTEGON_TEST_S3_ACCESS_KEY="$minio_user" \
    RUSTEGON_TEST_S3_SECRET_KEY="$minio_pass" \
    cargo nextest run -p rustegon-backup --all-features --profile ci -E 'test(/^tc_bkp_006_minio/)' \
    || minio_status=$?
else
  echo "MinIO did not become ready" >&2; minio_status=1
fi
docker stop "$minio_id" >/dev/null || true
if [[ "$minio_status" != 0 ]]; then exit "$minio_status"; fi

# M14a image (FR-INS-003, AC-INS-003, PD-150): TC-INS-007 smoke and TC-INS-008 docker.md §4
# compose, on the host architecture; RGN_DOCKER_PLATFORMS="linux/amd64 linux/arm64" also builds
# and tests the arm64 image (cross-compiled, run under QEMU).
# TC-INS-009 Docker variant (PD-156) right after the native image is loaded (the tag holds the
# last platform built; arm64 would run under QEMU).
docker_walkthrough() {
  if [[ -n "$no_walkthrough" || -n "$no_gui" ]]; then return 0; fi
  step "TC-INS-009: walk-through with the docker.md §4 compose (NFR-USE-001)"
  scripts/walkthrough.sh --docker
}
for platform in ${RGN_DOCKER_PLATFORMS:-}; do
  step "image $platform: TC-INS-007, TC-INS-008"
  scripts/docker-tests.sh --platform "$platform"
  if [[ "$platform" == linux/amd64 ]]; then docker_walkthrough; fi
done
if [[ -z "${RGN_DOCKER_PLATFORMS:-}" ]]; then
  step "image (host architecture): TC-INS-007, TC-INS-008"
  scripts/docker-tests.sh
  docker_walkthrough
fi

# Dev-build DEB/RPM (FR-INS-002, AC-INS-002, PD-201…PD-203): linux-x86_64 binaries built in
# rust:1-bookworm, packaged with nfpm, then TC-INS-004/005/013 in ubuntu:24.04, ubuntu:26.04 and
# fedora:45 containers. The GUI is embedded, so this needs the GUI step's toolchain.
if [[ -z "$no_gui" ]] && command -v npm >/dev/null 2>&1; then
  step "dist: linux-x86_64 DEB + RPM (FR-INS-002, PD-201)"
  cargo xtask dist --target linux-x86_64 --packages
  step "TC-INS-004/005/013: DEB and RPM in containers"; scripts/package-tests.sh
fi

# Git Bash on Windows needs a Windows path for the volume and no MSYS path rewriting.
src="$(pwd -W 2>/dev/null || pwd)"
for platform in amd64 arm64; do
  step "linux/$platform: clippy + tests"
  # Under QEMU a 50 000-row cursor outlives its 60 s transaction; the memory bound is the same.
  rows=50000; [[ "$platform" == arm64 ]] && rows=10000
  MSYS_NO_PATHCONV=1 docker run --rm --platform "linux/$platform" \
    -e CARGO_TARGET_DIR=/tmp/target -e RGQL_CURSOR_ROWS=$rows -v "$src:/src:ro" -w /src rust:1-bookworm \
    bash -euo pipefail -c 'rustup toolchain install >/dev/null 2>&1
      cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
      cargo test --locked --workspace --all-features'
done
step "all gates green"
