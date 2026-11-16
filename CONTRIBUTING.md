# Contributing to Rustegon

Thank you for helping build Rustegon. This file is the short version; the binding rules are in
[`docs/implementation/`](docs/implementation/) and [`CLAUDE.md`](CLAUDE.md).

## Author and maintainer
Rustegon is created and maintained by **Davide Pegoraro**
([davide.pegoraro@outlook.com](mailto:davide.pegoraro@outlook.com)).

## Before you start
1. Read [`PROGRESS.md`](PROGRESS.md) (current milestone, next action, known issues) and the
   milestone in [`docs/implementation/development-phases.md`](docs/implementation/development-phases.md).
2. Find the requirement you are implementing (`FR-…` / `NFR-…` in
   [`docs/requirements/`](docs/requirements/)). User-visible behaviour without a requirement ID is
   not accepted.
3. `docs/` and `decisions/` are the source of truth. If a spec is wrong or ambiguous, fix the
   spec first (or open a `PD-` entry in [`decisions/pending-decisions.md`](decisions/pending-decisions.md)),
   then implement. Code never silently diverges from the docs.

## Non-negotiable rules
- **Storage engine**: `rustegon-storage` is the only storage engine (ADR-003). RocksDB, sled, fjall,
  redb, LMDB and any other third-party KV/storage engine are banned in every form (dependency,
  fallback, feature flag, benchmark baseline). `cargo deny` enforces it. Performance problems are
  profiled and fixed in the engine.
- **Safety**: durability and isolation guarantees (`docs/architecture/transaction-management.md`,
  `consistency.md`) can only change through a new ADR.
- **Security**: no default credentials, TLS on by default, no OpenSSL (rustls only), secrets never
  logged (wrap them in `Redacted<T>`).
- **Determinism**: time, randomness, network and file I/O go through the `rustegon-sim-api` traits
  (ADR-029). `clippy.toml` rejects direct OS calls elsewhere.
- **Formats and protos**: persisted formats are versioned with compatibility fixtures; public
  protos change additively only (`buf breaking`); error codes in `proto/errors.yaml` are
  append-only.
- **No invented results**: performance numbers come only from `bench/results/`.

## Code
- English everywhere. Comments explain *why*; algorithms, transactions, concurrency, memory and
  distributed logic need explanatory comments (`docs/implementation/coding-standards.md`).
- Every file starts with the SPDX header:
  ```rust
  // SPDX-License-Identifier: Apache-2.0
  // Copyright The Rustegon Authors
  ```
- No `unwrap()` on fallible paths, no `TODO` without an issue reference (`TODO(RGN-<n>)`).
- New dependencies need a purpose, alternatives, license check and maintenance check
  (`implementation-rules.md §7`); core ones are listed in `repository-structure.md`.

## Tests
- Every change ships its tests; a task is done only when they pass in CI
  (`implementation-rules.md §2`). Bugs get a failing regression test first.
- Test names carry the test-case ID when one exists: `tc_ops_001_…`.
- Concurrency and distributed code also needs simulation tests (`rustegon-sim`).

## Local checks (same as CI)
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --all-features --doc
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check && cargo audit
(cd proto && buf lint)
```
Tools: `cargo install --locked cargo-nextest cargo-deny cargo-audit`; `buf` from
<https://buf.build/docs/installation>.

## Commits and pull requests
- [Conventional Commits](https://www.conventionalcommits.org/) with requirement IDs, e.g.
  `feat(txn): parallel commit (FR-TXN-004)`.
- Small pull requests (< 800 changed lines excluding generated code), CI green, at least one review
  for core crates (`storage`, `mvcc`, `txn`, `raft`, `cluster`).
- A pull request that completes an item updates `PROGRESS.md` and the `Impl`/`Tests` columns of
  `docs/requirements/traceability-matrix.md`.

## License
Contributions are accepted under the Apache License 2.0 (see [`LICENSE`](LICENSE)).
