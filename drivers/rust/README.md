# Rustegon Rust driver (`rustegon-driver`, crate `rustegon`)

Official Rust driver of Rustegon (FR-DRV-005, specification
[`docs/specifications/rust-driver.md`](../../docs/specifications/rust-driver.md)): async on Tokio
and tonic, the Driver Conceptual Model shared with the .NET, Java, Node.js, Python and Go drivers,
validated by the shared conformance suite in [`drivers/conformance/`](../conformance/README.md).

```rust
use rustegon::{Client, Filter, TransactionOptions, Update, doc};

#[tokio::main]
async fn main() -> rustegon::Result<()> {
    // Plain text matches a default single node (ADR-034); add ?tlsCaFile=… (or tls=true) for TLS.
    let client = Client::from_connection_string("rustegon://app_user:secret@localhost:7700/shop")?;
    let orders = client.default_database().collection("orders");

    orders.insert_one(doc! { "_id" => 42, "status" => "paid", "total" => 120 }).await?;
    let paid = orders
        .find(Filter::and([Filter::eq("status", "paid"), Filter::gte("total", 100)]))
        .limit(50)
        .to_list()
        .await?;
    orders
        .update_one(Filter::id(42), Update::new().set("status", "shipped").inc("version", 1))
        .await?;

    client
        .with_transaction(TransactionOptions::new(), |tx| async move {
            let acct = tx.collection("accounts");
            acct.update_one(Filter::id("a1"), Update::new().inc("balance", -10)).await?;
            acct.update_one(Filter::id("a2"), Update::new().inc("balance", 10)).await?;
            Ok(())
        })
        .await?;

    println!("{} paid orders", paid.len());
    client.close().await;
    Ok(())
}
```

- **Settings**: `Settings::builder()…build()` or `Settings::from_connection_string(uri)`; grammar,
  options and defaults in `drivers/conformance/connstring.yaml`. TLS is off by default; a CA file,
  server name, client certificate or `Credential::x509()` turns it on.
- **Credentials**: `Credential::scram(user, password)` (SCRAM-SHA-256 + SASLprep),
  `Credential::api_key(key)`, `Credential::x509()` with `TlsSettings::{certificate_file, key_file}`.
- **Operations** return awaitable builders: `.session(&s)`, `.timeout(d)`, `.if_rev(rev)`,
  `.upsert(true)`, `.ordered(false)`, `.batch_size(n)`, `.read_consistency(…)`, `.write_concern(…)`.
- **Errors**: `rustegon::Error`; catalog errors carry `code`, `name`, `ErrorClass`, `retryable`,
  `committed`, `trace_id` (`err.is(ErrorClass::DuplicateKey)`).
- **Retries** follow `drivers/conformance/retry.yaml`: retryable reads and writes once by default
  (same `rgn-request-id`), one deadline per operation, never inside a transaction.

## Layout

| Path | Content |
|---|---|
| `src/codec/` | value model, RDoc v1, extended JSON (copy of the server's `rustegon-doc`, PD-180) |
| `src/{settings,connstring,scram,auth,transport}.rs` | settings, connection strings, SCRAM, logins, pool and retry executor |
| `src/{client,database,collection,cursor,session,transaction,builders,options}.rs` | the API |
| `build.rs` | compiles `proto/rustegon/v1/*.proto` with `protox` (no `protoc`) |
| `tests/conformance/` | one test binary: shared vectors, fake server (`retry.yaml`), conformance runner, integration tests |

## Build and test

`drivers/rust` is a cargo workspace of its own (PD-180). From the repository root:

```bash
cargo build -p rustegond -p rustegon-cli                       # server binaries for the tests
cargo fmt   --manifest-path drivers/rust/Cargo.toml --all --check
cargo clippy --manifest-path drivers/rust/Cargo.toml --all-targets -- -D warnings
cargo nextest run --manifest-path drivers/rust/Cargo.toml     # RUSTEGON_BIN_DIR defaults to target/debug
cargo test  --manifest-path drivers/rust/Cargo.toml --doc
cargo deny  --manifest-path drivers/rust/Cargo.toml check      # root deny.toml
```

Tests that need a server start `rustegond` from `RUSTEGON_BIN_DIR` and skip with a message when
the binaries are missing (they fail under `CI=true`). The conformance runner writes
`conformance-results.json` (or `RUSTEGON_CONFORMANCE_RESULTS`) for the AC-DRV-003 comparison
(`crates/rustegon-common/tests/driver_results.rs`); `scripts/ci-local.sh` runs all of this in its
drivers step. `RGN_RETRY_SCENARIO=<name>` runs one `retry.yaml` scenario.

Divergences from the other drivers: [`drivers/DIVERGENCES.md`](../DIVERGENCES.md) §10.
