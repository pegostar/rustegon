<div align="center">

<img src=".github/assets/logo.svg" alt="Rustegon logo" width="128" height="128">

# Rustegon

### The PostgreSQL of NoSQL.

**A document database written in Rust that puts correctness first.**<br>
Every transaction is ACID and SERIALIZABLE by default, every acknowledged commit is on disk,<br>
and backup and restore is one command.

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-c2410c)
![Written in Rust](https://img.shields.io/badge/written%20in-Rust-da7108)
![Isolation: SERIALIZABLE](https://img.shields.io/badge/isolation-SERIALIZABLE-7c2d12)
![Status: R1 preview](https://img.shields.io/badge/status-R1%20preview-f59e0b)

[Why Rustegon](#why-rustegon) · [Features](#features) · [Compare](#how-it-compares) · [Quick start](#quick-start) · [Drivers](#drivers) · [Roadmap](#roadmap) · [Build](#building-from-source) · [Contact](#contact)

🌐 **[www.rustegon.com](https://www.rustegon.com)**: downloads, drivers and more details

</div>

---

## Why Rustegon

Most NoSQL databases ask you to make a trade: flexible documents and easy scaling **in exchange for** weaker isolation, writes acknowledged before they reach the disk, eventually consistent indexes, and backups bolted on afterwards. Safety is often something you have to switch on, and only if you know where the switch is.

**Rustegon does not accept that trade.** It brings the guarantees people trust in PostgreSQL to document-shaped data:

> **Correctness you do not have to configure.**
> The guarantees are the defaults. You opt *out* of safety on purpose, never *into* it by accident.

- 🛡️ **SERIALIZABLE by default.** Committed transactions behave as if they ran one after another, so anomalies such as write skew cannot happen. Transactions span documents, collections and whole databases. Even a single statement outside a transaction runs as an implicit transaction with the same guarantees. SNAPSHOT and READ COMMITTED are there when you ask for them.
- 💾 **Durable when acknowledged.** A commit is acknowledged only after it is synced to disk. It survives a process crash, an operating-system crash and a power cut.
- ♻️ **Backup is a feature, not an afterthought.** Online consistent backups, point-in-time recovery and logical dump/restore come built into the server and the CLI. Each one is a single command.
- 🔐 **Secure out of the box.** There are no default passwords and secrets are never logged. RBAC, encryption at rest and a tamper-evident audit log are part of the open-source product, not an enterprise upsell.
- 🦀 **One self-contained Rust binary.** It has its own storage engine and an embedded web console. There is no JVM and no third-party storage engine underneath.

Rustegon is built for applications where **a lost or anomalous write is not an option**: orders, payments, inventory, bookings, ledgers, records. It is also built for the teams who want document flexibility without giving up relational-grade guarantees.

## Features

<table>
<tr>
<td width="50%" valign="top">

### 🔎 RGQL, a query language built for documents
Readable statements for reads, writes and DDL. Parameters are never spliced into the text. Drivers get an equivalent structured form. Syntax errors report line and column. Also included: `EXPLAIN` / `EXPLAIN ANALYZE`, server-side cursors with continuation tokens, deadlines and cancellation.

</td>
<td width="50%" valign="top">

### 📄 Documents, with a schema only if you want one
Fields keep their order and their exact types: `int64`, `decimal128`, ObjectId, dates, binary and more. Documents are stored in the compact **RDoc** binary format and exchanged losslessly as extended JSON. `_id` is immutable, and revisions and timestamps are maintained by the server. Rich update operators are included. Optional **JSON Schema** validators point to the exact failing field.

</td>
</tr>
<tr>
<td valign="top">

### ⚡ Indexes and a cost-based planner
Single-field, compound, multikey, unique, sparse, partial and wildcard indexes are **updated in the same transaction as the data**, never eventually. Index builds run online and resume after a restart. The planner chooses access paths from collected statistics and reports index usage.

</td>
<td valign="top">

### 🔁 Transactions that drivers retry for you
MVCC with hybrid logical clocks. Interactive transactions can span requests. Every driver ships a `withTransaction` helper that retries on conflicts. An ambiguous commit is resolved by asking the server for the transaction's status, **never by running it twice**.

</td>
</tr>
<tr>
<td valign="top">

### ♻️ Backup and restore, one command each
- Online, consistent backups while writes continue, with verification.
- Hard-link snapshots and **point-in-time recovery** from the archived log.
- Logical dump/restore in extended JSON.
- Local, NFS and **S3-compatible** destinations; encrypted data stays encrypted.

</td>
<td valign="top">

### 🔐 Secure without default passwords
- SCRAM-SHA-256, API keys and X.509 client certificates.
- Role-based access control with built-in and custom roles, down to a single collection.
- **AES-256-GCM encryption at rest** and a **hash-chained audit log**.
- Rate limiting and account lockout.
- TLS 1.3 with one flag (`rustegon init --tls`); certificates reload without a restart.

</td>
</tr>
<tr>
<td valign="top">

### 🦀 Its own storage engine, in Rust
A purpose-built LSM engine with leveled compaction, LZ4 or Zstd block compression, checksums on every block and record, encryption hooks and checkpoints. A corrupted file is reported, never silently read.

</td>
<td valign="top">

### 📈 Observable and operable from day one
- gRPC (versioned `rustegon.v1` protobuf contracts) and a REST/JSON API described by **OpenAPI 3.1**.
- An OpenMetrics endpoint for Prometheus, plus liveness and readiness probes.
- Structured JSON logs in which secrets are always redacted.
- A `rustegon` CLI for init, shell, users, backups and certificates.

</td>
</tr>
</table>

### A web console built in

Every node serves a modern web console at `/ui/`. You can browse documents, write and explain queries, manage indexes, users and roles, and run backups, all with light and dark themes and an accessible UI.

<table>
<tr>
<td><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/query-dark.webp"><img src=".github/assets/query-light.webp" alt="Query editor of the Rustegon web console"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/explain-dark.webp"><img src=".github/assets/explain-light.webp" alt="EXPLAIN plan view of the Rustegon web console"></picture></td>
</tr>
<tr>
<td><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/documents-dark.webp"><img src=".github/assets/documents-light.webp" alt="Document browser of the Rustegon web console"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/backup-dark.webp"><img src=".github/assets/backup-light.webp" alt="Backup page of the Rustegon web console"></picture></td>
</tr>
</table>

## A taste of Rustegon

**RGQL**

```sql
FROM shop.orders AS o
WHERE o.status IN ['paid', 'shipped'] AND o.total >= $min
SELECT o._id, o.total, o.customer.name AS customer
ORDER BY o.total DESC
LIMIT 50;

UPDATE shop.orders SET status = 'paid' WHERE _id = 42 RETURNING NEW;
CREATE INDEX idx_status_total ON shop.orders (status ASC, total DESC);
EXPLAIN FROM shop.orders WHERE status = 'paid';
```

**.NET driver**: typed documents, source-generated codecs, Native AOT ready

```csharp
[RustegonDocument]
public sealed record Order([property: RgnId] long Id, string Customer, decimal Total);

await using var client = new RustegonClient($"rustegon://admin:{Uri.EscapeDataString(password)}@localhost:7700/shop");
var orders = client.GetDatabase().GetCollection<Order>("orders");

await orders.InsertOneAsync(new Order(42, "ada", 120m));
List<Order> big = await orders.Find(Filter.Gt<Order>(x => x.Total, 100m)).ToListAsync();

// SERIALIZABLE, retried automatically on conflict, never applied twice.
await client.WithTransactionAsync(async (txn, ct) =>
    await txn.Collection<Order>("orders").UpdateOneAsync(Filter.Id(42), Update.Inc("total", -10), cancellationToken: ct));
```

## How it compares

Rustegon's defaults line up with a relational database, while the data stays document-shaped. The comparison below covers guarantees and features only, not speed. Each product is described from its own official documentation (as of 2026-11).

| | **Rustegon** | PostgreSQL | MongoDB 9.0 | Cassandra 5.0 |
|---|---|---|---|---|
| Data model | Documents with exact types, optional JSON Schema | Tables; JSON in `jsonb` | Documents, flexible schema | Partitioned tables (CQL) |
| **Default isolation** | **SERIALIZABLE** | READ COMMITTED | Read concern `"local"`; snapshot on request | Within one partition only |
| Multi-document transactions | **Yes, across collections and databases** | Yes, across rows and tables | Yes | No multi-partition transactions |
| Durable on acknowledgement, by default | **Yes, fsync first** | Yes | Tunable write concern | Tunable consistency level |
| Secondary indexes | **Transactional**, same commit as the data | Transactional | Yes | SAI, local to each replica |
| Online backup + PITR built in | **Yes, open source** | Yes | PITR via Cloud/Ops Manager (Enterprise) | Snapshots; PITR via commit-log archiving |
| Encryption at rest & audit log | **Yes, open source** | Via extensions / tooling | Enterprise / Atlas | Audit log yes |
| Web console in the server | **Yes, `/ui`** | No (third-party tools) | Compass (desktop app) | Third-party tools |
| Licence | **Apache-2.0** | PostgreSQL Licence | SSPL / commercial | Apache-2.0 |

Rustegon is the only column that combines **document flexibility**, **SERIALIZABLE-by-default transactions**, **built-in point-in-time recovery** and **open-source security features** under the **Apache-2.0** licence.

## Engineered to be trusted

A database is worth only as much as the evidence behind its guarantees. Rustegon is built to produce that evidence:

- **Crash-tested at every I/O.** The storage engine is tested by crashing it at *every single* I/O operation and checking what survives. Its 24-hour crash campaign ran **171,700 workloads with zero failures**.
- **Deterministic simulation testing.** Every disk, network and clock access goes through one set of interfaces (`rustegon-sim-api`). Because of that, the whole database also runs inside a seeded simulator that injects crashes, I/O errors, power cuts and pauses, then checks the histories for isolation anomalies. Every failure prints its seed and replays exactly. The simulator has already caught a real durability bug before any release.
- **Independent oracles.** Query results are cross-checked against a separate reference interpreter, and the query parser is fuzzed.
- **Checksums everywhere.** Every persisted format is versioned and checksummed.
- **One conformance suite for every driver.** All six drivers run the same language-neutral suite and pass 107 of 107 cases.
- **Honest numbers only.** No performance figure is published until it is measured on reference hardware. Storage-engine measurements live in [`bench/results/`](bench/results/).

## Quick start

A single node listens on **7700** (gRPC, drivers) and **7780** (REST and the web console at `http://localhost:7780/ui/`).

**Docker** ([`pegostar/rustegon`](https://hub.docker.com/r/pegostar/rustegon), `linux/amd64` and `linux/arm64`)

```bash
openssl rand -base64 24 > admin_password.txt   # the admin password, at least 12 characters
chmod 644 admin_password.txt                    # the server runs as uid 10001 and must read it

docker run -d --name rustegon \
  -p 7700:7700 -p 7780:7780 \
  -v rustegon-data:/var/lib/rustegon \
  -v "$PWD/admin_password.txt:/run/secrets/admin_password:ro" \
  -e RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/admin_password \
  --stop-timeout 90 \
  pegostar/rustegon:0.1.0
# open http://localhost:7780/ui/ and sign in as admin
```

**Archive (Linux / Windows)**: see [`packaging/archive/README.md`](packaging/archive/README.md)

```bash
./rustegon init --data-dir ./data --admin-password-file admin.pw
./rustegond --config ./data/rustegon.toml --admin-password-file admin.pw
```

**Turnkey installers**: Windows MSI, Ubuntu DEB, Fedora RPM ([`packaging/`](packaging/)). They install, initialize and start a node as a service. Sign in at `http://localhost:7780/ui/` as `admin` / `admin`. That bootstrap account works only from the local machine and must be changed at the first sign-in.

Drivers connect with `rustegon://<user>:<password>@localhost:7700/<database>`.

## Drivers

Official drivers share one wire contract and one conformance suite ([`drivers/conformance/`](drivers/conformance/README.md)).

| Language | Install (0.1.0) | Registry | Directory |
|---|---|---|---|
| .NET 10 (trimming / Native AOT) | `dotnet add package Rustegon.Driver --version 0.1.0` | [nuget.org](https://www.nuget.org/packages/Rustegon.Driver) | [`drivers/dotnet`](drivers/dotnet/README.md) |
| Java 21+ | `com.rustegon:rustegon-driver:0.1.0` | [Maven Central](https://central.sonatype.com/artifact/com.rustegon/rustegon-driver) | [`drivers/java`](drivers/java/README.md) |
| Node.js 20+ | `npm install @rustegon/driver@0.1.0` | [npm](https://www.npmjs.com/package/@rustegon/driver) | [`drivers/node`](drivers/node/README.md) |
| Python | `pip install rustegon==0.1.0` | [PyPI](https://pypi.org/project/rustegon/) | [`drivers/python`](drivers/python/README.md) |
| Go | `go get github.com/pegostar/rustegon/drivers/go@v0.1.0` | [pkg.go.dev](https://pkg.go.dev/github.com/pegostar/rustegon/drivers/go) | [`drivers/go`](drivers/go/README.md) |
| Rust | `cargo add rustegon-driver@0.1.0` | [crates.io](https://crates.io/crates/rustegon-driver) | [`drivers/rust`](drivers/rust/README.md) |

## Roadmap

| Release | Scope | Status |
|---|---|---|
| **R1** | Complete single-node database: storage engine, ACID transactions, RGQL and indexes, security, backup/PITR, drivers, web console, Docker image, archives and installers | ✅ **Feature-complete preview** |
| **R2** | Three-node **Raft replication** with automatic failover, linearizable reads by default, mandatory mutual TLS between nodes, aggregation pipeline | 🛠️ Specified |
| **R3** | **Automatic sharding** and distributed transactions across shards, cluster-wide and incremental backups, OIDC sign-in, key management services | 🗺️ Specified |

> **Project status:** R1 is a feature-complete **preview**, not a released product. The six drivers and the Docker image are published as 0.1.0; the archives and installers are unsigned development builds. Replication (R2) and sharding (R3) are designed but not implemented. Until R2, the defence against losing a disk is the built-in backup.

## Building from source

**Requirements:** Rust **1.99.1** (pinned by `rust-toolchain.toml`), [`cargo-nextest`](https://nexte.st/), and Node.js ≥ 24 for the web console. Drivers need .NET 10, Java 21+, Python, Go or Node.js respectively.

```bash
# 1. Web console (embedded into the server binary; optional, /ui answers 503 without it)
(cd gui && npm ci && npm run build)

# 2. Server and CLI
cargo build --release -p rustegond -p rustegon-cli

# 3. Tests and quality gate
cargo nextest run --workspace
cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run -p rustegon-sim -- --seeds 200 --workload all    # deterministic simulation
cargo deny check

# 4. Packages: Docker, archives, MSI/DEB/RPM (output in dist/)
cargo xtask dist --packages
```

### Repository layout

| Path | Content |
|---|---|
| [`crates/`](crates/) | The database: storage engine, documents, indexes, query engine, transactions, security, backup, server, simulator |
| [`bins/`](bins/) | `rustegond` (the server) and `rustegon` (the CLI) |
| [`proto/`](proto/) · [`api/`](api/) | gRPC contracts (`rustegon.v1`), error catalog, OpenAPI |
| [`drivers/`](drivers/) | Official drivers and the shared conformance suite |
| [`gui/`](gui/) | Angular web console |
| [`packaging/`](packaging/) · [`xtask/`](xtask/) | Docker, archives, installers and the `dist` task |
| [`bench/`](bench/) · [`fuzz/`](fuzz/) | Benchmarks with recorded results, fuzz targets |

## Learn more

Downloads, driver guides and project news are at **[www.rustegon.com](https://www.rustegon.com)**. For the details, this repository is the reference.

## Contact

For information or questions, write to [info@rustegon.com](mailto:info@rustegon.com).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first, and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Rustegon is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.
You are free to use it for any purpose, commercial or not, and to do whatever you like with it.

## Buy me a coffee

Only if you feel like it: if Rustegon is useful to you, you can buy me a coffee.

<a href="https://www.buymeacoffee.com/davidepegoraro"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy me a coffee" height="50"></a>

## Sponsors

Thanks to those who support the project.

<a href="https://utechitalia.com/"><img src="https://www.rustegon.com/assets/img/sponsors/utech.png" alt="Utech Italia" width="240"></a>

<div align="center">
<sub>Built in Rust 🦀, with correctness as the default.</sub>
</div>
