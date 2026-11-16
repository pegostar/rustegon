# Rustegon driver conformance suite

Shared, language-neutral conformance suite of the Rustegon drivers (FR-DRV-003, AC-DRV-001…003,
testing-strategy.md §5). The .NET (`drivers/dotnet/`) and Java (`drivers/java/`) drivers run it
with their own runners; later drivers (DEC-014: Node.js, Rust, Python, Go) run the same files.
Test ids: `TC-DRV-CONF-<CATEGORY>-NNN`.

> **Status (M11 R1, lane DK).** The files are complete for the R1 scope (PD-069) and pass the
> static checks below, but **no driver runner has executed them yet**: expected results are
> derived from the specifications (data-model.md, query-language.md §4.3, transactions.md,
> protocol.md §3) and from reading the server code. When a runner disagrees, decide with the
> server as oracle unless a spec says otherwise, and fix either the test or the server (with a
> regression test) — never the expectation of one driver only.

## 1. Layout

| Path | Content | Produced by |
|---|---|---|
| `model.yaml` | Driver Conceptual Model operations: stable id, kind, status `r1` / `deferred(<milestone>)`, .NET and Java member, RPCs | hand-written |
| `errors-map.yaml` | error code → exception class of both drivers, hierarchy, unknown-code and transport fallbacks | hand-written (PD-075) |
| `connstring.yaml` | valid/invalid `rustegon://` strings and the parsed settings (DEC-014) | hand-written |
| `retry.yaml` | fake-server retry scenarios (PD-073) | hand-written |
| `schema/test.schema.json` | JSON Schema (2020-12) of a test file | hand-written |
| `crud/ query/ cursor/ bulk/ txn/ errors/ schema/ auth/ client/` `*.yaml` | test files (one category per directory) | hand-written |
| `generated/ErrorCodes.g.cs`, `generated/ErrorCodes.java`, `generated/errors.json` | error tables for the drivers | `crates/rustegon-common/tests/driver_tables.rs` |
| `codec/values.yaml`, `codec/documents.yaml`, `codec/invalid.yaml` | RDoc v1 codec vectors | `crates/rustegon-doc/tests/driver_vectors.rs` |
| `ast/filters.json`, `ast/updates.json`, `ast/statements.json` | builder → AST golden vectors (PD-070) | `crates/rustegon-server/tests/driver_ast.rs` |
| `mapping/vectors.yaml` | cross-driver object-mapping vectors: models, round trips, built values, refused inputs (PD-108…PD-113; .NET TC-DRV-NET-023, Java TC-DRV-JAVA-023) | hand-written; JSON texts checked by `driver_conformance` |
| `scram/vectors.yaml` | SASLprep cases and complete SCRAM-SHA-256 handshakes with fixed nonces (PD-074) | `crates/rustegon-security/tests/driver_scram.rs` |

Generated files are checked in. Each generator test fails when its files are stale; re-bless with
`RGN_FIXTURES_BLESS=1` (the same convention as `crates/rustegon-server/tests/golden_api.rs`) and
review the diff like any golden change:

```bash
RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-common --test driver_tables
RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-doc    --test driver_vectors
RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-server --test driver_ast
RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-security --test driver_scram
cargo nextest run -p rustegon-common --test driver_conformance   # static checks of the suite
RGN_DRIVER_RESULTS=<dotnet.json>,<jdk21.json>,<jdk25.json>   cargo nextest run -p rustegon-common --test driver_results     # AC-DRV-003 report (§6)
```

The driver builds include `generated/ErrorCodes.g.cs` / `generated/ErrorCodes.java` as they are
(link or copy at build time; never edit them in the driver trees).

## 2. Static checks (the suite cannot rot)

`crates/rustegon-common/tests/driver_conformance.rs` runs in the normal Rust gate and checks:
every test file against `schema/test.schema.json` (a small validator for the keywords the schema
uses; the `pattern` rules are checked by hand); test ids unique and named after their directory;
`covers` naming `r1` operations of `model.yaml`; **every `r1` operation covered by at least one
test**; operation names valid for the object they are called on; `saveAs` names defined before
use; data files of runner operations present; `model.yaml`, `connstring.yaml`, `retry.yaml` well
formed. `driver_tables.rs` checks that `errors-map.yaml` maps every catalog code.

Current figures (printed by the test): 107 tests, 109 `r1` operations, all covered; 13 deferred.

## 3. Codec vectors (`codec/`)

RDoc v1 is data-model.md §4. Documents travel as RDoc bytes (`Document.rdoc`); ids, parameters
and option values as the **value encoding** (`Value.rdoc_value`: type tag + payload, no header).
All strings in the vector files are YAML double-quoted scalars; `ext_json` is canonical extended
JSON text (data-model.md §2 notes), `extended_json` the extended mode (`$int64` / `$float`
everywhere), `hex` lowercase hex.

- `values.yaml` — `values[]`: `{name, type, input, ext_json, extended_json, hex, decode_only?}`.
  A driver must (1) parse `input` and `ext_json` to the same value, (2) encode it to `hex`
  (skip when `decode_only`: `counter` is never accepted as input), (3) decode `hex` and print
  `ext_json` / `extended_json` exactly. `noncanonical[]`: `{name, hex, canonical_hex, ext_json}`:
  decoding `hex` is accepted and re-encoding gives `canonical_hex`.
- `documents.yaml` — `documents[]`: `{name, ext_json, hex, name_hash16: [{name, hash}], decode_only?}`;
  same checks for whole documents (flags `0x01`), plus `name_hash16` (low 16 bits of
  `xxh3_64(name, seed 0)`, 4 hex digits) for every field name, including a hash collision (index
  order then falls back to the name bytes) and the depth limit (100). `noncanonical[]`: documents
  with flags `0x00` that must be accepted and re-encoded canonically.
- `invalid.yaml` — `documents[]` / `values[]`: `{name, hex, error, code}`; `json[]`:
  `{name, kind: document|value, json, error, code}`. Each input must be rejected (never a crash
  or a hang); `error` is the class (`malformed` 1001, `too_large` 1002, `too_deep` 1003,
  `invalid_field_name` 1004, `invalid_vector` 1040) and drivers should report `code`.

## 4. Builder → AST vectors (`ast/`) and the builder DSL

Builders produce the structured AST of `proto/rustegon/v1/query_ast.proto`, never RGQL text
(PD-070). Each case carries the builder call in the **builder DSL** below, the parameters
(`{name: {ext_json, hex}}`), the equivalent RGQL text (informative), and the canonical protobuf
JSON of the AST (lowerCamelCase field names, enum value names, 64-bit integers as strings,
default values omitted — what `Google.Protobuf.JsonFormatter` / `JsonFormat.printer()` print).
A driver test translates the DSL into its builder calls, builds the request and compares the
protobuf JSON of `ExecuteRequest.ast` (or `UpdateRequest.operations`) and the encoded parameters.
Every AST is also decoded by the server's validated decoder in the generator, so it is accepted
by `QueryService.Execute`.

- `filters.json` — `{name, filter, params, rgql, where, statement}`: `where` is the `AstExpr`,
  `statement` the `AstStatement` of ``FROM `c` WHERE <filter>``.
- `updates.json` — `{name, update, params, rgql, operations}`: `operations` is the
  `repeated AstUpdateOp` of `DocumentService.Update` / `BulkUpdate`.
- `statements.json` — `{name, op, args, params, rgql, statement}` for `find`, `updateOne`,
  `updateMany`, `replaceOne`, `deleteOne`, `deleteMany` with non-id filters.

**Builder DSL** (also used by the test files). A *filter* is `{}` (match everything,
`Filter.Empty`) or a one-key object:

| DSL | Builder (model id) | RGQL / AST |
|---|---|---|
| `{eq: [path, v]}` `ne` `gt` `gte` `lt` `lte` | `Filter.Eq` … `Filter.Lte` | `path = $f0` (`!=`, `>`, `>=`, `<`, `<=`) |
| `{in: [path, [v…]]}` / `{nin: …}` | `Filter.In` / `Filter.Nin` | `path IN $f0` / `NOT IN` (one array parameter) |
| `{exists: [path, true\|false]}` | `Filter.Exists` | `path IS NOT MISSING` / `IS MISSING` |
| `{isNull: path}` | `Filter.IsNull` | `path IS NULL` (null or missing) |
| `{contains: [path, v]}` `containsAny` `containsAll` | `Filter.Contains…` | `CONTAINS`, `CONTAINS ANY`, `CONTAINS ALL` |
| `{elemMatch: [path, filter]}` | `Filter.ElemMatch` | `ELEM MATCH (path, <filter on the element>)` |
| `{like: [path, pattern]}` / `{regex: [path, re]}` | `Filter.Like` / `Filter.Regex` | `LIKE` / `MATCHES` |
| `{and: [f…]}` / `{or: [f…]}` / `{not: f}` | `Filter.And/Or/Not` | n-ary `and`/`or`, `not` |
| `{id: v}` | `Filter.Id` | `_id = $f0` |

An *update* is a list of one-key objects, one `AstUpdateOp` each, in order: `{set: [path, v]}`,
`{unset: path}`, `{inc: [path, n]}`, `{mul: [path, n]}`, `{min: [path, v]}`, `{max: [path, v]}`,
`{push: [path, v]}`, `{addToSet: [path, v]}`, `{pull: [path, v]}` (removes elements equal to `v`:
`PULL p WHERE <last field of p> = $u0`), `{pop: [path, first|last]}`, `{rename: [from, to]}`,
`{currentDate: path}`, `{replace: document}` (sole operation). Paths are dotted strings; an
all-digit segment after the first is an array position. `sort` is a list of paths, `-path` =
descending; `projection` is `{include: [paths]}` or `{exclude: [paths]}`; `limit`, `skip`,
`batchSize` are integers. Values are canonical extended JSON.

**Builder rules (normative, PD-070):**
1. Every value the user passes to a filter becomes a named parameter `f0, f1, …` in DSL
   (depth-first, left-to-right) order; every update value `u0, u1, …`. Field names become
   `AstPath` segments, never text. `limit` / `skip` are `int64` literals.
2. Nested `and` inside `and` (and `or` inside `or`) are flattened: the server accepts only the
   canonical AST (`query_ast.proto` header; non-canonical → RGN-1010).
3. A filter that is exactly `Filter.Id(v)` routes `UpdateOne`/`ReplaceOne`/`DeleteOne` to
   `DocumentService.Update/Replace/Delete` (`Upsert` for `ReplaceOne` with upsert, which
   requires `Filter.Id`); any other filter uses `QueryService.Execute` with the statement form.
4. **Single-document writes with a non-id filter** use `UPDATE … WHERE … LIMIT 1`,
   `UPDATE … REPLACE WITH $u0 WHERE … LIMIT 1` and `DELETE FROM … WHERE … LIMIT 1`: RGQL has a
   single-row form (query-language.md §3 `update`/`delete` grammar), and matching documents are
   visited in `_id` order, so the document with the lowest `_id` is written (§4.3 "Writes").
   No `Many`-only fallback and no divergence entry are needed (PD-070 question answered).
5. The empty filter on `UpdateMany`/`DeleteMany` (and `UpdateOne`/`DeleteOne`) adds
   `OPTIONS (allow_full_scan_write = true)`; without it the server refuses the write (RGN-1013).
   User RGQL text is never rewritten (TC-DRV-CONF-QUERY-037).
6. `find` = ``FROM `c` [WHERE f] [SELECT projection] [ORDER BY sort] [LIMIT n] [OFFSET m]``.

## 5. Test files

Format (`schema/test.schema.json`):

```yaml
description: "…"
setup: {…}                    # optional default for tests without their own setup
tests:
  - id: TC-DRV-CONF-CRUD-001
    description: "…"
    covers: [Collection.InsertOne]       # model.yaml r1 ids
    requires: [admin]                    # optional fixture capabilities
    setup:
      collections: [{name: items, validator?: {jsonSchema, level?, action?}}]
      indexes: [{collection, name, keys: [{path, descending?}], unique?}]
      data: {items: [{…}, …]}
      users: [{name, password, roles: ["read@${database}"], mustChangePassword?}]
    operations:
      - object: collection               # client | database | collection | runner | <saved name>
        collection: items                # default: the first setup collection
        session: s1                      # optional saved session
        name: insertOne
        args: {document: {"_id": 1}}
        then: toList | first | cursor    # find only (default toList)
        saveAs: r1
        match: exact | subset            # default exact
        ordered: true                    # lists compared in order (default true)
        fieldOrder: false                # documents compared with field order (default false)
        expect: {result: …} | {error: {code, name, exception, retryable, committed}}
    outcome:
      items: [{…}]                       # collection content afterwards, by _id
```

**Fixture and lifecycle (PD-072).** One server per test run, started from `RUSTEGON_BIN_DIR`
(default `<repo>/target/debug`: `rustegon init`, then `rustegond --stop-on-stdin-eof` with
`rate_limit.auth_per_ip_per_min`, `auth_per_user_per_min`, `session_per_user_per_min` and
`admin_per_user_per_min` set to 0, so the many logins of a run never meet RGN-4003, PD-098); without
the binaries the runner skips with a message, and fails under `CI=true`. The default client is
the fixture's admin (SCRAM). Per file: a fresh database `${database}` =
`conf_<category>_<file stem>_<8 random hex>`, dropped at the end. Per test: drop every collection
of the database, create `setup.collections` (with validators), create `setup.indexes` and wait
until each is `READY`, insert `setup.data` in the listed order (`InsertMany` per collection),
create `setup.users` (dropped after the test); then run the operations in order, then compare
`outcome`. A test without `setup` uses the file's `setup`.

**Substitutions** in any string: `${database}`, `${host}`, `${port}`, `${adminUser}`,
`${adminPassword}`, `${adminUserEncoded}` / `${adminPasswordEncoded}` / `${caFileEncoded}`
(percent-encoded), `${caFile}`, `${apiKey}` (`requires: [api-key]`: an API key of the admin
created by the fixture), `${clientCertFile}` / `${clientKeyFile}` (`requires: [x509-client-cert]`:
a client certificate from `rustegon init` mapped to a user with `read_write@${database}`).
`requires` values: `admin` (create users/databases), `api-key`, `x509-client-cert`, `slow` (sleeps
of several seconds), `fixture-connection-string`; a runner lacking one reports the test as
skipped, never as passed.

**Operations** (`args` and results; model ids in parentheses). Collection operations are also
available on a saved client (`object: <client>`, with `collection`) and on a transaction
(`object: transaction` inside `withTransaction` callbacks / `manualTransaction` steps, or a saved
`beginTransaction`; `Transaction.GetCollection`).

| Object | name | args | result |
|---|---|---|---|
| client | `open` (Client.Create) | `credential: {scram: {user, password}} \| {apiKey} \| {x509: {certificateFile, keyFile}}`, `allowPasswordChangeOnly?` | saved client |
| client | `openFromConnectionString` (Client.CreateFromConnectionString) | `uri` | saved client |
| client | `getServerInfo` | — | `{serverVersion, protocolVersion, features}` |
| client | `listDatabaseNames` / `createDatabase` / `dropDatabase` | `name`, `ifNotExists?` / `ifExists?` | `[names]` / `{created}` / `{dropped}` |
| client | `startSession` | `causalConsistency?` | saved session |
| client | `beginTransaction` | `options?: {isolation: serializable\|snapshot\|read_committed, readOnly?, maxRetryTimeMs?}` | saved transaction |
| client | `withTransaction` | `options?`, `callback: [operations]` | `null` (the callback returns nothing) |
| client | `manualTransaction` | `options?`, `steps: [operations]` — begin, run the steps, close | `null` |
| client | `changePassword` | `currentPassword`, `newPassword` | `null` |
| client | `close` | — | `null`; idempotent; later calls → `InvalidState` |
| database | `query` (Database.Query) | `rgql`, `params?: {name: value}`, `batchSize?` | `[rows]` |
| database | `createCollection` / `dropCollection` / `listCollectionNames` | `name`, `validator?`, `ifNotExists?` / `ifExists?` | `{created}` / `{dropped}` / `[names]` (sorted) |
| collection | `insertOne` / `insertMany` | `document` / `documents` | `{insertedId}` / `{insertedIds}` |
| collection | `findById` | `id`, `options?` | document or `null` |
| collection | `find` | `filter`, `sort?`, `limit?`, `skip?`, `projection?`, `batchSize?`; `then` | `[docs]` / doc or `null` / saved cursor |
| collection | `updateOne` / `updateMany` | `filter`, `update`, `options?: {ifRev?}` | `{matchedCount, modifiedCount}` |
| collection | `replaceOne` | `filter`, `replacement`, `options?: {upsert?, ifRev?}` | `{matchedCount, modifiedCount, upsertedId?}` |
| collection | `deleteOne` / `deleteMany` | `filter`, `options?: {ifRev?}` | `{deletedCount}` |
| collection | `bulkWrite` | `operations: [{insert: {document}} \| {replace: {id, document, ifRev?}} \| {update: {id, update, ifRev?}} \| {upsert: {document}} \| {delete: {id, ifRev?}}]`, `ordered?` (default true) | `{insertedCount, matchedCount, modifiedCount, deletedCount, errors: [{index, code}]}` |
| collection | `createIndex` / `dropIndex` / `listIndexes` | `name`, `keys`, `unique?` / `name`, `ifExists?` / — | `{name, state}` / `{dropped}` / `[{name, keys, unique, state}]` |
| cursor | `next` / `close` | — | document, or `null` at the end / `null` |
| session | `causalityToken` / `close` | — | token or `null` / `null` (idempotent) |
| transaction | `query`, `commit`, `rollback`, `close`, `resolve` | `rgql`, `params?` (query) | rows / `null` / `null` / `null` / `committed \| aborted \| unknown` |
| runner | see §7 | | |

Result conventions: `UpdateResult` of a statement (non-id filter) reports the server's
`docs_affected` as both `matchedCount` and `modifiedCount` (the server rewrites every matched
document; see the spec gap in the M11 report); by-id updates report `UpdateResponse.matched` /
`modified`. `bulkWrite` reports per-operation failures in `errors` (it does not throw) unless the
call itself fails (inside a transaction any failure fails the call). Index `state` is
`building | ready | failed | hidden`.

**Values and matching.** YAML uses only its JSON-compatible subset; a value is canonical
extended JSON: a YAML integer is `int64`, a YAML float (with `.` or exponent) is `float64`,
special values use the `$` wrappers (`{"$float": "NaN"}`, `{"$decimal": "12.50"}`, …). Quote
strings that YAML would read otherwise (`"null"`, `"1"`, `"yes"`). Placeholders: the string
`"$$any"` matches any value (null included); `{"$$type": "<type>"}` matches any value of that
data-model §2 type name (`objectId`, `datetime`, `string`, …); `"$$ref:<name>[.<path>]"` is the
value saved by `saveAs: <name>` (a dotted path selects a field of it, e.g. `$$ref:doc._rev`).

- Before comparing, documents returned by the server lose `_rev`, `_createdAt`, `_updatedAt`
  unless the expected document names that field.
- `exact`: same fields (field order ignored unless `fieldOrder: true`), same values **and types**
  (`1` int64 ≠ `1.0` float64 ≠ `{"$decimal":"1"}`; NaN equals NaN; `-0.0` ≠ `0.0`), arrays
  element by element. `subset`: every expected field is present and matches (recursively);
  extra fields are allowed; arrays still need the same length. Lists of results are compared in
  order unless `ordered: false` (then as multisets); a result list with both `match: subset` and
  `ordered: false` may also hold extra rows (every expected row must match a distinct actual row:
  `listDatabaseNames` sees the databases of other files and runners).
- `expect.error`: the operation must throw; `code` equals `Code`/`code()`, `name` equals
  `Name`/`name()`, `exception` names a class id of `errors-map.yaml` and the thrown exception must
  be an **instance** of that class in the driver (`Argument` = the language argument exception,
  `InvalidState` = `ObjectDisposedException` / `IllegalStateException`), `retryable` / `committed`
  equal the exception's flags. `applicationError: true` = the exception thrown by
  `runner.throwApplicationError` propagated unchanged.
- An operation without `expect` must not throw; its result is not checked.
- `outcome`: for each collection, all documents sorted by `_id`, compared `exact`.

## 6. Results, normalisation and AC-DRV-003

Each runner writes `conformance-results.json`:

```json
{"driver": "dotnet|java|node|python|go|rust", "driverVersion": "…", "serverVersion": "…",
 "results": [{"id": "TC-DRV-CONF-CRUD-001", "status": "passed|failed|skipped", "reason": "…",
              "observations": [{"op": 0, "result": …} , {"op": 1, "error": {"code": 1005, "exception": "DuplicateKey", "retryable": false}}],
              "outcome": {"items": […]}}]}
```

`observations` are the results of the **top-level** operations of the test (`op` = position in
`operations`; callback and step operations are checked by their own `expect` only), after the
normalisation of §5 with system fields (`_rev`, `_createdAt`, `_updatedAt`) always removed,
written as canonical extended JSON with sorted object keys, with volatile values replaced by
tokens in order of first appearance: generated objectIds → `"<oid:1>"`, `"<oid:2>"`, …;
datetimes produced by the server (`currentDate`) → `"<datetime>"`; session and causality tokens,
trace ids → `"<volatile>"`; saved clients, sessions, cursors and transactions → `"<handle>"`;
`listDatabaseNames` keeps only the names starting with `${database}` (other files and runners
share the server), written with `${database}` replaced by `"<database>"`.

Where: .NET `RUSTEGON_CONFORMANCE_RESULTS` (default next to the test binaries); Java
`drivers/java/driver/build/conformance-results-jdk21.json` and `…-jdk25.json` (one per test
task); Node.js `RUSTEGON_CONFORMANCE_RESULTS` (default `drivers/node/build/conformance-results.json`);
Python `RUSTEGON_CONFORMANCE_RESULTS` (default `drivers/python/build/conformance-results.json`,
driver `"python"`, python-driver.md §11); Go `RUSTEGON_CONFORMANCE_RESULTS` (default
`drivers/go/conformance-results.json`, driver `"go"`, go-driver.md §11); Rust
`RUSTEGON_CONFORMANCE_RESULTS` (default `drivers/rust/conformance-results.json`, driver `"rust"`,
rust-driver.md §11). **AC-DRV-003 "identical results"**: `crates/rustegon-common/tests/driver_results.rs`
compares the files named by `RGN_DRIVER_RESULTS` (comma-separated, reference first;
`scripts/ci-local.sh` passes .NET, Java JDK 21, Java JDK 25, Node.js, Python, Go and Rust) test by test — every test of the
suite present, the same status, no failure, and identical `observations` and `outcome`
(compared as compact JSON with sorted keys, so whitespace and string escaping do not count) for
every test both passed. **Coverage**: an `r1` operation is covered when at least one test that
`covers` it passed in every file; AC-DRV-003 needs 100 % of the `r1` operations of `model.yaml`
(the static check already guarantees every one has a test).
Deferred operations are not counted; they move to `r1` additively when the server serves them
(gated on `GetServerInfo.features`, PD-069).

## 7. Runner operations

`object: runner`: `sleep {ms}`; `throwApplicationError` (callback throws an application
exception); `assertLastErrorHasTraceId` (the previous operation's exception has a non-empty
trace id); `checkErrorMapping {file}` (for every code of `generated/errors.json`, an
`ErrorDetail` with that code maps to the listed class, unknown codes to `unknown`, and every
transport fallback applies); `checkValueVectors` / `checkDocumentVectors` / `checkInvalidVectors`
`{file}` (§3); `checkAstVectors {file}` (§4); `checkConnectionStrings {file}`
(`connstring.yaml`); `runRetryScenarios {file}` (`retry.yaml` on the fake server, §8); `checkScramVectors {file}` (`scram/vectors.yaml`: every `saslprep` input gives `output` or is refused; for every exchange, with the client nonce forced to `clientNonce`, the client sends `clientFirst` and, after `serverFirst`, `clientFinal`, accepts `serverFinal` and rejects it with one character changed).

## 8. Fake server (retry.yaml, PD-073)

The retry policy is tested against an in-process fake gRPC server per driver, scripted by
`retry.yaml` (its header defines the contract and rules R1–R6). Default `ok` replies of RPCs a
scenario does not script: `SessionService.GetServerInfo` → `{serverVersion: "0.0.0-fake",
protocolVersion: "1.0", features: []}`; `TransactionService.Begin` →
`{txnId: "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60", heartbeatIntervalMs: 1000}`; `Commit`,
`Rollback`, `Heartbeat`, `Logout` → `{}`; `Status` → `{state: TRANSACTION_STATE_COMMITTED}`;
`DocumentService.Insert` → one `WriteResult` per document with its `_id`; `Get` → no document;
`QueryService.Execute` → one empty batch. Reconnect behaviour (kill and restart the real
server on the same data directory) is a driver-specific test (TC-DRV-NET/JAVA-026…030);
toxiproxy and a server fault flag come later (testing-strategy.md §5).
