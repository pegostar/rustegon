# Rustegon Node.js driver (`@rustegon/driver`)

The Node.js driver for Rustegon (FR-DRV-004, DEC-014). Specification: [`docs/specifications/node-driver.md`](../../docs/specifications/node-driver.md);
differences from the .NET and Java drivers: [`drivers/DIVERGENCES.md`](../DIVERGENCES.md) §7.
Not published to npm yet (`private: true`).

```ts
import { RustegonClient, Filter, Update } from '@rustegon/driver';

// host, port, user, password, database (DEC-014). Plain text unless a tls* option is given (ADR-034).
await using client = await RustegonClient.connect('rustegon://app@localhost:7700/shop', { password: process.env.RGN_PASSWORD });
const orders = client.db().collection('orders');
await orders.insertOne({ _id: 1n, status: 'paid', total: 12.5 });   // 1n = int64, 12.5 = float64
for await (const o of orders.find(Filter.eq('status', 'paid')).limit(10)) console.log(o);

await client.withTransaction(async (txn) => {
  await txn.collection('orders').updateOne(Filter.id(1n), Update.set('status', 'shipped'));
});
```

TLS: `rustegon://host/?tlsCaFile=/etc/rustegon/ca.crt` (any `tls*` option or `authMechanism=X509`
turns TLS on; `tls=false` with one of them is an error). API key: `{ apiKey: 'rgn_…' }`.

## Development

Requires Node.js ≥ 20 (developed on 24). The TypeScript sources run directly under `node --test`.

```bash
npm ci
npm run lint && npm run typecheck
npm test                      # unit: codec, SCRAM, connection strings, errors, AST, mapping, retry.yaml on the fake server
RUSTEGON_BIN_DIR=<dir with rustegon + rustegond> npm run conformance       # TC-DRV-CONF-*, writes build/conformance-results.json
RUSTEGON_BIN_DIR=<dir> npm run test:integration
npm run build                 # dist/
```

Without `RUSTEGON_BIN_DIR` (default `<repo>/target/debug`) the server tests are skipped with the reason;
with `CI=true` that is an error. `RUSTEGON_CONFORMANCE_RESULTS` overrides the results path.
`scripts/ci-local.sh` runs all of the above and compares the results with .NET and Java (AC-DRV-004).

`test/support/server.ts` starts the test node as ADR-034 defines it: plain text by default
(`TestServer.start(dir, { tls: false })`), TLS with `rustegon init --tls` (the shared node of the integration and conformance tests).

Generated code (never edited by hand): `src/generated/` (`npm run generate`, buf + protoc-gen-es from
`<repo>/proto`, PD-161), `src/errors/codes.generated.ts` (`npm run generate:errors`, from
`drivers/conformance/generated/errors.json`), `src/auth/saslprep-tables.generated.ts` (`scripts/generate-saslprep.mjs`).

## Tests (TC-DRV-NODE-*)

| TC | Scope | File |
|---|---|---|
| 001 | RDoc vectors of `drivers/conformance/codec/*.yaml`, xxh3 reference values | `test/unit/codec-vectors.test.ts`, `codec-xxh3.test.ts` |
| 002…005 | Random round trips, corruption only raises `RDocError`, malformed input, extended JSON, Decimal128, ObjectId | `test/unit/codec.test.ts` |
| 006 | Generated error table = `errors.json`, `checkErrorMapping`, hierarchy, corrupt trailers | `test/unit/errors.test.ts` |
| 007, 018 | SCRAM-SHA-256 (RFC 7677, mutual auth, malformed messages), SASLprep, `scram/vectors.yaml` | `test/unit/scram.test.ts` |
| 008 | `connstring.yaml`, ADR-034 TLS default, option overrides, secret redaction | `test/unit/settings.test.ts` |
| 009, 012 | Against `rustegond` (TLS): SCRAM login, ping, server info, wrong password; CRUD, find, RGQL | `test/integration/smoke.test.ts` |
| 010 | Against a plain-text `rustegond`: bare connection string logs in (ADR-034); TLS client fails with `UnavailableError` | `test/integration/plaintext.test.ts` |
| 011 | Builders → AST vectors of `drivers/conformance/ast/*.json` | `test/unit/ast.test.ts` |
| 016 | Every scenario of `retry.yaml` on the in-process fake gRPC server (R1–R8, `withTransaction`, RGN-2006 resolution) | `test/unit/retry.test.ts` |
| 020 | Conformance runner of `drivers/conformance/{crud,query,cursor,bulk,txn,errors,schema,auth,client}/` | `test/conformance/suite.test.ts` |
| 021…025 | Models, id/rev/counter, `mapping/vectors.yaml`, polymorphism, round trips | `test/unit/mapping.test.ts` |
| 027 | `DRIVER_VERSION` = `package.json` version | `test/unit/version.test.ts` |
