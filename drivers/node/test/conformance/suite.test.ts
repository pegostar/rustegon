// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * TC-DRV-NODE-020 (FR-DRV-004, AC-DRV-004): the runner of the shared conformance suite
 * (README §5–§7). Every test of `crud/ query/ cursor/ bulk/ txn/ errors/ schema/ auth/ client/`
 * is one case, run against the shared `rustegond` (PD-072) with a fresh database per file and a
 * reset of its collections per test, or without a server when it consists of runner operations
 * only. Every case is recorded in `conformance-results.json` (README §6;
 * `RUSTEGON_CONFORMANCE_RESULTS` overrides the path, default `drivers/node/build/`).
 */

import { test, after } from 'node:test';
import { mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import { AdminService, CreateApiKeyRequestSchema, CreateUserRequestSchema, DropUserRequestSchema } from '../../src/generated/rustegon/v1/admin_pb.js';
import { AuthService, WhoAmIRequestSchema } from '../../src/generated/rustegon/v1/auth_pb.js';
import { RoleGrantSchema, type RoleGrant } from '../../src/generated/rustegon/v1/common_pb.js';
import { Filter, Sort, RustegonClient, DRIVER_VERSION, type ClientOptions, type RValue } from '../../src/index.ts';
import { asList, asMap, asString, conformanceDir, nodeDriverDir, parseYaml, readConformanceText, type Yaml, type YamlMap } from '../support/files.ts';
import { TestServer, sharedServer } from '../support/server.ts';
import { ConformanceFailure, ConformanceRun, validatorOf } from '../support/conformance/run.ts';
import { runnerChecks } from '../support/conformance/checks.ts';
import { Dsl, keysOf } from '../support/conformance/dsl.ts';
import { Normalizer, isMap } from '../support/conformance/values.ts';

const CATEGORIES = ['crud', 'query', 'cursor', 'bulk', 'txn', 'errors', 'schema', 'auth', 'client'];
/** `requires` values this runner provides (README §5). */
const CAPABILITIES = ['admin', 'api-key', 'x509-client-cert', 'slow', 'fixture-connection-string'];

interface Entry {
  id: string;
  status: 'passed' | 'failed' | 'skipped';
  reason?: string;
  observations: string[];
  outcome?: string;
}

const results = new Map<string, Entry>();
let serverVersion = '';
const resultsPath = process.env.RUSTEGON_CONFORMANCE_RESULTS !== undefined && process.env.RUSTEGON_CONFORMANCE_RESULTS.length > 0
  ? process.env.RUSTEGON_CONFORMANCE_RESULTS
  : path.join(nodeDriverDir, 'build', 'conformance-results.json');

/** README §6 file; observations are raw JSON text (int64 `1` and float64 `1.0` must stay apart). */
function writeResults(): void {
  const ids = [...results.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const rows = ids.map((id) => {
    const e = results.get(id)!;
    const parts = [`"id":${JSON.stringify(e.id)}`, `"status":${JSON.stringify(e.status)}`];
    if (e.reason !== undefined) {
      parts.push(`"reason":${JSON.stringify(e.reason)}`);
    }
    parts.push(`"observations":[${e.observations.join(',')}]`);
    if (e.outcome !== undefined) {
      parts.push(`"outcome":${e.outcome}`);
    }
    return `    {${parts.join(',')}}`;
  });
  const text = `{\n  "driver": "node",\n  "driverVersion": ${JSON.stringify(DRIVER_VERSION)},\n  "serverVersion": ${JSON.stringify(serverVersion)},\n  "results": [\n${rows.join(',\n')}\n  ]\n}\n`;
  mkdirSync(path.dirname(resultsPath), { recursive: true });
  writeFileSync(resultsPath, text);
}

interface FileContext {
  database: string;
  client: RustegonClient;
}

const files = new Map<string, FileContext>();
let apiKey: string | undefined;
const server = await sharedServer();

after(async () => {
  for (const f of files.values()) {
    try {
      await f.client.dropDatabase(f.database, { ifExists: true });
    } finally {
      await f.client.close();
    }
  }
  await server?.stop();
});

async function fileContext(s: TestServer, relative: string): Promise<FileContext> {
  const existing = files.get(relative);
  if (existing !== undefined) {
    return existing;
  }
  const [category, name] = relative.split('/') as [string, string];
  const stem = name.replace(/\.yaml$/, '').replaceAll('-', '_');
  const database = `conf_${category}_${stem}_${randomBytes(4).toString('hex')}`;
  const client = await s.admin({ database });
  await client.createDatabase(database);
  const ctx = { database, client };
  files.set(relative, ctx);
  return ctx;
}

async function adminCall<T>(client: RustegonClient, f: () => Promise<T>): Promise<T> {
  void client;
  return f();
}

/** A role reference `role@db` / `role@db.coll` / `role` as a grant (protocol.md §8 mapping). */
function grant(reference: string): RoleGrant {
  const at = reference.indexOf('@');
  if (at < 0) {
    return create(RoleGrantSchema, { role: reference });
  }
  const scope = reference.slice(at + 1);
  return create(RoleGrantSchema, { role: reference.slice(0, at), resource: (scope.includes('.') ? 'collection:' : 'database:') + scope });
}

async function createApiKey(s: TestServer): Promise<string> {
  if (apiKey !== undefined) {
    return apiKey;
  }
  await using admin = await s.admin();
  const owner = await admin.executor.unary(AuthService.method.whoAmI, create(WhoAmIRequestSchema), { kind: 'none' });
  const created = await admin.executor.unary(
    AdminService.method.createApiKey,
    create(CreateApiKeyRequestSchema, { description: 'node conformance runner', roles: owner.roles }),
    { kind: 'none' },
  );
  apiKey = created.secret;
  return apiKey;
}

/** README §5 per-test fixture: reset the collections, then collections, indexes, data, users. */
async function setUp(file: FileContext, setup: YamlMap | undefined, users: string[], x509: boolean, substitute: (s: string) => string): Promise<string | undefined> {
  const db = file.client.db(file.database);
  for (const name of await db.listCollectionNames()) {
    await db.dropCollection(name, { ifExists: true });
  }
  let first: string | undefined;
  for (const c of asList(setup?.collections ?? []).map((x) => asMap(x))) {
    const name = asString(c.name);
    first ??= name;
    await db.createCollection(name, isMap(c.validator) ? { validator: validatorOf(c.validator) } : {});
  }
  for (const i of asList(setup?.indexes ?? []).map((x) => asMap(x))) {
    const index = await db.collection(asString(i.collection)).createIndex(asString(i.name), keysOf(i.keys ?? []), { unique: i.unique === true });
    if (index.state !== 'ready') {
      throw new ConformanceFailure(`setup index ${index.name} is ${index.state}`);
    }
  }
  const dsl = new Dsl();
  for (const [collection, docs] of Object.entries(isMap(setup?.data) ? setup.data : {})) {
    const list = asList(docs);
    if (list.length > 0) {
      await db.collection(collection).insertMany(list.map((d) => dsl.document(d)));
    }
  }
  const createUser = async (request: ReturnType<typeof create<typeof CreateUserRequestSchema>>): Promise<void> => {
    await adminCall(file.client, () => file.client.executor.unary(AdminService.method.createUser, request, { kind: 'none' }));
    users.push(request.name);
  };
  for (const u of asList(setup?.users ?? []).map((x) => asMap(x))) {
    await createUser(
      create(CreateUserRequestSchema, {
        name: asString(u.name),
        password: asString(u.password),
        mustChangePassword: u.mustChangePassword === true,
        roles: asList(u.roles).map((r) => grant(substitute(asString(r)))),
      }),
    );
  }
  if (x509) {
    // README §5: the init client certificate maps to a user with read-write on ${database}.
    await createUser(create(CreateUserRequestSchema, { name: `x509:CN=${TestServer.clientCertificateUser}`, roles: [grant(`read_write@${file.database}`)] }));
  }
  return first;
}

function openClient(s: TestServer, database: string, args: YamlMap, substitute: (x: string) => string): RustegonClient {
  const credential = asMap(args.credential);
  let options: ClientOptions;
  if (isMap(credential.scram)) {
    options = s.options({ user: substitute(asString(credential.scram.user)), password: substitute(asString(credential.scram.password)) });
  } else if (typeof credential.apiKey === 'string') {
    options = s.options({ apiKey: substitute(credential.apiKey) });
  } else {
    const x509 = asMap(credential.x509);
    options = s.options({ authMechanism: 'X509', tlsCertificateFile: substitute(asString(x509.certificateFile)), tlsKeyFile: substitute(asString(x509.keyFile)) });
  }
  return new RustegonClient({ ...options, database, allowPasswordChangeOnly: args.allowPasswordChangeOnly === true });
}

/** README §5 `outcome`: every listed collection, sorted by `_id`, compared exactly. */
async function checkOutcome(file: FileContext, run: ConformanceRun, expected: YamlMap, text: string): Promise<string> {
  const normalizer = new Normalizer(text);
  const parts: string[] = [];
  for (const collection of Object.keys(expected).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
    const actual = await file.client.db(file.database).collection(collection).find(Filter.empty).sort(Sort.ascending('_id')).toArray();
    const why = run.matcher.result(expected[collection] ?? null, actual as RValue, { subset: false, ordered: true, fieldOrder: false });
    if (why !== undefined) {
      throw new ConformanceFailure(`outcome of ${collection}: ${why}`);
    }
    parts.push(`${JSON.stringify(collection)}:${normalizer.json(actual as RValue)}`);
  }
  return `{${parts.join(',')}}`;
}

async function runTest(relative: string, t: YamlMap, root: YamlMap, text: string): Promise<{ observations: string[]; outcome?: string }> {
  const setup = isMap(t.setup) ? t.setup : isMap(root.setup) ? root.setup : undefined;
  const operations = asList(t.operations);
  const unitLevel = setup === undefined && operations.every((o) => asMap(o).object === 'runner');
  if (unitLevel) {
    // Runner operations need no server; the run still needs a client object, which is never used.
    const client = new RustegonClient({ hosts: ['unused.invalid:7700'], tls: false });
    const run = new ConformanceRun({ client, database: 'unused', defaultCollection: undefined, substitute: (s) => s, testText: text, runnerExtension: runnerChecks });
    try {
      await run.run(operations, true);
    } finally {
      await run.close();
      await client.close();
    }
    return { observations: run.observations };
  }
  const s = server!;
  const file = await fileContext(s, relative);
  if (serverVersion.length === 0) {
    serverVersion = (await file.client.getServerInfo()).serverVersion;
  }
  const requires = asList(t.requires ?? []).map((r) => asString(r));
  const key = requires.includes('api-key') ? await createApiKey(s) : '';
  const substitutions: [string, string][] = [
    ['${database}', file.database],
    ['${host}', s.host],
    ['${port}', s.port],
    ['${adminUser}', TestServer.adminUser],
    ['${adminPassword}', s.adminPassword],
    ['${adminUserEncoded}', encodeURIComponent(TestServer.adminUser)],
    ['${adminPasswordEncoded}', encodeURIComponent(s.adminPassword)],
    ['${caFile}', s.caFile],
    ['${caFileEncoded}', encodeURIComponent(s.caFile)],
    ['${apiKey}', key],
    ['${clientCertFile}', s.clientCertFile],
    ['${clientKeyFile}', s.clientKeyFile],
  ];
  const substitute = (x: string): string => substitutions.reduce((acc, [k, v]) => acc.replaceAll(k, v), x);
  const users: string[] = [];
  try {
    const firstCollection = await setUp(file, setup, users, requires.includes('x509-client-cert'), substitute);
    const run = new ConformanceRun({
      client: file.client,
      database: file.database,
      defaultCollection: firstCollection,
      substitute,
      testText: text,
      runnerExtension: runnerChecks,
      openClient: (args) => openClient(s, file.database, args, substitute),
    });
    try {
      await run.run(operations, true);
      const outcome = isMap(t.outcome) ? await checkOutcome(file, run, t.outcome, text) : undefined;
      return outcome === undefined ? { observations: run.observations } : { observations: run.observations, outcome };
    } finally {
      await run.close();
    }
  } finally {
    for (const u of users) {
      await file.client.executor.unary(AdminService.method.dropUser, create(DropUserRequestSchema, { name: u }), { kind: 'none' });
    }
  }
}

for (const category of CATEGORIES) {
  const dir = path.join(conformanceDir, category);
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.yaml')).sort()) {
    const relative = `${category}/${name}`;
    const text = readConformanceText(relative);
    const root = asMap(parseYaml(text));
    for (const t of asList(root.tests).map((x) => asMap(x))) {
      const id = asString(t.id);
      const missing = asList(t.requires ?? []).map((r: Yaml) => asString(r)).find((r) => !CAPABILITIES.includes(r));
      const setup = t.setup ?? root.setup;
      const unitLevel = setup === undefined && asList(t.operations).every((o) => asMap(o).object === 'runner');
      const skip = missing !== undefined ? `requires ${missing}` : !unitLevel && server === undefined ? 'no server binaries (RUSTEGON_BIN_DIR)' : undefined;
      void test(`TC-DRV-NODE-020 conformance ${relative}#${id}`, { skip: skip ?? false }, async () => {
        try {
          const r = await runTest(relative, t, root, text);
          results.set(id, { id, status: 'passed', observations: r.observations, ...(r.outcome === undefined ? {} : { outcome: r.outcome }) });
        } catch (e) {
          results.set(id, { id, status: 'failed', reason: e instanceof Error ? e.message : String(e), observations: [] });
          throw e;
        } finally {
          writeResults();
        }
      });
      if (skip !== undefined) {
        results.set(id, { id, status: 'skipped', reason: skip, observations: [] });
        writeResults();
      }
    }
  }
}
