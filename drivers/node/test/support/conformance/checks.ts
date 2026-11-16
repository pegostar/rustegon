// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Runner operations of README §7 (`object: runner`) driven by the shared data files: codec, AST,
 * connection-string, error-map and SCRAM vectors, and the retry scenarios on the fake server.
 * Each check throws an Error naming the first failing case; the unit tests call the same
 * functions case by case.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { create, toJson, type MessageShape } from '@bufbuild/protobuf';
import * as grpc from '@grpc/grpc-js';
import { AstExprSchema, AstStatementSchema, AstUpdateOpSchema } from '../../../src/generated/rustegon/v1/query_ast_pb.js';
import { ErrorDetailSchema } from '../../../src/generated/rustegon/v1/error_pb.js';
import { BinaryWriter } from '@bufbuild/protobuf/wire';
import { toBinary } from '@bufbuild/protobuf';
import { ParamSink, Update } from '../../../src/builders.ts';
import { Statements } from '../../../src/collection.ts';
import { errorFromServiceError } from '../../../src/transport/calls.ts';
import { RustegonClient, RustegonError, parseConnectionString, resolveSettings, type ResolvedSettings } from '../../../src/index.ts';
import { ERROR_CLASSES, RustegonError as BaseError } from '../../../src/errors/errors.ts';
import { checkDocumentVectors, checkInvalidVectors, checkValueVectors } from '../codec-checks.ts';
import { checkScramVectors } from '../scram-checks.ts';
import { asList, asMap, asString, conformanceDir, loadConformanceYaml, parseYaml, type Yaml, type YamlMap } from '../files.ts';
import { FakeServer, SCRAM_PASSWORD, SCRAM_USER } from '../fake-server.ts';
import { ConformanceFailure, ConformanceRun } from './run.ts';
import { Dsl, projectionOf, sortOf } from './dsl.ts';
import { isMap } from './values.ts';

/** The runner extension of the conformance engine (README §7). */
export async function runnerChecks(name: string, args: YamlMap): Promise<boolean> {
  const file = typeof args.file === 'string' ? args.file : '';
  switch (name) {
    case 'checkErrorMapping':
      for (const c of errorMappingCases(file)) {
        checkErrorMappingCase(file, c);
      }
      return true;
    case 'checkValueVectors':
      checkValueVectors(file);
      return true;
    case 'checkDocumentVectors':
      checkDocumentVectors(file);
      return true;
    case 'checkInvalidVectors':
      checkInvalidVectors(file);
      return true;
    case 'checkAstVectors':
      for (const c of astCases(file)) {
        checkAstCase(file, c);
      }
      return true;
    case 'checkConnectionStrings':
      for (const c of connectionStringCases(file)) {
        checkConnectionStringCase(file, c);
      }
      return true;
    case 'runRetryScenarios':
      for (const s of retryScenarioNames(file)) {
        await runRetryScenario(file, s);
      }
      return true;
    case 'checkScramVectors':
      await checkScramVectors(file);
      return true;
    default:
      return false;
  }
}

// ------------------------------------------------------------------ errors (TC-DRV-NODE-006)

interface ErrorsJson {
  codes: { code: number; name: string; grpc: string; exception: { id: string } }[];
  transport: { grpc: string; code: number; retryable: boolean; exception: { id: string } }[];
  unknown: { id: string };
  classes: { id: string; parent: string | null }[];
}

function errorsJson(file: string): ErrorsJson {
  return JSON.parse(readFileSync(path.join(conformanceDir, file), 'utf8')) as ErrorsJson;
}

/** Case ids: `code/<n>`, `unknown`, `transport/<STATUS>`, `classes`. */
export function errorMappingCases(file: string): string[] {
  const j = errorsJson(file);
  return [...j.codes.map((c) => `code/${c.code}`), 'unknown', ...j.transport.map((t) => `transport/${t.grpc}`), 'classes'];
}

function failedCall(code: number, metadata: grpc.Metadata, details: string): grpc.ServiceError {
  return Object.assign(new Error(details), { code, details, metadata }) as grpc.ServiceError;
}

function detailMetadata(code: number, retryable: boolean): grpc.Metadata {
  const detail = create(ErrorDetailSchema, { code, name: 'X', retryable, traceId: 'abc' });
  const any = new BinaryWriter().tag(1, 2).string('type.googleapis.com/rustegon.v1.ErrorDetail').tag(2, 2).bytes(toBinary(ErrorDetailSchema, detail)).finish();
  const status = new BinaryWriter().tag(1, 0).int32(2).tag(3, 2).bytes(any).finish();
  const md = new grpc.Metadata();
  md.set('grpc-status-details-bin', Buffer.from(status));
  return md;
}

export function checkErrorMappingCase(file: string, id: string): void {
  const j = errorsJson(file);
  const fail = (what: string): never => {
    throw new Error(`${file} ${id}: ${what}`);
  };
  if (id === 'classes') {
    for (const c of j.classes) {
      const cls = ERROR_CLASSES.get(c.id) ?? fail(`no Node class for ${c.id}`);
      const parent = c.parent === null ? Error : (ERROR_CLASSES.get(c.parent) ?? fail(`no Node class for ${c.parent}`));
      if (Object.getPrototypeOf(cls.prototype) !== parent.prototype) {
        fail(`${c.id} does not derive from ${c.parent ?? 'Error'}`);
      }
    }
    return;
  }
  if (id.startsWith('code/') || id === 'unknown') {
    const code = id === 'unknown' ? 9999 : Number(id.slice(5));
    const want = id === 'unknown' ? j.unknown.id : (j.codes.find((c) => c.code === code)?.exception.id ?? fail('no such code'));
    for (const retryable of [true, false]) {
      const e = errorFromServiceError(failedCall(2, detailMetadata(code, retryable), 'm'));
      const cls = ERROR_CLASSES.get(want) ?? fail(`unknown class ${want}`);
      if (!(e instanceof cls) || e.constructor !== cls || e.code !== code || e.retryable !== retryable || e.traceId !== 'abc') {
        fail(`got ${e.constructor.name} ${e.code} retryable=${e.retryable}, expected ${want}`);
      }
    }
    return;
  }
  const status = id.slice('transport/'.length);
  const t = j.transport.find((x) => x.grpc === status) ?? fail('no such fallback');
  const grpcCode = status === 'default' ? grpc.status.DATA_LOSS : ((grpc.status as unknown as Record<string, number>)[status] ?? fail('unknown status'));
  const e = errorFromServiceError(failedCall(grpcCode, new grpc.Metadata(), ''));
  const cls = ERROR_CLASSES.get(t.exception.id) ?? fail('unknown class');
  if (e.constructor !== cls || e.code !== t.code || e.retryable !== t.retryable) {
    fail(`got ${e.constructor.name} ${e.code} retryable=${e.retryable}`);
  }
  // A corrupt trailer falls back to the status mapping.
  const corrupt = new grpc.Metadata();
  corrupt.set('grpc-status-details-bin', Buffer.from([0xff, 0xff, 0xff]));
  if (errorFromServiceError(failedCall(grpcCode, corrupt, '')).code !== t.code) {
    fail('a corrupt trailer changed the mapping');
  }
  if (!(e instanceof BaseError)) {
    fail('not a RustegonError');
  }
}

// ------------------------------------------------------------------ AST vectors (TC-DRV-NODE-011)

function astFile(file: string): { collection: string; cases: YamlMap[] } {
  const root = JSON.parse(readFileSync(path.join(conformanceDir, file), 'utf8')) as { collection: string; cases: YamlMap[] };
  return root;
}

export function astCases(file: string): string[] {
  return astFile(file).cases.map((c) => String(c.name));
}

/** The builder DSL of a case, re-read as YAML so integers stay int64 (bigint). */
function model(file: string, name: string): YamlMap {
  const root = asMap(parseYaml(readFileSync(path.join(conformanceDir, file), 'utf8')));
  return asMap(asList(root.cases).find((c) => asMap(c).name === name));
}

function protoJson(schema: typeof AstExprSchema | typeof AstStatementSchema | typeof AstUpdateOpSchema, m: MessageShape<typeof schema>): unknown {
  return toJson(schema, m as never);
}

export function checkAstCase(file: string, name: string): void {
  const { collection, cases } = astFile(file);
  const raw = cases.find((c) => c.name === name) as unknown as Record<string, unknown>;
  const c = model(file, name);
  const dsl = new Dsl();
  const sink = new ParamSink();
  const label = `${file}#${name}`;
  try {
    switch (path.basename(file)) {
      case 'filters.json': {
        const filter = dsl.filter(c.filter ?? {});
        const where = filter.toAst(sink);
        assert.deepEqual(where === undefined ? undefined : protoJson(AstExprSchema, where), raw.where);
        checkParams(raw, sink);
        const sink2 = new ParamSink();
        assert.deepEqual(protoJson(AstStatementSchema, Statements.find(collection, filter, undefined, undefined, undefined, undefined, sink2)), raw.statement);
        checkParams(raw, sink2);
        break;
      }
      case 'updates.json': {
        const ops = asList(c.update);
        const only = ops.length === 1 && isMap(ops[0]) && 'replace' in ops[0] ? ops[0].replace : undefined;
        const actual = only !== undefined ? Update.replace(dsl.document(only)).toAst(sink) : dsl.update(ops).toAst(sink);
        assert.deepEqual(
          actual.map((o) => protoJson(AstUpdateOpSchema, o)),
          raw.operations,
        );
        checkParams(raw, sink);
        break;
      }
      case 'statements.json': {
        const args = asMap(c.args);
        const f = dsl.filter(args.filter ?? {});
        let statement;
        switch (c.op) {
          case 'find':
            statement = Statements.find(
              collection,
              f,
              args.sort === undefined ? undefined : sortOf(args.sort),
              isMap(args.projection) ? projectionOf(args.projection) : undefined,
              typeof args.limit === 'bigint' ? args.limit : undefined,
              typeof args.skip === 'bigint' ? args.skip : undefined,
              sink,
            );
            break;
          case 'updateOne':
          case 'updateMany':
            statement = Statements.update(collection, f, dsl.update(args.update ?? []), c.op === 'updateOne', sink);
            break;
          case 'replaceOne':
            statement = Statements.update(collection, f, Update.replace(dsl.document(args.replacement ?? null)), true, sink);
            break;
          case 'deleteOne':
          case 'deleteMany':
            statement = Statements.delete(collection, f, c.op === 'deleteOne', sink);
            break;
          default:
            throw new Error(`unknown op '${String(c.op)}'`);
        }
        assert.deepEqual(protoJson(AstStatementSchema, statement), raw.statement);
        checkParams(raw, sink);
        break;
      }
      default:
        throw new Error(`no AST check for ${file}`);
    }
  } catch (e) {
    throw new Error(`${label}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
  }
}

function checkParams(raw: Record<string, unknown>, sink: ParamSink): void {
  const expected = raw.params as Record<string, { hex: string }>;
  assert.deepEqual(Object.keys(sink.params).sort(), Object.keys(expected).sort());
  for (const [k, v] of Object.entries(expected)) {
    assert.equal(Buffer.from(sink.params[k]!.rdocValue).toString('hex'), v.hex, `parameter ${k}`);
  }
}

// ------------------------------------------------------------------ connection strings (TC-DRV-NODE-008)

export function connectionStringCases(file: string): string[] {
  return asList(asMap(loadConformanceYaml(file)).cases).map((c) => asString(asMap(c).name));
}

/** The settings of a valid case, as connstring.yaml names them. */
function settingsView(s: ResolvedSettings): Record<string, unknown> {
  return {
    hosts: s.hosts.map((h) => ({ host: h.host, port: BigInt(h.port) })),
    user: s.user,
    password: s.password,
    database: s.database,
    tls: s.tls,
    tlsCaFile: s.tlsCaFile,
    tlsServerName: s.tlsServerName,
    tlsCertificateFile: s.tlsCertificateFile,
    tlsKeyFile: s.tlsKeyFile,
    authMechanism: s.authMechanism,
    applicationName: s.applicationName,
    connectTimeoutMs: BigInt(s.connectTimeoutMs),
    operationTimeoutMs: BigInt(s.operationTimeoutMs),
    readConsistency: s.readConsistency,
    maxStalenessMs: s.maxStalenessMs === null ? null : BigInt(s.maxStalenessMs),
    writeConcern: s.writeConcern,
    retryReads: s.retryReads,
    retryWrites: s.retryWrites,
    maxRetries: BigInt(s.maxRetries),
    connectionsPerEndpoint: BigInt(s.connectionsPerEndpoint),
  };
}

export function checkConnectionStringCase(file: string, name: string): void {
  const root = asMap(loadConformanceYaml(file));
  const c = asMap(asList(root.cases).find((x) => asMap(x).name === name));
  const uri = asString(c.uri);
  const label = `${file}#${name}`;
  if (c.valid === false) {
    let error: unknown;
    try {
      resolveSettings(parseConnectionString(uri));
    } catch (e) {
      error = e;
    }
    if (!(error instanceof TypeError)) {
      throw new Error(`${label}: expected an argument error, got ${error === undefined ? 'success' : String(error)}`);
    }
    // The raw password: after the first ':' of the user information, up to the last '@'
    // (as the .NET runner; shorter ones would match ordinary words of the message).
    const start = uri.indexOf('://');
    const at = uri.lastIndexOf('@');
    const userInfo = start >= 0 && at > start ? uri.slice(start + 3, at) : '';
    const colon = userInfo.indexOf(':');
    const password = colon < 0 ? undefined : userInfo.slice(colon + 1);
    if (password !== undefined && password.length >= 3 && error.message.includes(password)) {
      throw new Error(`${label}: the error message contains the password`);
    }
    return;
  }
  const defaults = asMap(root.defaults);
  const expect = asMap(c.expect ?? {});
  const actual = settingsView(resolveSettings(parseConnectionString(uri)));
  for (const [k, d] of Object.entries(defaults)) {
    const want = k in expect ? expect[k] : d;
    try {
      assert.deepEqual(actual[k], want === undefined ? null : want);
    } catch {
      throw new Error(`${label}: ${k} = ${String(actual[k])}, expected ${JSON.stringify(want, (_, v: unknown) => (typeof v === 'bigint' ? v.toString() : v))}`);
    }
  }
}

// ------------------------------------------------------------------ retry scenarios (TC-DRV-NODE-016)

export function retryScenarioNames(file: string): string[] {
  return asList(asMap(loadConformanceYaml(file)).scenarios).map((s) => asString(asMap(s).name));
}

const TOLERANCE_MS = 250;

export async function runRetryScenario(file: string, name: string): Promise<void> {
  const root = asMap(loadConformanceYaml(file));
  const scenario = asMap(asList(root.scenarios).find((s) => asMap(s).name === name));
  const defaults = asMap(root.defaults);
  const settings: YamlMap = { ...asMap(defaults.settings), ...(isMap(scenario.settings) ? scenario.settings : {}) };
  const backoff = asMap(defaults.backoff);
  const fake = new FakeServer(isMap(scenario.server) ? scenario.server : undefined);
  const endpoint = await fake.start();
  const expect = asMap(scenario.expect);
  const op: YamlMap = { ...asMap(scenario.operation), expect: expect.outcome ?? null, match: 'subset' };
  try {
    const client = new RustegonClient({
      hosts: [endpoint],
      tls: false,
      ...(scenario.credential === 'scram' ? { user: SCRAM_USER, password: SCRAM_PASSWORD } : { apiKey: 'rgn_fake_key' }),
      retryReads: settings.retryReads as boolean,
      retryWrites: settings.retryWrites as boolean,
      maxRetries: Number(settings.maxRetries),
      operationTimeoutMs: Number(settings.operationTimeoutMs),
      database: 'fake',
      connectionsPerEndpoint: 1,
    });
    const run = new ConformanceRun({ client, database: 'fake', defaultCollection: 'c', substitute: (s) => s, testText: '' });
    try {
      await run.run([op], true);
    } catch (e) {
      if (e instanceof ConformanceFailure) {
        throw new Error(`${name}: ${e.message}`, { cause: e });
      }
      throw e;
    } finally {
      await run.close();
      await client.close();
    }
  } finally {
    await fake.stop();
  }
  const calls = fake.calls;
  for (const [rpc, n] of Object.entries(isMap(expect.calls) ? expect.calls : {})) {
    const count = calls.filter((c) => c.rpc === rpc).length;
    if (BigInt(count) !== n) {
      throw new Error(`${name}: ${rpc} called ${count} times, expected ${String(n)}; calls: ${calls.map((c) => c.rpc).join(', ')}`);
    }
  }
  for (const rpc of asList(expect.sameRequestId ?? []).map((x) => asString(x))) {
    const ids = [...new Set(calls.filter((c) => c.rpc === rpc).map((c) => c.requestId))];
    if (ids.length !== 1 || ids[0] === undefined || ids[0].length === 0) {
      throw new Error(`${name}: ${rpc} request ids ${ids.join(',')}`);
    }
  }
  if (expect.grpcTimeoutSent === true) {
    for (const c of calls.filter((x) => x.rpc !== 'AuthService.Logout')) {
      if (!c.hasDeadline) {
        throw new Error(`${name}: ${c.rpc} without grpc-timeout`);
      }
    }
  }
  if (Array.isArray(expect.delays)) {
    // Failed replies that led to a retry, in order (a failed best-effort rollback is not one).
    const failures = calls.filter((c) => c.failed && c.replied !== undefined && c.rpc !== 'TransactionService.Rollback').sort((a, b) => a.arrival - b.arrival);
    for (const d of expect.delays.map((x) => asMap(x))) {
      const n = Number(d.retry);
      const failed = failures[n - 1];
      if (failed?.replied === undefined) {
        throw new Error(`${name}: retry ${n} expected but only ${failures.length} failures`);
      }
      const replied = failed.replied;
      const next = calls
        .filter((c) => c.arrival > replied && c.rpc !== 'TransactionService.Rollback' && c.rpc !== 'TransactionService.Heartbeat')
        .sort((a, b) => a.arrival - b.arrival)[0];
      if (next === undefined) {
        throw new Error(`${name}: no call after failure ${n}`);
      }
      const gap = next.arrival - replied;
      if (typeof d.minMs === 'bigint') {
        if (gap < Number(d.minMs)) {
          throw new Error(`${name}: retry ${n} after ${gap.toFixed(1)} ms, expected at least ${d.minMs} ms`);
        }
      } else {
        const ceiling = Math.min(Number(backoff.capMs), Number(backoff.baseMs) * Number(backoff.factor) ** (n - 1));
        if (gap > ceiling + TOLERANCE_MS) {
          throw new Error(`${name}: retry ${n} after ${gap.toFixed(1)} ms, expected at most ${ceiling} ms + ${TOLERANCE_MS} ms`);
        }
      }
    }
  }
}

export type { Yaml, RustegonError };
