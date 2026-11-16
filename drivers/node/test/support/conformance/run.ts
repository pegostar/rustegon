// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Executes the operations of one conformance test (README §5, §7) against a client: the shared
 * engine of the server runner (TC-DRV-NODE-020) and of the fake-server retry scenarios
 * (TC-DRV-NODE-016). Results are turned into RDoc values with the field names of the README's
 * operation table so they can be matched and normalised uniformly.
 */

import { setTimeout as sleep } from 'node:timers/promises';
import {
  BulkOperation,
  ClientSession,
  CommitOutcomeUnknownError,
  Cursor,
  InvalidArgumentError,
  InvalidStateError,
  RustegonClient,
  RustegonError,
  Transaction,
  type Collection,
  type CollectionValidator,
  type Database,
  type RDocument,
  type RValue,
  type TransactionOptions,
} from '../../../src/index.ts';
import { classIdOf, ERROR_CLASSES } from '../../../src/errors/errors.ts';
import { asList, asMap, asString, type Yaml, type YamlMap } from '../files.ts';
import { Dsl, keysOf, projectionOf, sortOf } from './dsl.ts';
import { Matcher, Normalizer, isMap, toJson, type MatchMode } from './values.ts';

/** The error of `runner.throwApplicationError` (an error of the application, not of the driver). */
export class ApplicationError extends Error {
  constructor() {
    super('application error raised by the conformance callback');
  }
}

/** An expectation that did not hold (the test's failure reason). */
export class ConformanceFailure extends Error {}

type Saved = RValue | RustegonClient | Transaction | ClientSession | Cursor<RDocument>;

export interface RunOptions {
  client: RustegonClient;
  database: string;
  defaultCollection: string | undefined;
  substitute: (s: string) => string;
  testText: string;
  openClient?: (args: YamlMap) => RustegonClient;
  runnerExtension?: (name: string, args: YamlMap) => Promise<boolean>;
}

export class ConformanceRun {
  readonly observations: string[] = [];
  readonly matcher: Matcher;
  private readonly o: RunOptions;
  private readonly saved = new Map<string, Saved>();
  private readonly opened: RustegonClient[] = [];
  private readonly normalizer: Normalizer;
  private readonly dsl: Dsl;
  private transaction: Transaction | undefined;
  private lastError: unknown;

  constructor(options: RunOptions) {
    this.o = options;
    this.normalizer = new Normalizer(options.testText);
    this.dsl = new Dsl((s) => this.resolveString(s));
    this.matcher = new Matcher(options.substitute, (s) => this.resolveRef(s));
  }

  /** Runs operations in order; at the top level each is observed, inside callbacks an error propagates. */
  async run(operations: Yaml[], topLevel: boolean): Promise<void> {
    for (let i = 0; i < operations.length; i++) {
      await this.runOne(asMap(operations[i], 'operation'), topLevel ? i : undefined);
    }
  }

  private async runOne(op: YamlMap, index: number | undefined): Promise<void> {
    const name = asString(op.name, 'name');
    const target = asString(op.object, 'object');
    const expect = isMap(op.expect) ? op.expect : undefined;
    let result: Saved | undefined;
    let error: unknown;
    let failed = false;
    try {
      result = await this.dispatch(target, name, op);
    } catch (e) {
      if (e instanceof ConformanceFailure) {
        throw e;
      }
      failed = true;
      error = e;
      this.lastError = e;
    }
    const label = `${target}.${name}`;
    if (failed) {
      if (index !== undefined) {
        this.observations.push(`{"error":${errorJson(error)},"op":${index}}`);
      }
      const expectedError = expect !== undefined && isMap(expect.error) ? expect.error : undefined;
      if (expectedError === undefined) {
        if (index === undefined && (error instanceof RustegonError || error instanceof ApplicationError || isAbort(error))) {
          // Inside a callback or a step: the error belongs to the enclosing operation.
          throw error as Error;
        }
        throw new ConformanceFailure(`${label} threw ${describe(error)}`);
      }
      checkError(label, expectedError, error);
      return;
    }
    if (index !== undefined) {
      // Saved clients, sessions, cursors and transactions are observed as "<handle>" (README §6).
      const observed = isHandle(result) ? '"<handle>"' : this.normalizer.json(this.volatileResult(name, (result ?? null) as RValue));
      this.observations.push(`{"op":${index},"result":${observed}}`);
    }
    if (typeof op.saveAs === 'string') {
      this.saved.set(op.saveAs, result ?? null);
    }
    if (expect === undefined) {
      return;
    }
    if (expect.error !== undefined) {
      throw new ConformanceFailure(`${label} succeeded but an error was expected`);
    }
    if ('result' in expect) {
      const mode: MatchMode = { subset: op.match === 'subset', ordered: op.ordered !== false, fieldOrder: op.fieldOrder === true };
      const why = this.matcher.result(expect.result ?? null, isHandle(result) ? null : ((result ?? null) as RValue), mode);
      if (why !== undefined) {
        throw new ConformanceFailure(`${label}: ${why}`);
      }
    }
  }

  /**
   * Causality tokens are volatile; listDatabaseNames keeps only this file's databases, with
   * `${database}` as `<database>` (README §6).
   */
  private volatileResult(name: string, r: RValue): RValue {
    if (name === 'causalityToken' && typeof r === 'string') {
      return '<volatile>';
    }
    if (name === 'listDatabaseNames' && Array.isArray(r)) {
      return r.filter((n): n is string => typeof n === 'string' && n.startsWith(this.o.database)).map((n) => `<database>${n.slice(this.o.database.length)}`);
    }
    return r;
  }

  private async dispatch(target: string, name: string, op: YamlMap): Promise<Saved | undefined> {
    const args = isMap(op.args) ? op.args : {};
    switch (target) {
      case 'runner':
        await this.runner(name, args);
        return null;
      case 'client':
        return this.clientOp(this.o.client, name, op, args);
      case 'database':
        return this.databaseOp(this.o.client.db(this.o.database), name, args);
      case 'collection':
        return this.collectionOp(this.o.client.db(this.o.database).collection(this.collectionName(op)), name, op, args);
      case 'transaction':
        if (this.transaction === undefined) {
          throw new ConformanceFailure('object: transaction outside a callback');
        }
        return this.transactionOp(this.transaction, name, op, args);
      default:
        break;
    }
    const s = this.saved.get(target);
    if (s instanceof RustegonClient) {
      return this.clientOp(s, name, op, args);
    }
    if (s instanceof Transaction) {
      return this.transactionOp(s, name, op, args);
    }
    if (s instanceof ClientSession) {
      return this.sessionOp(s, name);
    }
    if (s instanceof Cursor) {
      return this.cursorOp(s, name);
    }
    throw new ConformanceFailure(`unknown object '${target}'`);
  }

  private collectionName(op: YamlMap): string {
    const c = typeof op.collection === 'string' ? op.collection : this.o.defaultCollection;
    if (c === undefined) {
      throw new ConformanceFailure('no collection');
    }
    return c;
  }

  private async clientOp(client: RustegonClient, name: string, op: YamlMap, args: YamlMap): Promise<Saved | undefined> {
    switch (name) {
      case 'open': {
        if (this.o.openClient === undefined) {
          throw new ConformanceFailure('client.open is not available here');
        }
        return this.connect(this.o.openClient(args));
      }
      case 'openFromConnectionString':
        return this.connect(new RustegonClient(this.o.substitute(asString(args.uri))));
      case 'getServerInfo': {
        const info = await client.getServerInfo();
        return doc(['serverVersion', info.serverVersion], ['protocolVersion', info.protocolVersion], ['features', [...info.features]]);
      }
      case 'listDatabaseNames':
        return await client.listDatabaseNames();
      case 'createDatabase':
        return doc(['created', await client.createDatabase(this.o.substitute(asString(args.name)), { ifNotExists: args.ifNotExists === true })]);
      case 'dropDatabase':
        return doc(['dropped', await client.dropDatabase(this.o.substitute(asString(args.name)), { ifExists: args.ifExists === true })]);
      case 'startSession':
        return client.startSession({ causalConsistency: args.causalConsistency !== false });
      case 'beginTransaction':
        return client.beginTransaction(txnOptions(args));
      case 'withTransaction': {
        const callback = asList(args.callback, 'callback');
        await client.withTransaction((txn) => this.inTransaction(txn, callback), txnOptions(args));
        return null;
      }
      case 'manualTransaction': {
        const txn = await client.beginTransaction(txnOptions(args));
        try {
          await this.inTransaction(txn, asList(args.steps, 'steps'));
        } finally {
          await txn.close();
        }
        return null;
      }
      case 'changePassword':
        await client.changePassword(asString(args.currentPassword), asString(args.newPassword));
        return null;
      case 'close':
        await client.close();
        return null;
      default:
        // README §5: collection operations are also available on a saved client.
        return this.collectionOp(client.db(this.o.database).collection(this.collectionName(op)), name, op, args);
    }
  }

  private async connect(client: RustegonClient): Promise<RustegonClient> {
    try {
      await client.connect();
    } catch (e) {
      await client.close();
      throw e;
    }
    this.opened.push(client);
    return client;
  }

  private async inTransaction(txn: Transaction, operations: Yaml[]): Promise<void> {
    const outer = this.transaction;
    this.transaction = txn;
    try {
      await this.run(operations, false);
    } finally {
      this.transaction = outer;
    }
  }

  private async transactionOp(txn: Transaction, name: string, op: YamlMap, args: YamlMap): Promise<Saved | undefined> {
    switch (name) {
      case 'query':
        return await txn.query(asString(args.rgql), this.params(args), batchSize(args)).toArray();
      case 'commit':
        await txn.commit();
        return null;
      case 'rollback':
        await txn.rollback();
        return null;
      case 'close':
        await txn.close();
        return null;
      case 'resolve':
        // In manual mode the error of the commit carries the resolver (transactions.md §5); the
        // transaction's own resolve() asks the same Status.
        return this.lastError instanceof CommitOutcomeUnknownError ? await this.lastError.resolve() : await txn.resolve();
      default:
        return this.collectionOp(txn.collection(this.collectionName(op)), name, op, args);
    }
  }

  private async sessionOp(session: ClientSession, name: string): Promise<Saved> {
    switch (name) {
      case 'causalityToken':
        return session.causalityToken;
      case 'close':
        await session.close();
        return null;
      default:
        throw new ConformanceFailure(`unknown session operation '${name}'`);
    }
  }

  private async cursorOp(cursor: Cursor<RDocument>, name: string): Promise<Saved> {
    switch (name) {
      case 'next':
        return await cursor.next();
      case 'close':
        await cursor.close();
        return null;
      default:
        throw new ConformanceFailure(`unknown cursor operation '${name}'`);
    }
  }

  private async databaseOp(db: Database, name: string, args: YamlMap): Promise<Saved> {
    switch (name) {
      case 'query':
        return await db.query(asString(args.rgql), this.params(args), batchSize(args)).toArray();
      case 'createCollection':
        return doc([
          'created',
          await db.createCollection(asString(args.name), {
            ifNotExists: args.ifNotExists === true,
            ...(isMap(args.validator) ? { validator: validatorOf(args.validator) } : {}),
          }),
        ]);
      case 'dropCollection':
        return doc(['dropped', await db.dropCollection(asString(args.name), { ifExists: args.ifExists === true })]);
      case 'listCollectionNames':
        return await db.listCollectionNames();
      default:
        throw new ConformanceFailure(`unknown database operation '${name}'`);
    }
  }

  private async collectionOp(c: Collection, name: string, op: YamlMap, args: YamlMap): Promise<Saved> {
    const sessionName = op.session;
    const session = typeof sessionName === 'string' ? (this.saved.get(sessionName) as ClientSession) : undefined;
    const options = isMap(args.options) ? args.options : {};
    const ifRev = typeof options.ifRev === 'string' ? (this.dsl.value(options.ifRev) as string) : undefined;
    const so = session === undefined ? {} : { session };
    const ro = ifRev === undefined ? so : { ...so, ifRev };
    switch (name) {
      case 'insertOne':
        return doc(['insertedId', (await c.insertOne(this.dsl.document(args.document ?? null), so)).insertedId]);
      case 'insertMany':
        return doc(['insertedIds', [...(await c.insertMany(asList(args.documents).map((d) => this.dsl.document(d)), so)).insertedIds]]);
      case 'findById':
        return await c.findById(this.dsl.value(args.id ?? null), so);
      case 'find': {
        const find = c.find(this.dsl.filter(args.filter ?? {}), so);
        if (args.sort !== undefined) {
          find.sort(sortOf(args.sort));
        }
        if (typeof args.limit === 'bigint') {
          find.limit(Number(args.limit));
        }
        if (typeof args.skip === 'bigint') {
          find.skip(Number(args.skip));
        }
        if (isMap(args.projection)) {
          find.project(projectionOf(args.projection));
        }
        if (typeof args.batchSize === 'bigint') {
          find.batchSize(Number(args.batchSize));
        }
        switch (op.then) {
          case 'first':
            return await find.first();
          case 'cursor':
            return await find.cursor();
          default:
            return await find.toArray();
        }
      }
      case 'updateOne':
      case 'updateMany': {
        const f = this.dsl.filter(args.filter ?? {});
        const u = this.dsl.update(args.update ?? []);
        return counts(name === 'updateOne' ? await c.updateOne(f, u, ro) : await c.updateMany(f, u, ro));
      }
      case 'replaceOne':
        return counts(await c.replaceOne(this.dsl.filter(args.filter ?? {}), this.dsl.document(args.replacement ?? null), { ...ro, upsert: options.upsert === true }));
      case 'deleteOne':
      case 'deleteMany': {
        const f = this.dsl.filter(args.filter ?? {});
        const r = name === 'deleteOne' ? await c.deleteOne(f, ro) : await c.deleteMany(f, ro);
        return doc(['deletedCount', BigInt(r.deletedCount)]);
      }
      case 'bulkWrite': {
        const b = await c.bulkWrite(
          asList(args.operations).map((o) => this.bulkOf(asMap(o))),
          { ...so, ordered: args.ordered !== false },
        );
        return doc(
          ['insertedCount', BigInt(b.insertedCount)],
          ['matchedCount', BigInt(b.matchedCount)],
          ['modifiedCount', BigInt(b.modifiedCount)],
          ['deletedCount', BigInt(b.deletedCount)],
          ['errors', b.errors.map((e) => doc(['index', BigInt(e.index)], ['code', BigInt(e.error.code)]))],
        );
      }
      case 'createIndex': {
        const created = await c.createIndex(asString(args.name), keysOf(args.keys ?? []), { unique: args.unique === true });
        return doc(['name', created.name], ['state', created.state]);
      }
      case 'dropIndex':
        return doc(['dropped', await c.dropIndex(asString(args.name), { ifExists: args.ifExists === true })]);
      case 'listIndexes':
        return (await c.listIndexes()).map((i) =>
          doc(['name', i.name], ['keys', i.keys.map((k) => doc(['path', k.path], ['descending', k.descending]))], ['unique', i.unique], ['state', i.state]),
        );
      default:
        throw new ConformanceFailure(`unknown collection operation '${name}'`);
    }
  }

  private async runner(name: string, args: YamlMap): Promise<void> {
    switch (name) {
      case 'sleep':
        await sleep(Number(args.ms));
        return;
      case 'throwApplicationError':
        throw new ApplicationError();
      case 'assertLastErrorHasTraceId':
        if (!(this.lastError instanceof RustegonError) || (this.lastError.traceId ?? '').length === 0) {
          throw new ConformanceFailure('the last error has no trace id');
        }
        return;
      default:
        break;
    }
    if (this.o.runnerExtension === undefined || !(await this.o.runnerExtension(name, args))) {
      throw new ConformanceFailure(`unknown runner operation '${name}'`);
    }
  }

  private params(args: YamlMap): Record<string, RValue> | undefined {
    return isMap(args.params) ? this.dsl.document(args.params) : undefined;
  }

  private resolveString(s: string): RValue {
    return s.startsWith('$$ref:') ? (this.resolveRef(s) ?? null) : this.o.substitute(s);
  }

  private resolveRef(reference: string): RValue | undefined {
    const parts = reference.slice('$$ref:'.length).split('.');
    let v = this.saved.get(parts[0]!) as RValue | undefined;
    if (v === undefined || isHandle(v)) {
      throw new ConformanceFailure(`no saved value '${parts[0]}'`);
    }
    for (const p of parts.slice(1)) {
      v = v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype ? (v as RDocument)[p] : undefined;
    }
    return v;
  }

  private bulkOf(o: YamlMap): BulkOperation {
    const [kind, a] = Object.entries(o)[0]!;
    const m = asMap(a);
    const ifRev = typeof m.ifRev === 'string' ? { ifRev: this.dsl.value(m.ifRev) as string } : {};
    switch (kind) {
      case 'insert':
        return BulkOperation.insert(this.dsl.document(m.document ?? null));
      case 'replace':
        return BulkOperation.replace(this.dsl.value(m.id ?? null), this.dsl.document(m.document ?? null), ifRev);
      case 'update':
        return BulkOperation.update(this.dsl.value(m.id ?? null), this.dsl.update(m.update ?? []), ifRev);
      case 'upsert':
        return BulkOperation.upsert(this.dsl.document(m.document ?? null));
      case 'delete':
        return BulkOperation.delete(this.dsl.value(m.id ?? null), ifRev);
      default:
        throw new Error(`unknown bulk operation '${kind}'`);
    }
  }

  async close(): Promise<void> {
    for (const v of this.saved.values()) {
      if (v instanceof Cursor || v instanceof Transaction) {
        await v.close();
      }
    }
    for (const c of this.opened) {
      await c.close();
    }
  }
}

function isHandle(v: unknown): v is RustegonClient | Transaction | ClientSession | Cursor<RDocument> {
  return v instanceof RustegonClient || v instanceof Transaction || v instanceof ClientSession || v instanceof Cursor;
}

function isAbort(e: unknown): boolean {
  return e instanceof Error && e.name === 'AbortError';
}

export function doc(...fields: [string, RValue][]): RDocument {
  const d: RDocument = {};
  for (const [k, v] of fields) {
    d[k] = v;
  }
  return d;
}

function counts(u: { matchedCount: number; modifiedCount: number; upsertedId?: RValue }): RDocument {
  const d = doc(['matchedCount', BigInt(u.matchedCount)], ['modifiedCount', BigInt(u.modifiedCount)]);
  if (u.upsertedId !== undefined) {
    d.upsertedId = u.upsertedId;
  }
  return d;
}

function batchSize(args: YamlMap): { batchSize: number } | undefined {
  return typeof args.batchSize === 'bigint' ? { batchSize: Number(args.batchSize) } : undefined;
}

function txnOptions(args: YamlMap): TransactionOptions | undefined {
  if (!isMap(args.options)) {
    return undefined;
  }
  const o = args.options;
  const options: TransactionOptions = { readOnly: o.readOnly === true };
  if (typeof o.isolation === 'string') {
    if (!['serializable', 'snapshot', 'read_committed'].includes(o.isolation)) {
      throw new Error(`isolation ${o.isolation}`);
    }
    options.isolation = o.isolation as TransactionOptions['isolation'];
  }
  if (typeof o.maxRetryTimeMs === 'bigint') {
    options.maxRetryTimeMs = Number(o.maxRetryTimeMs);
  }
  return options;
}

export function validatorOf(v: YamlMap): CollectionValidator {
  const validator: CollectionValidator = { jsonSchema: toJson(v.jsonSchema ?? null) };
  if (v.level !== undefined) {
    validator.level = v.level as CollectionValidator['level'];
  }
  if (v.action !== undefined) {
    validator.action = v.action as CollectionValidator['action'];
  }
  return validator;
}

/** The README §5 class id of an error (`Argument`, `InvalidState`, or errors-map.yaml ids). */
export function errorClassId(e: unknown): string {
  const id = classIdOf(e);
  if (id !== undefined) {
    return id;
  }
  if (e instanceof InvalidArgumentError || e instanceof TypeError || e instanceof RangeError) {
    return 'Argument';
  }
  if (e instanceof InvalidStateError) {
    return 'InvalidState';
  }
  return e instanceof Error ? e.constructor.name : typeof e;
}

/** Whether `e` is an instance of the class `id` (README §5 `exception`). */
export function isInstanceOf(e: unknown, id: string): boolean {
  switch (id) {
    case 'Argument':
      return e instanceof TypeError || e instanceof RangeError;
    case 'InvalidState':
      return e instanceof InvalidStateError;
    default: {
      const cls = ERROR_CLASSES.get(id);
      if (cls === undefined) {
        throw new Error(`unknown exception class id '${id}'`);
      }
      return e instanceof cls;
    }
  }
}

/** The observation of an error (README §6): code, class id, retryable. */
export function errorJson(e: unknown): string {
  if (e instanceof ApplicationError) {
    return '{"applicationError":true}';
  }
  if (e instanceof RustegonError) {
    return `{"code":${e.code},"exception":"${errorClassId(e)}","retryable":${e.retryable}}`;
  }
  return `{"exception":"${errorClassId(e)}"}`;
}

export function checkError(label: string, expected: YamlMap, error: unknown): void {
  const require = (ok: boolean, what: string): void => {
    if (!ok) {
      throw new ConformanceFailure(`${label}: ${what}; got ${describe(error)}`);
    }
  };
  if (expected.applicationError === true) {
    require(error instanceof ApplicationError, "expected the application's error unchanged");
    return;
  }
  const r = error instanceof RustegonError ? error : undefined;
  if (typeof expected.exception === 'string') {
    require(isInstanceOf(error, expected.exception), `expected an instance of ${expected.exception}`);
  }
  if (typeof expected.code === 'bigint') {
    require(r !== undefined && BigInt(r.code) === expected.code, `expected code ${expected.code}`);
  }
  if (typeof expected.name === 'string') {
    require(r?.errorName === expected.name, `expected name ${expected.name}`);
  }
  if (typeof expected.retryable === 'boolean') {
    require(r?.retryable === expected.retryable, `expected retryable ${expected.retryable}`);
  }
  if (typeof expected.committed === 'boolean') {
    require(r?.committed === expected.committed, `expected committed ${expected.committed}`);
  }
}

export function describe(e: unknown): string {
  if (e instanceof RustegonError) {
    return `${e.constructor.name} RGN-${e.code}: ${e.message}`;
  }
  return e instanceof Error ? `${e.constructor.name}: ${e.message}` : String(e);
}
