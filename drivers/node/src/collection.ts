// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import {
  DocumentService,
  BulkWriteRequestSchema,
  DeleteRequestSchema,
  GetRequestSchema,
  InsertRequestSchema,
  ReplaceRequestSchema,
  UpdateRequestSchema,
  UpsertRequestSchema,
  type BulkOperation as PbBulkOperation,
  BulkOperationSchema,
} from './generated/rustegon/v1/document_pb.js';
import { DocumentSchema, type Document } from './generated/rustegon/v1/common_pb.js';
import { ExecOptionsSchema, ExecuteRequestSchema, type ExecuteRequest } from './generated/rustegon/v1/query_pb.js';
import { AstIndexType, AstStatementSchema, type AstStatement } from './generated/rustegon/v1/query_ast_pb.js';
import {
  SchemaService,
  CreateIndexRequestSchema,
  DropIndexRequestSchema,
  IndexBuildProgressRequestSchema,
  IndexState as PbIndexState,
  ListIndexesRequestSchema,
  type IndexInfo,
} from './generated/rustegon/v1/schema_pb.js';
import { ParamSink, Filter, Update, Sort, Projection, IndexKeys, astPath, allowFullScanWrite, intLiteral, toValue, fromValue, pathText } from './builders.ts';
import { encodeDocument, decodeDocument, valueEquals, type RDocument, type RValue } from './codec/index.ts';
import type { DocumentCodec } from './mapping/index.ts';
import { Cursor } from './cursor.ts';
import type { Context } from './context.ts';
import type {
  BulkWriteOptions,
  BulkWriteResult,
  CreateIndexOptions,
  DeleteOptions,
  DeleteResult,
  DropOptions,
  FindOptions,
  IndexDescription,
  IndexState,
  InsertManyResult,
  InsertOneResult,
  OperationOptions,
  ReplaceOptions,
  UpdateOptions,
  UpdateResult,
  WriteOptions,
} from './options.ts';
import { InvalidArgumentError, codeName, errorFromInfo, errorFromTransport } from './errors/errors.ts';
import { delayAtLeast } from './transport/executor.ts';

/** The identity codec of schemaless collections (`RDocument` plain objects). */
export const RDOCUMENT_CODEC: DocumentCodec<RDocument> = {
  encode: (value) => value,
  decode: (doc) => doc,
};

/** Statements of non-id filters (README §4 rules 3–6). */
export const Statements = {
  find(collection: string, filter: Filter, sort: Sort | undefined, projection: Projection | undefined, limit: bigint | undefined, skip: bigint | undefined, sink: ParamSink): AstStatement {
    return create(AstStatementSchema, {
      kind: {
        case: 'query',
        value: {
          from: { source: { kind: { case: 'collection', value: { name: collection } } } },
          where: filter.toAst(sink),
          select: projection?.toAst(),
          orderBy: sort?.toAst() ?? [],
          limit: limit === undefined ? undefined : intLiteral(limit),
          offset: skip === undefined ? undefined : intLiteral(skip),
        },
      },
    });
  },

  update(collection: string, filter: Filter, update: Update, one: boolean, sink: ParamSink): AstStatement {
    const where = filter.toAst(sink);
    return create(AstStatementSchema, {
      kind: {
        case: 'update',
        value: {
          target: { name: collection },
          ops: update.toAst(sink),
          where,
          limit: one ? intLiteral(1) : undefined,
          // Without WHERE the server refuses a write unless asked explicitly (RGN-1013); the
          // empty filter is that explicit request (README §4 rule 5).
          options: filter.isEmpty ? [allowFullScanWrite()] : [],
        },
      },
    });
  },

  delete(collection: string, filter: Filter, one: boolean, sink: ParamSink): AstStatement {
    return create(AstStatementSchema, {
      kind: {
        case: 'delete',
        value: {
          target: { name: collection },
          where: filter.toAst(sink),
          limit: one ? intLiteral(1) : undefined,
          options: filter.isEmpty ? [allowFullScanWrite()] : [],
        },
      },
    });
  },
};

type BulkKind = 'insert' | 'upsert' | 'replace' | 'update' | 'delete';

/** One operation of a bulk write; documents are addressed by `_id` (BulkOperation of document.proto). */
export class BulkOperation<T = RDocument> {
  readonly kind: BulkKind;
  readonly id: RValue | undefined;
  readonly document: T | undefined;
  readonly update: Update | undefined;
  readonly ifRev: string | undefined;

  private constructor(kind: BulkKind, id: RValue | undefined, document: T | undefined, update: Update | undefined, ifRev: string | undefined) {
    this.kind = kind;
    this.id = id;
    this.document = document;
    this.update = update;
    this.ifRev = ifRev;
  }

  static insert<T = RDocument>(document: T): BulkOperation<T> {
    return new BulkOperation<T>('insert', undefined, required(document), undefined, undefined);
  }

  static upsert<T = RDocument>(document: T): BulkOperation<T> {
    return new BulkOperation<T>('upsert', undefined, required(document), undefined, undefined);
  }

  static replace<T = RDocument>(id: RValue, document: T, options: { ifRev?: string } = {}): BulkOperation<T> {
    return new BulkOperation<T>('replace', required(id), required(document), undefined, options.ifRev);
  }

  static update<T = RDocument>(id: RValue, update: Update, options: { ifRev?: string } = {}): BulkOperation<T> {
    if (!(update instanceof Update)) {
      throw new InvalidArgumentError('BulkOperation.update needs an Update.');
    }
    return new BulkOperation<T>('update', required(id), undefined, update, options.ifRev);
  }

  static delete<T = RDocument>(id: RValue, options: { ifRev?: string } = {}): BulkOperation<T> {
    return new BulkOperation<T>('delete', required(id), undefined, undefined, options.ifRev);
  }
}

function required<V>(v: V): V {
  if (v === undefined || v === null) {
    throw new InvalidArgumentError('A value is required.');
  }
  return v;
}

/** A collection handle (no I/O until an operation runs). `T` is mapped by the handle's codec. */
export class Collection<T = RDocument> {
  readonly name: string;
  private readonly context: Context;
  private readonly codec: DocumentCodec<T>;

  /** @internal */
  constructor(context: Context, name: string, codec: DocumentCodec<T>) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new InvalidArgumentError('A collection name is required.');
    }
    this.context = context;
    this.name = name;
    this.codec = codec;
  }

  get databaseName(): string {
    return this.context.database;
  }

  async insertOne(document: T, options?: WriteOptions): Promise<InsertOneResult> {
    const r = await this.insert([document], options);
    return { insertedId: r.insertedIds[0] ?? null };
  }

  async insertMany(documents: readonly T[], options?: WriteOptions): Promise<InsertManyResult> {
    if (!Array.isArray(documents) || documents.length === 0) {
      throw new InvalidArgumentError('insertMany needs at least one document.');
    }
    return this.insert(documents, options);
  }

  async findById(id: RValue, options?: FindOptions): Promise<T | null> {
    const request = create(GetRequestSchema, {
      database: this.context.database,
      collection: this.name,
      id: toValue(required(id)),
      consistency: this.context.consistency(options),
    });
    this.setTxn((t) => (request.txnId = t));
    const response = await this.context.executor.unary(DocumentService.method.get, request, this.context.spec('read', options));
    return response.document === undefined ? null : this.decode(response.document);
  }

  /** A find; refine it with `sort`, `limit`, `skip`, `project`, `batchSize`, then read it. */
  find(filter: Filter = Filter.empty, options?: FindOptions): FindQuery<T> {
    if (!(filter instanceof Filter)) {
      throw new InvalidArgumentError('find needs a Filter.');
    }
    return new FindQuery(this.context, this.name, this.codec, filter, options);
  }

  updateOne(filter: Filter, update: Update, options?: UpdateOptions): Promise<UpdateResult> {
    return this.updateWith(filter, update, options, true);
  }

  updateMany(filter: Filter, update: Update, options?: UpdateOptions): Promise<UpdateResult> {
    return this.updateWith(filter, update, options, false);
  }

  async replaceOne(filter: Filter, replacement: T, options?: ReplaceOptions): Promise<UpdateResult> {
    checkFilter(filter);
    const document = this.codec.encode(required(replacement));
    const id = filter.idValue;
    if (id === undefined) {
      if (options?.upsert === true) {
        throw new InvalidArgumentError('An upserting replaceOne needs Filter.id.');
      }
      requireNoIfRev(options?.ifRev);
      const sink = new ParamSink();
      const n = await this.executeWrite(Statements.update(this.name, filter, Update.replace(document), true, sink), sink, options);
      return { matchedCount: n, modifiedCount: n };
    }
    if (options?.upsert === true) {
      const request = create(UpsertRequestSchema, {
        database: this.context.database,
        collection: this.name,
        document: toDocument(withId(document, id)),
        options: this.context.writeOptions(options),
        ifRev: options.ifRev,
      });
      this.setTxn((t) => (request.txnId = t));
      const r = await this.context.executor.unary(DocumentService.method.upsert, request, this.context.spec('write', options));
      return r.inserted ? { matchedCount: 0, modifiedCount: 0, upsertedId: id } : { matchedCount: 1, modifiedCount: 1 };
    }
    const request = create(ReplaceRequestSchema, {
      database: this.context.database,
      collection: this.name,
      id: toValue(id),
      document: toDocument(document),
      options: this.context.writeOptions(options),
      ifRev: options?.ifRev,
    });
    this.setTxn((t) => (request.txnId = t));
    const r = await this.context.executor.unary(DocumentService.method.replace, request, this.context.spec('write', options));
    return r.matched ? { matchedCount: 1, modifiedCount: 1 } : { matchedCount: 0, modifiedCount: 0 };
  }

  deleteOne(filter: Filter, options?: DeleteOptions): Promise<DeleteResult> {
    return this.deleteWith(filter, options, true);
  }

  deleteMany(filter: Filter, options?: DeleteOptions): Promise<DeleteResult> {
    return this.deleteWith(filter, options, false);
  }

  async bulkWrite(operations: readonly BulkOperation<T>[], options?: BulkWriteOptions): Promise<BulkWriteResult> {
    if (!Array.isArray(operations) || operations.length === 0) {
      throw new InvalidArgumentError('A bulk write needs at least one operation.');
    }
    // One sink for the whole request: BulkWriteRequest.params is shared by every update, so
    // their parameters are numbered u0, u1, … across operations.
    const sink = new ParamSink();
    const request = create(BulkWriteRequestSchema, {
      database: this.context.database,
      collection: this.name,
      ordered: options?.ordered ?? true,
      operations: operations.map((op) => this.bulkOp(op, sink)),
      options: this.context.writeOptions(options),
    });
    request.params = sink.params;
    this.setTxn((t) => (request.txnId = t));
    const r = await this.context.executor.unary(DocumentService.method.bulkWrite, request, this.context.spec('write', options));
    return {
      insertedCount: Number(r.inserted),
      matchedCount: Number(r.matched),
      modifiedCount: Number(r.modified),
      deletedCount: Number(r.deleted),
      errors: r.errors.map((e) => ({
        index: e.index,
        message: e.message,
        error:
          e.error === undefined
            ? errorFromTransport('UNKNOWN', e.message)
            : errorFromInfo(
                {
                  code: e.error.code,
                  name: e.error.name.length > 0 ? e.error.name : codeName(e.error.code),
                  retryable: e.error.retryable,
                  committed: e.error.committed,
                  details: { ...e.error.details },
                  traceId: e.error.traceId.length > 0 ? e.error.traceId : undefined,
                },
                e.message,
              ),
      })),
    };
  }

  /** Creates an index and waits until its build has finished (README §5: the final state). */
  async createIndex(name: string, keys: IndexKeys, options?: CreateIndexOptions): Promise<IndexDescription> {
    if (typeof name !== 'string' || name.length === 0 || !(keys instanceof IndexKeys)) {
      throw new InvalidArgumentError('createIndex needs a name and IndexKeys.');
    }
    this.context.throwIfTransactional('createIndex');
    const definition = {
      indexType: options?.unique === true ? AstIndexType.UNIQUE : AstIndexType.STANDARD,
      name,
      on: { name: this.name },
      keys: keys.keys.map((k) => ({ path: astPath(k.path), descending: k.descending })),
    };
    const request = create(CreateIndexRequestSchema, { database: this.context.database, definition });
    const created = await this.context.executor.unary(SchemaService.method.createIndex, request, this.context.spec('none', options));
    // The build runs in the background; poll with a doubling interval so a quick build costs
    // milliseconds and a long one few calls.
    let state = created.index?.state ?? PbIndexState.BUILDING;
    let delay = 10;
    while (state === PbIndexState.BUILDING) {
      delay = Math.min(500, delay * 2);
      await delayAtLeast(delay, options?.signal);
      const p = await this.context.executor.unary(
        SchemaService.method.indexBuildProgress,
        create(IndexBuildProgressRequestSchema, { database: this.context.database, collection: this.name, name }),
        this.context.spec('read', options),
      );
      state = p.state;
    }
    return describe(created.index ?? { definition: request.definition, error: undefined }, state);
  }

  async dropIndex(name: string, options?: DropOptions): Promise<boolean> {
    if (typeof name !== 'string' || name.length === 0) {
      throw new InvalidArgumentError('dropIndex needs a name.');
    }
    this.context.throwIfTransactional('dropIndex');
    const request = create(DropIndexRequestSchema, { database: this.context.database, collection: this.name, name, ifExists: options?.ifExists ?? false });
    const r = await this.context.executor.unary(SchemaService.method.dropIndex, request, this.context.spec('none', options));
    return r.dropped;
  }

  /** The indexes, sorted by name. */
  async listIndexes(options?: OperationOptions): Promise<IndexDescription[]> {
    this.context.throwIfTransactional('listIndexes');
    const request = create(ListIndexesRequestSchema, { database: this.context.database, collection: this.name });
    const r = await this.context.executor.unary(SchemaService.method.listIndexes, request, this.context.spec('read', options));
    return r.indexes.map((i) => describe(i, i.state)).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  private async insert(documents: readonly T[], options?: WriteOptions): Promise<InsertManyResult> {
    const request = create(InsertRequestSchema, {
      database: this.context.database,
      collection: this.name,
      documents: documents.map((d) => toDocument(this.codec.encode(required(d)))),
      options: this.context.writeOptions(options),
    });
    this.setTxn((t) => (request.txnId = t));
    const r = await this.context.executor.unary(DocumentService.method.insert, request, this.context.spec('write', options));
    return { insertedIds: r.results.map((w) => fromValue(w.id) ?? null) };
  }

  private async updateWith(filter: Filter, update: Update, options: UpdateOptions | undefined, one: boolean): Promise<UpdateResult> {
    checkFilter(filter);
    if (!(update instanceof Update)) {
      throw new InvalidArgumentError('An Update is required.');
    }
    const sink = new ParamSink();
    const id = filter.idValue;
    if (one && id !== undefined) {
      const request = create(UpdateRequestSchema, {
        database: this.context.database,
        collection: this.name,
        id: toValue(id),
        operations: update.toAst(sink),
        options: this.context.writeOptions(options),
        ifRev: options?.ifRev,
      });
      request.params = sink.params;
      this.setTxn((t) => (request.txnId = t));
      const r = await this.context.executor.unary(DocumentService.method.update, request, this.context.spec('write', options));
      return { matchedCount: r.matched ? 1 : 0, modifiedCount: r.modified ? 1 : 0 };
    }
    requireNoIfRev(options?.ifRev);
    // A statement reports the documents it wrote (docs_affected); it rewrites every match, so
    // matched = modified (README §5 "Result conventions").
    const n = await this.executeWrite(Statements.update(this.name, filter, update, one, sink), sink, options);
    return { matchedCount: n, modifiedCount: n };
  }

  private async deleteWith(filter: Filter, options: DeleteOptions | undefined, one: boolean): Promise<DeleteResult> {
    checkFilter(filter);
    const id = filter.idValue;
    if (one && id !== undefined) {
      const request = create(DeleteRequestSchema, {
        database: this.context.database,
        collection: this.name,
        id: toValue(id),
        options: this.context.writeOptions(options),
        ifRev: options?.ifRev,
      });
      this.setTxn((t) => (request.txnId = t));
      const r = await this.context.executor.unary(DocumentService.method.delete, request, this.context.spec('write', options));
      return { deletedCount: r.deleted ? 1 : 0 };
    }
    requireNoIfRev(options?.ifRev);
    const sink = new ParamSink();
    return { deletedCount: await this.executeWrite(Statements.delete(this.name, filter, one, sink), sink, options) };
  }

  private async executeWrite(statement: AstStatement, sink: ParamSink, options: WriteOptions | undefined): Promise<number> {
    const request = create(ExecuteRequestSchema, {
      database: this.context.database,
      query: { case: 'ast', value: statement },
      options: create(ExecOptionsSchema, {}),
    });
    request.params = sink.params;
    const wo = this.context.writeOptions(options);
    if (wo !== undefined && request.options !== undefined) {
      request.options.writeConcern = wo.writeConcern;
    }
    let affected = 0;
    for (const b of await this.context.execute(request, this.context.spec('write', options))) {
      if (b.stats !== undefined) {
        affected = Number(b.stats.docsAffected);
      }
    }
    return affected;
  }

  private bulkOp(op: BulkOperation<T>, sink: ParamSink): PbBulkOperation {
    if (!(op instanceof BulkOperation)) {
      throw new InvalidArgumentError('bulkWrite takes BulkOperation values.');
    }
    const doc = (): Document => toDocument(this.codec.encode(op.document as T));
    switch (op.kind) {
      case 'insert':
        return create(BulkOperationSchema, { op: { case: 'insert', value: { document: doc() } } });
      case 'upsert':
        return create(BulkOperationSchema, { op: { case: 'upsert', value: { document: doc() } } });
      case 'replace':
        return create(BulkOperationSchema, { op: { case: 'replace', value: { id: toValue(op.id ?? null), document: doc(), ifRev: op.ifRev } } });
      case 'update':
        return create(BulkOperationSchema, { op: { case: 'update', value: { id: toValue(op.id ?? null), operations: op.update?.toAst(sink) ?? [], ifRev: op.ifRev } } });
      case 'delete':
        return create(BulkOperationSchema, { op: { case: 'delete', value: { id: toValue(op.id ?? null), ifRev: op.ifRev } } });
    }
  }

  private decode(d: Document): T {
    return this.codec.decode(decodeDocument(d.rdoc));
  }

  private setTxn(set: (id: string) => void): void {
    const id = this.context.txnId;
    if (id !== undefined) {
      set(id);
    }
  }
}

/** A find being built; nothing runs until it is read (`toArray`, `first`, `cursor`, `for await`). */
export class FindQuery<T> implements AsyncIterable<T> {
  private readonly context: Context;
  private readonly collection: string;
  private readonly codec: DocumentCodec<T>;
  private readonly filter: Filter;
  private readonly options: FindOptions | undefined;
  private sortValue: Sort | undefined;
  private projection: Projection | undefined;
  private limitValue: number | undefined;
  private skipValue: number | undefined;
  private batch: number | undefined;

  /** @internal */
  constructor(context: Context, collection: string, codec: DocumentCodec<T>, filter: Filter, options: FindOptions | undefined) {
    this.context = context;
    this.collection = collection;
    this.codec = codec;
    this.filter = filter;
    this.options = options;
    if (options?.batchSize !== undefined) {
      this.batchSize(options.batchSize);
    }
  }

  sort(sort: Sort): this {
    if (!(sort instanceof Sort)) {
      throw new InvalidArgumentError('sort needs a Sort.');
    }
    this.sortValue = sort;
    return this;
  }

  limit(n: number): this {
    this.limitValue = nonNegative(n, 'limit');
    return this;
  }

  skip(n: number): this {
    this.skipValue = nonNegative(n, 'skip');
    return this;
  }

  project(projection: Projection): this {
    if (!(projection instanceof Projection)) {
      throw new InvalidArgumentError('project needs a Projection.');
    }
    this.projection = projection;
    return this;
  }

  batchSize(n: number): this {
    if (!Number.isInteger(n) || n <= 0) {
      throw new InvalidArgumentError('batchSize must be a positive integer.');
    }
    this.batch = n;
    return this;
  }

  /** Opens a server cursor on the results. */
  cursor(): Promise<Cursor<T>> {
    return this.open(this.limitValue);
  }

  toArray(): Promise<T[]> {
    return this.open(this.limitValue).then((c) => c.toArray());
  }

  /** The first result (limit 1), or null. */
  async first(): Promise<T | null> {
    const c = await this.open(Math.min(this.limitValue ?? 1, 1));
    try {
      return await c.next();
    } finally {
      await c.close();
    }
  }

  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    yield* await this.cursor();
  }

  /** @internal The Execute request of this find. */
  request(limit: number | undefined): ExecuteRequest {
    const sink = new ParamSink();
    const statement = Statements.find(
      this.collection,
      this.filter,
      this.sortValue,
      this.projection,
      limit === undefined ? undefined : BigInt(limit),
      this.skipValue === undefined ? undefined : BigInt(this.skipValue),
      sink,
    );
    const request = create(ExecuteRequestSchema, {
      database: this.context.database,
      query: { case: 'ast', value: statement },
      options: create(ExecOptionsSchema, { consistency: this.context.consistency(this.options), batchSize: this.batch }),
    });
    request.params = sink.params;
    return request;
  }

  private open(limit: number | undefined): Promise<Cursor<T>> {
    return Cursor.open(this.context, this.codec, this.request(limit), this.context.spec('read', this.options));
  }
}

function nonNegative(n: number, what: string): number {
  if (!Number.isInteger(n) || n < 0) {
    throw new InvalidArgumentError(`${what} must be a non-negative integer.`);
  }
  return n;
}

function checkFilter(filter: Filter): void {
  if (!(filter instanceof Filter)) {
    throw new InvalidArgumentError('A Filter is required.');
  }
}

function requireNoIfRev(ifRev: string | undefined): void {
  if (ifRev !== undefined) {
    throw new InvalidArgumentError('ifRev applies to Filter.id operations only.');
  }
}

function toDocument(doc: RDocument): Document {
  return create(DocumentSchema, { rdoc: encodeDocument(doc) });
}

/** The replacement with `_id` first, or unchanged when it already has the same id. */
function withId(document: RDocument, id: RValue): RDocument {
  if (Object.prototype.hasOwnProperty.call(document, '_id')) {
    if (!valueEquals(document._id ?? null, id)) {
      throw new InvalidArgumentError("The replacement's _id differs from the id of Filter.id.");
    }
    return document;
  }
  const copy: RDocument = { _id: id };
  for (const [k, v] of Object.entries(document)) {
    Object.defineProperty(copy, k, { value: v, enumerable: true, writable: true, configurable: true });
  }
  return copy;
}

function stateOf(s: PbIndexState): IndexState {
  switch (s) {
    case PbIndexState.READY:
      return 'ready';
    case PbIndexState.FAILED:
      return 'failed';
    case PbIndexState.HIDDEN:
      return 'hidden';
    default:
      return 'building';
  }
}

function describe(info: Pick<IndexInfo, 'definition' | 'error'>, state: PbIndexState): IndexDescription {
  const d = info.definition;
  const out: IndexDescription = {
    name: d?.name ?? '',
    keys: (d?.keys ?? []).map((k) => ({ path: pathText(k.path), descending: k.descending })),
    unique: d?.indexType === AstIndexType.UNIQUE,
    state: stateOf(state),
    ...(info.error === undefined ? {} : { error: info.error }),
  };
  return out;
}

