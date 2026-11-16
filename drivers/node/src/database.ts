// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import { ExecOptionsSchema, ExecuteRequestSchema } from './generated/rustegon/v1/query_pb.js';
import {
  SchemaService,
  CreateCollectionRequestSchema,
  DropCollectionRequestSchema,
  ListCollectionsRequestSchema,
  ValidationAction as PbValidationAction,
  ValidationLevel as PbValidationLevel,
} from './generated/rustegon/v1/schema_pb.js';
import type { Context } from './context.ts';
import { Collection, RDOCUMENT_CODEC } from './collection.ts';
import { Cursor } from './cursor.ts';
import { toValue } from './builders.ts';
import type { RDocument, RValue } from './codec/index.ts';
import type { DocumentCodec } from './mapping/index.ts';
import type { CreateCollectionOptions, DropOptions, OperationOptions, QueryOptions } from './options.ts';
import { InvalidArgumentError } from './errors/errors.ts';

/** Named RGQL parameters (`$name` in the text); values are never interpolated into the text. */
export type QueryParams = Readonly<Record<string, RValue>>;

/** A database handle (no I/O until an operation runs). */
export class Database {
  private readonly context: Context;

  /** @internal */
  constructor(context: Context) {
    this.context = context;
  }

  get name(): string {
    return this.context.database;
  }

  /** A collection handle; with a model codec (`model({...})`) documents are mapped to `T`. */
  collection<T = RDocument>(name: string, codec?: DocumentCodec<T>): Collection<T> {
    return new Collection<T>(this.context, name, codec ?? (RDOCUMENT_CODEC as unknown as DocumentCodec<T>));
  }

  /**
   * An RGQL statement with parameters (model.yaml Database.Query). Nothing runs until the result
   * is read; rows of `SELECT VALUE` arrive as `{value: x}` documents.
   */
  query<T = RDocument>(rgql: string, params?: QueryParams, options?: QueryOptions & { codec?: DocumentCodec<T> }): QueryResult<T> {
    if (typeof rgql !== 'string' || rgql.length === 0) {
      throw new InvalidArgumentError('query needs RGQL text.');
    }
    if (options?.batchSize !== undefined && (!Number.isInteger(options.batchSize) || options.batchSize <= 0)) {
      throw new InvalidArgumentError('batchSize must be a positive integer.');
    }
    return new QueryResult<T>(this.context, rgql, params, options);
  }

  async createCollection(name: string, options?: CreateCollectionOptions): Promise<boolean> {
    checkName(name);
    this.context.throwIfTransactional('createCollection');
    const request = create(CreateCollectionRequestSchema, { database: this.name, name, ifNotExists: options?.ifNotExists ?? false });
    const v = options?.validator;
    if (v !== undefined) {
      request.validator = {
        $typeName: 'rustegon.v1.Validator',
        // Validators are kept as JSON text: `$`-prefixed keywords are not RDoc field names (PD-027).
        definitionJson: `{"$jsonSchema":${v.jsonSchema}}`,
        level:
          v.level === undefined ? PbValidationLevel.UNSPECIFIED : v.level === 'off' ? PbValidationLevel.OFF : v.level === 'strict' ? PbValidationLevel.STRICT : PbValidationLevel.MODERATE,
        action: v.action === undefined ? PbValidationAction.UNSPECIFIED : v.action === 'error' ? PbValidationAction.ERROR : PbValidationAction.WARN,
      };
    }
    const r = await this.context.executor.unary(SchemaService.method.createCollection, request, this.context.spec('none', options));
    return r.created;
  }

  async dropCollection(name: string, options?: DropOptions): Promise<boolean> {
    checkName(name);
    this.context.throwIfTransactional('dropCollection');
    const request = create(DropCollectionRequestSchema, { database: this.name, name, ifExists: options?.ifExists ?? false });
    const r = await this.context.executor.unary(SchemaService.method.dropCollection, request, this.context.spec('none', options));
    return r.dropped;
  }

  /** The collection names, sorted. */
  async listCollectionNames(options?: OperationOptions): Promise<string[]> {
    this.context.throwIfTransactional('listCollectionNames');
    const r = await this.context.executor.unary(
      SchemaService.method.listCollections,
      create(ListCollectionsRequestSchema, { database: this.name }),
      this.context.spec('read', options),
    );
    return r.collections.map((c) => c.name).sort(ordinal);
  }
}

/** The lazy result of `Database.query`: read it with `toArray`, `cursor` or `for await`. */
export class QueryResult<T> implements AsyncIterable<T> {
  private readonly context: Context;
  private readonly rgql: string;
  private readonly params: QueryParams | undefined;
  private readonly options: (QueryOptions & { codec?: DocumentCodec<T> }) | undefined;

  /** @internal */
  constructor(context: Context, rgql: string, params: QueryParams | undefined, options: (QueryOptions & { codec?: DocumentCodec<T> }) | undefined) {
    this.context = context;
    this.rgql = rgql;
    this.params = params;
    this.options = options;
  }

  /** Runs the statement and opens a cursor on its rows. */
  cursor(): Promise<Cursor<T>> {
    const request = create(ExecuteRequestSchema, {
      database: this.context.database,
      query: { case: 'rgql', value: this.rgql },
      options: create(ExecOptionsSchema, { consistency: this.context.consistency(this.options), batchSize: this.options?.batchSize }),
    });
    for (const [k, v] of Object.entries(this.params ?? {})) {
      request.params[k] = toValue(v);
    }
    const wo = this.context.writeOptions(this.options);
    if (wo !== undefined && request.options !== undefined) {
      request.options.writeConcern = wo.writeConcern;
    }
    // RGQL text may write: it is retried as a write (RetryWrites; the server deduplicates a
    // resent write by its request id, protocol.md §5.1), as .NET and Java do (PD-097).
    const codec = this.options?.codec ?? (RDOCUMENT_CODEC as unknown as DocumentCodec<T>);
    return Cursor.open(this.context, codec, request, this.context.spec('write', this.options));
  }

  async toArray(): Promise<T[]> {
    return (await this.cursor()).toArray();
  }

  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    yield* await this.cursor();
  }
}

function checkName(name: string): void {
  if (typeof name !== 'string' || name.length === 0) {
    throw new InvalidArgumentError('A name is required.');
  }
}

/** Ordinal (UTF-16 code unit) order, as .NET `StringComparer.Ordinal`. */
export function ordinal(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
