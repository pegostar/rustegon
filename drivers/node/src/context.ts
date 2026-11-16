// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import { QueryService, type ExecuteRequest, type ResultBatch, ResultBatchSchema } from './generated/rustegon/v1/query_pb.js';
import { ReadConsistencySchema, ReadConsistencyLevel, WriteConcern as PbWriteConcern, type ReadConsistency as PbReadConsistency } from './generated/rustegon/v1/common_pb.js';
import type { CallSpec, OperationExecutor, OperationKind } from './transport/executor.ts';
import type { OperationOptions, ReadOptions, WriteOptions } from './options.ts';
import type { ReadConsistency, WriteConcern } from './settings.ts';
import { InvalidArgumentError } from './errors/errors.ts';
import type { Transaction } from './transaction.ts';

/** The executor, database and (optional) transaction an operation runs in. */
export class Context {
  readonly executor: OperationExecutor;
  readonly database: string;
  readonly transaction: Transaction | undefined;

  constructor(executor: OperationExecutor, database: string, transaction?: Transaction) {
    if (typeof database !== 'string' || database.length === 0) {
      throw new InvalidArgumentError('A database name is required.');
    }
    this.executor = executor;
    this.database = database;
    this.transaction = transaction;
  }

  /** The transaction id for a request; throws when the transaction is closed. */
  get txnId(): string | undefined {
    return this.transaction?.idForOperation();
  }

  /** Inside a transaction nothing is retried alone and sessions do not apply (R2). */
  spec(kind: OperationKind, options?: OperationOptions): CallSpec {
    this.executor.throwIfClosed();
    if (options?.timeoutMs !== undefined && (!Number.isInteger(options.timeoutMs) || options.timeoutMs <= 0)) {
      throw new InvalidArgumentError('timeoutMs must be a positive integer.');
    }
    return this.transaction === undefined
      ? { kind, timeoutMs: options?.timeoutMs, session: options?.session, signal: options?.signal }
      : { kind: 'none', timeoutMs: options?.timeoutMs, signal: options?.signal };
  }

  /** The read consistency of a non-transactional read (settings, overridden per operation). */
  consistency(options?: ReadOptions): PbReadConsistency | undefined {
    return this.transaction === undefined ? consistencyOf(this.executor, options?.readConsistency, options?.maxStalenessMs) : undefined;
  }

  /** The write concern of a non-transactional write (inside a transaction `Begin` carries it). */
  writeOptions(options?: WriteOptions): { writeConcern: PbWriteConcern } | undefined {
    return this.transaction === undefined ? { writeConcern: concernOf(this.executor, options?.writeConcern) } : undefined;
  }

  throwIfTransactional(what: string): void {
    if (this.transaction !== undefined) {
      throw new InvalidArgumentError(`${what} is not transactional; run it on a handle of client.db().`);
    }
  }

  /** `QueryService.Execute`, every streamed batch. */
  async execute(request: ExecuteRequest, spec: CallSpec): Promise<ResultBatch[]> {
    const txn = this.txnId;
    if (txn !== undefined) {
      request.txnId = txn;
    }
    const responses = await this.executor.serverStream(QueryService.method.execute, request, spec);
    return responses.map((r) => r.batch ?? create(ResultBatchSchema));
  }
}

export function consistencyOf(executor: OperationExecutor, level: ReadConsistency | undefined, maxStalenessMs: number | undefined): PbReadConsistency | undefined {
  const effective = level ?? executor.settings.readConsistency ?? undefined;
  if (effective === undefined) {
    return undefined;
  }
  const staleness = maxStalenessMs ?? executor.settings.maxStalenessMs ?? undefined;
  if (effective === 'bounded_staleness' && staleness === undefined) {
    throw new InvalidArgumentError("readConsistency 'bounded_staleness' needs maxStalenessMs.");
  }
  if (staleness !== undefined && (!Number.isFinite(staleness) || staleness <= 0)) {
    throw new InvalidArgumentError('maxStalenessMs must be positive.');
  }
  const c = create(ReadConsistencySchema, {
    level:
      effective === 'linearizable'
        ? ReadConsistencyLevel.LINEARIZABLE
        : effective === 'bounded_staleness'
          ? ReadConsistencyLevel.BOUNDED_STALENESS
          : ReadConsistencyLevel.FOLLOWER,
  });
  if (effective !== 'linearizable' && staleness !== undefined) {
    c.maxStalenessMs = Math.min(0xffff_ffff, Math.ceil(staleness));
  }
  return c;
}

export function concernOf(executor: OperationExecutor, concern: WriteConcern | undefined): PbWriteConcern {
  switch (concern ?? executor.settings.writeConcern) {
    case 'majority':
      return PbWriteConcern.MAJORITY;
    case 'all':
      return PbWriteConcern.ALL;
    default:
      return PbWriteConcern.UNSPECIFIED;
  }
}
