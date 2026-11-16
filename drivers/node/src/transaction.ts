// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import {
  TransactionService,
  BeginRequestSchema,
  CommitRequestSchema,
  HeartbeatRequestSchema,
  RollbackRequestSchema,
  StatusRequestSchema,
  TransactionState,
} from './generated/rustegon/v1/transaction_pb.js';
import { AstIsolation } from './generated/rustegon/v1/query_ast_pb.js';
import { Context, concernOf, consistencyOf } from './context.ts';
import { Database, type QueryParams, type QueryResult } from './database.ts';
import type { Collection } from './collection.ts';
import type { RDocument } from './codec/index.ts';
import type { DocumentCodec } from './mapping/index.ts';
import type { QueryOptions, TransactionOptions } from './options.ts';
import { backoffMs, delayAtLeast, type OperationExecutor } from './transport/executor.ts';
import { errorDetailOf, isServiceError } from './transport/calls.ts';
import {
  CommitOutcomeUnknownError,
  InvalidArgumentError,
  InvalidStateError,
  RustegonError,
  TransactionAbortedError,
  codeName,
  type TransactionOutcome,
} from './errors/errors.ts';

type State = 'active' | 'committed' | 'unknown' | 'ended';

/**
 * An interactive transaction (transactions.md; model.yaml `Transaction.*`). Operations on its
 * handles carry its id and are never retried alone (R2). `close()` — also through
 * `await using` — rolls back unless it committed. A heartbeat keeps it alive while it is open.
 */
export class Transaction implements AsyncDisposable {
  readonly id: string;
  private readonly executor: OperationExecutor;
  private readonly defaultDatabase: string | null;
  private state: State = 'active';
  private disposed = false;
  private heartbeat: NodeJS.Timeout | undefined;

  private constructor(executor: OperationExecutor, defaultDatabase: string | null, id: string, heartbeatIntervalMs: number) {
    this.executor = executor;
    this.defaultDatabase = defaultDatabase;
    this.id = id;
    if (heartbeatIntervalMs > 0) {
      this.heartbeat = setInterval(() => {
        this.sendHeartbeat().catch(() => {
          // Ignored: a lost heartbeat only shortens the idle timeout; the next operation reports
          // an expired transaction itself.
        });
      }, heartbeatIntervalMs);
      // The heartbeat must not keep a process alive on its own.
      this.heartbeat.unref();
    }
  }

  /** @internal */
  static async begin(executor: OperationExecutor, defaultDatabase: string | null, options?: TransactionOptions): Promise<Transaction> {
    executor.throwIfClosed();
    const request = create(BeginRequestSchema, {
      isolation:
        options?.isolation === undefined
          ? AstIsolation.UNSPECIFIED
          : options.isolation === 'serializable'
            ? AstIsolation.SERIALIZABLE
            : options.isolation === 'snapshot'
              ? AstIsolation.SNAPSHOT
              : AstIsolation.READ_COMMITTED,
      readOnly: options?.readOnly ?? false,
      writeConcern: concernOf(executor, options?.writeConcern),
    });
    // Follower and bounded-staleness reads exist only for read-only transactions (consistency.md).
    if (request.readOnly) {
      request.consistency = consistencyOf(executor, options?.readConsistency, options?.maxStalenessMs);
    }
    const r = await executor.unary(TransactionService.method.begin, request, { kind: 'none', signal: options?.signal });
    return new Transaction(executor, defaultDatabase, r.txnId, r.heartbeatIntervalMs);
  }

  /** @internal The id for an operation; throws once the transaction is closed. */
  idForOperation(): string {
    if (this.disposed) {
      throw new InvalidStateError('The transaction is closed.');
    }
    return this.id;
  }

  /** A database handle bound to this transaction. */
  db(name?: string): Database {
    return new Database(new Context(this.executor, name ?? this.defaultName(), this));
  }

  /** A collection of this transaction: `"db.coll"` or a collection of the default database. */
  collection<T = RDocument>(name: string, codec?: DocumentCodec<T>): Collection<T> {
    if (typeof name !== 'string' || name.length === 0) {
      throw new InvalidArgumentError('A collection name is required.');
    }
    const dot = name.indexOf('.');
    return dot > 0 ? this.db(name.slice(0, dot)).collection(name.slice(dot + 1), codec) : this.db().collection(name, codec);
  }

  /** RGQL inside the transaction (default database). */
  query<T = RDocument>(rgql: string, params?: QueryParams, options?: QueryOptions & { codec?: DocumentCodec<T> }): QueryResult<T> {
    return this.db().query<T>(rgql, params, options);
  }

  /**
   * Commits. RGN-2006 (and a commit reply lost after it was sent, PD-122) raises
   * `CommitOutcomeUnknownError` whose `resolve()` asks the server for the outcome.
   */
  async commit(options?: { signal?: AbortSignal }): Promise<void> {
    const id = this.idForOperation();
    try {
      await this.executor.unary(TransactionService.method.commit, create(CommitRequestSchema, { txnId: id }), { kind: 'none', signal: options?.signal });
      this.leave('committed');
    } catch (e) {
      if (e instanceof CommitOutcomeUnknownError) {
        this.leave('unknown');
        e.resolver = (signal) => this.resolve({ signal });
        throw e;
      }
      if (e instanceof RustegonError && mayHaveReachedServer(e)) {
        // A commit lost after it was sent (connection reset, node killed, deadline without an
        // answer) may have committed: never a retryable transport error, or withTransaction
        // would run the callback again (PD-122, PD-119).
        const unknown = new CommitOutcomeUnknownError(
          { code: 2006, name: codeName(2006), retryable: false, traceId: e.traceId },
          `The commit reply was lost (${e.message}); the outcome is unknown.`,
          { cause: e },
        );
        this.leave('unknown');
        unknown.resolver = (signal) => this.resolve({ signal });
        throw unknown;
      }
      throw e;
    }
  }

  /** Rolls back (the transaction is ended first: a failed rollback is not repeated by close). */
  async rollback(options?: { signal?: AbortSignal }): Promise<void> {
    const id = this.idForOperation();
    this.leave('ended');
    await this.executor.unary(TransactionService.method.rollback, create(RollbackRequestSchema, { txnId: id }), { kind: 'none', signal: options?.signal });
  }

  /** The outcome according to `TransactionService.Status` (ACTIVE/COMMITTING → `unknown`, never guessed). */
  async resolve(options?: { signal?: AbortSignal }): Promise<TransactionOutcome> {
    this.executor.throwIfClosed();
    const r = await this.executor.unary(TransactionService.method.status, create(StatusRequestSchema, { txnId: this.id }), { kind: 'none', signal: options?.signal });
    switch (r.state) {
      case TransactionState.COMMITTED:
        return 'committed';
      case TransactionState.ABORTED:
        return 'aborted';
      default:
        return 'unknown';
    }
  }

  /** Closes the transaction: rolls back when it is still active (best effort, idempotent). */
  async close(): Promise<void> {
    if (this.disposed) {
      return;
    }
    if (this.state === 'active') {
      this.leave('ended');
      try {
        await this.executor.unary(TransactionService.method.rollback, create(RollbackRequestSchema, { txnId: this.id }), { kind: 'none' });
      } catch (e) {
        // Best effort: the server rolls an abandoned transaction back when it expires.
        if (!(e instanceof RustegonError) && !(e instanceof InvalidStateError)) {
          throw e;
        }
      }
    }
    this.disposed = true;
    this.stopHeartbeat();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /** @internal Rollback that never throws (withTransaction). */
  async rollbackBestEffort(): Promise<void> {
    if (this.state !== 'active') {
      return;
    }
    try {
      await this.rollback();
    } catch (e) {
      if (!(e instanceof RustegonError) && !(e instanceof InvalidStateError)) {
        throw e;
      }
    }
  }

  private sendHeartbeat(): Promise<unknown> {
    return this.executor.unary(TransactionService.method.heartbeat, create(HeartbeatRequestSchema, { txnId: this.id }), { kind: 'none' });
  }

  private leave(state: State): void {
    if (this.state === 'active') {
      this.state = state;
      this.stopHeartbeat();
    }
  }

  private stopHeartbeat(): void {
    if (this.heartbeat !== undefined) {
      clearInterval(this.heartbeat);
      this.heartbeat = undefined;
    }
  }

  private defaultName(): string {
    if (this.defaultDatabase === null) {
      throw new InvalidArgumentError('The client has no default database: name the collection "db.coll" or use db(name).');
    }
    return this.defaultDatabase;
  }
}

/**
 * Whether a failed commit may have reached the server: any failure without ErrorDetail, except
 * those raised before the request left (connect timeout, refused or unresolvable connection).
 */
function mayHaveReachedServer(e: RustegonError): boolean {
  const cause = e.cause;
  if (!isServiceError(cause)) {
    return false; // Raised by the driver before any call (e.g. the connect timeout).
  }
  if (errorDetailOf(cause.metadata) !== undefined) {
    return false; // An ErrorDetail answered: the server decided.
  }
  const text = `${e.message} ${cause.message}`;
  return !/No connection established|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|Name resolution failed/i.test(text);
}

/** `withTransaction`: transactions.md §5, retry.yaml R6. */
export async function runTransaction<R>(
  executor: OperationExecutor,
  defaultDatabase: string | null,
  callback: (txn: Transaction, signal?: AbortSignal) => Promise<R>,
  options?: TransactionOptions,
): Promise<R> {
  if (typeof callback !== 'function') {
    throw new InvalidArgumentError('withTransaction needs a callback.');
  }
  const deadline = Date.now() + (options?.maxRetryTimeMs ?? 120_000);
  const signal = options?.signal;
  const isRetryable = (e: unknown): e is RustegonError =>
    e instanceof RustegonError && e.retryable && !(e instanceof CommitOutcomeUnknownError) && Date.now() < deadline;
  for (let attempt = 1; ; attempt++) {
    const txn = await Transaction.begin(executor, defaultDatabase, options);
    try {
      let retryable: RustegonError | undefined;
      let result: { value: R } | undefined;
      try {
        result = { value: await callback(txn, signal) };
      } catch (e) {
        if (!isRetryable(e)) {
          // Non-retryable errors, errors at the deadline and exceptions of the callback itself:
          // roll back and propagate unchanged.
          await txn.rollbackBestEffort();
          throw e;
        }
        retryable = e;
      }
      if (result !== undefined) {
        try {
          await txn.commit({ signal });
          return result.value;
        } catch (e) {
          if (e instanceof CommitOutcomeUnknownError) {
            // Never re-run blindly while the outcome is unknown: ask the server.
            if (await resolveOutcome(txn, e, deadline, signal)) {
              return result.value;
            }
            // Resolved as ABORTED: it definitely did not commit, handled like a retryable error.
            retryable = new TransactionAbortedError(
              { code: 2002, name: codeName(2002), retryable: true, committed: false, traceId: e.traceId },
              'The commit outcome was unknown and the transaction status reports it aborted.',
              { cause: e },
            );
          } else if (isRetryable(e)) {
            retryable = e;
          } else {
            await txn.rollbackBestEffort();
            throw e;
          }
        }
      }
      await txn.rollbackBestEffort();
      if (Date.now() >= deadline) {
        throw retryable;
      }
    } finally {
      await txn.close();
    }
    await delayAtLeast(clamp(backoffMs(attempt), deadline), signal);
  }
}

async function resolveOutcome(txn: Transaction, unknown: CommitOutcomeUnknownError, deadline: number, signal: AbortSignal | undefined): Promise<boolean> {
  for (let attempt = 1; ; attempt++) {
    let outcome: TransactionOutcome;
    try {
      outcome = await txn.resolve({ signal });
    } catch (e) {
      if (!(e instanceof RustegonError)) {
        throw e;
      }
      // A failed Status call says nothing about the commit: still unknown. It must never reach
      // the re-run path (the transaction could apply twice): keep polling.
      outcome = 'unknown';
    }
    if (outcome === 'committed') {
      return true;
    }
    if (outcome === 'aborted') {
      return false;
    }
    if (Date.now() >= deadline) {
      throw unknown;
    }
    await delayAtLeast(clamp(backoffMs(attempt), deadline), signal);
  }
}

function clamp(delay: number, deadline: number): number {
  const left = deadline - Date.now();
  return left <= 0 ? 0 : Math.min(delay, left);
}
