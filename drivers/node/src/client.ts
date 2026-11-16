// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import { SessionService, GetServerInfoRequestSchema, PingRequestSchema } from './generated/rustegon/v1/session_pb.js';
import { SchemaService, CreateDatabaseRequestSchema, DropDatabaseRequestSchema, ListDatabasesRequestSchema } from './generated/rustegon/v1/schema_pb.js';
import { AdminService, ChangePasswordRequestSchema } from './generated/rustegon/v1/admin_pb.js';
import { OperationExecutor } from './transport/executor.ts';
import { Context } from './context.ts';
import { Database, ordinal } from './database.ts';
import { ClientSession, type SessionOptions } from './session.ts';
import { Transaction, runTransaction } from './transaction.ts';
import { parseConnectionString, redactSettings, resolveSettings, type ClientOptions, type ResolvedSettings } from './settings.ts';
import type { CreateDatabaseOptions, DropOptions, OperationOptions, ServerInfo, TransactionOptions } from './options.ts';
import { InvalidArgumentError } from './errors/errors.ts';

/**
 * The client (model.yaml `Client.*`): long-lived, safe for concurrent use, owns the channel
 * pool. Creating it does no I/O; `connect()` (or `RustegonClient.connect`) logs in eagerly.
 *
 * ```ts
 * const client = await RustegonClient.connect('rustegon://db1:7700/shop', { user: 'app', password });
 * ```
 */
export class RustegonClient implements AsyncDisposable {
  /** The resolved settings (secrets redacted when printed). */
  readonly settings: ResolvedSettings;
  /** @internal */
  readonly executor: OperationExecutor;

  /**
   * @param uriOrOptions a `rustegon://` connection string or an options object
   * @param options options that override the connection string (e.g. the password)
   */
  constructor(uriOrOptions: string | ClientOptions = {}, options: ClientOptions = {}) {
    const base = typeof uriOrOptions === 'string' ? parseConnectionString(uriOrOptions) : uriOrOptions;
    this.settings = resolveSettings(base, options);
    this.executor = new OperationExecutor(this.settings);
  }

  /** Creates a client and logs in (Client.Create: wrong credentials fail here). */
  static async connect(uriOrOptions: string | ClientOptions = {}, options: ClientOptions & { signal?: AbortSignal } = {}): Promise<RustegonClient> {
    const { signal, ...rest } = options;
    const client = new RustegonClient(uriOrOptions, rest);
    try {
      await client.connect({ signal });
    } catch (e) {
      await client.close();
      throw e;
    }
    return client;
  }

  /** Logs in now (SCRAM / X.509); a no-op for API keys and anonymous clients. */
  async connect(options?: { signal?: AbortSignal }): Promise<void> {
    await this.executor.connect(options?.signal);
  }

  /** The default database of the settings. */
  get defaultDatabase(): string | null {
    return this.settings.database;
  }

  async ping(options?: OperationOptions): Promise<void> {
    await this.executor.unary(SessionService.method.ping, create(PingRequestSchema), this.spec('read', options));
  }

  async getServerInfo(options?: OperationOptions): Promise<ServerInfo> {
    const r = await this.executor.unary(SessionService.method.getServerInfo, create(GetServerInfoRequestSchema), this.spec('read', options));
    return { serverVersion: r.serverVersion, protocolVersion: r.protocolVersion, features: [...r.features], nodeAddresses: [...r.nodeAddresses] };
  }

  /** A database handle (no I/O); the default database when `name` is omitted. */
  db(name?: string): Database {
    this.executor.throwIfClosed();
    const db = name ?? this.settings.database;
    if (db === null) {
      throw new InvalidArgumentError('No database name and no default database in the settings.');
    }
    return new Database(new Context(this.executor, db));
  }

  /** The database names, sorted. */
  async listDatabaseNames(options?: OperationOptions): Promise<string[]> {
    const r = await this.executor.unary(SchemaService.method.listDatabases, create(ListDatabasesRequestSchema), this.spec('read', options));
    return r.databases.map((d) => d.name).sort(ordinal);
  }

  async createDatabase(name: string, options?: CreateDatabaseOptions): Promise<boolean> {
    checkName(name);
    const r = await this.executor.unary(
      SchemaService.method.createDatabase,
      create(CreateDatabaseRequestSchema, { name, ifNotExists: options?.ifNotExists ?? false }),
      this.spec('none', options),
    );
    return r.created;
  }

  async dropDatabase(name: string, options?: DropOptions): Promise<boolean> {
    checkName(name);
    const r = await this.executor.unary(
      SchemaService.method.dropDatabase,
      create(DropDatabaseRequestSchema, { name, ifExists: options?.ifExists ?? false }),
      this.spec('none', options),
    );
    return r.dropped;
  }

  /** A causal-consistency session (no server call in R1). */
  startSession(options?: SessionOptions): ClientSession {
    this.executor.throwIfClosed();
    return new ClientSession(options);
  }

  /** Begins an interactive transaction; close it (or `await using`) to roll back. */
  beginTransaction(options?: TransactionOptions): Promise<Transaction> {
    return Transaction.begin(this.executor, this.settings.database, options);
  }

  /**
   * Runs `callback` in a transaction and commits, re-running it on retryable errors until
   * `maxRetryTimeMs` (transactions.md §5); an unknown commit outcome is resolved with the server.
   */
  withTransaction<R>(callback: (txn: Transaction, signal?: AbortSignal) => Promise<R>, options?: TransactionOptions): Promise<R> {
    this.executor.throwIfClosed();
    return runTransaction(this.executor, this.settings.database, callback, options);
  }

  /** Changes the password of the logged-in user (PD-076). */
  async changePassword(currentPassword: string, newPassword: string, options?: OperationOptions): Promise<void> {
    if (typeof currentPassword !== 'string' || currentPassword.length === 0 || typeof newPassword !== 'string' || newPassword.length === 0) {
      throw new InvalidArgumentError('changePassword needs the current and the new password.');
    }
    await this.executor.unary(AdminService.method.changePassword, create(ChangePasswordRequestSchema, { currentPassword, newPassword }), this.spec('write', options));
  }

  /** Logs out (best effort) and closes the channels; idempotent. Later calls fail with InvalidStateError. */
  async close(): Promise<void> {
    await this.executor.close();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /** Never prints secrets. */
  toJSON(): Record<string, unknown> {
    return redactSettings(this.settings);
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `RustegonClient ${JSON.stringify(redactSettings(this.settings))}`;
  }

  private spec(kind: 'read' | 'write' | 'none', options?: OperationOptions) {
    this.executor.throwIfClosed();
    return { kind, timeoutMs: options?.timeoutMs, signal: options?.signal } as const;
  }
}

function checkName(name: string): void {
  if (typeof name !== 'string' || name.length === 0) {
    throw new InvalidArgumentError('A database name is required.');
  }
}
