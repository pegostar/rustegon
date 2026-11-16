// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import type { ClientSession } from './session.ts';
import type { ReadConsistency, WriteConcern } from './settings.ts';
import type { RValue } from './codec/index.ts';
import type { RustegonError } from './errors/errors.ts';

/** Options every operation accepts (dotnet-driver.md §6 per-operation overrides, PD-095, PD-097). */
export interface OperationOptions {
  /** Cancels the operation; the promise rejects with `signal.reason`. */
  signal?: AbortSignal;
  /** One deadline for the whole operation, retries included (retry.yaml R8). */
  timeoutMs?: number;
  /** Causal-consistency session (ignored inside a transaction). */
  session?: ClientSession;
}

export interface ReadOptions extends OperationOptions {
  readConsistency?: ReadConsistency;
  maxStalenessMs?: number;
}

export interface WriteOptions extends OperationOptions {
  writeConcern?: WriteConcern;
}

export interface QueryOptions extends ReadOptions, WriteOptions {
  batchSize?: number;
}

export interface FindOptions extends ReadOptions {
  batchSize?: number;
}

export interface UpdateOptions extends WriteOptions {
  /** Optimistic concurrency: only `Filter.id` operations (`_rev` must match). */
  ifRev?: string;
}

export interface ReplaceOptions extends UpdateOptions {
  /** Insert when no document has the id (needs `Filter.id`). */
  upsert?: boolean;
}

export type DeleteOptions = UpdateOptions;

export interface BulkWriteOptions extends WriteOptions {
  /** Stop at the first failed operation (default true). */
  ordered?: boolean;
}

export interface CreateDatabaseOptions extends OperationOptions {
  ifNotExists?: boolean;
}

export interface DropOptions extends OperationOptions {
  ifExists?: boolean;
}

export type ValidationLevel = 'off' | 'strict' | 'moderate';
export type ValidationAction = 'error' | 'warn';

/** A collection validator (data-model.md §5): the JSON Schema text, level and action. */
export interface CollectionValidator {
  /** The `$jsonSchema` object as JSON text (it may hold `$`-prefixed keywords). */
  jsonSchema: string;
  level?: ValidationLevel;
  action?: ValidationAction;
}

export interface CreateCollectionOptions extends OperationOptions {
  ifNotExists?: boolean;
  validator?: CollectionValidator;
}

export interface CreateIndexOptions extends OperationOptions {
  unique?: boolean;
}

export type IsolationLevel = 'serializable' | 'snapshot' | 'read_committed';

export interface TransactionOptions {
  isolation?: IsolationLevel;
  readOnly?: boolean;
  /** `withTransaction` retries until this much time has passed (default 2 min, transactions.md §5). */
  maxRetryTimeMs?: number;
  writeConcern?: WriteConcern;
  /** Sent for read-only transactions only (followers serve read-only transactions). */
  readConsistency?: ReadConsistency;
  maxStalenessMs?: number;
  signal?: AbortSignal;
}

export interface ServerInfo {
  readonly serverVersion: string;
  readonly protocolVersion: string;
  /** Feature flags (`GetServerInfo.features`): deferred APIs come back gated on these (PD-069). */
  readonly features: readonly string[];
  readonly nodeAddresses: readonly string[];
}

export interface InsertOneResult {
  readonly insertedId: RValue;
}

export interface InsertManyResult {
  readonly insertedIds: readonly RValue[];
}

/** By-id writes report `UpdateResponse.matched/modified`; statements report `docs_affected` as both. */
export interface UpdateResult {
  readonly matchedCount: number;
  readonly modifiedCount: number;
  readonly upsertedId?: RValue;
}

export interface DeleteResult {
  readonly deletedCount: number;
}

export interface BulkWriteError {
  readonly index: number;
  readonly error: RustegonError;
  readonly message: string;
}

export interface BulkWriteResult {
  readonly insertedCount: number;
  readonly matchedCount: number;
  readonly modifiedCount: number;
  readonly deletedCount: number;
  /** Per-operation failures (the call itself does not throw for them). */
  readonly errors: readonly BulkWriteError[];
}

export type IndexState = 'building' | 'ready' | 'failed' | 'hidden';

export interface IndexDescription {
  readonly name: string;
  readonly keys: readonly { readonly path: string; readonly descending: boolean }[];
  readonly unique: boolean;
  readonly state: IndexState;
  readonly error?: string;
}
