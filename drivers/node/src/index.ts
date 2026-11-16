// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/** Public API of the Rustegon Node.js driver (node-driver.md). */

export { RustegonClient } from './client.ts';
export { Database, QueryResult, type QueryParams } from './database.ts';
export { Collection, FindQuery, BulkOperation } from './collection.ts';
export { Cursor } from './cursor.ts';
export { Transaction } from './transaction.ts';
export { ClientSession, type SessionOptions } from './session.ts';
export { Filter, Update, Sort, Projection, IndexKeys } from './builders.ts';
export {
  parseConnectionString,
  resolveSettings,
  InvalidSettingsError,
  DEFAULTS,
  type ClientOptions,
  type ResolvedSettings,
  type HostPort,
  type ReadConsistency,
  type WriteConcern,
  type AuthMechanism,
} from './settings.ts';
export type * from './options.ts';
export {
  RustegonError,
  RustegonClientError,
  RDocError,
  QuerySyntaxError,
  DuplicateKeyError,
  DocumentValidationError,
  TransactionConflictError,
  TransactionAbortedError,
  CommitOutcomeUnknownError,
  AuthenticationError,
  PasswordChangeRequiredError,
  AuthorizationError,
  UnavailableError,
  RateLimitedError,
  RustegonTimeoutError,
  RustegonServerError,
  InvalidArgumentError,
  InvalidStateError,
  type ErrorInfo,
  type TransactionOutcome,
} from './errors/errors.ts';
export * from './codec/index.ts';
export * from './mapping/index.ts';
export { DRIVER_VERSION } from './version.ts';
