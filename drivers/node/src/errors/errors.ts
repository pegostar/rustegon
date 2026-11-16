// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { CODES, TRANSPORT, UNKNOWN_CLASS_ID } from './codes.generated.ts';

/**
 * The error data of a failed operation (ErrorDetail of protocol.md §7, or a transport fallback
 * of errors-map.yaml). `retryable` and `committed` come from the server's reply, never from the
 * catalog (PD-075).
 */
export interface ErrorInfo {
  readonly code: number;
  readonly name: string;
  readonly retryable: boolean;
  readonly committed?: boolean | undefined;
  readonly details?: Readonly<Record<string, string>> | undefined;
  readonly traceId?: string | undefined;
  readonly retryAfterMs?: number | undefined;
}

/** The catalog name of a code (`""` when unknown to this driver version). */
export function codeName(code: number): string {
  return CODES.get(code)?.name ?? '';
}

/** A client-side error of `code` with the catalog name, not retryable. */
export function clientInfo(code: number): ErrorInfo {
  return { code, name: codeName(code), retryable: false };
}

/**
 * Base class of every error the driver raises for a failed operation (errors-map.yaml class
 * `Base`). The subclass is chosen from the code only; unknown codes give this class.
 */
export class RustegonError extends Error {
  readonly info: ErrorInfo;

  constructor(info: ErrorInfo, message: string, options?: ErrorOptions) {
    super(message, options);
    this.info = info;
    this.name = new.target.name;
  }

  /** The numeric code (RGN-<code>). */
  get code(): number {
    return this.info.code;
  }

  /** The stable error name of the catalog (e.g. `DuplicateKey`). */
  get errorName(): string {
    return this.info.name;
  }

  get retryable(): boolean {
    return this.info.retryable;
  }

  /** For commit errors: whether the transaction is known to have committed. */
  get committed(): boolean | undefined {
    return this.info.committed;
  }

  get details(): Readonly<Record<string, string>> {
    return this.info.details ?? {};
  }

  get traceId(): string | undefined {
    return this.info.traceId;
  }
}

/** Client errors (1xxx not mapped to a more specific class). */
export class RustegonClientError extends RustegonError {}

/** An RDoc value or document the codec refuses (RGN-1001/1002/1003/1004/1040). */
export class RDocError extends RustegonClientError {
  /** Byte offset of the problem in the decoded input, when known. */
  readonly position: number | undefined;

  constructor(code: number, message: string, position?: number) {
    super(clientInfo(code), position === undefined ? message : `${message} (at offset ${position})`);
    this.position = position;
  }
}

export class QuerySyntaxError extends RustegonClientError {}
export class DuplicateKeyError extends RustegonError {}
export class DocumentValidationError extends RustegonError {}
export class TransactionConflictError extends RustegonError {}
export class TransactionAbortedError extends RustegonError {}

/** The final state of a transaction whose commit outcome was unknown (transactions.md §5). */
export type TransactionOutcome = 'committed' | 'aborted' | 'unknown';

/**
 * RGN-2006: the commit may or may not have applied. Raised by a manual `commit()` with a
 * resolver attached (`resolve()` asks `TransactionService.Status`); `withTransaction` resolves
 * it itself.
 */
export class CommitOutcomeUnknownError extends RustegonError {
  /** @internal */
  resolver: ((signal?: AbortSignal) => Promise<TransactionOutcome>) | undefined;

  /** Asks the server for the transaction's outcome. */
  resolve(signal?: AbortSignal): Promise<TransactionOutcome> {
    if (this.resolver === undefined) {
      throw new Error('This error was not raised by Transaction.commit(); there is no transaction to resolve.');
    }
    return this.resolver(signal);
  }
}

export class AuthenticationError extends RustegonError {}

/** PD-076: the account must change its password first (raised after a successful login). */
export class PasswordChangeRequiredError extends AuthenticationError {}

export class AuthorizationError extends RustegonError {}
export class UnavailableError extends RustegonError {}
export class RateLimitedError extends RustegonError {}

/** RGN-5006 / 2003 / 1024 / 3006 (named after Java: `TimeoutError` would shadow the DOM name). */
export class RustegonTimeoutError extends RustegonError {}

export class RustegonServerError extends RustegonError {}

/**
 * An invalid argument detected before any I/O (README §5 class id `Argument`; .NET
 * ArgumentException, Java IllegalArgumentException). A `TypeError`, the JavaScript convention.
 */
export class InvalidArgumentError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * An operation on a closed client, cursor, session or transaction (README §5 class id
 * `InvalidState`; .NET ObjectDisposedException, Java IllegalStateException).
 */
export class InvalidStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

type ErrorClass =new (info: ErrorInfo, message: string, options?: ErrorOptions) => RustegonError;

/** errors-map.yaml class id → Node class (DIVERGENCES: the Node names end in `Error`). */
export const ERROR_CLASSES: ReadonlyMap<string, ErrorClass> = new Map<string, ErrorClass>([
  ['Base', RustegonError],
  ['Client', RustegonClientError],
  ['QuerySyntax', QuerySyntaxError],
  ['DuplicateKey', DuplicateKeyError],
  ['DocumentValidation', DocumentValidationError],
  ['TransactionConflict', TransactionConflictError],
  ['TransactionAborted', TransactionAbortedError],
  ['CommitOutcomeUnknown', CommitOutcomeUnknownError],
  ['Authentication', AuthenticationError],
  ['PasswordChangeRequired', PasswordChangeRequiredError],
  ['Authorization', AuthorizationError],
  ['Unavailable', UnavailableError],
  ['RateLimited', RateLimitedError],
  ['Timeout', RustegonTimeoutError],
  ['Server', RustegonServerError],
]);

/** The error for `info`, its class chosen by the code (unknown codes → the base class). */
export function errorFromInfo(info: ErrorInfo, message: string, cause?: unknown): RustegonError {
  const id = CODES.get(info.code)?.classId ?? UNKNOWN_CLASS_ID;
  return errorOfClass(id, info, message, cause);
}

export function errorOfClass(classId: string, info: ErrorInfo, message: string, cause?: unknown): RustegonError {
  const cls = ERROR_CLASSES.get(classId) ?? RustegonError;
  return new cls(info, message, cause === undefined ? undefined : { cause });
}

/**
 * The error of a failure without ErrorDetail, by gRPC status name (errors-map.yaml `transport`):
 * the fallback names the class as well as the code.
 */
export function errorFromTransport(statusName: string, message: string, cause?: unknown): RustegonError {
  const f = TRANSPORT.get(statusName) ?? TRANSPORT.get('default');
  if (f === undefined) {
    throw new Error('errors table has no default transport fallback (driver bug)');
  }
  return errorOfClass(f.classId, { code: f.code, name: codeName(f.code), retryable: f.retryable }, message, cause);
}

/** The errors-map.yaml class id of the most specific listed class `e` is an instance of. */
export function classIdOf(e: unknown): string | undefined {
  if (!(e instanceof RustegonError)) {
    return undefined;
  }
  for (let proto: object | null = Object.getPrototypeOf(e) as object | null; proto !== null; proto = Object.getPrototypeOf(proto) as object | null) {
    for (const [id, cls] of ERROR_CLASSES) {
      if (cls.prototype === proto) {
        return id;
      }
    }
  }
  return undefined;
}
