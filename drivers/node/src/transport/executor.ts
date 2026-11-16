// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import * as grpc from '@grpc/grpc-js';
import { setTimeout as sleep } from 'node:timers/promises';
import { randomInt } from 'node:crypto';
import type { DescMessage, DescMethod, MessageShape } from '@bufbuild/protobuf';
import { ChannelPool, type Slot } from './channel-pool.ts';
import { CAUSALITY_TOKEN_HEADER, REQUEST_ID_HEADER, errorFromServiceError, isServiceError, newRequestId, serverStreamCall, unaryCall } from './calls.ts';
import { SessionAuthenticator } from '../auth/session.ts';
import { InvalidStateError, RateLimitedError, RustegonError } from '../errors/errors.ts';
import type { ResolvedSettings } from '../settings.ts';
import type { ClientSession } from '../session.ts';

/** Retry class of an operation (retry.yaml R7). */
export type OperationKind = 'read' | 'write' | 'none';

export interface CallSpec {
  readonly kind: OperationKind;
  /** Operation timeout (one deadline for every attempt, R8); default `operationTimeoutMs`. */
  readonly timeoutMs?: number | undefined;
  readonly session?: ClientSession | undefined;
  readonly signal?: AbortSignal | undefined;
}

/** retry.yaml backoff: full jitter, base 10 ms, factor 2, cap 1 s. */
export const BACKOFF_BASE_MS = 10;
export const BACKOFF_CAP_MS = 1_000;

/** The backoff before retry number `attempt` (1-based): uniform in [0, min(cap, base·2^(n−1))]. */
export function backoffMs(attempt: number): number {
  const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1));
  return randomInt(Math.floor(ceiling) + 1);
}

/** Sleeps at least `ms` (timers may fire a little early on some platforms). */
export async function delayAtLeast(ms: number, signal?: AbortSignal): Promise<void> {
  const start = performance.now();
  let left = ms;
  while (left > 0) {
    await sleep(Math.ceil(left), undefined, { signal });
    left = ms - (performance.now() - start);
  }
}

/**
 * Runs gRPC calls with the driver's policy: authentication, request id, deadline, causality
 * token, error mapping and the retry rules R1–R8 of retry.yaml.
 */
export class OperationExecutor {
  readonly pool: ChannelPool;
  readonly auth: SessionAuthenticator;
  readonly settings: ResolvedSettings;
  private closed = false;

  constructor(settings: ResolvedSettings) {
    this.settings = settings;
    this.auth = new SessionAuthenticator(settings);
    this.pool = new ChannelPool(settings);
  }

  get isClosed(): boolean {
    return this.closed;
  }

  throwIfClosed(): void {
    if (this.closed) {
      throw new InvalidStateError('The client is closed.');
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    await this.auth.logout(this.pool.acquire().client);
    this.pool.close();
  }

  /** Logs in now (Client.Create: credentials are checked when the client connects). */
  async connect(signal?: AbortSignal): Promise<void> {
    await this.run({ kind: 'none', signal }, (slot) => this.auth.authorization(slot.client, signal));
  }

  async unary<I extends DescMessage, O extends DescMessage>(
    method: DescMethod & { input: I; output: O; methodKind: 'unary' },
    request: MessageShape<I>,
    call: CallSpec,
  ): Promise<MessageShape<O>> {
    return this.run(call, async (slot, md, options) => {
      const r = await unaryCall(slot.client, method, request, md, options, call.signal);
      call.session?.observe(r.trailers);
      return r.value;
    });
  }

  /** A server stream read to the end; never retried once a message arrived (R3). */
  async serverStream<I extends DescMessage, O extends DescMessage>(
    method: DescMethod & { input: I; output: O; methodKind: 'server_streaming' },
    request: MessageShape<I>,
    call: CallSpec,
  ): Promise<MessageShape<O>[]> {
    return this.run(call, async (slot, md, options, attempt) => {
      const received: MessageShape<O>[] = [];
      try {
        const trailers = await serverStreamCall(slot.client, method, request, md, options, received, call.signal);
        call.session?.observe(trailers);
        return received;
      } catch (e) {
        if (received.length > 0) {
          attempt.noRetry = true;
        }
        throw e;
      }
    });
  }

  private async run<T>(
    call: CallSpec,
    body: (slot: Slot, md: grpc.Metadata, options: grpc.CallOptions, attempt: { noRetry: boolean }) => Promise<T>,
  ): Promise<T> {
    this.throwIfClosed();
    call.signal?.throwIfAborted();
    // One id for every attempt: a resent write after a lost reply is deduplicated by the server
    // (protocol.md §5.1) instead of executing twice.
    const requestId = newRequestId();
    const deadline = Date.now() + (call.timeoutMs ?? this.settings.operationTimeoutMs);
    let retries = 0;
    let reauthenticated = false;
    let failed: Slot | undefined;
    for (;;) {
      const slot = this.pool.acquire(failed);
      let authorization: string | undefined;
      const attempt = { noRetry: false };
      let failure: RustegonError;
      slot.inFlight++;
      try {
        await this.pool.ensureConnected(slot, call.signal);
        authorization = await this.auth.authorization(slot.client, call.signal);
        const md = new grpc.Metadata();
        md.set(REQUEST_ID_HEADER, requestId);
        if (authorization !== undefined) {
          md.set('authorization', authorization);
        }
        const token = call.session?.tokenToSend();
        if (token !== undefined) {
          md.set(CAUSALITY_TOKEN_HEADER, token);
        }
        return await body(slot, md, { deadline }, attempt);
      } catch (e) {
        if (call.signal?.aborted === true) {
          // The caller's cancellation is reported with its own reason (errors-map.yaml header).
          throw call.signal.reason as Error;
        }
        if (isServiceError(e)) {
          failure = errorFromServiceError(e);
        } else if (e instanceof RustegonError) {
          // A failed login (already mapped) follows the same policy.
          failure = e;
        } else {
          throw e;
        }
      } finally {
        slot.inFlight--;
      }
      failed = slot;
      if (attempt.noRetry || !(await this.shouldRetry(call, failure, authorization, deadline, ++retries, reauthenticated))) {
        throw failure;
      }
      if (failure.code === 4005) {
        reauthenticated = true;
        retries--;
      }
    }
  }

  private async shouldRetry(
    call: CallSpec,
    failure: RustegonError,
    authorization: string | undefined,
    deadline: number,
    retry: number,
    reauthenticated: boolean,
  ): Promise<boolean> {
    if (failure.code === 4005) {
      // R5: an expired session is cured by a new login, once, outside the retry budget.
      if (reauthenticated || !this.auth.usesSessions) {
        return false;
      }
      this.auth.invalidate(authorization);
      return true;
    }
    const allowed = call.kind === 'read' ? this.settings.retryReads : call.kind === 'write' ? this.settings.retryWrites : false;
    if (!failure.retryable || !allowed || retry > this.settings.maxRetries) {
      return false;
    }
    let delay = backoffMs(retry);
    const after = failure instanceof RateLimitedError ? failure.info.retryAfterMs : undefined;
    if (after !== undefined && after > delay) {
      delay = after;
    }
    // R8: no retry once the backoff would pass the operation's single deadline.
    if (Date.now() + delay >= deadline) {
      return false;
    }
    await delayAtLeast(delay, call.signal);
    return true;
  }
}
