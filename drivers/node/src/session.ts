// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import type * as grpc from '@grpc/grpc-js';
import { CAUSALITY_TOKEN_HEADER } from './transport/calls.ts';
import { InvalidStateError } from './errors/errors.ts';

export interface SessionOptions {
  /** Send the last causality token on later calls (default true). */
  causalConsistency?: boolean;
}

/**
 * A causal-consistency session (R1: pass-through of the `rgn-causality-token` trailer, PD-069;
 * no server-side session). Pass it as `{ session }` in an operation's options.
 */
export class ClientSession {
  readonly causalConsistency: boolean;
  private token: string | null = null;
  private closed = false;

  /** @internal Created by `RustegonClient.startSession`. */
  constructor(options: SessionOptions = {}) {
    this.causalConsistency = options.causalConsistency ?? true;
  }

  /** The last causality token observed, or null. */
  get causalityToken(): string | null {
    return this.token;
  }

  /** @internal */
  tokenToSend(): string | undefined {
    if (this.closed) {
      throw new InvalidStateError('The session is closed.');
    }
    return this.causalConsistency && this.token !== null ? this.token : undefined;
  }

  /** @internal */
  observe(trailers: grpc.Metadata): void {
    const v = trailers.get(CAUSALITY_TOKEN_HEADER)[0];
    if (typeof v === 'string' && v.length > 0) {
      this.token = v;
    }
  }

  /** Ends the session (idempotent). */
  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}
