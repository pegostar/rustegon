// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { readFileSync } from 'node:fs';
import * as grpc from '@grpc/grpc-js';
import { authorityOf, type ResolvedSettings } from '../settings.ts';
import { InvalidArgumentError, UnavailableError, clientInfo } from '../errors/errors.ts';

/** One gRPC channel (HTTP/2 connection) and the calls in flight on it. */
export interface Slot {
  readonly client: grpc.Client;
  readonly target: string;
  inFlight: number;
}

/**
 * `connectionsPerEndpoint` channels per endpoint (node-driver.md §3). Every channel uses its own
 * subchannel pool: grpc-js shares one connection between clients with the same target and
 * options otherwise, which would turn the configured channels into one connection.
 */
export class ChannelPool {
  private readonly slots: Slot[] = [];
  private readonly connectTimeoutMs: number;

  constructor(settings: ResolvedSettings) {
    this.connectTimeoutMs = settings.connectTimeoutMs;
    const credentials = channelCredentials(settings);
    for (const host of settings.hosts) {
      const target = authorityOf(host);
      for (let i = 0; i < settings.connectionsPerEndpoint; i++) {
        const options: grpc.ChannelOptions = {
          'grpc.use_local_subchannel_pool': 1,
          'grpc.keepalive_time_ms': 30_000,
          'grpc.keepalive_timeout_ms': 10_000,
          'grpc.keepalive_permit_without_calls': 1,
          // PD-119 (as .NET and Java): a failed channel reconnects with backoff capped at 5 s.
          'grpc.initial_reconnect_backoff_ms': 100,
          'grpc.max_reconnect_backoff_ms': 5_000,
          'grpc.max_receive_message_length': 64 * 1024 * 1024,
          'grpc.max_send_message_length': 64 * 1024 * 1024,
          'grpc.primary_user_agent': 'rustegon-node',
        };
        if (settings.tlsServerName !== null) {
          options['grpc.ssl_target_name_override'] = settings.tlsServerName;
          options['grpc.default_authority'] = settings.tlsServerName;
        }
        this.slots.push({ client: new grpc.Client(target, credentials, options), target, inFlight: 0 });
      }
    }
  }

  /**
   * Picks a channel: power of two choices on calls in flight (dotnet-driver.md §3), avoiding the
   * channel whose call just failed when there is another one.
   */
  acquire(avoid?: Slot): Slot {
    const candidates = this.slots.length > 1 && avoid !== undefined ? this.slots.filter((s) => s !== avoid) : this.slots;
    const a = candidates[Math.floor(Math.random() * candidates.length)];
    const b = candidates[Math.floor(Math.random() * candidates.length)];
    if (a === undefined || b === undefined) {
      throw new Error('channel pool is empty (driver bug)');
    }
    return a.inFlight <= b.inFlight ? a : b;
  }

  /**
   * Waits until the slot's channel is connected, at most `connectTimeoutMs` (PD-081, as Java: the
   * TLS handshake is included). A channel in TRANSIENT_FAILURE returns at once so that the call
   * fails fast with UNAVAILABLE instead of waiting for the next reconnect.
   */
  async ensureConnected(slot: Slot, signal?: AbortSignal): Promise<void> {
    const channel = slot.client.getChannel();
    const deadline = Date.now() + this.connectTimeoutMs;
    for (;;) {
      const state = channel.getConnectivityState(true);
      if (state === grpc.connectivityState.READY || state === grpc.connectivityState.TRANSIENT_FAILURE) {
        return;
      }
      if (state === grpc.connectivityState.SHUTDOWN) {
        throw new UnavailableError({ ...clientInfo(3002), retryable: true }, 'the channel is shut down');
      }
      signal?.throwIfAborted();
      const changed = await new Promise<boolean>((resolve) => {
        channel.watchConnectivityState(state, deadline, (err?: Error) => resolve(err === undefined));
      });
      if (!changed) {
        throw new UnavailableError(
          { ...clientInfo(3002), retryable: true },
          `could not connect to ${slot.target} within ${this.connectTimeoutMs} ms`,
        );
      }
    }
  }

  close(): void {
    for (const s of this.slots) {
      s.client.close();
    }
  }

  get size(): number {
    return this.slots.length;
  }
}

function channelCredentials(settings: ResolvedSettings): grpc.ChannelCredentials {
  if (!settings.tls) {
    return grpc.credentials.createInsecure();
  }
  const read = (path: string | null, what: string): Buffer | null => {
    if (path === null) {
      return null;
    }
    try {
      return readFileSync(path);
    } catch (e) {
      throw new InvalidArgumentError(`cannot read the ${what} (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
    }
  };
  // Without tlsCaFile the system roots verify the server (Node's default CA store).
  return grpc.credentials.createSsl(
    read(settings.tlsCaFile, 'tlsCaFile'),
    read(settings.tlsKeyFile, 'tlsKeyFile'),
    read(settings.tlsCertificateFile, 'tlsCertificateFile'),
  );
}
