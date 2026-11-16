// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import * as grpc from '@grpc/grpc-js';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  AuthMechanism as PbAuthMechanism,
  AuthService,
  AuthenticateRequestSchema,
  AuthenticateResponseSchema,
  LogoutRequestSchema,
  type AuthSuccess,
  type AuthenticateResponse,
} from '../generated/rustegon/v1/auth_pb.js';
import { ScramSha256Client } from './scram.ts';
import { AuthenticationError, PasswordChangeRequiredError, RustegonError, clientInfo, InvalidArgumentError } from '../errors/errors.ts';
import { REQUEST_ID_HEADER, errorFromServiceError, isServiceError, newRequestId, pathOf, unaryCall } from '../transport/calls.ts';
import type { ResolvedSettings } from '../settings.ts';
import { DRIVER_NAME, DRIVER_VERSION } from '../version.ts';

/** A session token from a login; `toString` never shows it. */
class SessionToken {
  readonly token: string;
  readonly expiresAtMs: number | null;

  constructor(token: string, expiresAtMs: number | null) {
    this.token = token;
    this.expiresAtMs = expiresAtMs;
  }

  /** Refreshed 30 s before it expires, so a call never starts with a token about to lapse. */
  isExpiring(now: number): boolean {
    return this.expiresAtMs !== null && this.expiresAtMs - 30_000 <= now;
  }

  toString(): string {
    return 'SessionToken ‹redacted›';
  }
}

/**
 * Credentials on the wire (protocol.md §4): an API key is sent as `authorization: ApiKey …` on
 * every call; SCRAM-SHA-256 and X.509 log in once through `AuthService.Authenticate` and send
 * the session token as `authorization: Bearer …`. Concurrent first calls share one login.
 */
export class SessionAuthenticator {
  private readonly settings: ResolvedSettings;
  private login: Promise<SessionToken> | undefined;
  private current: SessionToken | undefined;

  constructor(settings: ResolvedSettings) {
    this.settings = settings;
    if (settings.authMechanism === 'SCRAM-SHA-256' && (settings.user === null || settings.password === null)) {
      // connstring.yaml user_without_password: the string may omit the password; the client
      // refuses the credential until it is given in code.
      throw new InvalidArgumentError('SCRAM-SHA-256 needs a user and a password (pass `password` in the options)');
    }
  }

  /** True when the credential logs in (an expired session can be cured by a new login). */
  get usesSessions(): boolean {
    return this.settings.authMechanism === 'SCRAM-SHA-256' || this.settings.authMechanism === 'X509';
  }

  /** The `authorization` header value for a call, logging in first when needed. */
  async authorization(client: grpc.Client, signal?: AbortSignal): Promise<string | undefined> {
    switch (this.settings.authMechanism) {
      case null:
        return undefined;
      case 'APIKEY':
        return `ApiKey ${this.settings.apiKey ?? ''}`;
      default:
        break;
    }
    if (this.login === undefined || (this.current?.isExpiring(Date.now()) ?? false)) {
      const login = this.doLogin(client);
      this.login = login;
      this.current = undefined;
      login.then(
        (t) => {
          if (this.login === login) {
            this.current = t;
          }
        },
        () => {
          // A failed login is not cached: the next call tries again.
          if (this.login === login) {
            this.login = undefined;
          }
        },
      );
    }
    const token = await raceAbort(this.login, signal);
    return `Bearer ${token.token}`;
  }

  /** Forgets the session of `authorization` (RGN-4005): the next call logs in again. */
  invalidate(authorization: string | undefined): void {
    if (this.current !== undefined && `Bearer ${this.current.token}` === authorization) {
      this.login = undefined;
      this.current = undefined;
    }
  }

  /** Best-effort `AuthService.Logout` of the current session. */
  async logout(client: grpc.Client): Promise<void> {
    const token = this.current;
    this.login = undefined;
    this.current = undefined;
    if (token === undefined) {
      return;
    }
    const md = new grpc.Metadata();
    md.set('authorization', `Bearer ${token.token}`);
    md.set(REQUEST_ID_HEADER, newRequestId());
    try {
      await unaryCall(client, AuthService.method.logout, create(LogoutRequestSchema), md, { deadline: Date.now() + 5_000 });
    } catch {
      // Best effort: the session expires on its own; closing must not fail because the server
      // is gone.
    }
  }

  private async doLogin(client: grpc.Client): Promise<SessionToken> {
    const md = new grpc.Metadata();
    md.set(REQUEST_ID_HEADER, newRequestId());
    const call = client.makeBidiStreamRequest(
      pathOf(AuthService.method.authenticate),
      (v: ReturnType<typeof create<typeof AuthenticateRequestSchema>>) => Buffer.from(toBinary(AuthenticateRequestSchema, v)),
      (b: Buffer) => fromBinary(AuthenticateResponseSchema, b),
      md,
      { deadline: Date.now() + this.settings.operationTimeoutMs },
    );
    const responses = call[Symbol.asyncIterator]() as AsyncIterator<AuthenticateResponse>;
    const next = async (expected: 'challenge' | 'success', failure: string): Promise<AuthenticateResponse> => {
      const r = await responses.next();
      if (r.done === true || r.value.step.case !== expected) {
        throw new AuthenticationError(clientInfo(4001), `authentication failed: ${failure}`);
      }
      return r.value;
    };
    const clientInfoMsg = {
      driverName: DRIVER_NAME,
      driverVersion: DRIVER_VERSION,
      application: this.settings.applicationName ?? '',
    };
    try {
      let success: AuthSuccess;
      if (this.settings.authMechanism === 'X509') {
        call.write(create(AuthenticateRequestSchema, { mechanism: PbAuthMechanism.X509, clientInfo: clientInfoMsg }));
        const done = await next('success', 'no X.509 success');
        success = done.step.value as AuthSuccess;
      } else {
        const scram = new ScramSha256Client(this.settings.user ?? '', this.settings.password ?? '');
        call.write(
          create(AuthenticateRequestSchema, {
            mechanism: PbAuthMechanism.SCRAM_SHA_256,
            payload: new TextEncoder().encode(scram.clientFirst),
            clientInfo: clientInfoMsg,
          }),
        );
        const challenge = await next('challenge', 'no SCRAM challenge');
        const clientFinal = await scram.processServerFirst(new TextDecoder().decode(challenge.step.value as Uint8Array));
        call.write(create(AuthenticateRequestSchema, { payload: new TextEncoder().encode(clientFinal) }));
        const done = await next('success', 'no SCRAM success');
        success = done.step.value as AuthSuccess;
        // Mutual authentication: the server proves it knows the stored key before the token is used.
        scram.verifyServerFinal(new TextDecoder().decode(success.serverFinal));
      }
      call.end();
      return this.accept(success);
    } catch (e) {
      call.cancel();
      if (isServiceError(e)) {
        throw errorFromServiceError(e);
      }
      if (e instanceof RustegonError) {
        throw e;
      }
      throw new AuthenticationError(clientInfo(4001), 'authentication failed', { cause: e });
    }
  }

  private accept(success: AuthSuccess): SessionToken {
    if (success.sessionToken.length === 0) {
      throw new AuthenticationError(clientInfo(4001), 'authentication failed: the server returned no session token');
    }
    if (success.mustChangePassword && !this.settings.allowPasswordChangeOnly) {
      throw new PasswordChangeRequiredError(
        clientInfo(4002),
        `The account '${success.user}' must change its password before other operations are allowed (set allowPasswordChangeOnly to change it through this client).`,
      );
    }
    const expires = success.expiresAtUnixMs > 0n ? Number(success.expiresAtUnixMs) : null;
    return new SessionToken(success.sessionToken, expires);
  }
}

/** `promise`, or the signal's reason as soon as it aborts (the shared login itself goes on). */
export function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) {
    return promise;
  }
  if (signal.aborted) {
    return Promise.reject(signal.reason as Error);
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason as Error);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e as Error);
      },
    );
  });
}
