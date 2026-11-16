// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { createHash, createHmac, pbkdf2, randomInt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { AuthenticationError, clientInfo } from '../errors/errors.ts';
import { saslPrep, SaslPrepError } from './saslprep.ts';

const pbkdf2Async = promisify(pbkdf2);

/** gs2 header without channel binding (PD-074: no transport exposes the TLS exporter). */
export const GS2_HEADER = 'n,,';
/** RFC 7677 minimum; a lower count from the server is a downgrade attempt. */
export const MIN_ITERATIONS = 4096;
/** Upper bound so a hostile server cannot make the client spin for minutes. */
export const MAX_ITERATIONS = 10_000_000;
const MAX_MESSAGE_LENGTH = 4096;
const NONCE_LENGTH = 24;
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Client side of SCRAM-SHA-256 (RFC 5802 / RFC 7677) without channel binding, as the .NET and
 * Java drivers (scram/vectors.yaml). One instance per login attempt.
 */
export class ScramSha256Client {
  readonly #password: string;
  readonly #clientNonce: string;
  readonly #bare: string;
  #serverSignature: Buffer | undefined;

  /** @param options.clientNonce forces the nonce (test vectors only). */
  constructor(user: string, password: string, options?: { clientNonce?: string }) {
    this.#password = password;
    this.#clientNonce = options?.clientNonce ?? Array.from({ length: NONCE_LENGTH }, () => BASE62[randomInt(BASE62.length)]).join('');
    this.#bare = `n=${encodeSaslName(user)},r=${this.#clientNonce}`;
  }

  get clientFirst(): string {
    return GS2_HEADER + this.#bare;
  }

  /** Validates the server-first message and returns the client-final message with the proof. */
  async processServerFirst(serverFirst: string): Promise<string> {
    if (serverFirst.length > MAX_MESSAGE_LENGTH) {
      throw fail('server-first message too long');
    }
    const attrs = serverFirst.split(',');
    if (attrs.length !== 3) {
      throw fail('malformed server-first message');
    }
    const nonce = attr(attrs[0], 'r');
    const salt = decodeBase64(attr(attrs[1], 's'));
    const iterationText = attr(attrs[2], 'i');
    const iterations = /^[0-9]{1,9}$/.test(iterationText) ? Number(iterationText) : -1;
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
      throw fail('iteration count out of bounds');
    }
    if (!/^[\x21-\x2b\x2d-\x7e]+$/.test(nonce) || nonce.length <= this.#clientNonce.length || !nonce.startsWith(this.#clientNonce) || salt.length === 0) {
      throw fail('malformed server-first message');
    }
    let prepared: string;
    try {
      prepared = saslPrep(this.#password);
    } catch (e) {
      if (e instanceof SaslPrepError) {
        throw fail('the password is not valid SASLprep text');
      }
      throw e;
    }
    // Async PBKDF2 runs on the libuv pool: a high iteration count never blocks the event loop.
    const salted = await pbkdf2Async(Buffer.from(prepared, 'utf8'), salt, iterations, 32, 'sha256');
    const clientKey = hmac(salted, 'Client Key');
    const storedKey = createHash('sha256').update(clientKey).digest();
    const serverKey = hmac(salted, 'Server Key');
    salted.fill(0);

    const withoutProof = `c=${Buffer.from(GS2_HEADER, 'ascii').toString('base64')},r=${nonce}`;
    const authMessage = `${this.#bare},${serverFirst},${withoutProof}`;
    const signature = hmac(storedKey, authMessage);
    const proof = Buffer.alloc(clientKey.length);
    for (let i = 0; i < proof.length; i++) {
      proof[i] = (clientKey[i] ?? 0) ^ (signature[i] ?? 0);
    }
    clientKey.fill(0);
    this.#serverSignature = hmac(serverKey, authMessage);
    serverKey.fill(0);
    return `${withoutProof},p=${proof.toString('base64')}`;
  }

  /** Mutual authentication: the server must prove it knows the stored key. */
  verifyServerFinal(serverFinal: string): void {
    if (this.#serverSignature === undefined) {
      throw new Error('server-first has not been processed');
    }
    if (serverFinal.length > MAX_MESSAGE_LENGTH || !serverFinal.startsWith('v=')) {
      throw fail('server signature missing');
    }
    const sig = decodeBase64(serverFinal.slice(2));
    if (sig.length !== this.#serverSignature.length || !timingSafeEqual(sig, this.#serverSignature)) {
      throw fail('server signature mismatch');
    }
  }

  toString(): string {
    return 'ScramSha256Client ‹redacted›';
  }
}

/** RFC 5802 saslname: `=` → `=3D`, `,` → `=2C`. */
export function encodeSaslName(s: string): string {
  return s.replaceAll('=', '=3D').replaceAll(',', '=2C');
}

function hmac(key: Buffer, data: string | Buffer): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

function attr(part: string | undefined, key: string): string {
  if (part === undefined || part.length < 2 || part[0] !== key || part[1] !== '=') {
    throw fail('malformed SCRAM message');
  }
  return part.slice(2);
}

function decodeBase64(s: string): Buffer {
  // Buffer.from(…, 'base64') ignores invalid characters: validate strictly first.
  if (!BASE64.test(s)) {
    throw fail('malformed base64 in SCRAM message');
  }
  return Buffer.from(s, 'base64');
}

function fail(reason: string): AuthenticationError {
  return new AuthenticationError(clientInfo(4001), `authentication failed: ${reason}`);
}
