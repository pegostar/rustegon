// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Client settings and the `rustegon://` connection string (DEC-014, connstring.yaml): the same
 * grammar, option keys, defaults and validation as the .NET and Java drivers. The options object
 * uses the connection-string option names, so `new RustegonClient(uri, options)` and
 * `new RustegonClient(options)` configure the same fields (node-driver.md §3).
 */

import { InvalidArgumentError } from './errors/errors.ts';

export type ReadConsistency = 'linearizable' | 'bounded_staleness' | 'follower';
export type WriteConcern = 'majority' | 'all';
export type AuthMechanism = 'SCRAM-SHA-256' | 'X509' | 'APIKEY';

export interface HostPort {
  readonly host: string;
  readonly port: number;
}

/** Options of a client: every key is optional; unset keys take the defaults of connstring.yaml. */
export interface ClientOptions {
  /** Seeds `host[:port]` (IPv6 in brackets); default `localhost:7700`. */
  hosts?: readonly (string | HostPort)[];
  /** SCRAM user (or informative with X.509). */
  user?: string;
  /** SCRAM password: prefer this option over the connection string (it is a secret). */
  password?: string;
  /** API key `rgn_…` (implies `authMechanism: 'APIKEY'`). */
  apiKey?: string;
  authMechanism?: AuthMechanism | 'API-KEY';
  /** Default database of `client.db()` and of transactions. */
  database?: string;
  /**
   * TLS on or off. Unset (ADR-034): off, unless a `tls*` option or `authMechanism: 'X509'` is
   * given; `false` together with a `tls*` option is an error.
   */
  tls?: boolean;
  tlsCaFile?: string;
  tlsServerName?: string;
  tlsCertificateFile?: string;
  tlsKeyFile?: string;
  applicationName?: string;
  connectTimeoutMs?: number;
  operationTimeoutMs?: number;
  readConsistency?: ReadConsistency;
  maxStalenessMs?: number;
  writeConcern?: WriteConcern;
  retryReads?: boolean;
  retryWrites?: boolean;
  maxRetries?: number;
  connectionsPerEndpoint?: number;
  /** PD-076: log in although the account must change its password (only `changePassword` works). */
  allowPasswordChangeOnly?: boolean;
}

/** Fully resolved settings (the `defaults` + `expect` keys of connstring.yaml, plus secrets). */
export interface ResolvedSettings {
  readonly hosts: readonly HostPort[];
  readonly user: string | null;
  readonly password: string | null;
  readonly apiKey: string | null;
  readonly database: string | null;
  readonly tls: boolean;
  readonly tlsCaFile: string | null;
  readonly tlsServerName: string | null;
  readonly tlsCertificateFile: string | null;
  readonly tlsKeyFile: string | null;
  readonly authMechanism: AuthMechanism | null;
  readonly applicationName: string | null;
  readonly connectTimeoutMs: number;
  readonly operationTimeoutMs: number;
  readonly readConsistency: ReadConsistency | null;
  readonly maxStalenessMs: number | null;
  readonly writeConcern: WriteConcern | null;
  readonly retryReads: boolean;
  readonly retryWrites: boolean;
  readonly maxRetries: number;
  readonly connectionsPerEndpoint: number;
  readonly allowPasswordChangeOnly: boolean;
}

export const DEFAULT_PORT = 7700;

/** The defaults of connstring.yaml (`tls` per ADR-034: off unless a TLS option asks for it). */
export const DEFAULTS: ResolvedSettings = Object.freeze({
  hosts: Object.freeze([Object.freeze({ host: 'localhost', port: DEFAULT_PORT })]),
  user: null,
  password: null,
  apiKey: null,
  database: null,
  tls: false,
  tlsCaFile: null,
  tlsServerName: null,
  tlsCertificateFile: null,
  tlsKeyFile: null,
  authMechanism: null,
  applicationName: null,
  connectTimeoutMs: 10_000,
  operationTimeoutMs: 30_000,
  readConsistency: null,
  maxStalenessMs: null,
  writeConcern: null,
  retryReads: true,
  retryWrites: true,
  maxRetries: 1,
  connectionsPerEndpoint: 2,
  allowPasswordChangeOnly: false,
});

/** Invalid settings or connection string; the message never quotes a value (it may be a secret). */
export class InvalidSettingsError extends InvalidArgumentError {
  constructor(reason: string) {
    super(`Invalid connection settings: ${reason}.`);
    this.name = 'InvalidSettingsError';
  }
}

const SCHEME = 'rustegon://';
const SRV_SCHEME = 'rustegon+srv://';

/** Parses a connection string into options (no defaults applied, nothing validated across keys). */
export function parseConnectionString(text: string): ClientOptions {
  if (typeof text !== 'string') {
    throw new InvalidSettingsError('the connection string must be a string');
  }
  if (text.startsWith(SRV_SCHEME)) {
    throw new InvalidSettingsError('DNS SRV seeds (rustegon+srv://) are not supported yet (PD-069)');
  }
  // connstring.yaml scheme_upper_case_is_not_accepted: the scheme is case-sensitive.
  if (!text.startsWith(SCHEME)) {
    throw new InvalidSettingsError('the connection string must start with rustegon://');
  }
  let rest = text.slice(SCHEME.length);
  const q = rest.indexOf('?');
  const query = q < 0 ? null : rest.slice(q + 1);
  rest = q < 0 ? rest : rest.slice(0, q);

  // The user information ends at the first '@'; a second one is an unescaped '@' of the password
  // (RFC 3986 needs %40) and is refused rather than guessed at.
  let at = rest.indexOf('@');
  if (at >= 0 && rest.indexOf('@', at + 1) >= 0) {
    throw new InvalidSettingsError("the user information contains a raw '@': percent-encode it as %40");
  }
  const slash = rest.indexOf('/', at + 1);
  let authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? null : rest.slice(slash + 1);

  const options: ClientOptions = {};
  at = authority.indexOf('@');
  if (at >= 0) {
    const userInfo = authority.slice(0, at);
    authority = authority.slice(at + 1);
    const colon = userInfo.indexOf(':');
    const user = decode(colon < 0 ? userInfo : userInfo.slice(0, colon), 'user');
    if (user.length === 0) {
      throw new InvalidSettingsError('empty user name');
    }
    options.user = user;
    if (colon >= 0) {
      options.password = decode(userInfo.slice(colon + 1), 'password');
    }
  }
  if (authority.length === 0) {
    throw new InvalidSettingsError('at least one host is required');
  }
  options.hosts = authority.split(',').map(parseHost);
  if (path !== null && path.length > 0) {
    if (path.includes('/')) {
      throw new InvalidSettingsError("the database name cannot contain '/'");
    }
    options.database = decode(path, 'database');
  }
  if (query !== null && query.length > 0) {
    applyQuery(options, query);
  }
  return options;
}

function applyQuery(options: ClientOptions, query: string): void {
  const seen = new Set<string>();
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq <= 0) {
      throw new InvalidSettingsError('every option needs a name and a value (name=value)');
    }
    const key = pair.slice(0, eq);
    const upper = key.toUpperCase();
    const value = decode(pair.slice(eq + 1), `option ${key}`);
    if (seen.has(upper)) {
      throw new InvalidSettingsError(`option '${key}' is repeated`);
    }
    seen.add(upper);
    switch (upper) {
      case 'TLS':
        options.tls = bool(key, value);
        break;
      case 'TLSCAFILE':
        options.tlsCaFile = nonEmpty(key, value);
        break;
      case 'TLSSERVERNAME':
        options.tlsServerName = nonEmpty(key, value);
        break;
      case 'TLSCERTIFICATEFILE':
        options.tlsCertificateFile = nonEmpty(key, value);
        break;
      case 'TLSKEYFILE':
        options.tlsKeyFile = nonEmpty(key, value);
        break;
      case 'AUTHMECHANISM':
        options.authMechanism = value.toUpperCase() as AuthMechanism;
        break;
      case 'APIKEY':
        options.apiKey = nonEmpty(key, value);
        break;
      case 'APPNAME':
        options.applicationName = nonEmpty(key, value);
        break;
      case 'CONNECTTIMEOUTMS':
        options.connectTimeoutMs = int(key, value, 1, 2_147_483_647);
        break;
      case 'OPERATIONTIMEOUTMS':
        options.operationTimeoutMs = int(key, value, 1, 2_147_483_647);
        break;
      case 'CONNECTIONSPERENDPOINT':
        options.connectionsPerEndpoint = int(key, value, 1, 64);
        break;
      case 'READCONSISTENCY':
        options.readConsistency = oneOf<ReadConsistency>(key, value, ['linearizable', 'bounded_staleness', 'follower']);
        break;
      case 'MAXSTALENESSMS':
        options.maxStalenessMs = int(key, value, 1, 2_147_483_647);
        break;
      case 'WRITECONCERN':
        options.writeConcern = oneOf<WriteConcern>(key, value, ['majority', 'all']);
        break;
      case 'RETRYREADS':
        options.retryReads = bool(key, value);
        break;
      case 'RETRYWRITES':
        options.retryWrites = bool(key, value);
        break;
      case 'MAXRETRIES':
        options.maxRetries = int(key, value, 0, 10);
        break;
      default:
        throw new InvalidSettingsError(`unknown option '${key}'`);
    }
  }
}

/**
 * Resolves options (from a connection string, an options object, or both: `overrides` win) into
 * validated settings. Every rule of connstring.yaml is checked here, before any I/O.
 */
export function resolveSettings(base: ClientOptions, overrides: ClientOptions = {}): ResolvedSettings {
  const o: ClientOptions = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (v !== undefined) {
      (o as Record<string, unknown>)[k] = v;
    }
  }
  const hosts = (o.hosts ?? DEFAULTS.hosts).map((h) => (typeof h === 'string' ? parseHost(h) : checkHostPort(h)));
  if (hosts.length === 0) {
    throw new InvalidSettingsError('at least one host is required');
  }

  const tlsOptions = [o.tlsCaFile, o.tlsServerName, o.tlsCertificateFile, o.tlsKeyFile];
  for (const v of tlsOptions) {
    if (v !== undefined && (typeof v !== 'string' || v.length === 0)) {
      throw new InvalidSettingsError('a tls option is empty');
    }
  }
  if ((o.tlsCertificateFile === undefined) !== (o.tlsKeyFile === undefined)) {
    throw new InvalidSettingsError('tlsCertificateFile and tlsKeyFile go together');
  }
  const mechanism = mechanismOf(o);
  // ADR-034: TLS is off by default; any tls* option or X.509 turns it on unless it is explicitly
  // off, and an explicit `tls=false` beside a tls* option is a contradiction, not a silent choice.
  const otherTls = tlsOptions.some((v) => v !== undefined);
  if (o.tls === false && otherTls) {
    throw new InvalidSettingsError('tls=false contradicts the other tls options');
  }
  if (o.tls === false && mechanism === 'X509') {
    throw new InvalidSettingsError('authMechanism=X509 needs TLS');
  }
  const tls = o.tls ?? (otherTls || mechanism === 'X509');

  if (o.readConsistency !== undefined && !['linearizable', 'bounded_staleness', 'follower'].includes(o.readConsistency)) {
    throw new InvalidSettingsError('unknown readConsistency');
  }
  if (o.writeConcern !== undefined && !['majority', 'all'].includes(o.writeConcern)) {
    throw new InvalidSettingsError('unknown writeConcern');
  }
  if (o.readConsistency === 'bounded_staleness' && o.maxStalenessMs === undefined) {
    throw new InvalidSettingsError('readConsistency=bounded_staleness needs maxStalenessMs');
  }
  const settings: ResolvedSettings = {
    hosts,
    user: o.user ?? null,
    password: o.password ?? null,
    apiKey: o.apiKey ?? null,
    database: o.database ?? null,
    tls,
    tlsCaFile: o.tlsCaFile ?? null,
    tlsServerName: o.tlsServerName ?? null,
    tlsCertificateFile: o.tlsCertificateFile ?? null,
    tlsKeyFile: o.tlsKeyFile ?? null,
    authMechanism: mechanism,
    applicationName: o.applicationName ?? null,
    connectTimeoutMs: intOption('connectTimeoutMs', o.connectTimeoutMs, DEFAULTS.connectTimeoutMs, 1, 2_147_483_647),
    operationTimeoutMs: intOption('operationTimeoutMs', o.operationTimeoutMs, DEFAULTS.operationTimeoutMs, 1, 2_147_483_647),
    readConsistency: o.readConsistency ?? null,
    maxStalenessMs: o.maxStalenessMs === undefined ? null : intOption('maxStalenessMs', o.maxStalenessMs, 0, 1, 2_147_483_647),
    writeConcern: o.writeConcern ?? null,
    retryReads: boolOption('retryReads', o.retryReads, DEFAULTS.retryReads),
    retryWrites: boolOption('retryWrites', o.retryWrites, DEFAULTS.retryWrites),
    maxRetries: intOption('maxRetries', o.maxRetries, DEFAULTS.maxRetries, 0, 10),
    connectionsPerEndpoint: intOption('connectionsPerEndpoint', o.connectionsPerEndpoint, DEFAULTS.connectionsPerEndpoint, 1, 64),
    allowPasswordChangeOnly: boolOption('allowPasswordChangeOnly', o.allowPasswordChangeOnly, false),
  };
  return settings;
}

/** The effective mechanism and the credential rules of connstring.yaml. */
function mechanismOf(o: ClientOptions): AuthMechanism | null {
  const m = o.authMechanism?.toUpperCase();
  const apiKey = o.apiKey;
  if (apiKey !== undefined && apiKey.length === 0) {
    throw new InvalidSettingsError("option 'apiKey' is empty");
  }
  switch (m) {
    case undefined:
      if (apiKey !== undefined) {
        if (o.user !== undefined) {
          throw new InvalidSettingsError('authMechanism=APIKEY needs apiKey=... and no user');
        }
        return 'APIKEY';
      }
      return o.user === undefined ? null : 'SCRAM-SHA-256';
    case 'APIKEY':
    case 'API-KEY':
      if (apiKey === undefined || o.user !== undefined) {
        throw new InvalidSettingsError('authMechanism=APIKEY needs apiKey=... and no user');
      }
      return 'APIKEY';
    case 'X509':
      if (o.password !== undefined || apiKey !== undefined) {
        throw new InvalidSettingsError('authMechanism=X509 takes no password or apiKey');
      }
      return 'X509';
    case 'SCRAM-SHA-256':
      if (apiKey !== undefined) {
        throw new InvalidSettingsError('apiKey is only valid with authMechanism=APIKEY');
      }
      return 'SCRAM-SHA-256';
    default:
      throw new InvalidSettingsError('unknown authMechanism');
  }
}

/** `host[:port]`, `[v6][:port]`; host names are lower-cased (connstring.yaml host_is_lowercased). */
export function parseHost(text: string): HostPort {
  if (text.length === 0) {
    throw new InvalidSettingsError('empty host');
  }
  let host: string;
  let portText: string | null = null;
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0) {
      throw new InvalidSettingsError('unterminated IPv6 literal');
    }
    host = text.slice(1, end);
    const after = text.slice(end + 1);
    if (after.length > 0) {
      if (!after.startsWith(':')) {
        throw new InvalidSettingsError('unexpected text after an IPv6 literal');
      }
      portText = after.slice(1);
    }
    if (!/^[0-9a-fA-F:.]+$/.test(host) || !host.includes(':')) {
      throw new InvalidSettingsError('invalid IPv6 literal');
    }
    host = host.toLowerCase();
  } else {
    const colon = text.indexOf(':');
    if (colon >= 0 && text.indexOf(':', colon + 1) >= 0) {
      throw new InvalidSettingsError('an IPv6 address must be in brackets');
    }
    host = colon < 0 ? text : text.slice(0, colon);
    portText = colon < 0 ? null : text.slice(colon + 1);
    // Same host characters as .NET and Java: DNS labels or IPv4 (letters, digits, '-', '_', '.').
    if (host.length === 0 || !/^[A-Za-z0-9._-]+$/.test(host)) {
      throw new InvalidSettingsError('invalid host name');
    }
    host = host.toLowerCase();
  }
  let port = DEFAULT_PORT;
  if (portText !== null) {
    if (!/^[0-9]{1,5}$/.test(portText)) {
      throw new InvalidSettingsError('the port must be a number in 1..65535');
    }
    port = Number(portText);
    if (port < 1 || port > 65_535) {
      throw new InvalidSettingsError('the port must be a number in 1..65535');
    }
  }
  return { host, port };
}

function checkHostPort(h: HostPort): HostPort {
  const parsed = parseHost(h.host.includes(':') ? `[${h.host}]` : h.host);
  if (!Number.isInteger(h.port) || h.port < 1 || h.port > 65_535) {
    throw new InvalidSettingsError('the port must be a number in 1..65535');
  }
  return { host: parsed.host, port: h.port };
}

/** The gRPC target of a host (`[v6]:port` for IPv6). */
export function authorityOf(h: HostPort): string {
  return h.host.includes(':') ? `[${h.host}]:${h.port}` : `${h.host}:${h.port}`;
}

/**
 * Strict UTF-8 percent-decoding: '+' stays a plus sign; malformed escapes, invalid UTF-8,
 * whitespace and control characters are errors (the decoded value is never quoted: it may be a
 * password).
 */
function decode(s: string, what: string): string {
  const bytes: number[] = [];
  const encoder = new TextEncoder();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x25) {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
        throw new InvalidSettingsError(`invalid percent-encoding in the ${what}`);
      }
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else if (c <= 0x20 || c === 0x7f) {
      throw new InvalidSettingsError(`whitespace or a control character in the ${what}`);
    } else {
      const cp = s.codePointAt(i) ?? c;
      const ch = String.fromCodePoint(cp);
      bytes.push(...encoder.encode(ch));
      i += ch.length - 1;
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    throw new InvalidSettingsError(`the ${what} is not valid percent-encoded UTF-8`);
  }
}

function nonEmpty(key: string, value: string): string {
  if (value.length === 0) {
    throw new InvalidSettingsError(`option '${key}' is empty`);
  }
  return value;
}

function bool(key: string, value: string): boolean {
  switch (value.toUpperCase()) {
    case 'TRUE':
      return true;
    case 'FALSE':
      return false;
    default:
      throw new InvalidSettingsError(`option '${key}' must be true or false`);
  }
}

function int(key: string, value: string, min: number, max: number): number {
  if (!/^[0-9]{1,10}$/.test(value)) {
    throw new InvalidSettingsError(`option '${key}' must be an integer in ${min}..${max}`);
  }
  const n = Number(value);
  if (n < min || n > max) {
    throw new InvalidSettingsError(`option '${key}' must be an integer in ${min}..${max}`);
  }
  return n;
}

function oneOf<T extends string>(key: string, value: string, allowed: readonly T[]): T {
  const v = value.toLowerCase();
  const found = allowed.find((a) => a === v);
  if (found === undefined) {
    throw new InvalidSettingsError(`unknown value of option '${key}'`);
  }
  return found;
}

function intOption(key: string, v: number | undefined, fallback: number, min: number, max: number): number {
  if (v === undefined) {
    return fallback;
  }
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new InvalidSettingsError(`option '${key}' must be an integer in ${min}..${max}`);
  }
  return v;
}

function boolOption(key: string, v: boolean | undefined, fallback: boolean): boolean {
  if (v === undefined) {
    return fallback;
  }
  if (typeof v !== 'boolean') {
    throw new InvalidSettingsError(`option '${key}' must be true or false`);
  }
  return v;
}

/** A copy without secrets, for logs and `inspect` (rule 9: secrets never logged). */
export function redactSettings(s: ResolvedSettings): Record<string, unknown> {
  return { ...s, password: s.password === null ? null : '‹redacted›', apiKey: s.apiKey === null ? null : '‹redacted›' };
}
