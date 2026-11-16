// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * The RDoc value model of the Node driver (data-model.md §2, PD-160).
 *
 * JavaScript values are used where the language has an exact equivalent: `null`, `boolean`,
 * `string`, `bigint` (int64), `number` (float64, always — `1` is written as float64 1.0, use
 * `1n` for int64), `Date` (datetime, ms), `Float32Array` (vector_f32), arrays and plain objects
 * (documents). The other types are the small classes below. Decoding gives back exactly these
 * forms, so decode → encode is byte-identical.
 *
 * Documents are plain objects: field order is insertion order, except that JavaScript always
 * enumerates integer-like keys ("1", "42") first — a documented limitation. Fields whose value
 * is `undefined` are skipped when encoding (as JSON.stringify does).
 */

import { RDocError } from '../errors/errors.ts';
import { Decimal128 } from './decimal128.ts';

export { Decimal128 };

const MALFORMED = 1001;

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}

function bytesOfHex(text: string, length: number, what: string): Uint8Array {
  if (text.length !== length * 2 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new RDocError(MALFORMED, `${what} must be ${length * 2} hexadecimal digits`);
  }
  return new Uint8Array(Buffer.from(text, 'hex'));
}

function copyExact(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length !== length) {
    throw new RDocError(MALFORMED, `${what} has exactly ${length} bytes`);
  }
  return new Uint8Array(bytes);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// data-model.md §2: 5 random bytes per process and a counter starting at a random value.
const processRandom = crypto.getRandomValues(new Uint8Array(5));
let oidCounter = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;

/** A 12-byte ObjectId (4 B seconds BE, 5 B per-process random, 3 B counter BE). */
export class ObjectId {
  readonly bytes: Uint8Array;

  constructor(value: Uint8Array | string) {
    this.bytes = typeof value === 'string' ? bytesOfHex(value, 12, 'an ObjectId') : copyExact(value, 12, 'an ObjectId');
  }

  /** A new id for the current time. */
  static generate(time: Date = new Date()): ObjectId {
    const b = new Uint8Array(12);
    new DataView(b.buffer).setUint32(0, Math.floor(time.getTime() / 1000) >>> 0);
    b.set(processRandom, 4);
    oidCounter = (oidCounter + 1) >>> 0;
    b[9] = (oidCounter >>> 16) & 0xff;
    b[10] = (oidCounter >>> 8) & 0xff;
    b[11] = oidCounter & 0xff;
    return new ObjectId(b);
  }

  toHexString(): string {
    return hexOf(this.bytes);
  }

  toString(): string {
    return this.toHexString();
  }

  toJSON(): string {
    return this.toHexString();
  }

  equals(other: unknown): boolean {
    return other instanceof ObjectId && equalBytes(this.bytes, other.bytes);
  }
}

/** A 16-byte UUID (RDoc type uuid, not binary subtype 4). */
export class Uuid {
  readonly bytes: Uint8Array;

  constructor(value: Uint8Array | string) {
    if (typeof value === 'string') {
      if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value)) {
        throw new RDocError(MALFORMED, 'a UUID is 8-4-4-4-12 hexadecimal digits');
      }
      this.bytes = bytesOfHex(value.replaceAll('-', ''), 16, 'a UUID');
    } else {
      this.bytes = copyExact(value, 16, 'a UUID');
    }
  }

  /** A random (version 4) UUID. */
  static random(): Uuid {
    return new Uuid(crypto.randomUUID());
  }

  toString(): string {
    const h = hexOf(this.bytes);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  toJSON(): string {
    return this.toString();
  }

  equals(other: unknown): boolean {
    return other instanceof Uuid && equalBytes(this.bytes, other.bytes);
  }
}

/** Binary data with its subtype (0 generic, 4 uuid with 16 bytes, 0x80–0xFF user defined). */
export class Binary {
  readonly bytes: Uint8Array;
  readonly subtype: number;

  constructor(bytes: Uint8Array, subtype = 0) {
    const error = binarySubtypeError(subtype, bytes.length);
    if (error !== undefined) {
      throw new RDocError(MALFORMED, error);
    }
    this.bytes = bytes;
    this.subtype = subtype;
  }
}

/** Why a subtype/length pair is not a valid binary value, or undefined. */
export function binarySubtypeError(subtype: number, length: number): string | undefined {
  if (!Number.isInteger(subtype) || subtype < 0 || subtype > 0xff) {
    return 'binary subtype is one byte';
  }
  if (subtype === 0 || subtype >= 0x80) {
    return undefined;
  }
  if (subtype === 4) {
    return length === 16 ? undefined : 'binary subtype 4 (uuid) needs 16 bytes';
  }
  return 'reserved binary subtype';
}

const U64_MAX = (1n << 64n) - 1n;

/** A hybrid timestamp: wall (u64) and logical (u32). */
export class Timestamp {
  readonly wall: bigint;
  readonly logical: number;

  constructor(wall: bigint, logical: number) {
    if (wall < 0n || wall > U64_MAX) {
      throw new RDocError(MALFORMED, 'timestamp wall is an unsigned 64-bit integer');
    }
    if (!Number.isInteger(logical) || logical < 0 || logical > 0xffffffff) {
      throw new RDocError(MALFORMED, 'timestamp logical is an unsigned 32-bit integer');
    }
    this.wall = wall;
    this.logical = logical;
  }

  toString(): string {
    return `${this.wall}.${this.logical}`;
  }
}

/** A document counter as read from the server (read-only projection; never accepted as JSON input). */
export class Counter {
  readonly value: bigint;

  constructor(value: bigint) {
    this.value = value;
  }
}

/** A datetime outside the range of a JavaScript `Date` (±8.64e15 ms); ms since the epoch. */
export class RDateTime {
  readonly ms: bigint;

  constructor(ms: bigint) {
    if (ms < INT64_MIN || ms > INT64_MAX) {
      throw new RDocError(MALFORMED, 'datetime outside the int64 range');
    }
    this.ms = ms;
  }
}

export class MinKey {}
export class MaxKey {}
export const MIN_KEY = new MinKey();
export const MAX_KEY = new MaxKey();

export const INT64_MIN = -(1n << 63n);
export const INT64_MAX = (1n << 63n) - 1n;

/** Largest |ms| a JavaScript `Date` represents. */
export const MAX_DATE_MS = 8.64e15;

/** A document: a plain object (see the module comment for the field-order caveat). */
export interface RDocument {
  [field: string]: RValue;
}

/** Every value the codec reads or writes (PD-160). */
export type RValue =
  | null
  | boolean
  | bigint
  | number
  | string
  | Date
  | RDateTime
  | Binary
  | Uint8Array
  | Decimal128
  | ObjectId
  | Uuid
  | Timestamp
  | Float32Array
  | Counter
  | MinKey
  | MaxKey
  | RValue[]
  | RDocument;

/** The data-model §2 type names. */
export type RDocTypeName =
  | 'null'
  | 'bool'
  | 'int64'
  | 'float64'
  | 'decimal128'
  | 'string'
  | 'binary'
  | 'datetime'
  | 'timestamp'
  | 'objectId'
  | 'uuid'
  | 'array'
  | 'object'
  | 'vector_f32'
  | 'counter'
  | 'minKey'
  | 'maxKey';

/** True for a plain object (prototype Object.prototype or null): a document. */
export function isDocument(v: unknown): v is RDocument {
  if (v === null || typeof v !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** The RDoc type of `v`, or undefined when `v` is not a value (undefined, a function, a Map, …). */
export function typeOf(v: unknown): RDocTypeName | undefined {
  switch (typeof v) {
    case 'boolean':
      return 'bool';
    case 'bigint':
      return 'int64';
    case 'number':
      return 'float64';
    case 'string':
      return 'string';
    case 'object':
      break;
    default:
      return undefined;
  }
  if (v === null) {
    return 'null';
  }
  if (Array.isArray(v)) {
    return 'array';
  }
  if (v instanceof Float32Array) {
    return 'vector_f32';
  }
  if (v instanceof Uint8Array || v instanceof Binary) {
    return 'binary';
  }
  if (v instanceof Date || v instanceof RDateTime) {
    return 'datetime';
  }
  if (v instanceof Decimal128) {
    return 'decimal128';
  }
  if (v instanceof ObjectId) {
    return 'objectId';
  }
  if (v instanceof Uuid) {
    return 'uuid';
  }
  if (v instanceof Timestamp) {
    return 'timestamp';
  }
  if (v instanceof Counter) {
    return 'counter';
  }
  if (v instanceof MinKey) {
    return 'minKey';
  }
  if (v instanceof MaxKey) {
    return 'maxKey';
  }
  return isDocument(v) ? 'object' : undefined;
}

/** Milliseconds of a datetime value (Date or RDateTime). */
export function datetimeMs(v: Date | RDateTime): bigint {
  if (v instanceof RDateTime) {
    return v.ms;
  }
  const ms = v.getTime();
  if (Number.isNaN(ms)) {
    throw new RDocError(MALFORMED, 'invalid Date');
  }
  return BigInt(ms);
}

/** A datetime value for `ms`: a Date when it fits, else RDateTime. */
export function datetimeOf(ms: bigint): Date | RDateTime {
  return ms >= -MAX_DATE_MS && ms <= MAX_DATE_MS ? new Date(Number(ms)) : new RDateTime(ms);
}

function binaryParts(v: Uint8Array | Binary): [number, Uint8Array] {
  return v instanceof Binary ? [v.subtype, v.bytes] : [0, v];
}

/**
 * Exact equality: same type and value; NaN equals NaN, -0 ≠ 0; datetimes by ms; documents
 * with the same fields in any order; vectors bit for bit.
 */
export function valueEquals(a: RValue, b: RValue): boolean {
  const t = typeOf(a);
  if (t === undefined || t !== typeOf(b)) {
    return false;
  }
  switch (t) {
    case 'float64':
      return Object.is(a, b);
    case 'null':
    case 'bool':
    case 'int64':
    case 'string':
      return a === b;
    case 'minKey':
    case 'maxKey':
      return true;
    case 'datetime':
      return datetimeMs(a as Date | RDateTime) === datetimeMs(b as Date | RDateTime);
    case 'decimal128':
    case 'objectId':
    case 'uuid':
      return (a as Decimal128 | ObjectId | Uuid).equals(b);
    case 'timestamp':
      return (a as Timestamp).wall === (b as Timestamp).wall && (a as Timestamp).logical === (b as Timestamp).logical;
    case 'counter':
      return (a as Counter).value === (b as Counter).value;
    case 'binary': {
      const [sa, ba] = binaryParts(a as Uint8Array | Binary);
      const [sb, bb] = binaryParts(b as Uint8Array | Binary);
      return sa === sb && equalBytes(ba, bb);
    }
    case 'vector_f32': {
      const va = a as Float32Array;
      const vb = b as Float32Array;
      return va.length === vb.length && va.every((x, i) => Object.is(x, vb[i]));
    }
    case 'array': {
      const xa = a as RValue[];
      const xb = b as RValue[];
      return xa.length === xb.length && xa.every((x, i) => valueEquals(x, xb[i] as RValue));
    }
    case 'object': {
      const da = a as RDocument;
      const db = b as RDocument;
      const ka = Object.keys(da).filter((k) => da[k] !== undefined);
      const kb = Object.keys(db).filter((k) => db[k] !== undefined);
      return ka.length === kb.length && ka.every((k) => Object.hasOwn(db, k) && valueEquals(da[k] as RValue, db[k] as RValue));
    }
  }
}

/** Adds a field to a decoded document without ever touching the prototype (`__proto__`). */
export function defineField(doc: RDocument, name: string, value: RValue): void {
  if (name === '__proto__') {
    Object.defineProperty(doc, name, { value, enumerable: true, writable: true, configurable: true });
  } else {
    doc[name] = value;
  }
}
