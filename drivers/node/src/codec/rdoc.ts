// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * RDoc v1 encoder and decoder (data-model.md §4), a port of the .NET RDocWriter / RDocReader.
 * The encoder always writes the canonical form (flag bit 0), byte for byte what the server's
 * `rustegon_doc::rdoc::encode` writes. The decoder rejects every malformed input with an
 * RDocError (never another exception) and normalizes non-canonical input when the canonical flag
 * is clear.
 */

import { RDocError } from '../errors/errors.ts';
import { Decimal128 } from './decimal128.ts';
import {
  Binary,
  Counter,
  INT64_MAX,
  INT64_MIN,
  MaxKey,
  MAX_KEY,
  MinKey,
  MIN_KEY,
  ObjectId,
  RDateTime,
  Timestamp,
  Uuid,
  binarySubtypeError,
  datetimeMs,
  datetimeOf,
  defineField,
  isDocument,
  type RDocument,
  type RValue,
} from './values.ts';
import { xxh3_64 } from './xxh3.ts';

const MAGIC = 0xd7;
const VERSION = 1;
const FLAG_CANONICAL = 0x01;
const HEADER_LENGTH = 7;
const MAX_DOCUMENT_SIZE = 16 * 1024 * 1024;
const MAX_DEPTH = 100;
const MAX_FIELD_NAME_LENGTH = 1024;
const CANONICAL_NAN_BITS = 0x7ff8000000000000n;

const MALFORMED = 1001;
const TOO_LARGE = 1002;
const TOO_DEEP = 1003;
const INVALID_FIELD_NAME = 1004;
const INVALID_VECTOR = 1040;

const T_NULL = 0x01;
const T_BOOL = 0x02;
const T_INT64 = 0x03;
const T_FLOAT64 = 0x04;
const T_DECIMAL = 0x05;
const T_STRING = 0x06;
const T_BINARY = 0x07;
const T_DATETIME = 0x08;
const T_TIMESTAMP = 0x09;
const T_OBJECTID = 0x0a;
const T_UUID = 0x0b;
const T_ARRAY = 0x0c;
const T_OBJECT = 0x0d;
const T_VECTOR = 0x0e;
const T_COUNTER = 0x0f;
const T_MINKEY = 0x10;
const T_MAXKEY = 0x11;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** The low 16 bits of xxh3_64(UTF-8 name), seed 0. */
export function nameHash16(name: string): number {
  return Number(xxh3_64(utf8Encoder.encode(name)) & 0xffffn);
}

/** Why `name` is not a valid field name (data-model.md §2.2), or undefined. */
export function fieldNameError(name: string, utf8Length: number): string | undefined {
  if (name.length === 0) {
    return 'empty field name';
  }
  if (utf8Length > MAX_FIELD_NAME_LENGTH) {
    return 'field name longer than 1024 bytes';
  }
  if (name.includes('\0')) {
    return 'field name contains NUL';
  }
  return name.startsWith('$') ? "field name starts with '$'" : undefined;
}

/** Strict UTF-8 bytes of `s`: a lone surrogate is an error (it has no UTF-8 form). */
export function utf8(s: string, fieldName: boolean): Uint8Array {
  if (LONE_SURROGATE.test(s)) {
    throw new RDocError(fieldName ? INVALID_FIELD_NAME : MALFORMED, 'string is not valid UTF-16 (lone surrogate)');
  }
  return utf8Encoder.encode(s);
}

function zigzag(v: bigint): bigint {
  return BigInt.asUintN(64, (v << 1n) ^ (v >> 63n));
}

function unzigzag(z: bigint): bigint {
  return BigInt.asIntN(64, (z >> 1n) ^ -(z & 1n));
}

// ---------------------------------------------------------------------------------- encoder

/**
 * Bytes are collected as chunks and concatenated once: containers carry their body length
 * before the body, so a child is encoded first and its header is written in front of it.
 */
class Chunks {
  readonly parts: Uint8Array[] = [];
  length = 0;

  push(b: Uint8Array): void {
    this.parts.push(b);
    this.length += b.length;
    if (this.length > MAX_DOCUMENT_SIZE) {
      throw new RDocError(TOO_LARGE, `document of more than ${MAX_DOCUMENT_SIZE} bytes`);
    }
  }

  byte(b: number): void {
    this.push(Uint8Array.of(b));
  }

  varint(v: number | bigint): void {
    let x = BigInt(v);
    const out: number[] = [];
    while (x >= 0x80n) {
      out.push(Number(x & 0x7fn) | 0x80);
      x >>= 7n;
    }
    out.push(Number(x));
    this.push(Uint8Array.from(out));
  }

  append(other: Chunks): void {
    for (const p of other.parts) {
      this.push(p);
    }
  }

  concat(): Uint8Array {
    const out = new Uint8Array(this.length);
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
}

function checkDepth(depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new RDocError(TOO_DEEP, `nesting deeper than ${MAX_DEPTH} levels`);
  }
}

function le(bytes: number, write: (view: DataView) => void): Uint8Array {
  const b = new Uint8Array(bytes);
  write(new DataView(b.buffer));
  return b;
}

function int64(v: bigint): bigint {
  if (v < INT64_MIN || v > INT64_MAX) {
    throw new RDocError(MALFORMED, `${v} is outside the int64 range`);
  }
  return v;
}

function writeVector(out: Chunks, xs: Float32Array): void {
  out.byte(T_VECTOR);
  out.varint(xs.length);
  out.push(
    le(4 * xs.length, (view) => {
      xs.forEach((x, i) => {
        if (!Number.isFinite(x)) {
          throw new RDocError(INVALID_VECTOR, 'vector element is not finite');
        }
        view.setFloat32(4 * i, x, true);
      });
    }),
  );
}

function writeValue(out: Chunks, v: RValue, depth: number): void {
  switch (typeof v) {
    case 'boolean':
      out.push(Uint8Array.of(T_BOOL, v ? 1 : 0));
      return;
    case 'bigint':
      out.byte(T_INT64);
      out.varint(zigzag(int64(v)));
      return;
    case 'number':
      out.byte(T_FLOAT64);
      out.push(
        le(8, (view) => {
          if (Number.isNaN(v)) {
            view.setBigUint64(0, CANONICAL_NAN_BITS, true);
          } else {
            view.setFloat64(0, v, true);
          }
        }),
      );
      return;
    case 'string': {
      const b = utf8(v, false);
      out.byte(T_STRING);
      out.varint(b.length);
      out.push(b);
      return;
    }
    case 'object':
      break;
    default:
      throw new RDocError(MALFORMED, `a ${typeof v} is not an RDoc value`);
  }
  if (v === null) {
    out.byte(T_NULL);
  } else if (Array.isArray(v)) {
    writeArray(out, v, depth + 1);
  } else if (v instanceof Float32Array) {
    writeVector(out, v);
  } else if (v instanceof Uint8Array || v instanceof Binary) {
    const [subtype, bytes] = v instanceof Binary ? [v.subtype, v.bytes] : [0, v];
    out.push(Uint8Array.of(T_BINARY, subtype));
    out.varint(bytes.length);
    out.push(new Uint8Array(bytes));
  } else if (v instanceof Date || v instanceof RDateTime) {
    out.byte(T_DATETIME);
    out.varint(zigzag(datetimeMs(v)));
  } else if (v instanceof Decimal128) {
    out.byte(T_DECIMAL);
    out.push(v.bytes);
  } else if (v instanceof ObjectId) {
    out.byte(T_OBJECTID);
    out.push(new Uint8Array(v.bytes));
  } else if (v instanceof Uuid) {
    out.byte(T_UUID);
    out.push(new Uint8Array(v.bytes));
  } else if (v instanceof Timestamp) {
    out.byte(T_TIMESTAMP);
    out.push(
      le(12, (view) => {
        view.setBigUint64(0, v.wall, true);
        view.setUint32(8, v.logical, true);
      }),
    );
  } else if (v instanceof Counter) {
    out.byte(T_COUNTER);
    out.varint(zigzag(int64(v.value)));
  } else if (v instanceof MinKey) {
    out.byte(T_MINKEY);
  } else if (v instanceof MaxKey) {
    out.byte(T_MAXKEY);
  } else if (isDocument(v)) {
    writeObject(out, v, depth + 1);
  } else {
    throw new RDocError(MALFORMED, `a ${(v as object).constructor.name} is not an RDoc value`);
  }
}

function writeArray(out: Chunks, items: RValue[], depth: number): void {
  checkDepth(depth);
  const body = new Chunks();
  const offsets = le(4 * items.length, (view) => {
    items.forEach((item, i) => {
      view.setUint32(4 * i, body.length, true);
      if ((item as RValue | undefined) === undefined) {
        throw new RDocError(MALFORMED, 'undefined is not an RDoc value');
      }
      writeValue(body, item, depth);
    });
  });
  out.byte(T_ARRAY);
  out.varint(items.length);
  out.varint(body.length);
  out.push(offsets);
  out.append(body);
}

interface IndexEntry {
  readonly hash: number;
  readonly name: Uint8Array;
  readonly offset: number;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) {
      return d;
    }
  }
  return a.length - b.length;
}

function writeObject(out: Chunks, doc: RDocument, depth: number): void {
  checkDepth(depth);
  const body = new Chunks();
  const entries: IndexEntry[] = [];
  for (const name of Object.keys(doc)) {
    const value = doc[name];
    if (value === undefined) {
      continue; // undefined fields are skipped (as JSON.stringify does)
    }
    const nameBytes = utf8(name, true);
    const error = fieldNameError(name, nameBytes.length);
    if (error !== undefined) {
      throw new RDocError(INVALID_FIELD_NAME, error);
    }
    entries.push({ hash: Number(xxh3_64(nameBytes) & 0xffffn), name: nameBytes, offset: body.length });
    body.varint(nameBytes.length);
    body.push(nameBytes);
    writeValue(body, value, depth);
  }
  // Index order (hash, name bytes) makes lookups a binary search and the bytes canonical.
  entries.sort((a, b) => a.hash - b.hash || compareBytes(a.name, b.name));
  out.byte(T_OBJECT);
  out.varint(entries.length);
  out.varint(body.length);
  out.push(
    le(6 * entries.length, (view) => {
      entries.forEach((e, i) => {
        view.setUint16(6 * i, e.hash, true);
        view.setUint32(6 * i + 2, e.offset, true);
      });
    }),
  );
  out.append(body);
}

/** Encodes a document as canonical RDoc v1 (RGN-1002 above 16 MiB, 1003 beyond 100 levels, 1004 bad names). */
export function encodeDocument(doc: RDocument): Uint8Array {
  if (!isDocument(doc)) {
    throw new RDocError(MALFORMED, 'a document must be a plain object');
  }
  const out = new Chunks();
  out.push(Uint8Array.of(MAGIC, VERSION, FLAG_CANONICAL, 0, 0, 0, 0));
  writeObject(out, doc, 1);
  const bytes = out.concat();
  new DataView(bytes.buffer).setUint32(3, bytes.length, true);
  return bytes;
}

/** Encodes one value in the RDoc value encoding: tag and payload, no header (`Value.rdoc_value`). */
export function encodeValue(v: RValue): Uint8Array {
  const out = new Chunks();
  writeValue(out, v, 0);
  return out.concat();
}

// ---------------------------------------------------------------------------------- decoder

function malformed(position: number, reason: string): RDocError {
  return new RDocError(MALFORMED, reason, position);
}

interface Field {
  readonly name: string;
  readonly value: RValue;
  readonly start: number;
  readonly nameAt: number;
  readonly nameLength: number;
}

class Decoder {
  private readonly buf: Uint8Array;
  private readonly view: DataView;
  private readonly strict: boolean;
  /** Position after the last item read. */
  next = 0;

  constructor(buf: Uint8Array, strict: boolean) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.strict = strict;
  }

  private checkedEnd(pos: number, length: number, end: number): number {
    const stop = pos + length;
    if (length < 0 || stop > end) {
      throw malformed(pos, 'length exceeds the enclosing value');
    }
    return stop;
  }

  private varint(pos: number, end: number): bigint {
    let v = 0n;
    for (let i = 0; i < 10; i++) {
      const p = pos + i;
      if (p >= end) {
        throw malformed(p, 'truncated varint');
      }
      const b = this.buf[p] ?? 0;
      if (i === 9 && b > 1) {
        throw malformed(p, 'varint overflows u64');
      }
      v |= BigInt(b & 0x7f) << BigInt(7 * i);
      if ((b & 0x80) === 0) {
        if (this.strict && i > 0 && b === 0) {
          throw malformed(p, 'non-minimal varint');
        }
        this.next = p + 1;
        return v;
      }
    }
    throw malformed(pos, 'varint too long');
  }

  private length(pos: number, end: number): number {
    const v = this.varint(pos, end);
    // Any length beyond the input cannot be satisfied; it also keeps the arithmetic exact.
    if (v > BigInt(this.buf.length)) {
      throw malformed(pos, 'length exceeds the enclosing value');
    }
    return Number(v);
  }

  private header(pos: number, end: number, entryLength: number): { count: number; tableAt: number; bodyAt: number; bodyEnd: number } {
    const count = this.length(pos, end);
    const bodyLength = this.length(this.next, end);
    const tableAt = this.next;
    const bodyAt = this.checkedEnd(tableAt, count * entryLength, end);
    const bodyEnd = this.checkedEnd(bodyAt, bodyLength, end);
    return { count, tableAt, bodyAt, bodyEnd };
  }

  private string(pos: number, end: number): { text: string; nameAt: number; length: number } {
    const length = this.length(pos, end);
    const nameAt = this.next;
    this.next = this.checkedEnd(nameAt, length, end);
    try {
      return { text: utf8Decoder.decode(this.buf.subarray(nameAt, nameAt + length)), nameAt, length };
    } catch {
      throw malformed(nameAt, 'invalid UTF-8');
    }
  }

  value(pos: number, end: number, depth: number): RValue {
    if (pos >= end) {
      throw malformed(pos, 'missing value');
    }
    const tag = this.buf[pos];
    const at = pos + 1;
    switch (tag) {
      case T_NULL:
        this.next = at;
        return null;
      case T_MINKEY:
        this.next = at;
        return MIN_KEY;
      case T_MAXKEY:
        this.next = at;
        return MAX_KEY;
      case T_BOOL:
        this.next = this.checkedEnd(at, 1, end);
        switch (this.buf[at]) {
          case 0:
            return false;
          case 1:
            return true;
          default:
            throw malformed(at, 'bool byte not 0 or 1');
        }
      case T_INT64:
        return unzigzag(this.varint(at, end));
      case T_DATETIME:
        return datetimeOf(unzigzag(this.varint(at, end)));
      case T_COUNTER:
        return new Counter(unzigzag(this.varint(at, end)));
      case T_FLOAT64: {
        this.next = this.checkedEnd(at, 8, end);
        const f = this.view.getFloat64(at, true);
        if (this.strict && Number.isNaN(f) && this.view.getBigUint64(at, true) !== CANONICAL_NAN_BITS) {
          throw malformed(at, 'non-canonical NaN');
        }
        return f;
      }
      case T_DECIMAL: {
        this.next = this.checkedEnd(at, 16, end);
        const { value, canonical } = Decimal128.fromBytes(this.buf.subarray(at, at + 16));
        if (this.strict && !canonical) {
          throw malformed(at, 'non-canonical decimal128');
        }
        return value;
      }
      case T_STRING:
        return this.string(at, end).text;
      case T_BINARY: {
        this.checkedEnd(at, 1, end);
        const subtype = this.buf[at] ?? 0;
        const length = this.length(at + 1, end);
        const dataAt = this.next;
        this.next = this.checkedEnd(dataAt, length, end);
        if (binarySubtypeError(subtype, length) !== undefined) {
          throw malformed(at, 'bad binary');
        }
        return new Binary(this.buf.slice(dataAt, dataAt + length), subtype);
      }
      case T_TIMESTAMP:
        this.next = this.checkedEnd(at, 12, end);
        return new Timestamp(this.view.getBigUint64(at, true), this.view.getUint32(at + 8, true));
      case T_OBJECTID:
        this.next = this.checkedEnd(at, 12, end);
        return new ObjectId(this.buf.subarray(at, at + 12));
      case T_UUID:
        this.next = this.checkedEnd(at, 16, end);
        return new Uuid(this.buf.subarray(at, at + 16));
      case T_VECTOR:
        return this.vector(at, end);
      case T_ARRAY:
        return this.array(at, end, depth + 1);
      case T_OBJECT:
        return this.object(at, end, depth + 1);
      default:
        throw malformed(pos, 'unknown type tag');
    }
  }

  private vector(pos: number, end: number): Float32Array {
    const dims = this.length(pos, end);
    const q = this.next;
    this.next = this.checkedEnd(q, 4 * dims, end);
    const v = new Float32Array(dims);
    for (let i = 0; i < dims; i++) {
      const x = this.view.getFloat32(q + 4 * i, true);
      if (!Number.isFinite(x)) {
        throw new RDocError(INVALID_VECTOR, 'non-finite vector element', q + 4 * i);
      }
      v[i] = x;
    }
    return v;
  }

  object(pos: number, end: number, depth: number): RDocument {
    checkDepth(depth);
    const h = this.header(pos, end, 6);
    // Each field takes at least 3 bytes (name length, one name byte, tag): bound the count
    // before allocating so a forged count cannot reserve huge arrays.
    if (h.count > (h.bodyEnd - h.bodyAt) / 3) {
      throw malformed(pos, 'field count exceeds the body');
    }
    const fields: Field[] = [];
    let q = h.bodyAt;
    for (let i = 0; i < h.count; i++) {
      const start = q - h.bodyAt;
      const name = this.string(q, h.bodyEnd);
      const error = fieldNameError(name.text, name.length);
      if (error !== undefined) {
        throw new RDocError(INVALID_FIELD_NAME, error, q);
      }
      const value = this.value(this.next, h.bodyEnd, depth);
      q = this.next;
      fields.push({ name: name.text, value, start, nameAt: name.nameAt, nameLength: name.length });
    }
    if (q !== h.bodyEnd) {
      throw malformed(q, 'object body length mismatch');
    }
    this.checkIndex(h.tableAt, fields);
    const doc: RDocument = {};
    for (const f of fields) {
      defineField(doc, f.name, f.value);
    }
    this.next = h.bodyEnd;
    return doc;
  }

  private checkIndex(tableAt: number, fields: Field[]): void {
    const byStart = new Map(fields.map((f) => [f.start, f]));
    let prev: Field | undefined;
    let prevHash = 0;
    for (let i = 0; i < fields.length; i++) {
      const at = tableAt + 6 * i;
      const hash = this.view.getUint16(at, true);
      const f = byStart.get(this.view.getUint32(at + 2, true));
      if (f === undefined) {
        throw malformed(at, 'index offset is not a field start');
      }
      const name = this.buf.subarray(f.nameAt, f.nameAt + f.nameLength);
      if (Number(xxh3_64(name) & 0xffffn) !== hash) {
        throw malformed(at, 'index hash mismatch');
      }
      if (prev !== undefined) {
        const c = prevHash !== hash ? prevHash - hash : compareBytes(this.buf.subarray(prev.nameAt, prev.nameAt + prev.nameLength), name);
        if (c === 0) {
          throw new RDocError(INVALID_FIELD_NAME, 'duplicate field name', at);
        }
        if (c > 0) {
          throw malformed(at, 'index not sorted');
        }
      }
      prev = f;
      prevHash = hash;
    }
  }

  array(pos: number, end: number, depth: number): RValue[] {
    checkDepth(depth);
    const h = this.header(pos, end, 4);
    if (h.count > h.bodyEnd - h.bodyAt) {
      throw malformed(pos, 'element count exceeds the body');
    }
    const items: RValue[] = [];
    let q = h.bodyAt;
    for (let i = 0; i < h.count; i++) {
      const at = h.tableAt + 4 * i;
      if (this.view.getUint32(at, true) !== q - h.bodyAt) {
        throw malformed(at, 'array offset mismatch');
      }
      items.push(this.value(q, h.bodyEnd, depth));
      q = this.next;
    }
    if (q !== h.bodyEnd) {
      throw malformed(q, 'array body length mismatch');
    }
    this.next = h.bodyEnd;
    return items;
  }
}

/** Checks the header; returns whether the canonical flag is set. */
export function isCanonicalFlagSet(bytes: Uint8Array): boolean {
  if (bytes.length < HEADER_LENGTH + 1) {
    throw malformed(bytes.length, 'truncated header');
  }
  if (bytes[0] !== MAGIC) {
    throw malformed(0, 'bad magic');
  }
  if (bytes[1] !== VERSION) {
    throw malformed(1, 'unsupported RDoc version');
  }
  const flags = bytes[2] ?? 0;
  if ((flags & ~FLAG_CANONICAL) !== 0) {
    throw malformed(2, 'unknown flag bits');
  }
  const total = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(3, true);
  if (total > MAX_DOCUMENT_SIZE) {
    throw new RDocError(TOO_LARGE, `document of ${total} bytes exceeds the ${MAX_DOCUMENT_SIZE}-byte limit`);
  }
  if (total !== bytes.length) {
    throw malformed(3, 'total_len does not match the input length');
  }
  return (flags & FLAG_CANONICAL) !== 0;
}

/** Decodes an RDoc v1 document (non-canonical input accepted only when the canonical flag is clear). */
export function decodeDocument(bytes: Uint8Array): RDocument {
  const d = new Decoder(bytes, isCanonicalFlagSet(bytes));
  if (bytes[HEADER_LENGTH] !== T_OBJECT) {
    throw malformed(HEADER_LENGTH, 'root is not an object');
  }
  const doc = d.object(HEADER_LENGTH + 1, bytes.length, 1);
  if (d.next !== bytes.length) {
    throw malformed(d.next, 'trailing bytes after the root object');
  }
  return doc;
}

/** Decodes one value of the RDoc value encoding (non-canonical forms accepted). */
export function decodeValue(bytes: Uint8Array): RValue {
  const d = new Decoder(bytes, false);
  const v = d.value(0, bytes.length, 0);
  if (d.next !== bytes.length) {
    throw malformed(d.next, 'trailing bytes after value');
  }
  return v;
}
