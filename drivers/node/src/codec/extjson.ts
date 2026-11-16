// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Extended JSON (data-model.md §2 notes, conformance README §3), a port of the .NET
 * RDocJsonWriter / RDocJsonReader / FloatText / DateTimeText. Canonical mode writes int64 as a
 * plain number up to 2^53 and float64 as a number with a fraction or exponent (the Rust `{:?}`
 * layout); extended mode wraps every int64 (`$int64`) and finite float64 (`$float`).
 */

import { RDocError } from '../errors/errors.ts';
import { Decimal128 } from './decimal128.ts';
import { fieldNameError, utf8 } from './rdoc.ts';
import {
  Binary,
  Counter,
  MAX_KEY,
  MaxKey,
  MIN_KEY,
  MinKey,
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

const MALFORMED = 1001;
const TOO_DEEP = 1003;
const INVALID_FIELD_NAME = 1004;
const INVALID_VECTOR = 1040;
const MAX_SAFE = 1n << 53n;

// ------------------------------------------------------------------------------ float text

/**
 * Rust `{:?}` layout of the shortest round-trip digits: plain notation for 1e-4 ≤ |x| < 1e16
 * (always with a fraction, `1.0`), else `d.ddde<exp>`.
 */
function layout(shortest: string, exponential: boolean): string {
  const negative = shortest.startsWith('-');
  let s = negative ? shortest.slice(1) : shortest;
  let exp = 0;
  const e = s.search(/[eE]/);
  if (e >= 0) {
    exp = Number(s.slice(e + 1));
    s = s.slice(0, e);
  }
  const point = s.indexOf('.');
  const digits = point < 0 ? s : s.slice(0, point) + s.slice(point + 1);
  const intLength = point < 0 ? s.length : point;
  // value = digits × 10^(exp + intLength − digits.length); strip zeros on both sides.
  let e10 = exp + intLength - digits.length;
  let d = digits.replace(/^0+/, '');
  const trimmed = d.length;
  d = d.replace(/0+$/, '');
  e10 += trimmed - d.length;
  const sign = negative ? '-' : '';
  if (d.length === 0) {
    return `${sign}0.0`;
  }
  if (exponential) {
    return `${sign}${d[0] ?? ''}${d.length > 1 ? '.' + d.slice(1) : ''}e${e10 + d.length - 1}`;
  }
  if (e10 >= 0) {
    return `${sign}${d}${'0'.repeat(e10)}.0`;
  }
  const pointAt = d.length + e10;
  if (pointAt > 0) {
    return `${sign}${d.slice(0, pointAt)}.${d.slice(pointAt)}`;
  }
  return `${sign}0.${'0'.repeat(-pointAt)}${d}`;
}

/** Text of a finite float64. */
export function formatFloat64(x: number): string {
  const abs = Math.abs(x);
  // ECMAScript Number→String gives the shortest round-trip digits, as .NET "R".
  return layout(Object.is(x, -0) ? '-0' : String(x), abs !== 0 && (abs < 1e-4 || abs >= 1e16));
}

const F32_MIN_PLAIN = Math.fround(1e-4);
const F32_PLAIN_LIMIT = Math.fround(1e16);

/** Text of a finite float32 (vector element): the shortest digits that read back to the same float32. */
export function formatFloat32(x: number): string {
  const abs = Math.abs(x);
  let shortest = String(x);
  // shortcut: picks the nearest p-digit decimal for the smallest p that round-trips; at a power of
  // two this can differ from Ryu's choice in the last digit (never seen in the vectors); port a
  // float32 Ryu if a cross-driver difference shows up.
  for (let p = 1; p <= 9; p++) {
    const candidate = Number(x.toPrecision(p));
    if (Math.fround(candidate) === x) {
      shortest = String(candidate);
      break;
    }
  }
  return layout(Object.is(x, -0) ? '-0' : shortest, abs !== 0 && (abs < F32_MIN_PLAIN || abs >= F32_PLAIN_LIMIT));
}

// ------------------------------------------------------------------------------ datetime text

const MS_PER_DAY = 86_400_000n;
// Days between 0000-03-01 and 1970-01-01 (Hinnant's epoch shift).
const EPOCH_SHIFT = 719_468;
const DAYS_PER_ERA = 146_097;

function floorDiv(a: number, b: number): number {
  return Math.floor(a / b);
}

function civilFromDays(days: number): [number, number, number] {
  const z = days + EPOCH_SHIFT;
  const era = floorDiv(z, DAYS_PER_ERA);
  const doe = z - era * DAYS_PER_ERA;
  const yoe = Math.trunc((doe - Math.trunc(doe / 1460) + Math.trunc(doe / 36_524) - Math.trunc(doe / 146_096)) / 365);
  const doy = doe - (365 * yoe + Math.trunc(yoe / 4) - Math.trunc(yoe / 100));
  const mp = Math.trunc((5 * doy + 2) / 153);
  const d = doy - Math.trunc((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  const y = yoe + era * 400;
  return [m <= 2 ? y + 1 : y, m, d];
}

function daysFromCivil(year: bigint, m: number, d: number): bigint {
  const y = m <= 2 ? year - 1n : year;
  const era = (y >= 0n ? y : y - 399n) / 400n;
  const yoe = Number(y - era * 400n);
  const mp = m > 2 ? m - 3 : m + 9;
  const doy = Math.trunc((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.trunc(yoe / 4) - Math.trunc(yoe / 100) + doy;
  return era * BigInt(DAYS_PER_ERA) + BigInt(doe - EPOCH_SHIFT);
}

const pad = (n: number, width: number): string => String(n).padStart(width, '0');

/** `YYYY-MM-DDTHH:MM:SS.mmmZ`, expanded `±YYYYYY` outside 0000–9999. */
export function formatDateTime(ms: bigint): string {
  let days = ms / MS_PER_DAY;
  let rem = ms % MS_PER_DAY;
  if (rem < 0n) {
    days -= 1n;
    rem += MS_PER_DAY;
  }
  const [y, mo, d] = civilFromDays(Number(days));
  const r = Number(rem);
  const year = y >= 0 && y <= 9999 ? pad(y, 4) : (y < 0 ? '-' : '+') + pad(Math.abs(y), 6);
  return `${year}-${pad(mo, 2)}-${pad(d, 2)}T${pad(Math.trunc(r / 3_600_000), 2)}:${pad(Math.trunc(r / 60_000) % 60, 2)}:${pad(Math.trunc(r / 1000) % 60, 2)}.${pad(r % 1000, 3)}Z`;
}

function daysInMonth(y: bigint, m: number): number {
  if (m === 2) {
    return (y % 4n === 0n && y % 100n !== 0n) || y % 400n === 0n ? 29 : 28;
  }
  return m === 4 || m === 6 || m === 9 || m === 11 ? 30 : 31;
}

/** Parses the `$date` text (ms precision at most, `Z` only); undefined when invalid or out of range. */
export function parseDateTime(s: string): bigint | undefined {
  const m = /^(?:([+-])(\d{6,12})|(\d{4}))-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(s);
  if (m === null) {
    return undefined;
  }
  const year = m[2] !== undefined ? BigInt(m[2]) * (m[1] === '-' ? -1n : 1n) : BigInt(m[3] ?? '0');
  const [month, day, hour, minute, second] = [m[4], m[5], m[6], m[7], m[8]].map(Number) as [number, number, number, number, number];
  const millis = m[9] === undefined ? 0 : Number(m[9].padEnd(3, '0'));
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  const total = daysFromCivil(year, month, day) * MS_PER_DAY + BigInt(hour * 3_600_000 + minute * 60_000 + second * 1000 + millis);
  return total < -(1n << 63n) || total > (1n << 63n) - 1n ? undefined : total;
}

// ------------------------------------------------------------------------------ writer

function writeString(s: string): string {
  let out = '"';
  for (const c of s) {
    switch (c) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      default:
        out += c < ' ' ? '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0') : c;
    }
  }
  return out + '"';
}

const wrap = (key: string, text: string): string => `{"${key}":"${text}"}`;

function writeValue(v: RValue, extended: boolean): string {
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'bigint':
      return !extended && (v < 0n ? -v : v) <= MAX_SAFE ? v.toString() : wrap('$int64', v.toString());
    case 'number':
      if (Number.isNaN(v)) {
        return wrap('$float', 'NaN');
      }
      if (!Number.isFinite(v)) {
        return wrap('$float', v > 0 ? 'Infinity' : '-Infinity');
      }
      return extended ? wrap('$float', formatFloat64(v)) : formatFloat64(v);
    case 'string':
      return writeString(v);
    case 'object':
      break;
    default:
      throw new RDocError(MALFORMED, `a ${typeof v} has no JSON form`);
  }
  if (v === null) {
    return 'null';
  }
  if (Array.isArray(v)) {
    return '[' + v.map((x) => writeValue(x, extended)).join(',') + ']';
  }
  if (v instanceof Float32Array) {
    return '{"$vector":[' + Array.from(v, formatFloat32).join(',') + ']}';
  }
  if (v instanceof Uint8Array || v instanceof Binary) {
    const [subtype, bytes] = v instanceof Binary ? [v.subtype, v.bytes] : [0, v];
    const base64 = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
    return `{"$binary":{"base64":"${base64}","subType":"${subtype.toString(16).padStart(2, '0')}"}}`;
  }
  if (v instanceof Date || v instanceof RDateTime) {
    return wrap('$date', formatDateTime(datetimeMs(v)));
  }
  if (v instanceof Decimal128) {
    return wrap('$decimal', v.toString());
  }
  if (v instanceof ObjectId) {
    return wrap('$oid', v.toHexString());
  }
  if (v instanceof Uuid) {
    return wrap('$uuid', v.toString());
  }
  if (v instanceof Timestamp) {
    return wrap('$ts', v.toString());
  }
  if (v instanceof Counter) {
    return `{"$counter":${v.value}}`;
  }
  if (v instanceof MinKey) {
    return '{"$minKey":1}';
  }
  if (v instanceof MaxKey) {
    return '{"$maxKey":1}';
  }
  if (isDocument(v)) {
    const parts: string[] = [];
    for (const k of Object.keys(v)) {
      const x = v[k];
      if (x !== undefined) {
        parts.push(writeString(k) + ':' + writeValue(x, extended));
      }
    }
    return '{' + parts.join(',') + '}';
  }
  throw new RDocError(MALFORMED, `a ${(v as object).constructor.name} has no JSON form`);
}

/** Canonical (default) or extended JSON text of a value; compact, field order kept. */
export function toExtJson(v: RValue, options?: { extended?: boolean }): string {
  return writeValue(v, options?.extended === true);
}

// ------------------------------------------------------------------------------ reader

class JsonReader {
  private readonly s: string;
  pos = 0;

  constructor(s: string) {
    this.s = s;
  }

  error(reason: string): RDocError {
    return new RDocError(MALFORMED, reason, this.pos);
  }

  private peek(): string | undefined {
    return this.s[this.pos];
  }

  ws(): void {
    while (this.pos < this.s.length && ' \t\n\r'.includes(this.s[this.pos] ?? '')) {
      this.pos++;
    }
  }

  get done(): boolean {
    return this.pos === this.s.length;
  }

  private eat(c: string): void {
    this.ws();
    if (this.peek() !== c) {
      throw this.error(`expected '${c}'`);
    }
    this.pos++;
  }

  private literal<T extends RValue>(word: string, v: T): T {
    if (!this.s.startsWith(word, this.pos)) {
      throw this.error('invalid literal');
    }
    this.pos += word.length;
    return v;
  }

  value(depth: number): RValue {
    this.ws();
    const c = this.peek();
    switch (c) {
      case '{':
        return this.object(depth + 1);
      case '[':
        return this.array(depth + 1);
      case '"':
        return this.string();
      case 't':
        return this.literal('true', true);
      case 'f':
        return this.literal('false', false);
      case 'n':
        return this.literal('null', null);
      default:
        if (c !== undefined && (c === '-' || (c >= '0' && c <= '9'))) {
          return this.numberValue(this.scanNumber());
        }
        throw this.error('expected a value');
    }
  }

  private static checkDepth(depth: number): void {
    if (depth > 100) {
      throw new RDocError(TOO_DEEP, 'nesting deeper than 100 levels');
    }
  }

  private array(depth: number): RValue[] {
    JsonReader.checkDepth(depth);
    this.pos++;
    const items: RValue[] = [];
    this.ws();
    if (this.peek() === ']') {
      this.pos++;
      return items;
    }
    for (;;) {
      items.push(this.value(depth));
      this.ws();
      const c = this.peek();
      this.pos++;
      if (c === ']') {
        return items;
      }
      if (c !== ',') {
        this.pos--;
        throw this.error("expected ',' or ']'");
      }
    }
  }

  private object(depth: number): RValue {
    JsonReader.checkDepth(depth);
    this.pos++;
    const doc: RDocument = {};
    let count = 0;
    this.ws();
    if (this.peek() === '}') {
      this.pos++;
      return doc;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== '"') {
        throw this.error('expected a field name');
      }
      const name = this.string();
      this.eat(':');
      if (count === 0 && name.startsWith('$')) {
        // A `$` name is legal only as the single key of an extended-JSON wrapper.
        const w = this.wrapper(name);
        this.eat('}');
        return w;
      }
      const nameError = fieldNameError(name, utf8(name, true).length);
      if (nameError !== undefined) {
        throw new RDocError(INVALID_FIELD_NAME, nameError, this.pos);
      }
      const v = this.value(depth);
      if (Object.hasOwn(doc, name)) {
        throw new RDocError(INVALID_FIELD_NAME, 'duplicate field name', this.pos);
      }
      defineField(doc, name, v);
      count++;
      this.ws();
      const c = this.peek();
      this.pos++;
      if (c === '}') {
        return doc;
      }
      if (c !== ',') {
        this.pos--;
        throw this.error("expected ',' or '}'");
      }
    }
  }

  string(): string {
    this.pos++;
    let out = '';
    for (;;) {
      const start = this.pos;
      while (this.pos < this.s.length) {
        const c = this.s[this.pos] ?? '';
        if (c === '"' || c === '\\' || c < ' ') {
          break;
        }
        this.pos++;
      }
      out += this.s.slice(start, this.pos);
      const c = this.peek();
      if (c === '"') {
        this.pos++;
        return out;
      }
      if (c === '\\') {
        this.pos++;
        out += this.escape();
      } else if (c === undefined) {
        throw this.error('unterminated string');
      } else {
        throw this.error('control character in string');
      }
    }
  }

  private escape(): string {
    const c = this.peek();
    if (c === undefined) {
      throw this.error('unterminated escape');
    }
    this.pos++;
    switch (c) {
      case '"':
      case '\\':
      case '/':
        return c;
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case 'u': {
        const hi = this.hex4();
        if (hi >= 0xd800 && hi < 0xdc00) {
          if (!this.s.startsWith('\\u', this.pos)) {
            throw this.error('lone surrogate');
          }
          this.pos += 2;
          const lo = this.hex4();
          if (lo < 0xdc00 || lo >= 0xe000) {
            throw this.error('lone surrogate');
          }
          return String.fromCharCode(hi, lo);
        }
        if (hi >= 0xdc00 && hi < 0xe000) {
          throw this.error('lone surrogate');
        }
        return String.fromCharCode(hi);
      }
      default:
        throw this.error('invalid escape');
    }
  }

  private hex4(): number {
    const t = this.s.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(t)) {
      throw this.error('bad \\u escape');
    }
    this.pos += 4;
    return parseInt(t, 16);
  }

  scanNumber(): { text: string; integral: boolean } {
    const start = this.pos;
    if (this.peek() === '-') {
      this.pos++;
    }
    const intStart = this.pos;
    const n = this.digits();
    if (n === 0 || (n > 1 && this.s[intStart] === '0')) {
      throw this.error('invalid number');
    }
    let integral = true;
    if (this.peek() === '.') {
      this.pos++;
      integral = false;
      if (this.digits() === 0) {
        throw this.error('invalid number fraction');
      }
    }
    if (this.peek() === 'e' || this.peek() === 'E') {
      this.pos++;
      integral = false;
      if (this.peek() === '+' || this.peek() === '-') {
        this.pos++;
      }
      if (this.digits() === 0) {
        throw this.error('invalid number exponent');
      }
    }
    return { text: this.s.slice(start, this.pos), integral };
  }

  private digits(): number {
    const from = this.pos;
    while (this.pos < this.s.length && (this.s[this.pos] ?? '') >= '0' && (this.s[this.pos] ?? '') <= '9') {
      this.pos++;
    }
    return this.pos - from;
  }

  private numberValue(n: { text: string; integral: boolean }): RValue {
    if (n.integral) {
      const i = BigInt(n.text);
      if (i >= -(1n << 63n) && i < 1n << 63n) {
        return i;
      }
    }
    // ECMAScript number parsing is correctly rounded and overflows to infinity, which plain JSON
    // cannot mean, so it is rejected.
    const f = Number(n.text);
    if (!Number.isFinite(f)) {
      throw this.error('number outside the float64 range');
    }
    return f;
  }

  private wrapperString(): string {
    this.ws();
    if (this.peek() !== '"') {
      throw this.error('expected a string');
    }
    return this.string();
  }

  private wrapper(key: string): RValue {
    const at = this.pos;
    const bad = (reason: string): RDocError => new RDocError(MALFORMED, `${key}: ${reason}`, at);
    switch (key) {
      case '$int64': {
        const s = this.wrapperString();
        if (!/^[+-]?\d+$/.test(s)) {
          throw bad('not an int64');
        }
        const i = BigInt(s);
        if (i < -(1n << 63n) || i >= 1n << 63n) {
          throw bad('not an int64');
        }
        return i;
      }
      case '$float':
        return floatWrapper(this.wrapperString(), bad);
      case '$decimal': {
        const d = Decimal128.tryParse(this.wrapperString());
        if (typeof d === 'string') {
          throw bad('not an exact decimal128');
        }
        return d;
      }
      case '$date': {
        const ms = parseDateTime(this.wrapperString());
        if (ms === undefined) {
          throw bad('invalid $date (expected YYYY-MM-DDTHH:MM:SS.mmmZ)');
        }
        return datetimeOf(ms);
      }
      case '$oid': {
        const s = this.wrapperString();
        if (!/^[0-9a-fA-F]{24}$/.test(s)) {
          throw bad('objectId must be 24 hex digits');
        }
        return new ObjectId(s);
      }
      case '$uuid': {
        const s = this.wrapperString();
        if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s)) {
          throw bad('expected 8-4-4-4-12 hex');
        }
        return new Uuid(s);
      }
      case '$ts': {
        const m = /^(\d+)\.(\d+)$/.exec(this.wrapperString());
        if (m === null) {
          throw bad('expected wall.logical');
        }
        const wall = BigInt(m[1] ?? '');
        const logical = BigInt(m[2] ?? '');
        if (wall >= 1n << 64n) {
          throw bad('wall out of range');
        }
        if (logical > 0xffffffffn) {
          throw bad('logical out of range');
        }
        return new Timestamp(wall, Number(logical));
      }
      case '$binary':
        return this.binary();
      case '$vector':
        return this.vector();
      case '$minKey':
      case '$maxKey': {
        this.ws();
        const c = this.peek();
        if (c === undefined || !(c === '-' || (c >= '0' && c <= '9'))) {
          throw this.error('expected a value');
        }
        if (this.scanNumber().text !== '1') {
          throw bad('expected 1');
        }
        return key === '$minKey' ? MIN_KEY : MAX_KEY;
      }
      case '$counter':
        throw new RDocError(INVALID_FIELD_NAME, '$counter is a read-only projection, not accepted as input', at);
      default:
        throw new RDocError(INVALID_FIELD_NAME, "field name starts with '$'", at);
    }
  }

  private binary(): RValue {
    const at = this.pos;
    const bad = (r: string): RDocError => new RDocError(MALFORMED, `$binary: ${r}`, at);
    this.eat('{');
    let data: Uint8Array | undefined;
    let subtype = -1;
    for (let i = 0; i < 2; i++) {
      if (i > 0) {
        this.eat(',');
      }
      this.ws();
      if (this.peek() !== '"') {
        throw bad('expected base64 and subType');
      }
      const k = this.string();
      this.eat(':');
      const v = this.wrapperString();
      if (k === 'base64' && data === undefined) {
        data = strictBase64(v);
        if (data === undefined) {
          throw bad('invalid base64');
        }
      } else if (k === 'subType' && subtype < 0) {
        if (!/^[0-9a-fA-F]{2}$/.test(v)) {
          throw bad('subType is 2 hex digits');
        }
        subtype = parseInt(v, 16);
      } else {
        throw bad('expected base64 and subType');
      }
    }
    this.eat('}');
    const bytes = data ?? new Uint8Array(0);
    const error = binarySubtypeError(subtype, bytes.length);
    if (error !== undefined) {
      throw bad(error);
    }
    return new Binary(bytes, subtype);
  }

  private vector(): Float32Array {
    this.eat('[');
    const xs: number[] = [];
    this.ws();
    if (this.peek() === ']') {
      this.pos++;
      return new Float32Array(0);
    }
    for (;;) {
      this.ws();
      const c = this.peek();
      if (c === undefined || !(c === '-' || (c >= '0' && c <= '9'))) {
        throw this.error('invalid number');
      }
      // shortcut: decimal → float64 → float32 is a double rounding (.NET parses straight to
      // float32); they differ only for decimal texts within 2^-53 relative of a float32 tie.
      const x = Math.fround(Number(this.scanNumber().text));
      if (!Number.isFinite(x)) {
        throw new RDocError(INVALID_VECTOR, 'vector element outside the f32 range', this.pos);
      }
      xs.push(x);
      this.ws();
      const d = this.peek();
      this.pos++;
      if (d === ']') {
        return Float32Array.from(xs);
      }
      if (d !== ',') {
        this.pos--;
        throw this.error("expected ',' or ']'");
      }
    }
  }
}

function floatWrapper(s: string, bad: (reason: string) => RDocError): number {
  switch (s) {
    case 'NaN':
      return NaN;
    case 'Infinity':
      return Infinity;
    case '-Infinity':
      return -Infinity;
  }
  const first = s[0];
  if (first === undefined || !(first === '-' || (first >= '0' && first <= '9'))) {
    throw bad('not a number');
  }
  const p = new JsonReader(s);
  let text: string;
  try {
    text = p.scanNumber().text;
  } catch {
    throw bad('not a number');
  }
  if (!p.done) {
    throw bad('not a number');
  }
  // As Rust's `str::parse::<f64>`, an out-of-range magnitude gives ±Infinity here.
  return Number(text);
}

function strictBase64(s: string): Uint8Array | undefined {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/=]*$/.test(s)) {
    return undefined;
  }
  const data = Buffer.from(s, 'base64');
  // Re-encoding gives the one canonical text: this rejects non-zero unused bits and misplaced
  // padding that the lenient Node decoder accepts.
  return data.toString('base64') === s ? new Uint8Array(data) : undefined;
}

/** Parses one extended-JSON value (`1` int64, `1.0` float64, `$` wrappers); errors are RDocError. */
export function parseExtJson(text: string): RValue {
  const p = new JsonReader(text);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (!p.done) {
    throw p.error('trailing characters');
  }
  return v;
}

/** Parses an extended-JSON document (the text must be an object). */
export function parseExtJsonDocument(text: string): RDocument {
  const v = parseExtJson(text);
  if (!isDocument(v)) {
    throw new RDocError(MALFORMED, 'a document must be a JSON object', 0);
  }
  return v;
}
