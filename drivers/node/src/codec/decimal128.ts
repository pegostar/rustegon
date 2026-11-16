// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { RDocError } from '../errors/errors.ts';

const MAX_COEFFICIENT = 10n ** 34n - 1n;
const MAX_DIGITS = 34;
const MIN_EXPONENT = -6176;
const MAX_EXPONENT = 6111;
const EXPONENT_BIAS = 6176;
// Combination-field patterns (bits 126..122): 11110 infinity, 11111 NaN (quiet, no payload).
const INFINITY_BITS = 0x78n << 120n;
const NAN_BITS = 0x7cn << 120n;
const COEFFICIENT_MASK = (1n << 113n) - 1n;

type Kind = 'finite' | 'infinity' | 'nan';

/**
 * IEEE 754-2008 decimal128 in BID encoding (data-model.md §2, §4). Values keep their cohort
 * (`1.0` and `1.00` are distinct); equality compares the canonical bits. Port of the .NET
 * `Decimal128` (same parse rules, same text).
 */
export class Decimal128 {
  readonly kind: Kind;
  readonly negative: boolean;
  /** Coefficient, 0 ≤ c ≤ 10^34 − 1 (0 for NaN / infinities). */
  readonly coefficient: bigint;
  /** Exponent, −6176 ≤ e ≤ 6111. */
  readonly exponent: number;

  private constructor(kind: Kind, negative: boolean, coefficient: bigint, exponent: number) {
    this.kind = kind;
    this.negative = negative;
    this.coefficient = coefficient;
    this.exponent = exponent;
  }

  static readonly NaN = new Decimal128('nan', false, 0n, 0);
  static readonly POSITIVE_INFINITY = new Decimal128('infinity', false, 0n, 0);
  static readonly NEGATIVE_INFINITY = new Decimal128('infinity', true, 0n, 0);

  /** A finite value `(-1)^negative × coefficient × 10^exponent`. */
  static fromParts(negative: boolean, coefficient: bigint, exponent: number): Decimal128 {
    if (coefficient < 0n || coefficient > MAX_COEFFICIENT) {
      throw new RDocError(1001, 'a decimal128 coefficient has at most 34 digits');
    }
    if (!Number.isInteger(exponent) || exponent < MIN_EXPONENT || exponent > MAX_EXPONENT) {
      throw new RDocError(1001, 'decimal128 exponent out of range');
    }
    return new Decimal128('finite', negative, coefficient, exponent);
  }

  /** The 128-bit BID value (canonical). */
  get bits(): bigint {
    const sign = this.negative ? 1n << 127n : 0n;
    switch (this.kind) {
      case 'nan':
        return NAN_BITS;
      case 'infinity':
        return sign | INFINITY_BITS;
      default:
        return sign | (BigInt(this.exponent + EXPONENT_BIAS) << 113n) | this.coefficient;
    }
  }

  /** The 16 bytes of the BID value, little-endian (the RDoc payload). */
  get bytes(): Uint8Array {
    const out = new Uint8Array(16);
    const view = new DataView(out.buffer);
    const b = this.bits;
    view.setBigUint64(0, b & 0xffffffffffffffffn, true);
    view.setBigUint64(8, b >> 64n, true);
    return out;
  }

  /** Decodes 16 little-endian bytes; `canonical` is false for non-canonical encodings. */
  static fromBytes(bytes: Uint8Array): { value: Decimal128; canonical: boolean } {
    const view = new DataView(bytes.buffer, bytes.byteOffset, 16);
    const bits = view.getBigUint64(0, true) | (view.getBigUint64(8, true) << 64n);
    const negative = bits >> 127n === 1n;
    const combination = Number((bits >> 122n) & 0x1fn);
    if (combination === 0x1f) {
      return { value: Decimal128.NaN, canonical: bits === NAN_BITS };
    }
    if (combination === 0x1e) {
      return {
        value: negative ? Decimal128.NEGATIVE_INFINITY : Decimal128.POSITIVE_INFINITY,
        canonical: (bits & ((1n << 122n) - 1n)) === 0n,
      };
    }
    let biased: number;
    let coefficient: bigint;
    let canonical: boolean;
    if (Number((bits >> 125n) & 3n) === 3) {
      // Large-coefficient form: the implied coefficient is ≥ 2^113 > 10^34 − 1, so the value is
      // zero and the encoding never canonical.
      biased = Number((bits >> 111n) & 0x3fffn);
      coefficient = 0n;
      canonical = false;
    } else {
      biased = Number((bits >> 113n) & 0x3fffn);
      const c = bits & COEFFICIENT_MASK;
      canonical = c <= MAX_COEFFICIENT;
      coefficient = canonical ? c : 0n;
    }
    // The large form can carry a biased exponent above 12287; clamp it (the value is zero).
    const exponent = Math.min(biased, MAX_EXPONENT + EXPONENT_BIAS) - EXPONENT_BIAS;
    return { value: new Decimal128('finite', negative, coefficient, exponent), canonical };
  }

  /** Parses decimal text (`12.50`, `-1E+3`, `NaN`, `Infinity`); inexact values are refused. */
  static parse(text: string): Decimal128 {
    const r = Decimal128.tryParse(text);
    if (typeof r === 'string') {
      throw new RDocError(1001, `decimal128: ${r}`);
    }
    return r;
  }

  /** The value, or the reason the text is not an exact decimal128. */
  static tryParse(text: string): Decimal128 | string {
    let body = text;
    let negative = false;
    if (body.startsWith('-') || body.startsWith('+')) {
      negative = body.startsWith('-');
      body = body.slice(1);
    }
    const lower = body.toLowerCase();
    if (lower === 'inf' || lower === 'infinity') {
      return negative ? Decimal128.NEGATIVE_INFINITY : Decimal128.POSITIVE_INFINITY;
    }
    if (lower === 'nan') {
      return Decimal128.NaN;
    }
    const m = /^([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?)([0-9]*))?$/.exec(body);
    if (m === null) {
      return 'unexpected character';
    }
    const intPart = m[1] ?? '';
    const fracPart = m[2] ?? '';
    if (intPart.length + fracPart.length === 0) {
      return 'no digits';
    }
    let expLit = 0;
    if (m[3] !== undefined || m[4] !== undefined) {
      const digits = m[4] ?? '';
      if (digits.length === 0) {
        return 'empty exponent';
      }
      // Saturate: anything beyond ±10^12 is out of range whatever the digits are.
      const significant = digits.replace(/^0+/, '');
      expLit = significant.length > 13 ? 1_000_000_000_000 : Math.min(Number(significant || '0'), 1_000_000_000_000);
      if (m[3] === '-') {
        expLit = -expLit;
      }
    }
    const digits = (intPart + fracPart).replace(/^0+/, '').split('').map(Number);
    let exponent = expLit - fracPart.length;
    if (digits.length === 0) {
      // Zero: clamping the exponent does not change the value (IEEE 754 does the same).
      return new Decimal128('finite', negative, 0n, Math.min(Math.max(exponent, MIN_EXPONENT), MAX_EXPONENT));
    }
    while (digits.length > MAX_DIGITS && digits[digits.length - 1] === 0) {
      digits.pop();
      exponent++;
    }
    if (digits.length > MAX_DIGITS) {
      return 'more than 34 significant digits (inexact)';
    }
    while (exponent > MAX_EXPONENT && digits.length < MAX_DIGITS) {
      digits.push(0);
      exponent--;
    }
    if (exponent > MAX_EXPONENT) {
      return 'exponent overflow';
    }
    while (exponent < MIN_EXPONENT && digits[digits.length - 1] === 0) {
      digits.pop();
      exponent++;
    }
    if (exponent < MIN_EXPONENT) {
      return 'exponent underflow (inexact)';
    }
    return new Decimal128('finite', negative, BigInt(digits.join('')), exponent);
  }

  /** Scientific text of IEEE 754 / the .NET driver (`12.50`, `1.2E+5`, `-0E-7`, `NaN`). */
  toString(): string {
    if (this.kind === 'nan') {
      return 'NaN';
    }
    if (this.kind === 'infinity') {
      return this.negative ? '-Infinity' : 'Infinity';
    }
    const sign = this.negative ? '-' : '';
    const digits = this.coefficient.toString();
    const n = digits.length;
    const exponent = this.exponent;
    const adjusted = exponent + n - 1;
    if (exponent <= 0 && adjusted >= -6) {
      if (exponent === 0) {
        return sign + digits;
      }
      const point = n + exponent;
      if (point > 0) {
        return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
      }
      return `${sign}0.${'0'.repeat(-point)}${digits}`;
    }
    const mantissa = digits.length > 1 ? `${digits[0] ?? ''}.${digits.slice(1)}` : digits;
    return `${sign}${mantissa}E${adjusted < 0 ? '-' : '+'}${Math.abs(adjusted)}`;
  }

  toJSON(): string {
    return this.toString();
  }

  /** Same canonical bits (so `1.0` ≠ `1.00`, and every NaN equals NaN). */
  equals(other: unknown): boolean {
    return other instanceof Decimal128 && this.bits === other.bits;
  }
}
