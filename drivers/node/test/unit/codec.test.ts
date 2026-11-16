// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Binary,
  Decimal128,
  MAX_KEY,
  MIN_KEY,
  ObjectId,
  RDateTime,
  Timestamp,
  Uuid,
  decodeDocument,
  decodeValue,
  encodeDocument,
  encodeValue,
  parseExtJson,
  parseExtJsonDocument,
  toExtJson,
  typeOf,
  valueEquals,
  type RDocument,
  type RValue,
} from '../../src/codec/index.ts';
import { RDocError } from '../../src/errors/errors.ts';

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

function rejects(code: number, f: () => unknown): void {
  assert.throws(f, (e: unknown) => e instanceof RDocError && e.code === code);
}

/** mulberry32: a small seeded PRNG so failures reproduce (no property-testing dependency). */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomValue(r: () => number, depth: number): RValue {
  const int = (n: number): number => Math.floor(r() * n);
  const kinds = depth > 3 ? 14 : 16;
  switch (int(kinds)) {
    case 0:
      return null;
    case 1:
      return r() < 0.5;
    case 2:
      return BigInt.asIntN(64, BigInt(int(2 ** 32)) * BigInt(int(2 ** 32)) - BigInt(int(2 ** 31)));
    case 3:
      return [0, -0, NaN, Infinity, -Infinity, 1.5, 1e300, 5e-324][int(8)] ?? (r() - 0.5) * 10 ** int(40);
    case 4:
      return Decimal128.fromParts(r() < 0.5, BigInt(int(1e9)), int(40) - 20);
    case 5:
      return String.fromCodePoint(...Array.from({ length: int(8) }, () => int(0x2ffff) % 0xd7ff));
    case 6:
      return new Binary(Uint8Array.from({ length: int(10) }, () => int(256)), [0, 0x80, 0xff][int(3)]);
    case 7:
      return new Date(int(4e12) - 2e12);
    case 8:
      return new Timestamp(BigInt(int(2 ** 32)) << 20n, int(2 ** 32));
    case 9:
      return ObjectId.generate();
    case 10:
      return Uuid.random();
    case 11:
      return Float32Array.from({ length: int(5) }, () => Math.fround((r() - 0.5) * 100));
    case 12:
      return MIN_KEY;
    case 13:
      return MAX_KEY;
    case 14:
      return Array.from({ length: int(4) }, () => randomValue(r, depth + 1));
    default:
      return randomDocument(r, depth + 1);
  }
}

function randomDocument(r: () => number, depth: number): RDocument {
  const doc: RDocument = {};
  const n = Math.floor(r() * 6);
  for (let i = 0; i < n; i++) {
    doc[`f${Math.floor(r() * 1000)}_${String.fromCharCode(97 + i)}`] = randomValue(r, depth);
  }
  return doc;
}

void test('TC-DRV-NODE-002 random values and documents round trip byte-exact (bytes and JSON)', () => {
  const r = prng(20261114);
  for (let i = 0; i < 500; i++) {
    const v = randomValue(r, 0);
    const bytes = encodeValue(v);
    const back = decodeValue(bytes);
    assert.ok(valueEquals(v, back), `value ${toExtJson(v)}`);
    assert.equal(hex(encodeValue(back)), hex(bytes));
    for (const extended of [false, true]) {
      const json = toExtJson(v, { extended });
      assert.equal(hex(encodeValue(parseExtJson(json))), hex(bytes), json);
    }
    const doc = randomDocument(r, 1);
    const d = encodeDocument(doc);
    assert.equal(hex(encodeDocument(decodeDocument(d))), hex(d));
    assert.equal(toExtJson(parseExtJsonDocument(toExtJson(doc))), toExtJson(doc));
  }
});

void test('TC-DRV-NODE-002 single-byte corruption only ever raises RDocError', () => {
  const r = prng(7);
  for (let i = 0; i < 40; i++) {
    const bytes = encodeDocument({ a: randomDocument(r, 2), b: randomValue(r, 2) });
    for (let at = 0; at < bytes.length; at++) {
      const bad = new Uint8Array(bytes);
      bad[at] = (bad[at] ?? 0) ^ (1 << Math.floor(r() * 8));
      try {
        decodeDocument(bad);
      } catch (e) {
        assert.ok(e instanceof RDocError, `offset ${at}: ${String(e)}`);
      }
    }
  }
});

void test('TC-DRV-NODE-003 malformed documents: truncations, header, index, names, depth, size', () => {
  const ok = encodeDocument({ a: 1n, bb: 'x', c: [1n, { d: true }] });
  for (let n = 0; n < ok.length; n++) {
    rejects(1001, () => decodeDocument(ok.subarray(0, n)));
  }
  const flagged = new Uint8Array(ok);
  flagged[2] = 0x02;
  rejects(1001, () => decodeDocument(flagged));
  // Non-minimal varint: accepted without the canonical flag, refused with it.
  const nonMinimal = Uint8Array.from([0xd7, 1, 1, 0, 0, 0, 0, 0x0d, 0x01, 0x05, 0x1f, 0x4e, 0, 0, 0, 0, 0x01, 0x61, 0x03, 0x82, 0x00]);
  new DataView(nonMinimal.buffer).setUint32(3, nonMinimal.length, true);
  rejects(1001, () => decodeDocument(nonMinimal));
  nonMinimal[2] = 0;
  assert.deepEqual(decodeDocument(nonMinimal), { a: 1n });

  rejects(1004, () => encodeDocument({ '': 1n }));
  rejects(1004, () => encodeDocument({ $set: 1n }));
  rejects(1004, () => encodeDocument({ 'a\0b': 1n }));
  rejects(1004, () => encodeDocument({ ['x'.repeat(1025)]: 1n }));
  encodeDocument({ ['x'.repeat(1024)]: 1n });
  rejects(1004, () => encodeDocument({ '\ud800': 1n }));
  rejects(1001, () => encodeValue('\udc00'));
  rejects(1001, () => encodeValue(1n << 63n));
  rejects(1001, () => encodeValue(new Date(NaN)));
  rejects(1040, () => encodeValue(Float32Array.of(NaN)));

  const nest = (n: number): RDocument => (n === 1 ? {} : { x: nest(n - 1) });
  assert.equal(Object.keys(decodeDocument(encodeDocument(nest(100)))).length, 1);
  rejects(1003, () => encodeDocument(nest(101)));
  rejects(1003, () => parseExtJson(JSON.stringify(nest(101))));

  rejects(1002, () => encodeDocument({ s: 'x'.repeat(16 * 1024 * 1024) }));
  const max = encodeDocument({ s: 'x'.repeat(16 * 1024 * 1024 - 26) });
  assert.equal(max.length, 16 * 1024 * 1024);
});

void test('TC-DRV-NODE-003 decoding never changes the prototype (__proto__ field)', () => {
  const doc = parseExtJsonDocument('{"__proto__":{"polluted":1}}');
  assert.equal(Object.getPrototypeOf(doc), Object.prototype);
  const back = decodeDocument(encodeDocument(doc));
  assert.equal(Object.getPrototypeOf(back), Object.prototype);
  assert.deepEqual(Object.keys(back), ['__proto__']);
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

void test('TC-DRV-NODE-004 extended JSON: float layout, wrappers, number mapping', () => {
  const floats: [number, string][] = [
    [0.1, '0.1'],
    [1.0, '1.0'],
    [-0.0, '-0.0'],
    [0.0, '0.0'],
    [123.456, '123.456'],
    [0.0001, '0.0001'],
    [0.00001, '1e-5'],
    [1e15, '1000000000000000.0'],
    [1e16, '1e16'],
    [1.5e-7, '1.5e-7'],
    [5e-324, '5e-324'],
    [1.7976931348623157e308, '1.7976931348623157e308'],
    [-2.5e20, '-2.5e20'],
    [2 ** 53 + 1, '9007199254740992.0'],
  ];
  for (const [x, text] of floats) {
    assert.equal(toExtJson(x), text);
  }
  assert.equal(toExtJson(1n, { extended: true }), '{"$int64":"1"}');
  assert.equal(toExtJson(1e300, { extended: true }), '{"$float":"1e300"}');
  assert.equal(toExtJson(9007199254740992n), '9007199254740992');
  assert.equal(toExtJson(9007199254740993n), '{"$int64":"9007199254740993"}');
  assert.equal(typeOf(parseExtJson('1')), 'int64');
  assert.equal(typeOf(parseExtJson('1.0')), 'float64');
  assert.equal(typeOf(parseExtJson('1e3')), 'float64');
  assert.equal(typeOf(parseExtJson('9223372036854775808')), 'float64');
  assert.equal(toExtJson(parseExtJson('{"$decimal":"-1.50e10"}')), '{"$decimal":"-1.50E+10"}');
  assert.equal(toExtJson(parseExtJson('{"$oid":"65A1B2C3D4E5F60718293A4B"}')), '{"$oid":"65a1b2c3d4e5f60718293a4b"}');
  assert.equal(
    toExtJson(parseExtJson('{"$uuid":"01234567-89AB-CDEF-0123-456789ABCDEF"}')),
    '{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"}',
  );
  assert.equal(toExtJson(parseExtJson('{"$vector":[]}')), '{"$vector":[]}');
  assert.equal(toExtJson(Float32Array.of(0.1, 1, 1e-5)), '{"$vector":[0.1,1.0,1e-5]}');
  assert.equal(toExtJson(new Date(-1)), '{"$date":"1969-12-31T23:59:59.999Z"}');
  assert.equal(toExtJson(new RDateTime(-(1n << 63n))), '{"$date":"-292275055-05-16T16:47:04.192Z"}');
  assert.ok(parseExtJson('{"$date":"+292278994-08-17T07:12:55.807Z"}') instanceof RDateTime);
  rejects(1001, () => parseExtJson('{"$date":"+292278994-08-17T07:12:55.808Z"}'));
  rejects(1004, () => parseExtJson('{"$counter":1}'));
  rejects(1004, () => parseExtJson('{"a":1,"a":2}'));
  rejects(1001, () => parseExtJson('1e999'));
  assert.equal(toExtJson({ x: 1n, y: [true, null], z: new Date(Date.UTC(2026, 0, 1)) }), '{"x":1,"y":[true,null],"z":{"$date":"2026-01-01T00:00:00.000Z"}}');
  assert.equal(toExtJson({ s: 'a"\\\n\u0001é' }), '{"s":"a\\"\\\\\\n\\u0001é"}');
  // Fields holding undefined are skipped, as JSON.stringify does.
  assert.equal(toExtJson({ a: 1n, b: undefined as unknown as RValue }), '{"a":1}');
  assert.equal(hex(encodeDocument({ a: 1n, b: undefined as unknown as RValue })), hex(encodeDocument({ a: 1n })));
});

void test('TC-DRV-NODE-005 Decimal128 parse, text and BID bits', () => {
  const cases: [string, string][] = [
    ['12.50', '12.50'],
    ['0', '0'],
    ['-0', '-0'],
    ['1E+3', '1E+3'],
    ['0.000001', '0.000001'],
    ['0.0000001', '1E-7'],
    ['1234567890123456789012345678901234', '1234567890123456789012345678901234'],
    ['inf', 'Infinity'],
    ['-Infinity', '-Infinity'],
    ['nan', 'NaN'],
    ['1.000000000000000000000000000000000000E+2', '100.0000000000000000000000000000000'],
  ];
  for (const [input, text] of cases) {
    assert.equal(Decimal128.parse(input).toString(), text, input);
  }
  assert.ok(!Decimal128.parse('1.0').equals(Decimal128.parse('1.00')));
  assert.ok(Decimal128.parse('NaN').equals(Decimal128.parse('nan')));
  for (const bad of ['', '.', '1e', 'abc', '12345678901234567890123456789012345', '1E+9999', '1E-9999']) {
    rejects(1001, () => Decimal128.parse(bad));
  }
  const one = Decimal128.parse('1');
  assert.equal(hex(one.bytes), '01000000000000000000000000004030');
  assert.ok(Decimal128.fromBytes(one.bytes).value.equals(one));
  assert.equal(Decimal128.fromBytes(one.bytes).canonical, true);
});

void test('TC-DRV-NODE-005 ObjectId text, bytes and generation', () => {
  const id = new ObjectId('65A1B2C3D4E5F60718293A4B');
  assert.equal(id.toHexString(), '65a1b2c3d4e5f60718293a4b');
  assert.equal(String(id), '65a1b2c3d4e5f60718293a4b');
  assert.ok(id.equals(new ObjectId(id.bytes)));
  assert.throws(() => new ObjectId('xyz'), RDocError);
  assert.throws(() => new ObjectId(new Uint8Array(11)), RDocError);
  const a = ObjectId.generate(new Date(Date.UTC(2026, 0, 1)));
  const b = ObjectId.generate(new Date(Date.UTC(2026, 0, 1)));
  assert.ok(!a.equals(b));
  assert.equal(a.toHexString().slice(0, 8), (Date.UTC(2026, 0, 1) / 1000).toString(16));
  assert.equal(a.toHexString().slice(8, 18), b.toHexString().slice(8, 18));
  assert.equal(typeOf(new Uuid('01234567-89ab-cdef-0123-456789abcdef')), 'uuid');
  assert.equal(typeOf(new Map()), undefined);
  assert.equal(typeOf(undefined), undefined);
  assert.ok(valueEquals(new Date(5), new RDateTime(5n)));
  assert.ok(valueEquals({ a: 1n, b: 2n }, { b: 2n, a: 1n }));
  assert.ok(!valueEquals(1n, 1));
  assert.ok(!valueEquals(0, -0));
  assert.ok(valueEquals(NaN, NaN));
  assert.ok(valueEquals(Uint8Array.of(1), new Binary(Uint8Array.of(1))));
});
