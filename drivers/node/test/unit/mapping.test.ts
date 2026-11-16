// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Decimal128, encodeDocument, parseExtJsonDocument, toExtJson, type RDocument } from '../../src/codec/index.ts';
import { RDocError } from '../../src/errors/errors.ts';
import { model, t, union, type DocumentCodec, type Infer } from '../../src/mapping/index.ts';
import { asList, asMap, asString, loadConformanceYaml } from '../support/files.ts';

// The models of mapping/vectors.yaml, member for member and in that order.
const MapItem = model({
  name: t.string().nullable(),
  id: t.string().nullable(),
  count: t.int32(),
  ratio: t.float32(),
  price: t.decimal().nullable(),
  tags: t.list(t.string()).nullable(),
  note: t.string().nullable(),
  status: t.enum(['Draft', 'Paid']).nullable(),
  postalCode: t.string().nullable().field('zip'),
  rev: t.string().nullable().rev(),
  views: t.int64().counter(),
  when: t.datetime().nullable(),
});
type MapItem = Infer<typeof MapItem>;

const MapGeo = model({
  key: t.string().nullable().id(),
  embedding: t.vector(3).nullable(),
  location: t.geoPoint().nullable(),
});

const MapCircle = model({ id: t.string().nullable(), radius: t.float64() });
const MapSquare = model({ side: t.float64() });
const MapShape = union('_type', { circle: MapCircle, MapSquare });

const MapDrawing = model({
  id: t.string().nullable(),
  main: t.of(MapShape).nullable(),
  shapes: t.list(MapShape).nullable(),
});

const MODELS: Record<string, DocumentCodec<never>> = { MapItem, MapGeo, MapShape, MapDrawing } as unknown as Record<string, DocumentCodec<never>>;

const item = (fields: Partial<MapItem>): MapItem => ({
  name: null,
  id: null,
  count: 0,
  ratio: 0,
  price: null,
  tags: null,
  note: null,
  status: null,
  postalCode: null,
  rev: null,
  views: 0n,
  when: null,
  ...fields,
});

const BUILD: Record<string, MapItem> = {
  null_id_omitted_read_only_not_written: item({ name: 'n', rev: 'r1', views: 99n }),
  // A Date holds ms only: parsing truncates the sub-ms digits (rounded down, also before 1970).
  datetime_rounded_down_to_ms: item({ id: 't1', when: new Date('2026-11-12T10:15:30.123456789Z') }),
  datetime_rounded_down_before_1970: item({ id: 't2', when: new Date('1969-12-31T23:59:59.9995Z') }),
  datetime_offset_dropped: item({ id: 't3', when: new Date('2026-01-02T03:04:05.999+02:00') }),
  float_widened_to_float64: item({ id: 'f1', ratio: 0.1 }),
};

function assertWrites(codec: DocumentCodec<never>, value: unknown, json: string): void {
  const written: RDocument = codec.encode(value as never);
  assert.equal(toExtJson(written), json);
  assert.deepEqual(encodeDocument(written), encodeDocument(parseExtJsonDocument(json)));
}

const vectors = asMap(loadConformanceYaml('mapping/vectors.yaml'));

for (const section of ['roundTrip', 'build', 'invalid']) {
  void test(`TC-DRV-NODE-023 cross-driver mapping vectors: ${section}`, async (tc) => {
    for (const entry of asList(vectors[section])) {
      const v = asMap(entry);
      const name = asString(v['name']);
      await tc.test(name, () => {
        const codec = MODELS[asString(v['model'])];
        assert.ok(codec, `unknown model ${String(v['model'])}`);
        const json = typeof v['json'] === 'string' ? v['json'] : '';
        if (section === 'roundTrip') {
          const input = typeof v['input'] === 'string' ? v['input'] : json;
          assertWrites(codec, codec.decode(parseExtJsonDocument(input)), json);
          assertWrites(codec, codec.decode(parseExtJsonDocument(json)), json);
        } else if (section === 'build') {
          const value = BUILD[name];
          assert.ok(value, `unknown build vector ${name}`);
          assertWrites(codec, value, json);
        } else {
          assert.throws(() => codec.decode(parseExtJsonDocument(asString(v['input']))), RDocError);
        }
      });
    }
  });
}

void test('TC-DRV-NODE-021 a model gives the static type and reads every member', () => {
  const doc = parseExtJsonDocument(
    '{"_id":"i1","_rev":"0000000000000001","name":"w","count":-3,"ratio":0.25,"price":{"$decimal":"12.50"},"tags":["x"],"note":null,"status":"Paid","zip":"35100","views":41,"when":{"$date":"2026-11-12T10:15:30.123Z"}}',
  );
  const it: MapItem = MapItem.decode(doc);
  assert.equal(it.id, 'i1');
  assert.equal(it.rev, '0000000000000001');
  assert.equal(it.views, 41n);
  assert.equal(it.postalCode, '35100');
  assert.equal(it.status, 'Paid');
  assert.ok(it.price?.equals(Decimal128.parse('12.50')));
  assert.deepEqual(Object.keys(it), ['name', 'id', 'count', 'ratio', 'price', 'tags', 'note', 'status', 'postalCode', 'rev', 'views', 'when']);
});

void test('TC-DRV-NODE-022 id, field names, read-only members and errors naming the field', () => {
  assert.equal(toExtJson(MapItem.encode(item({ id: 'a', views: 5n, rev: 'x' }))).startsWith('{"_id":"a","name":null'), true);
  assert.throws(() => MapItem.encode(item({ count: 1.5 })), /count: 1.5 is not an int32/);
  assert.throws(() => MapItem.encode(item({ status: 'Shipped' as 'Paid' })), /status/);
  assert.throws(() => MapItem.decode(parseExtJsonDocument('{"_id":"a","tags":["x",1]}')), /tags\[1\]: expected a string/);
  assert.throws(() => MapGeo.encode({ key: 'g', embedding: Float32Array.of(1), location: null }), /embedding/);
  assert.throws(() => MapGeo.encode({ key: 'g', embedding: null, location: [200, 0] }), /location/);
  assert.throws(() => model({ a: t.string().id(), b: t.string().id() }), /at most one id/);
  // A member that is neither nullable nor numeric/boolean must be present.
  const Strict = model({ title: t.string() });
  assert.throws(() => Strict.decode({}), /title: missing field/);
});

void test('TC-DRV-NODE-024 polymorphism: discriminator after _id, dispatch, unknown/missing discriminators', () => {
  const circle = MapShape.decode(parseExtJsonDocument('{"radius":1.5,"_type":"circle","_id":"c1"}'));
  assert.equal(circle._type, 'circle');
  if (circle._type === 'circle') {
    assert.equal(circle.radius, 1.5);
    assert.equal(circle.id, 'c1');
  }
  assert.equal(toExtJson(MapShape.encode({ _type: 'MapSquare', side: 2 })), '{"_type":"MapSquare","side":2.0}');
  assert.throws(() => MapShape.decode({ _type: 'hexagon' }), /unknown discriminator hexagon/);
  assert.throws(() => MapShape.decode({ radius: 1 }), /missing discriminator/);
  assert.throws(() => MapShape.encode({ _type: 'nope' } as never), RDocError);
});

void test('TC-DRV-NODE-025 encode then decode returns an equal value (many items)', () => {
  for (let i = 0; i < 200; i++) {
    const v = item({
      id: `i${i}`,
      name: i % 3 === 0 ? null : `n${i}`,
      count: (i * 7919) % 2 ** 31 - 2 ** 30,
      ratio: Math.fround(i / 7),
      price: i % 2 === 0 ? Decimal128.parse(`${i}.${i}`) : null,
      tags: i % 5 === 0 ? [] : [`t${i}`],
      status: i % 2 === 0 ? 'Draft' : 'Paid',
      when: new Date(i * 86_400_123 - 1e12),
    });
    const back = MapItem.decode(MapItem.encode(v));
    assert.deepEqual({ ...back, price: back.price?.toString() ?? null }, { ...v, price: v.price?.toString() ?? null });
  }
});
