// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Object mapping of the Node driver (FR-DRV-004; rules of the cross-driver vectors
 * `drivers/conformance/mapping/vectors.yaml`, PD-108…PD-113, PD-162). No decorators, no
 * reflection: a model is declared once with typed field builders and gives both the codec and
 * the static TypeScript type.
 *
 * ```ts
 * const Item = model({
 *   id: t.string().nullable(),                 // a member named `id` is `_id` (or mark one with .id())
 *   name: t.string().nullable(),
 *   count: t.int32(),                          // absent → 0; explicit null → error
 *   price: t.decimal().nullable(),
 *   postalCode: t.string().nullable().field('zip'),
 *   rev: t.string().nullable().rev(),          // read from `_rev`, never written
 *   views: t.int64().counter(),                // read only
 *   embedding: t.vector(3).nullable(),         // Float32Array of exactly 3
 *   location: t.geoPoint().nullable(),         // [lon, lat] ↔ GeoJSON Point
 * });
 * type Item = Infer<typeof Item>;
 * const Shape = union('_type', { circle: Circle, MapSquare: Square });   // `_type` after `_id`
 * ```
 *
 * Writing: `_id` first (omitted when null), then the discriminator of a union, then the other
 * members in declaration order; `rev()` and `counter()` members are never written. Reading:
 * unknown and system fields are ignored; an absent field gives null (nullable members), 0 /
 * 0n / false (numbers, booleans), else an error; every refused input is an RDocError 1001
 * naming the field. int32 is stored as int64 (read back with a range check), float32 as float64,
 * enums by member name, datetimes as ms (a Date has no sub-ms part and no offset).
 */

import { RDocError } from '../errors/errors.ts';
import {
  Binary,
  Counter,
  Decimal128,
  ObjectId,
  Uuid,
  defineField,
  isDocument,
  type RDocument,
  type RValue,
} from '../codec/values.ts';

/** Encodes values of `T` to documents and back (a model, a union, or a hand-written codec). */
export interface DocumentCodec<T> {
  encode(value: T): RDocument;
  decode(doc: RDocument): T;
}

/** Converts one member value; `path` names the field in errors. */
export interface ValueCodec<T> {
  read(v: RValue, path: string): T;
  write(v: T, path: string): RValue;
  /** The value of an absent non-nullable field (absent → error when undefined). */
  readonly zero?: T | undefined;
}

function fail(path: string, what: string): never {
  throw new RDocError(1001, `${path}: ${what}`);
}

type Role = 'plain' | 'id' | 'rev' | 'counter';

/** A member of a model: a value codec plus storage options (immutable; every option returns a copy). */
export class Field<T> {
  readonly codec: ValueCodec<T>;
  readonly isNullable: boolean;
  readonly storedName: string | undefined;
  readonly role: Role;

  constructor(codec: ValueCodec<T>, isNullable = false, storedName?: string, role: Role = 'plain') {
    this.codec = codec;
    this.isNullable = isNullable;
    this.storedName = storedName;
    this.role = role;
  }

  /** Accepts and writes `null` (and reads an absent field as `null`). */
  nullable(): Field<T | null> {
    const inner = this.codec;
    const codec: ValueCodec<T | null> = {
      read: (v, path) => (v === null ? null : inner.read(v, path)),
      write: (v, path) => (v === null ? null : inner.write(v, path)),
    };
    return new Field<T | null>(codec, true, this.storedName, this.role);
  }

  /** Stores the member under another field name. */
  field(name: string): Field<T> {
    return new Field(this.codec, this.isNullable, name, this.role);
  }

  /** This member is the document id (`_id`). */
  id(): Field<T> {
    return new Field(this.codec, this.isNullable, this.storedName, 'id');
  }

  /** Read from `_rev`, never written. */
  rev(): Field<T> {
    return new Field(this.codec, this.isNullable, this.storedName, 'rev');
  }

  /** A counter projection: read (int64 or counter), never written. */
  counter(): Field<T> {
    return new Field(this.codec, this.isNullable, this.storedName, 'counter');
  }
}

type Shape = Record<string, Field<unknown>>;

/** The TypeScript type of a model, union or field. */
export type Infer<C> = C extends DocumentCodec<infer T> ? T : C extends Field<infer F> ? F : never;

type ShapeType<S extends Shape> = { [K in keyof S]: S[K] extends Field<infer T> ? T : never };

interface Member {
  readonly key: string;
  readonly stored: string;
  readonly field: Field<unknown>;
}

/** A document model (see the module comment). Also usable as a nested member (`t.of(model)`). */
export class Model<S extends Shape> implements DocumentCodec<ShapeType<S>>, ValueCodec<ShapeType<S>> {
  readonly shape: S;
  private readonly idMember: Member | undefined;
  private readonly members: readonly Member[];

  constructor(shape: S) {
    this.shape = shape;
    const entries = Object.entries(shape);
    const explicit = entries.filter(([, f]) => f.role === 'id');
    if (explicit.length > 1) {
      throw new Error('a model has at most one id member');
    }
    const idKey = explicit[0]?.[0] ?? (Object.hasOwn(shape, 'id') && shape['id']?.role === 'plain' ? 'id' : undefined);
    const members: Member[] = [];
    let idMember: Member | undefined;
    for (const [key, field] of entries) {
      const stored = key === idKey ? '_id' : field.role === 'rev' ? '_rev' : (field.storedName ?? key);
      const m = { key, stored, field };
      if (key === idKey) {
        idMember = m;
      } else {
        members.push(m);
      }
    }
    this.idMember = idMember;
    this.members = members;
  }

  /** Encodes `value`; `discriminator` is written after `_id` (unions). */
  encodeWith(value: ShapeType<S>, discriminator?: [string, string], path = ''): RDocument {
    if (!isDocument(value) && (value === null || typeof value !== 'object')) {
      fail(path || '$', 'expected an object');
    }
    const source = value as Record<string, unknown>;
    const doc: RDocument = {};
    const id = this.idMember;
    if (id !== undefined) {
      const v = source[id.key];
      if (v !== null && v !== undefined) {
        defineField(doc, '_id', id.field.codec.write(v, join(path, id.key)));
      }
    }
    if (discriminator !== undefined) {
      defineField(doc, discriminator[0], discriminator[1]);
    }
    for (const m of this.members) {
      if (m.field.role === 'rev' || m.field.role === 'counter') {
        continue;
      }
      const p = join(path, m.key);
      let v = source[m.key];
      if (v === undefined) {
        v = m.field.isNullable ? null : m.field.codec.zero;
        if (v === undefined) {
          fail(p, 'missing value');
        }
      }
      if (v === null && !m.field.isNullable) {
        fail(p, 'null for a non-nullable member');
      }
      defineField(doc, m.stored, m.field.codec.write(v, p));
    }
    return doc;
  }

  encode(value: ShapeType<S>): RDocument {
    return this.encodeWith(value);
  }

  decodeAt(doc: RDocument, path: string): ShapeType<S> {
    const out: Record<string, unknown> = {};
    const all = this.idMember === undefined ? this.members : [this.idMember, ...this.members];
    const byKey = new Map(all.map((m) => [m.key, m]));
    // Declaration order of the shape, id included where it was declared.
    for (const key of Object.keys(this.shape)) {
      const m = byKey.get(key);
      if (m === undefined) {
        continue;
      }
      const p = join(path, m.stored);
      const present = Object.hasOwn(doc, m.stored);
      const v = doc[m.stored];
      let value: unknown;
      if (!present || v === undefined) {
        value = m.field.isNullable ? null : m.field.codec.zero;
        if (value === undefined) {
          fail(p, 'missing field');
        }
      } else if (v === null && !m.field.isNullable) {
        fail(p, 'null for a non-nullable member');
      } else {
        value = m.field.codec.read(v, p);
      }
      defineField(out as RDocument, key, value as RValue);
    }
    return out as ShapeType<S>;
  }

  decode(doc: RDocument): ShapeType<S> {
    return this.decodeAt(doc, '');
  }

  read(v: RValue, path: string): ShapeType<S> {
    if (!isDocument(v)) {
      fail(path, 'expected a document');
    }
    return this.decodeAt(v, path);
  }

  write(v: ShapeType<S>, path: string): RValue {
    return this.encodeWith(v, undefined, path);
  }
}

function join(path: string, key: string): string {
  return path === '' ? key : `${path}.${key}`;
}

/** Declares a document model. */
export function model<S extends Shape>(shape: S): Model<S> {
  return new Model(shape);
}

type Variants = Record<string, Model<Shape>>;

type UnionType<F extends string, V extends Variants> = {
  [K in keyof V & string]: Record<F, K> & Infer<V[K]>;
}[keyof V & string];

/**
 * A polymorphic model: the discriminator field (`_type` in the cross-driver vectors) selects the
 * variant; decoded values carry it as a property, so they form a TypeScript discriminated union.
 */
export class Union<F extends string, V extends Variants> implements DocumentCodec<UnionType<F, V>>, ValueCodec<UnionType<F, V>> {
  readonly discriminator: F;
  readonly variants: V;

  constructor(discriminator: F, variants: V) {
    this.discriminator = discriminator;
    this.variants = variants;
  }

  private variant(name: unknown, path: string): Model<Shape> {
    if (typeof name !== 'string' || !Object.hasOwn(this.variants, name)) {
      fail(join(path, this.discriminator), name === undefined ? 'missing discriminator' : `unknown discriminator ${String(name)}`);
    }
    return this.variants[name] as Model<Shape>;
  }

  write(value: UnionType<F, V>, path: string): RDocument {
    const name = (value as Record<string, unknown>)[this.discriminator];
    return this.variant(name, path).encodeWith(value as ShapeType<Shape>, [this.discriminator, name as string], path);
  }

  read(v: RValue, path: string): UnionType<F, V> {
    if (!isDocument(v)) {
      fail(path, 'expected a document');
    }
    const name = v[this.discriminator];
    const decoded = this.variant(name, path).decodeAt(v, path) as Record<string, unknown>;
    return { [this.discriminator]: name, ...decoded } as UnionType<F, V>;
  }

  encode(value: UnionType<F, V>): RDocument {
    return this.write(value, '');
  }

  decode(doc: RDocument): UnionType<F, V> {
    return this.read(doc, '');
  }
}

/** Declares a polymorphic model: `union('_type', { circle: Circle, MapSquare: Square })`. */
export function union<F extends string, V extends Variants>(discriminator: F, variants: V): Union<F, V> {
  return new Union(discriminator, variants);
}

// ------------------------------------------------------------------------------ field types

function codec<T>(expected: string, accept: (v: RValue) => T | undefined, write: (v: T, path: string) => RValue, zero?: T): ValueCodec<T> {
  return {
    read: (v, path) => {
      const r = accept(v);
      return r === undefined ? fail(path, `expected ${expected}`) : r;
    },
    write,
    zero,
  };
}

const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;

function int32Of(v: RValue): number | undefined {
  return typeof v === 'bigint' && v >= BigInt(INT32_MIN) && v <= BigInt(INT32_MAX) ? Number(v) : undefined;
}

/** A float read: float64, or int64 widened (as the .NET and Java mappers). */
function doubleOf(v: RValue): number | undefined {
  return typeof v === 'number' ? v : typeof v === 'bigint' ? Number(v) : undefined;
}

function geoWrite(v: [number, number], path: string): RValue {
  const [lon, lat] = v;
  if (v.length !== 2 || !(lon >= -180 && lon <= 180) || !(lat >= -90 && lat <= 90)) {
    fail(path, 'a geo point is [longitude, latitude] with longitude in [-180, 180] and latitude in [-90, 90]');
  }
  return { type: 'Point', coordinates: [lon, lat] };
}

function geoRead(v: RValue): [number, number] | undefined {
  if (!isDocument(v) || v['type'] !== 'Point' || !Array.isArray(v['coordinates']) || v['coordinates'].length !== 2) {
    return undefined;
  }
  const lon = doubleOf(v['coordinates'][0] ?? null);
  const lat = doubleOf(v['coordinates'][1] ?? null);
  return lon === undefined || lat === undefined ? undefined : [lon, lat];
}

function vectorOf(dimensions: number | undefined): ValueCodec<Float32Array> {
  const check = (x: Float32Array, path: string): Float32Array =>
    dimensions === undefined || x.length === dimensions ? x : fail(path, `the vector has ${x.length} dimensions, not ${dimensions}`);
  return {
    read: (v, path) => (v instanceof Float32Array ? check(v, path) : fail(path, 'expected a vector_f32')),
    write: (v, path) => check(v, path),
  };
}

function listOf<T>(item: ValueCodec<T> | Field<T>): ValueCodec<T[]> {
  const c = item instanceof Field ? item.codec : item;
  return {
    read: (v, path) => (Array.isArray(v) ? v.map((x, i) => c.read(x, `${path}[${i}]`)) : fail(path, 'expected an array')),
    write: (v, path) => v.map((x, i) => c.write(x, `${path}[${i}]`)),
  };
}

/** Field builders. */
export const t = {
  string: (): Field<string> => new Field(codec('a string', (v) => (typeof v === 'string' ? v : undefined), (v) => v)),
  bool: (): Field<boolean> => new Field(codec('a bool', (v) => (typeof v === 'boolean' ? v : undefined), (v) => v, false)),
  /** A JavaScript number stored as int64; reads check the int32 range. */
  int32: (): Field<number> =>
    new Field(
      codec('an int64 in the int32 range', int32Of, (v, path) =>
        Number.isInteger(v) && v >= INT32_MIN && v <= INT32_MAX ? BigInt(v) : fail(path, `${v} is not an int32`),
      0),
    ),
  int64: (): Field<bigint> =>
    new Field(
      codec(
        'an int64',
        (v) => (typeof v === 'bigint' ? v : v instanceof Counter ? v.value : undefined),
        (v) => v,
        0n,
      ),
    ),
  float64: (): Field<number> => new Field(codec('a float64', doubleOf, (v) => v, 0)),
  /** Rounded to float32 on both sides; stored as float64 (0.1 → 0.10000000149011612). */
  float32: (): Field<number> =>
    new Field(
      codec(
        'a float64',
        (v) => {
          const d = doubleOf(v);
          return d === undefined ? undefined : Math.fround(d);
        },
        (v) => Math.fround(v),
        0,
      ),
    ),
  decimal: (): Field<Decimal128> => new Field(codec('a decimal128', (v) => (v instanceof Decimal128 ? v : undefined), (v) => v)),
  /** A Date (ms precision, UTC instant); datetimes outside the Date range are refused. */
  datetime: (): Field<Date> =>
    new Field(
      codec(
        'a datetime within the Date range',
        (v) => (v instanceof Date ? v : undefined),
        (v, path) => (v instanceof Date && !Number.isNaN(v.getTime()) ? v : fail(path, 'expected a valid Date')),
      ),
    ),
  /** Stored by member name, verbatim; unknown names are refused. */
  enum: <const E extends string>(names: readonly E[]): Field<E> =>
    new Field(
      codec<E>(
        `one of ${names.join(', ')}`,
        (v) => (typeof v === 'string' && (names as readonly string[]).includes(v) ? (v as E) : undefined),
        (v, path) => ((names as readonly string[]).includes(v) ? v : fail(path, `${v} is not one of ${names.join(', ')}`)),
      ),
    ),
  objectId: (): Field<ObjectId> => new Field(codec('an objectId', (v) => (v instanceof ObjectId ? v : undefined), (v) => v)),
  uuid: (): Field<Uuid> => new Field(codec('a uuid', (v) => (v instanceof Uuid ? v : undefined), (v) => v)),
  binary: (): Field<Binary> =>
    new Field(codec('a binary', (v) => (v instanceof Binary ? v : v instanceof Uint8Array && !(v instanceof Float32Array) ? new Binary(v) : undefined), (v) => v)),
  /** A vector_f32, of exactly `dimensions` elements when given. */
  vector: (dimensions?: number): Field<Float32Array> => new Field(vectorOf(dimensions)),
  /** `[longitude, latitude]` ↔ GeoJSON `{"type":"Point","coordinates":[lon, lat]}`. */
  geoPoint: (): Field<[number, number]> => new Field(codec('a GeoJSON point', geoRead, geoWrite)),
  list: <T>(item: ValueCodec<T> | Field<T>): Field<T[]> => new Field(listOf(item)),
  /** A nested model or union (or any value codec). */
  of: <T>(c: ValueCodec<T>): Field<T> => new Field(c),
  /** Any RDoc value, unchanged. */
  any: (): Field<RValue> => new Field<RValue>({ read: (v) => v, write: (v) => v }),
};

