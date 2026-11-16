// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Values of the conformance files (README §5 "Values and matching"): YAML (integers as bigint)
 * to RDoc values, the expectation matcher with its placeholders (`$$any`, `$$type`, `$$ref`)
 * and the result normalisation of README §6.
 */

import { ObjectId, RDateTime, parseExtJson, toExtJson, typeOf, valueEquals, type RDocument, type RValue } from '../../../src/index.ts';
import type { Yaml, YamlMap } from '../files.ts';

const WRAPPERS = new Set(['$oid', '$date', '$int64', '$float', '$decimal', '$binary', '$uuid', '$vector', '$ts', '$minKey', '$maxKey', '$counter']);

/** System fields removed from server documents unless the expectation names them (README §5). */
export const SYSTEM_FIELDS = ['_rev', '_createdAt', '_updatedAt'];

export function isMap(v: Yaml | undefined): v is YamlMap {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v);
}

export function isWrapper(m: YamlMap): boolean {
  const keys = Object.keys(m);
  return keys.length === 1 && WRAPPERS.has(keys[0]!);
}

/** A YAML value as an RDoc value; `resolve` substitutes strings (`${…}`, `$$ref:`). */
export function toValue(yaml: Yaml, resolve?: (s: string) => RValue): RValue {
  if (yaml === null || typeof yaml === 'boolean' || typeof yaml === 'bigint' || typeof yaml === 'number') {
    return yaml;
  }
  if (typeof yaml === 'string') {
    return resolve === undefined ? yaml : resolve(yaml);
  }
  if (Array.isArray(yaml)) {
    return yaml.map((e) => toValue(e, resolve));
  }
  if (isWrapper(yaml)) {
    return parseExtJson(toJson(yaml));
  }
  return toDocument(yaml, resolve);
}

/** A YAML mapping as a document, field by field (names the codec rejects fail when encoded). */
export function toDocument(map: YamlMap, resolve?: (s: string) => RValue): RDocument {
  const doc: RDocument = {};
  for (const [k, v] of Object.entries(map)) {
    Object.defineProperty(doc, k, { value: toValue(v, resolve), enumerable: true, writable: true, configurable: true });
  }
  return doc;
}

/** Plain JSON text of a YAML value (floats keep a fraction so they stay float64). */
export function toJson(yaml: Yaml): string {
  if (yaml === null) {
    return 'null';
  }
  switch (typeof yaml) {
    case 'boolean':
      return String(yaml);
    case 'bigint':
      return yaml.toString();
    case 'number': {
      const t = String(yaml);
      return /[.eE]/.test(t) || !Number.isFinite(yaml) ? t : `${t}.0`;
    }
    case 'string':
      return JSON.stringify(yaml);
    default:
      break;
  }
  if (Array.isArray(yaml)) {
    return `[${yaml.map(toJson).join(',')}]`;
  }
  return `{${Object.entries(yaml)
    .map(([k, v]) => `${JSON.stringify(k)}:${toJson(v)}`)
    .join(',')}}`;
}

/** How an expectation is compared (README §5). */
export interface MatchMode {
  readonly subset: boolean;
  readonly ordered: boolean;
  readonly fieldOrder: boolean;
}

function json(v: RValue | undefined): string {
  if (v === undefined) {
    return 'missing';
  }
  try {
    return toExtJson(v);
  } catch {
    return String(v);
  }
}

function isDoc(v: RValue | undefined): v is RDocument {
  return v !== undefined && typeOf(v) === 'object';
}

/** The README §5 expectation matcher. */
export class Matcher {
  private readonly substitute: (s: string) => string;
  private readonly resolveRef: (s: string) => RValue | undefined;

  constructor(substitute: (s: string) => string, resolveRef: (s: string) => RValue | undefined) {
    this.substitute = substitute;
    this.resolveRef = resolveRef;
  }

  /** Undefined when `actual` matches, else why not. */
  result(expected: Yaml, actual: RValue, mode: MatchMode): string | undefined {
    if (!mode.ordered && Array.isArray(expected) && Array.isArray(actual)) {
      // README §5: with match: subset an unordered result list may hold extra rows.
      if (mode.subset ? actual.length < expected.length : actual.length !== expected.length) {
        return `expected ${expected.length} rows, got ${actual.length}: ${json(actual)}`;
      }
      const left = [...actual];
      for (const e of expected) {
        const i = left.findIndex((a) => this.why(e, a, mode, '') === undefined);
        if (i < 0) {
          return `no row matches ${toJson(e)} in ${json(actual)}`;
        }
        left.splice(i, 1);
      }
      return undefined;
    }
    return this.why(expected, actual, mode, '$');
  }

  private why(e: Yaml, a: RValue | undefined, mode: MatchMode, at: string): string | undefined {
    const fail = (what: string): string => `${at}: ${what} (actual ${json(a)})`;
    if (e === '$$any') {
      return undefined;
    }
    if (typeof e === 'string' && e.startsWith('$$ref:')) {
      const r = this.resolveRef(e);
      return a !== undefined && r !== undefined && valueEquals(a, r) ? undefined : fail(`expected ${json(r)}`);
    }
    if (typeof e === 'string') {
      const want = this.substitute(e);
      return typeof a === 'string' && a === want ? undefined : fail(`expected "${want}"`);
    }
    if (e === null) {
      return a === null ? undefined : fail('expected null');
    }
    if (typeof e === 'boolean') {
      return a === e ? undefined : fail(`expected ${e}`);
    }
    if (typeof e === 'bigint') {
      return typeof a === 'bigint' && a === e ? undefined : fail(`expected int64 ${e}`);
    }
    if (typeof e === 'number') {
      return typeof a === 'number' && valueEquals(a, e) ? undefined : fail(`expected float64 ${e}`);
    }
    if (Array.isArray(e)) {
      if (!Array.isArray(a) || a.length !== e.length) {
        return fail(`expected an array of ${e.length}`);
      }
      for (let i = 0; i < e.length; i++) {
        const inner = this.why(e[i]!, a[i], mode, `${at}[${i}]`);
        if (inner !== undefined) {
          return inner;
        }
      }
      return undefined;
    }
    const keys = Object.keys(e);
    if (keys.length === 1 && keys[0] === '$$type') {
      return a !== undefined && typeName(a) === e.$$type ? undefined : fail(`expected type ${String(e.$$type)}`);
    }
    if (isWrapper(e)) {
      const v = toValue(e);
      return a !== undefined && valueEquals(a, v) ? undefined : fail(`expected ${json(v)}`);
    }
    if (!isDoc(a)) {
      return fail('expected a document');
    }
    const names = Object.keys(a).filter((n) => !SYSTEM_FIELDS.includes(n) || keys.includes(n));
    for (const k of keys) {
      if (!Object.prototype.hasOwnProperty.call(a, k)) {
        return fail(`missing field '${k}'`);
      }
      const inner = this.why(e[k]!, a[k], mode, `${at}.${k}`);
      if (inner !== undefined) {
        return inner;
      }
    }
    if (!mode.subset && names.length !== keys.length) {
      return fail(`unexpected fields ${names.filter((n) => !keys.includes(n)).join(', ')}`);
    }
    if (mode.fieldOrder && !mode.subset && names.join(',') !== keys.join(',')) {
      return fail(`field order ${names.join(',')} instead of ${keys.join(',')}`);
    }
    return undefined;
  }
}

/** The data-model §2 name of a value's type (for `{"$$type": …}`). */
export function typeName(v: RValue): string {
  return typeOf(v) ?? 'missing';
}

/**
 * README §6 normalisation of observed results: system fields removed, sorted object keys,
 * canonical extended JSON, volatile values replaced by tokens in order of first appearance:
 * objectIds and datetimes that do not appear in the test file are server-generated.
 */
export class Normalizer {
  private readonly testText: string;
  private readonly testTextLower: string;
  private readonly oids = new Map<string, string>();

  constructor(testText: string) {
    this.testText = testText;
    this.testTextLower = testText.toLowerCase();
  }

  json(v: RValue): string {
    return toExtJson(this.normalize(v));
  }

  normalize(v: RValue): RValue {
    if (v instanceof ObjectId) {
      const hex = v.toHexString();
      if (this.testTextLower.includes(hex.toLowerCase())) {
        return v;
      }
      let token = this.oids.get(hex);
      if (token === undefined) {
        token = `<oid:${this.oids.size + 1}>`;
        this.oids.set(hex, token);
      }
      return token;
    }
    if (v instanceof Date || v instanceof RDateTime) {
      const text = toExtJson(v);
      const iso = text.slice(text.indexOf(':') + 2, -2);
      return this.testText.includes(iso) ? v : '<datetime>';
    }
    if (Array.isArray(v)) {
      return v.map((x) => this.normalize(x));
    }
    if (isDoc(v)) {
      const sorted: RDocument = {};
      for (const k of Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        // System fields are always removed from observations (README §6): the expectation
        // checks them, and their values are volatile.
        if (!SYSTEM_FIELDS.includes(k)) {
          Object.defineProperty(sorted, k, { value: this.normalize(v[k] ?? null), enumerable: true, writable: true, configurable: true });
        }
      }
      return sorted;
    }
    return v;
  }
}
