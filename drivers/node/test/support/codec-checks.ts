// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * The codec vector checks of the conformance README §3 (`codec/values.yaml`, `documents.yaml`,
 * `invalid.yaml`), shared by the unit tests (TC-DRV-NODE-001, one subtest per vector) and the
 * conformance runner operations `checkValueVectors` / `checkDocumentVectors` /
 * `checkInvalidVectors` (client/vectors.yaml).
 */

import {
  decodeDocument,
  decodeValue,
  encodeDocument,
  encodeValue,
  isCanonicalFlagSet,
  nameHash16,
  parseExtJson,
  parseExtJsonDocument,
  toExtJson,
} from '../../src/codec/index.ts';
import { RDocError } from '../../src/errors/errors.ts';
import { asList, asMap, asString, loadConformanceYaml, type YamlMap } from './files.ts';

/** One vector: `<file>#<section>/<name>` and its check (throws an Error when it fails). */
export interface CodecVector {
  readonly id: string;
  readonly check: () => void;
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const bytes = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));

function expectEqual(what: string, actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error(`${what}: expected ${expected}, got ${actual}`);
  }
}

function expectRejected(v: YamlMap, parse: () => unknown): void {
  const code = Number(v['code']);
  try {
    parse();
  } catch (e) {
    if (!(e instanceof RDocError)) {
      throw new Error(`expected RDocError ${code}, got ${String(e)}`, { cause: e });
    }
    expectEqual('error code', String(e.code), String(code));
    return;
  }
  throw new Error(`expected RDocError ${code}, but the input was accepted`);
}

function checkValue(v: YamlMap): void {
  const h = asString(v['hex']);
  if (v['decode_only'] !== true) {
    expectEqual('encode(input)', hex(encodeValue(parseExtJson(asString(v['input'])))), h);
    expectEqual('encode(ext_json)', hex(encodeValue(parseExtJson(asString(v['ext_json'])))), h);
  }
  const decoded = decodeValue(bytes(h));
  expectEqual('canonical JSON', toExtJson(decoded), asString(v['ext_json']));
  expectEqual('extended JSON', toExtJson(decoded, { extended: true }), asString(v['extended_json']));
}

function checkNoncanonicalValue(v: YamlMap): void {
  const decoded = decodeValue(bytes(asString(v['hex'])));
  expectEqual('re-encoded', hex(encodeValue(decoded)), asString(v['canonical_hex']));
  expectEqual('canonical JSON', toExtJson(decoded), asString(v['ext_json']));
}

function checkDocument(v: YamlMap): void {
  const h = asString(v['hex']);
  const json = asString(v['ext_json']);
  if (v['decode_only'] !== true) {
    expectEqual('encode(ext_json)', hex(encodeDocument(parseExtJsonDocument(json))), h);
  }
  if (!isCanonicalFlagSet(bytes(h))) {
    throw new Error('canonical flag not set');
  }
  const decoded = decodeDocument(bytes(h));
  expectEqual('canonical JSON', toExtJson(decoded), json);
  expectEqual('re-encoded', hex(encodeDocument(decoded)), h);
  for (const entry of v['name_hash16'] == null ? [] : asList(v['name_hash16'])) {
    const e = asMap(entry);
    const expected = parseInt(asString(e['hash']), 16);
    expectEqual(`name_hash16(${asString(e['name'])})`, nameHash16(asString(e['name'])).toString(16).padStart(4, '0'), asString(e['hash']));
    // The index stores the hash little-endian: it must be in the encoded document.
    const le = hex(Uint8Array.of(expected & 0xff, expected >> 8));
    if (!(h.match(/../g) ?? []).join(' ').includes(le.match(/../g)?.join(' ') ?? '')) {
      throw new Error(`hash ${asString(e['hash'])} not in the index`);
    }
  }
}

function checkNoncanonicalDocument(v: YamlMap): void {
  const h = bytes(asString(v['hex']));
  if (isCanonicalFlagSet(h)) {
    throw new Error('canonical flag set on a non-canonical vector');
  }
  const decoded = decodeDocument(h);
  expectEqual('re-encoded', hex(encodeDocument(decoded)), asString(v['canonical_hex']));
  expectEqual('canonical JSON', toExtJson(decoded), asString(v['ext_json']));
}

function checkerOf(file: string, section: string): ((v: YamlMap) => void) | undefined {
  switch (`${file}#${section}`) {
    case 'values.yaml#values':
      return checkValue;
    case 'values.yaml#noncanonical':
      return checkNoncanonicalValue;
    case 'documents.yaml#documents':
      return checkDocument;
    case 'documents.yaml#noncanonical':
      return checkNoncanonicalDocument;
    case 'invalid.yaml#documents':
      return (v) => expectRejected(v, () => decodeDocument(bytes(asString(v['hex']))));
    case 'invalid.yaml#values':
      return (v) => expectRejected(v, () => decodeValue(bytes(asString(v['hex']))));
    case 'invalid.yaml#json':
      return (v) => {
        const json = asString(v['json']);
        const kind = asString(v['kind']);
        if (kind !== 'document' && kind !== 'value') {
          throw new Error(`unknown kind '${kind}'`);
        }
        expectRejected(v, () => (kind === 'document' ? parseExtJsonDocument(json) : parseExtJson(json)));
      };
    default:
      return undefined;
  }
}

/** Every vector of `relative` (e.g. `codec/values.yaml`), one entry per `<section>/<name>`. */
export function codecVectors(relative: string): CodecVector[] {
  const file = relative.slice(relative.lastIndexOf('/') + 1);
  const root = asMap(loadConformanceYaml(relative), relative);
  if (root['version'] !== 1n) {
    throw new Error(`${relative}: unsupported version`);
  }
  const vectors: CodecVector[] = [];
  for (const [section, entries] of Object.entries(root)) {
    if (!Array.isArray(entries)) {
      continue;
    }
    const check = checkerOf(file, section);
    if (check === undefined) {
      throw new Error(`no runner for ${file}#${section}`);
    }
    for (const e of entries) {
      const v = asMap(e);
      vectors.push({ id: `${file}#${section}/${asString(v['name'])}`, check: () => check(v) });
    }
  }
  return vectors;
}

function runAll(relative: string): void {
  for (const v of codecVectors(relative)) {
    try {
      v.check();
    } catch (e) {
      throw new Error(`${v.id}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    }
  }
}

/** Runner operation `checkValueVectors {file}`. */
export function checkValueVectors(file: string): void {
  runAll(file);
}

/** Runner operation `checkDocumentVectors {file}`. */
export function checkDocumentVectors(file: string): void {
  runAll(file);
}

/** Runner operation `checkInvalidVectors {file}`. */
export function checkInvalidVectors(file: string): void {
  runAll(file);
}
