// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

/** `drivers/node`. */
export const nodeDriverDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** The repository root (`drivers/node/../..`). */
export const repoRoot = path.resolve(nodeDriverDir, '..', '..');

/** The shared conformance suite (`drivers/conformance`). */
export const conformanceDir = path.join(repoRoot, 'drivers', 'conformance');

/** A YAML value of the suite: the JSON subset, YAML integers as `bigint` (int64), floats as `number`. */
export type Yaml = null | boolean | bigint | number | string | Yaml[] | YamlMap;
export interface YamlMap {
  [key: string]: Yaml;
}

/** Reads a conformance file (path relative to `drivers/conformance`) as text. */
export function readConformanceText(relative: string): string {
  return readFileSync(path.join(conformanceDir, relative), 'utf8');
}

/**
 * Parses YAML text of the suite. Integers become `bigint` so that `1` (int64) and `1.0` (float64)
 * stay distinct (README §5 "Values and matching").
 */
export function parseYaml(text: string): Yaml {
  return parse(text, { intAsBigInt: true, uniqueKeys: true }) as Yaml;
}

/** Loads a conformance YAML file (path relative to `drivers/conformance`). */
export function loadConformanceYaml(relative: string): Yaml {
  return parseYaml(readConformanceText(relative));
}

/** Loads a conformance JSON file; the JSON is parsed as YAML so integers stay `bigint`. */
export function loadConformanceJson(relative: string): Yaml {
  return parseYaml(readConformanceText(relative));
}

export function asMap(v: Yaml | undefined, what = 'value'): YamlMap {
  if (v === null || v === undefined || typeof v !== 'object' || Array.isArray(v)) {
    throw new Error(`${what} is not a mapping`);
  }
  return v;
}

export function asList(v: Yaml | undefined, what = 'value'): Yaml[] {
  if (!Array.isArray(v)) {
    throw new Error(`${what} is not a list`);
  }
  return v;
}

export function asString(v: Yaml | undefined, what = 'value'): string {
  if (typeof v !== 'string') {
    throw new Error(`${what} is not a string`);
  }
  return v;
}
