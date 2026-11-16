// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/** The builder DSL of the conformance suite (README §4) translated into the driver's builders. */

import { Filter, IndexKeys, Projection, Sort, Update, type RDocument, type RValue } from '../../../src/index.ts';
import { asList, asMap, asString, type Yaml, type YamlMap } from '../files.ts';
import { toDocument, toValue } from './values.ts';

export class Dsl {
  private readonly resolve: (s: string) => RValue;

  constructor(resolve: (s: string) => RValue = (s) => s) {
    this.resolve = resolve;
  }

  value(yaml: Yaml): RValue {
    return toValue(yaml, this.resolve);
  }

  document(yaml: Yaml): RDocument {
    return toDocument(asMap(yaml, 'document'), this.resolve);
  }

  filter(yaml: Yaml): Filter {
    const map = asMap(yaml, 'filter');
    const entries = Object.entries(map);
    if (entries.length === 0) {
      return Filter.empty;
    }
    const [op, a] = entries[0]!;
    const l = (): Yaml[] => asList(a, op);
    const p = (): string => asString(l()[0], `${op} path`);
    const v = (): RValue => this.value(l()[1] ?? null);
    const values = (): RValue[] => asList(l()[1], `${op} values`).map((x) => this.value(x));
    switch (op) {
      case 'eq':
        return Filter.eq(p(), v());
      case 'ne':
        return Filter.ne(p(), v());
      case 'gt':
        return Filter.gt(p(), v());
      case 'gte':
        return Filter.gte(p(), v());
      case 'lt':
        return Filter.lt(p(), v());
      case 'lte':
        return Filter.lte(p(), v());
      case 'in':
        return Filter.in(p(), values());
      case 'nin':
        return Filter.nin(p(), values());
      case 'exists':
        return Filter.exists(p(), l()[1] as boolean);
      case 'isNull':
        return Filter.isNull(asString(a));
      case 'contains':
        return Filter.contains(p(), v());
      case 'containsAny':
        return Filter.containsAny(p(), values());
      case 'containsAll':
        return Filter.containsAll(p(), values());
      case 'elemMatch':
        return Filter.elemMatch(p(), this.filter(l()[1] ?? {}));
      case 'like':
        return Filter.like(p(), asString(l()[1]));
      case 'regex':
        return Filter.regex(p(), asString(l()[1]));
      case 'and':
        return Filter.and(...l().map((f) => this.filter(f)));
      case 'or':
        return Filter.or(...l().map((f) => this.filter(f)));
      case 'not':
        return Filter.not(this.filter(a ?? {}));
      case 'id':
        return Filter.id(this.value(a ?? null));
      default:
        throw new Error(`unknown filter operator '${op}'`);
    }
  }

  /** A DSL update: one-key objects, chained in order. */
  update(yaml: Yaml): Update {
    let result: Update | undefined;
    for (const item of asList(yaml, 'update')) {
      const [op, a] = Object.entries(asMap(item, 'update operator'))[0]!;
      const l = (): Yaml[] => asList(a, op);
      const p = (): string => asString(l()[0], `${op} path`);
      const v = (): RValue => this.value(l()[1] ?? null);
      let next: Update;
      switch (op) {
        case 'set':
          next = Update.set(p(), v());
          break;
        case 'unset':
          next = Update.unset(asString(a));
          break;
        case 'inc':
          next = Update.inc(p(), v());
          break;
        case 'mul':
          next = Update.mul(p(), v());
          break;
        case 'min':
          next = Update.min(p(), v());
          break;
        case 'max':
          next = Update.max(p(), v());
          break;
        case 'push':
          next = Update.push(p(), v());
          break;
        case 'addToSet':
          next = Update.addToSet(p(), v());
          break;
        case 'pull':
          next = Update.pull(p(), v());
          break;
        case 'pop':
          next = asString(l()[1]) === 'first' ? Update.popFirst(p()) : Update.popLast(p());
          break;
        case 'rename':
          next = Update.rename(p(), asString(l()[1]));
          break;
        case 'currentDate':
          next = Update.currentDate(asString(a));
          break;
        default:
          throw new Error(`unknown update operator '${op}'`);
      }
      result = result === undefined ? next : Update.combine(result, next);
    }
    if (result === undefined) {
      throw new Error('empty update');
    }
    return result;
  }
}

export function sortOf(keys: Yaml): Sort {
  let sort: Sort | undefined;
  for (const k of asList(keys, 'sort').map((x) => asString(x))) {
    const desc = k.startsWith('-');
    const path = desc ? k.slice(1) : k;
    sort = sort === undefined ? (desc ? Sort.descending(path) : Sort.ascending(path)) : desc ? sort.thenDescending(path) : sort.thenAscending(path);
  }
  if (sort === undefined) {
    throw new Error('empty sort');
  }
  return sort;
}

export function projectionOf(p: YamlMap): Projection {
  return p.include !== undefined
    ? Projection.include(...asList(p.include).map((x) => asString(x)))
    : Projection.exclude(...asList(p.exclude).map((x) => asString(x)));
}

export function keysOf(keys: Yaml): IndexKeys {
  let result: IndexKeys | undefined;
  for (const k of asList(keys, 'keys').map((x) => asMap(x))) {
    const path = asString(k.path);
    const desc = k.descending === true;
    result = result === undefined ? (desc ? IndexKeys.descending(path) : IndexKeys.ascending(path)) : desc ? result.thenDescending(path) : result.thenAscending(path);
  }
  if (result === undefined) {
    throw new Error('no keys');
  }
  return result;
}
