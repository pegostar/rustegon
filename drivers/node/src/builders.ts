// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Filter, update, sort, projection and index-key builders (model.yaml `builder` entries). They
 * produce the structured AST of `query_ast.proto`, never RGQL text (PD-070); the exact output is
 * pinned by drivers/conformance/ast/*.json. Builders are immutable values.
 */

import { create, type MessageInitShape } from '@bufbuild/protobuf';
import {
  AstBinaryOp,
  AstExprSchema,
  AstIsTest,
  AstOptionItemSchema,
  AstOrderItemSchema,
  AstSelectSchema,
  AstPathSchema,
  AstPopEnd,
  AstUpdateOpSchema,
  type AstExpr,
  type AstOptionItem,
  type AstOrderItem,
  type AstPath,
  type AstSelect,
  type AstUpdateOp,
} from './generated/rustegon/v1/query_ast_pb.js';
import { ValueSchema, type Value } from './generated/rustegon/v1/common_pb.js';
import { encodeValue, decodeValue, type RValue, type RDocument } from './codec/index.ts';
import { InvalidArgumentError } from './errors/errors.ts';

/** Named parameters of one request: filter values `f0, f1, …`, update values `u0, u1, …` (PD-070 rule 1). */
export class ParamSink {
  private filters = 0;
  private updates = 0;
  readonly params: Record<string, Value> = {};

  filter(value: RValue): AstExpr {
    return this.add(`f${this.filters++}`, value);
  }

  update(value: RValue): AstExpr {
    return this.add(`u${this.updates++}`, value);
  }

  private add(name: string, value: RValue): AstExpr {
    this.params[name] = toValue(value);
    return create(AstExprSchema, { kind: { case: 'param', value: { name } } });
  }
}

/** A value in the RDoc value encoding (`Value.rdoc_value`). */
export function toValue(value: RValue): Value {
  if (value === undefined) {
    throw new InvalidArgumentError('A value cannot be undefined; use null.');
  }
  return create(ValueSchema, { rdocValue: encodeValue(value) });
}

/** The decoded value of a `Value`, or undefined when absent. */
export function fromValue(value: Value | undefined): RValue | undefined {
  return value === undefined ? undefined : decodeValue(value.rdocValue);
}

/** A dotted path as AST segments; an all-digit segment after the first is an array position. */
export function astPath(path: string): AstPath {
  if (typeof path !== 'string' || path.length === 0) {
    throw new InvalidArgumentError('A path must be a non-empty string.');
  }
  const segments = path.split('.').map((p, i) => {
    if (p.length === 0) {
      throw new InvalidArgumentError(`The path '${path}' has an empty segment.`);
    }
    if (i > 0 && /^[0-9]+$/.test(p) && Number(p) <= 0xffff_ffff) {
      return { segment: { case: 'position' as const, value: Number(p) } };
    }
    return { segment: { case: 'field' as const, value: p } };
  });
  return create(AstPathSchema, { segments });
}

/** The dotted text of an AST path (index listings). */
export function pathText(path: AstPath | undefined): string {
  return (path?.segments ?? []).map((s) => (s.segment.case === 'position' ? String(s.segment.value) : String(s.segment.value ?? ''))).join('.');
}

export function pathExpr(path: AstPath): AstExpr {
  return create(AstExprSchema, { kind: { case: 'path', value: { path } } });
}

export function intLiteral(v: bigint | number): AstExpr {
  return create(AstExprSchema, { kind: { case: 'literal', value: { value: { case: 'intValue', value: BigInt(v) } } } });
}

/** `OPTIONS (allow_full_scan_write = true)`: the explicit request of an empty-filter write (rule 5). */
export function allowFullScanWrite(): AstOptionItem {
  return create(AstOptionItemSchema, {
    name: 'allow_full_scan_write',
    value: { kind: { case: 'literal', value: { value: { case: 'boolValue', value: true } } } },
  });
}

type FilterNode =
  | { kind: 'empty' }
  | { kind: 'id'; value: RValue }
  | { kind: 'binary'; path: string; op: AstBinaryOp; value: RValue }
  | { kind: 'exists'; path: string; exists: boolean }
  | { kind: 'isNull'; path: string }
  | { kind: 'elemMatch'; path: string; child: Filter }
  | { kind: 'and' | 'or'; children: readonly Filter[] }
  | { kind: 'not'; child: Filter };

/** A filter (WHERE condition); `Filter.empty` matches every document. */
export class Filter {
  /** @internal */
  readonly node: FilterNode;

  private constructor(node: FilterNode) {
    this.node = node;
  }

  static readonly empty: Filter = new Filter({ kind: 'empty' });

  static id(id: RValue): Filter {
    return new Filter({ kind: 'id', value: checked(id) });
  }

  static eq(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.EQ, value);
  }

  static ne(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.NE, value);
  }

  static gt(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.GT, value);
  }

  static gte(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.GE, value);
  }

  static lt(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.LT, value);
  }

  static lte(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.LE, value);
  }

  static in(path: string, values: readonly RValue[]): Filter {
    return Filter.binary(path, AstBinaryOp.IN, list(values));
  }

  static nin(path: string, values: readonly RValue[]): Filter {
    return Filter.binary(path, AstBinaryOp.NOT_IN, list(values));
  }

  /** `exists = true` is `IS NOT MISSING`, `false` is `IS MISSING`. */
  static exists(path: string, exists = true): Filter {
    astPath(path);
    return new Filter({ kind: 'exists', path, exists });
  }

  /** `IS NULL` (null or missing). */
  static isNull(path: string): Filter {
    astPath(path);
    return new Filter({ kind: 'isNull', path });
  }

  static contains(path: string, value: RValue): Filter {
    return Filter.binary(path, AstBinaryOp.CONTAINS, value);
  }

  static containsAny(path: string, values: readonly RValue[]): Filter {
    return Filter.binary(path, AstBinaryOp.CONTAINS_ANY, list(values));
  }

  static containsAll(path: string, values: readonly RValue[]): Filter {
    return Filter.binary(path, AstBinaryOp.CONTAINS_ALL, list(values));
  }

  /** `ELEM MATCH (path, <filter on the element>)`. */
  static elemMatch(path: string, filter: Filter): Filter {
    astPath(path);
    if (!(filter instanceof Filter) || filter.isEmpty) {
      throw new InvalidArgumentError('elemMatch needs a non-empty element filter.');
    }
    return new Filter({ kind: 'elemMatch', path, child: filter });
  }

  static like(path: string, pattern: string): Filter {
    return Filter.binary(path, AstBinaryOp.LIKE, checkedString(pattern));
  }

  static regex(path: string, regex: string): Filter {
    return Filter.binary(path, AstBinaryOp.MATCHES, checkedString(regex));
  }

  static and(...filters: Filter[]): Filter {
    return Filter.nary('and', filters);
  }

  static or(...filters: Filter[]): Filter {
    return Filter.nary('or', filters);
  }

  static not(filter: Filter): Filter {
    if (!(filter instanceof Filter) || filter.isEmpty) {
      throw new InvalidArgumentError('not() of the empty filter matches nothing; use a real condition.');
    }
    return new Filter({ kind: 'not', child: filter });
  }

  /** `this AND other`. */
  and(other: Filter): Filter {
    return Filter.and(this, other);
  }

  /** `this OR other`. */
  or(other: Filter): Filter {
    return Filter.or(this, other);
  }

  get isEmpty(): boolean {
    return this.node.kind === 'empty';
  }

  /** The id of a filter that is exactly `Filter.id(v)` (by-id routing, PD-070 rule 3). */
  get idValue(): RValue | undefined {
    return this.node.kind === 'id' ? this.node.value : undefined;
  }

  /** @internal The AST of the filter, or undefined for the empty filter. */
  toAst(sink: ParamSink): AstExpr | undefined {
    const n = this.node;
    switch (n.kind) {
      case 'empty':
        return undefined;
      case 'id':
        return binary('_id', AstBinaryOp.EQ, sink.filter(n.value));
      case 'binary':
        return binary(n.path, n.op, sink.filter(n.value));
      case 'exists':
        return create(AstExprSchema, { kind: { case: 'is', value: { expr: pathExpr(astPath(n.path)), test: AstIsTest.MISSING, negated: n.exists } } });
      case 'isNull':
        return create(AstExprSchema, { kind: { case: 'is', value: { expr: pathExpr(astPath(n.path)), test: AstIsTest.NULL } } });
      case 'elemMatch':
        return create(AstExprSchema, { kind: { case: 'elemMatch', value: { path: astPath(n.path), predicate: n.child.toAst(sink) } } });
      case 'not':
        return create(AstExprSchema, { kind: { case: 'not', value: { expr: n.child.toAst(sink) } } });
      case 'and':
      case 'or': {
        const args = n.children.map((c) => c.toAst(sink)).filter((e): e is AstExpr => e !== undefined);
        return create(AstExprSchema, { kind: { case: n.kind, value: { args } } });
      }
    }
  }

  private static binary(path: string, op: AstBinaryOp, value: RValue): Filter {
    astPath(path);
    return new Filter({ kind: 'binary', path, op, value: checked(value) });
  }

  private static nary(kind: 'and' | 'or', filters: Filter[]): Filter {
    const flat: Filter[] = [];
    for (const f of filters) {
      if (!(f instanceof Filter)) {
        throw new InvalidArgumentError(`${kind}() takes filters.`);
      }
      if (f.isEmpty) {
        continue;
      }
      // The server accepts only canonical ASTs: an `and` inside an `and` must already be flat
      // (PD-070 rule 2; RGN-1010 otherwise).
      if (f.node.kind === kind) {
        flat.push(...f.node.children);
      } else {
        flat.push(f);
      }
    }
    if (flat.length === 0) {
      return Filter.empty;
    }
    if (flat.length === 1) {
      return flat[0] ?? Filter.empty;
    }
    return new Filter({ kind, children: flat });
  }
}

function binary(path: string, op: AstBinaryOp, right: AstExpr): AstExpr {
  return create(AstExprSchema, { kind: { case: 'binary', value: { op, left: pathExpr(astPath(path)), right } } });
}

function checked(value: RValue): RValue {
  if (value === undefined) {
    throw new InvalidArgumentError('A filter value cannot be undefined; use null.');
  }
  return value;
}

function checkedString(v: string): string {
  if (typeof v !== 'string') {
    throw new InvalidArgumentError('A pattern must be a string.');
  }
  return v;
}

function list(values: readonly RValue[]): RValue[] {
  if (!Array.isArray(values)) {
    throw new InvalidArgumentError('A list of values is required.');
  }
  return values.map(checked);
}

type UpdateMaker = (sink: ParamSink) => AstUpdateOp;

/** An update: one or more operators applied in order (`Update.set(…).inc(…)`). */
export class Update {
  private readonly ops: readonly UpdateMaker[];

  private constructor(ops: readonly UpdateMaker[]) {
    this.ops = ops;
  }

  static set(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => ({ kind: { case: 'set', value: { items: [{ path: p, value: v }] } } }));
  }

  static unset(path: string): Update {
    const p = astPath(path);
    return new Update([() => create(AstUpdateOpSchema, { kind: { case: 'unset', value: { paths: [p] } } })]);
  }

  static inc(path: string, amount: RValue): Update {
    return Update.one(path, amount, (p, v) => ({ kind: { case: 'inc', value: { path: p, by: v } } }));
  }

  static mul(path: string, factor: RValue): Update {
    return Update.one(path, factor, (p, v) => ({ kind: { case: 'mul', value: { path: p, by: v } } }));
  }

  static min(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => ({ kind: { case: 'min', value: { path: p, value: v } } }));
  }

  static max(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => ({ kind: { case: 'max', value: { path: p, value: v } } }));
  }

  static push(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => ({ kind: { case: 'push', value: { path: p, value: v } } }));
  }

  static addToSet(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => ({ kind: { case: 'addToSet', value: { path: p, value: v } } }));
  }

  /** Removes the elements equal to `value`: `PULL p WHERE <last field of p> = $u`. */
  static pull(path: string, value: RValue): Update {
    return Update.one(path, value, (p, v) => {
      // Inside the predicate the element is addressed by the array's own field name (README §4,
      // ast/updates.json pull_nested_path).
      const last = p.segments[p.segments.length - 1]?.segment;
      const element = create(AstPathSchema, { segments: [{ segment: { case: 'field', value: String(last?.value ?? '') } }] });
      return { kind: { case: 'pull', value: { path: p, where: create(AstExprSchema, { kind: { case: 'binary', value: { op: AstBinaryOp.EQ, left: pathExpr(element), right: v } } }) } } };
    });
  }

  static popFirst(path: string): Update {
    return Update.pop(path, AstPopEnd.FIRST);
  }

  static popLast(path: string): Update {
    return Update.pop(path, AstPopEnd.LAST);
  }

  static rename(from: string, to: string): Update {
    const f = astPath(from);
    const t = astPath(to);
    return new Update([() => create(AstUpdateOpSchema, { kind: { case: 'rename', value: { from: f, to: t } } })]);
  }

  static currentDate(path: string): Update {
    const p = astPath(path);
    return new Update([() => create(AstUpdateOpSchema, { kind: { case: 'currentDate', value: { path: p } } })]);
  }

  /** The operators of every update, in order. */
  static combine(...updates: Update[]): Update {
    const ops: UpdateMaker[] = [];
    for (const u of updates) {
      if (!(u instanceof Update)) {
        throw new InvalidArgumentError('combine() takes updates.');
      }
      ops.push(...u.ops);
    }
    return new Update(ops);
  }

  /** @internal The whole-document replacement (`REPLACE WITH $u0`, sole operation). */
  static replace(document: RDocument): Update {
    return new Update([(s) => create(AstUpdateOpSchema, { kind: { case: 'replace', value: { value: s.update(document) } } })]);
  }

  set(path: string, value: RValue): Update {
    return Update.combine(this, Update.set(path, value));
  }

  unset(path: string): Update {
    return Update.combine(this, Update.unset(path));
  }

  inc(path: string, amount: RValue): Update {
    return Update.combine(this, Update.inc(path, amount));
  }

  mul(path: string, factor: RValue): Update {
    return Update.combine(this, Update.mul(path, factor));
  }

  min(path: string, value: RValue): Update {
    return Update.combine(this, Update.min(path, value));
  }

  max(path: string, value: RValue): Update {
    return Update.combine(this, Update.max(path, value));
  }

  push(path: string, value: RValue): Update {
    return Update.combine(this, Update.push(path, value));
  }

  addToSet(path: string, value: RValue): Update {
    return Update.combine(this, Update.addToSet(path, value));
  }

  pull(path: string, value: RValue): Update {
    return Update.combine(this, Update.pull(path, value));
  }

  popFirst(path: string): Update {
    return Update.combine(this, Update.popFirst(path));
  }

  popLast(path: string): Update {
    return Update.combine(this, Update.popLast(path));
  }

  rename(from: string, to: string): Update {
    return Update.combine(this, Update.rename(from, to));
  }

  currentDate(path: string): Update {
    return Update.combine(this, Update.currentDate(path));
  }

  get count(): number {
    return this.ops.length;
  }

  /** @internal */
  toAst(sink: ParamSink): AstUpdateOp[] {
    if (this.ops.length === 0) {
      throw new InvalidArgumentError('An update needs at least one operator.');
    }
    return this.ops.map((op) => op(sink));
  }

  private static one(path: string, value: RValue, make: (p: AstPath, v: AstExpr) => MessageInitShape<typeof AstUpdateOpSchema>): Update {
    const p = astPath(path);
    if (value === undefined) {
      throw new InvalidArgumentError('An update value cannot be undefined; use null or unset().');
    }
    return new Update([(s) => create(AstUpdateOpSchema, make(p, s.update(value)))]);
  }

  private static pop(path: string, end: AstPopEnd): Update {
    const p = astPath(path);
    return new Update([() => create(AstUpdateOpSchema, { kind: { case: 'pop', value: { path: p, end } } })]);
  }
}

/** A sort order (`ORDER BY`). */
export class Sort {
  private readonly keys: readonly (readonly [string, boolean])[];

  private constructor(keys: readonly (readonly [string, boolean])[]) {
    this.keys = keys;
  }

  static ascending(...paths: string[]): Sort {
    return Sort.of(paths, false);
  }

  static descending(...paths: string[]): Sort {
    return Sort.of(paths, true);
  }

  thenAscending(...paths: string[]): Sort {
    return new Sort([...this.keys, ...Sort.of(paths, false).keys]);
  }

  thenDescending(...paths: string[]): Sort {
    return new Sort([...this.keys, ...Sort.of(paths, true).keys]);
  }

  /** @internal */
  toAst(): AstOrderItem[] {
    return this.keys.map(([p, descending]) => create(AstOrderItemSchema, { expr: pathExpr(astPath(p)), descending }));
  }

  private static of(paths: string[], descending: boolean): Sort {
    if (paths.length === 0) {
      throw new InvalidArgumentError('A sort needs at least one path.');
    }
    for (const p of paths) {
      astPath(p);
    }
    return new Sort(paths.map((p) => [p, descending] as const));
  }
}

/** A projection (`SELECT` of a find): only some fields, or all but some. */
export class Projection {
  private readonly paths: readonly string[];
  private readonly exclude: boolean;

  private constructor(paths: readonly string[], exclude: boolean) {
    this.paths = paths;
    this.exclude = exclude;
  }

  static include(...paths: string[]): Projection {
    return Projection.of(paths, false);
  }

  static exclude(...paths: string[]): Projection {
    return Projection.of(paths, true);
  }

  /** @internal */
  toAst(): AstSelect {
    const items = this.paths.map((p) =>
      this.exclude
        ? { kind: { case: 'exclude' as const, value: { path: astPath(p) } } }
        : { kind: { case: 'expr' as const, value: { expr: pathExpr(astPath(p)) } } },
    );
    return create(AstSelectSchema, { kind: { case: 'items', value: { items } } });
  }

  private static of(paths: string[], exclude: boolean): Projection {
    if (paths.length === 0) {
      throw new InvalidArgumentError('A projection needs at least one path.');
    }
    for (const p of paths) {
      astPath(p);
    }
    return new Projection(paths, exclude);
  }
}

/** The keys of an index, in order. */
export class IndexKeys {
  readonly keys: readonly { readonly path: string; readonly descending: boolean }[];

  private constructor(keys: readonly { readonly path: string; readonly descending: boolean }[]) {
    this.keys = keys;
  }

  static ascending(...paths: string[]): IndexKeys {
    return IndexKeys.of(paths, false);
  }

  static descending(...paths: string[]): IndexKeys {
    return IndexKeys.of(paths, true);
  }

  thenAscending(...paths: string[]): IndexKeys {
    return new IndexKeys([...this.keys, ...IndexKeys.of(paths, false).keys]);
  }

  thenDescending(...paths: string[]): IndexKeys {
    return new IndexKeys([...this.keys, ...IndexKeys.of(paths, true).keys]);
  }

  private static of(paths: string[], descending: boolean): IndexKeys {
    if (paths.length === 0) {
      throw new InvalidArgumentError('An index needs at least one key.');
    }
    for (const p of paths) {
      astPath(p);
    }
    return new IndexKeys(paths.map((path) => ({ path, descending })));
  }
}
