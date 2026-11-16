# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Filter, update, sort, projection and bulk builders (python-driver.md §4, PD-070).

Builders produce the structured AST of ``proto/rustegon/v1/query_ast.proto``, never RGQL text:
every value becomes a named parameter (``f0, f1, …`` for filters, ``u0, u1, …`` for updates, in
depth-first left-to-right order), field names become path segments, nested ``and``/``or`` are
flattened (the server accepts only the canonical AST). The exact output is pinned by
``drivers/conformance/ast/*.json`` (TC-DRV-PY-012).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from rustegon import rdoc
from rustegon._pb import common_pb2
from rustegon._pb import query_ast_pb2 as ast

__all__ = [
    "BulkOperation",
    "Filter",
    "IndexKey",
    "Projection",
    "Sort",
    "Update",
    "Updates",
]


# ------------------------------------------------------------------------- AST helpers


class ParamSink:
    """Names and encodes the parameters of one statement (``prefix`` + counter)."""

    def __init__(self, prefix: str, params: dict[str, common_pb2.Value] | None = None) -> None:
        self.prefix = prefix
        self.params: dict[str, common_pb2.Value] = {} if params is None else params
        self._next = 0

    def add(self, value: Any) -> ast.AstExpr:
        name = f"{self.prefix}{self._next}"
        self._next += 1
        self.params[name] = common_pb2.Value(rdoc_value=rdoc.encode_value(value))
        return ast.AstExpr(param=ast.AstParam(name=name))


def path(dotted: str) -> ast.AstPath:
    """``a.b.0`` -> segments ``a``, ``b``, position 0 (an all-digit segment after the first)."""
    if not isinstance(dotted, str) or not dotted:
        raise ValueError("a field path must not be empty")
    p = ast.AstPath()
    for i, s in enumerate(dotted.split(".")):
        if not s:
            raise ValueError(f"empty segment in the field path {dotted!r}")
        if i > 0 and s.isascii() and s.isdigit() and len(s) <= 9:
            p.segments.append(ast.AstSegment(position=int(s)))
        else:
            p.segments.append(ast.AstSegment(field=s))
    return p


def path_expr(dotted: str) -> ast.AstExpr:
    return ast.AstExpr(path=ast.AstPathExpr(path=path(dotted)))


def int_literal(v: int) -> ast.AstExpr:
    return ast.AstExpr(literal=ast.AstLiteral(int_value=v))


def dotted(p: ast.AstPath) -> str:
    return ".".join(str(s.position) if s.WhichOneof("segment") == "position" else s.field for s in p.segments)


# ------------------------------------------------------------------------- filters

_BINARY: Final = {
    "id": ast.AST_BINARY_OP_EQ,
    "eq": ast.AST_BINARY_OP_EQ,
    "ne": ast.AST_BINARY_OP_NE,
    "gt": ast.AST_BINARY_OP_GT,
    "gte": ast.AST_BINARY_OP_GE,
    "lt": ast.AST_BINARY_OP_LT,
    "lte": ast.AST_BINARY_OP_LE,
    "in": ast.AST_BINARY_OP_IN,
    "nin": ast.AST_BINARY_OP_NOT_IN,
    "contains": ast.AST_BINARY_OP_CONTAINS,
    "containsAny": ast.AST_BINARY_OP_CONTAINS_ANY,
    "containsAll": ast.AST_BINARY_OP_CONTAINS_ALL,
    "like": ast.AST_BINARY_OP_LIKE,
    "regex": ast.AST_BINARY_OP_MATCHES,
}


class Filter:
    """An immutable filter; combine with ``&``, ``|``, ``~`` or ``and_``/``or_``/``not_``."""

    __slots__ = ("_args", "_op", "_path", "_value")

    def __init__(self, op: str, path: str | None = None, value: Any = None, args: Sequence[Filter] = ()) -> None:
        self._op = op
        self._path = path
        self._value = value
        self._args = tuple(args)

    # -- factories (model ids Filter.*)
    @staticmethod
    def empty() -> Filter:
        """Matches every document."""
        return _EMPTY

    @staticmethod
    def id(value: Any) -> Filter:
        """``_id = value``; routes single-document writes to the by-id RPCs."""
        return Filter("id", None, value)

    @staticmethod
    def eq(path: str, value: Any) -> Filter:
        return Filter._field("eq", path, value)

    @staticmethod
    def ne(path: str, value: Any) -> Filter:
        return Filter._field("ne", path, value)

    @staticmethod
    def gt(path: str, value: Any) -> Filter:
        return Filter._field("gt", path, value)

    @staticmethod
    def gte(path: str, value: Any) -> Filter:
        return Filter._field("gte", path, value)

    @staticmethod
    def lt(path: str, value: Any) -> Filter:
        return Filter._field("lt", path, value)

    @staticmethod
    def lte(path: str, value: Any) -> Filter:
        return Filter._field("lte", path, value)

    @staticmethod
    def in_(path: str, values: Iterable[Any]) -> Filter:
        return Filter._field("in", path, list(values))

    @staticmethod
    def nin(path: str, values: Iterable[Any]) -> Filter:
        return Filter._field("nin", path, list(values))

    @staticmethod
    def exists(path: str, exists: bool = True) -> Filter:
        """``path IS NOT MISSING`` (``exists=False``: ``IS MISSING``); null is present."""
        return Filter._field("exists", path, bool(exists))

    @staticmethod
    def is_null(path: str) -> Filter:
        """``path IS NULL``: null or missing."""
        return Filter._field("isNull", path, None)

    @staticmethod
    def contains(path: str, value: Any) -> Filter:
        return Filter._field("contains", path, value)

    @staticmethod
    def contains_any(path: str, values: Iterable[Any]) -> Filter:
        return Filter._field("containsAny", path, list(values))

    @staticmethod
    def contains_all(path: str, values: Iterable[Any]) -> Filter:
        return Filter._field("containsAll", path, list(values))

    @staticmethod
    def elem_match(path: str, filter: Filter) -> Filter:  # noqa: A002 - mirrors the model
        """An array element matching ``filter`` (paths inside are relative to the element)."""
        if not isinstance(filter, Filter):
            raise TypeError("elem_match takes a Filter")
        return Filter("elemMatch", Filter._check(path), None, (filter,))

    @staticmethod
    def like(path: str, pattern: str) -> Filter:
        """SQL ``LIKE`` on the whole string (``%`` and ``_``)."""
        return Filter._field("like", path, pattern)

    @staticmethod
    def regex(path: str, pattern: str) -> Filter:
        """Unanchored regular expression (Rust ``regex`` syntax)."""
        return Filter._field("regex", path, pattern)

    @staticmethod
    def and_(*filters: Filter) -> Filter:
        return Filter("and", None, None, filters)

    @staticmethod
    def or_(*filters: Filter) -> Filter:
        return Filter("or", None, None, filters)

    @staticmethod
    def not_(filter: Filter) -> Filter:  # noqa: A002 - mirrors the model
        if not isinstance(filter, Filter):
            raise TypeError("not_ takes a Filter")
        return Filter("not", None, None, (filter,))

    def __and__(self, other: Filter) -> Filter:
        return Filter.and_(self, other)

    def __or__(self, other: Filter) -> Filter:
        return Filter.or_(self, other)

    def __invert__(self) -> Filter:
        return Filter.not_(self)

    @staticmethod
    def _check(p: str) -> str:
        path(p)
        return p

    @staticmethod
    def _field(op: str, p: str, value: Any) -> Filter:
        return Filter(op, Filter._check(p), value)

    @property
    def is_empty(self) -> bool:
        return self._op == "empty"

    @property
    def is_id(self) -> bool:
        return self._op == "id"

    @property
    def id_value(self) -> Any:
        return self._value

    def to_ast(self, params: ParamSink) -> ast.AstExpr:
        """The ``AstExpr`` of this filter, adding its values to ``params``."""
        op = self._op
        if op == "empty":
            raise ValueError("the empty filter cannot be nested in another filter")
        if op in _BINARY:
            left = path_expr("_id" if op == "id" else self._path or "")
            return ast.AstExpr(binary=ast.AstBinary(op=_BINARY[op], left=left, right=params.add(self._value)))
        if op == "exists":
            # exists(p, true) = p IS NOT MISSING; exists(p, false) = p IS MISSING.
            return _expr("is", _is(self._path or "", ast.AST_IS_TEST_MISSING, bool(self._value)))
        if op == "isNull":
            return _expr("is", _is(self._path or "", ast.AST_IS_TEST_NULL, False))
        if op == "elemMatch":
            return ast.AstExpr(
                elem_match=ast.AstElemMatch(path=path(self._path or ""), predicate=self._args[0].to_ast(params))
            )
        if op == "not":
            return _expr("not", ast.AstUnary(expr=self._args[0].to_ast(params)))
        args: list[ast.AstExpr] = []
        for f in self._args:
            if f.is_empty:
                continue
            e = f.to_ast(params)
            if op == "and" and e.WhichOneof("kind") == "and":
                args.extend(getattr(e, "and").args)
            elif op == "or" and e.WhichOneof("kind") == "or":
                args.extend(getattr(e, "or").args)
            else:
                args.append(e)
        if not args:
            raise ValueError("and/or needs at least one non-empty filter")
        if len(args) == 1:
            return args[0]
        return _expr(op, ast.AstNary(args=args))

    def __repr__(self) -> str:
        # Values are user data (possibly secrets): never part of the text.
        inner = ", ".join(repr(a) for a in self._args)
        return f"Filter({self._op}{' ' + self._path if self._path else ''}{' [' + inner + ']' if inner else ''})"


def _expr(field: str, value: Any) -> ast.AstExpr:
    """An ``AstExpr`` whose oneof member is a Python keyword (``and``, ``or``, ``not``, ``is``)."""
    e = ast.AstExpr()
    getattr(e, field).CopyFrom(value)
    return e


def _is(p: str, test: ast.AstIsTest.ValueType, negated: bool) -> ast.AstIs:
    return ast.AstIs(expr=path_expr(p), negated=negated, test=test)


_EMPTY: Final = Filter("empty")


# ------------------------------------------------------------------------- updates


class Update:
    """An immutable list of update operators, applied in order; chain the methods.

    Start from ``Updates.set(...)`` (or ``Update()``): ``Updates.set("a", 1).inc("n", 1)``.
    """

    __slots__ = ("_ops",)

    def __init__(self, ops: Sequence[tuple[str, str | None, Any]] = ()) -> None:
        self._ops = tuple(ops)

    def _with(self, kind: str, p: str | None, value: Any = None) -> Update:
        if p is not None:
            path(p)
        return Update((*self._ops, (kind, p, value)))

    def set(self, p: str, value: Any) -> Update:
        return self._with("set", p, value)

    def unset(self, p: str) -> Update:
        return self._with("unset", p)

    def inc(self, p: str, by: Any) -> Update:
        return self._with("inc", p, by)

    def mul(self, p: str, by: Any) -> Update:
        return self._with("mul", p, by)

    def min(self, p: str, value: Any) -> Update:
        return self._with("min", p, value)

    def max(self, p: str, value: Any) -> Update:
        return self._with("max", p, value)

    def push(self, p: str, value: Any) -> Update:
        return self._with("push", p, value)

    def add_to_set(self, p: str, value: Any) -> Update:
        return self._with("addToSet", p, value)

    def pull(self, p: str, value: Any) -> Update:
        """Removes the array elements equal to ``value``."""
        return self._with("pull", p, value)

    def pop_first(self, p: str) -> Update:
        return self._with("popFirst", p)

    def pop_last(self, p: str) -> Update:
        return self._with("popLast", p)

    def rename(self, source: str, target: str) -> Update:
        path(target)
        return self._with("rename", source, target)

    def current_date(self, p: str) -> Update:
        return self._with("currentDate", p)

    def combine(self, other: Update) -> Update:
        return Update((*self._ops, *other._ops))

    @staticmethod
    def replace_with(document: Mapping[str, Any]) -> Update:
        return Update((("replace", None, document),))

    def to_ast(self, params: ParamSink) -> list[ast.AstUpdateOp]:
        if not self._ops:
            raise ValueError("an update needs at least one operator")
        out: list[ast.AstUpdateOp] = []
        for kind, p, value in self._ops:
            ap = path(p) if p is not None else None
            if kind == "set":
                op = ast.AstUpdateOp(set=ast.AstSetStage(items=[ast.AstSetItem(path=ap, value=params.add(value))]))
            elif kind == "unset":
                op = ast.AstUpdateOp(unset=ast.AstUnsetStage(paths=[ap] if ap else []))
            elif kind == "inc":
                op = ast.AstUpdateOp(inc=ast.AstPathBy(path=ap, by=params.add(value)))
            elif kind == "mul":
                op = ast.AstUpdateOp(mul=ast.AstPathBy(path=ap, by=params.add(value)))
            elif kind == "min":
                op = ast.AstUpdateOp(min=ast.AstPathValue(path=ap, value=params.add(value)))
            elif kind == "max":
                op = ast.AstUpdateOp(max=ast.AstPathValue(path=ap, value=params.add(value)))
            elif kind == "addToSet":
                op = ast.AstUpdateOp(add_to_set=ast.AstPathValue(path=ap, value=params.add(value)))
            elif kind == "push":
                op = ast.AstUpdateOp(push=ast.AstPushOp(path=ap, value=params.add(value)))
            elif kind == "pull":
                # PULL p WHERE <last field of p> = $u: the element is named after the array field.
                last = ap.segments[-1].field if ap else ""
                where = ast.AstExpr(
                    binary=ast.AstBinary(op=ast.AST_BINARY_OP_EQ, left=path_expr(last), right=params.add(value))
                )
                op = ast.AstUpdateOp(pull=ast.AstPullOp(path=ap, where=where))
            elif kind in ("popFirst", "popLast"):
                end = ast.AST_POP_END_FIRST if kind == "popFirst" else ast.AST_POP_END_LAST
                op = ast.AstUpdateOp(pop=ast.AstPopOp(path=ap, end=end))
            elif kind == "rename":
                op = ast.AstUpdateOp(rename=ast.AstRenameOp(to=path(value)))
                getattr(op.rename, "from").CopyFrom(ap)
            elif kind == "currentDate":
                op = ast.AstUpdateOp(current_date=ast.AstPathOnly(path=ap))
            else:  # replace
                op = ast.AstUpdateOp(replace=ast.AstReplaceOp(value=params.add(value)))
            out.append(op)
        return out

    def __repr__(self) -> str:
        # Operands are user data: only operator kinds and paths are shown.
        return "Update(" + "; ".join(f"{k} {p}" if p else k for k, p, _ in self._ops) + ")"


class Updates:
    """Starting points of update chains: ``Updates.set("status", "shipped").inc("version", 1)``."""

    @staticmethod
    def set(p: str, value: Any) -> Update:
        return Update().set(p, value)

    @staticmethod
    def unset(p: str) -> Update:
        return Update().unset(p)

    @staticmethod
    def inc(p: str, by: Any) -> Update:
        return Update().inc(p, by)

    @staticmethod
    def mul(p: str, by: Any) -> Update:
        return Update().mul(p, by)

    @staticmethod
    def min(p: str, value: Any) -> Update:
        return Update().min(p, value)

    @staticmethod
    def max(p: str, value: Any) -> Update:
        return Update().max(p, value)

    @staticmethod
    def push(p: str, value: Any) -> Update:
        return Update().push(p, value)

    @staticmethod
    def add_to_set(p: str, value: Any) -> Update:
        return Update().add_to_set(p, value)

    @staticmethod
    def pull(p: str, value: Any) -> Update:
        return Update().pull(p, value)

    @staticmethod
    def pop_first(p: str) -> Update:
        return Update().pop_first(p)

    @staticmethod
    def pop_last(p: str) -> Update:
        return Update().pop_last(p)

    @staticmethod
    def rename(source: str, target: str) -> Update:
        return Update().rename(source, target)

    @staticmethod
    def current_date(p: str) -> Update:
        return Update().current_date(p)


# ------------------------------------------------------------------------- sort / projection


class Sort:
    """Sort keys in order; ``Sort.asc("a") + Sort.desc("b")`` or ``Sort.asc("a").then(...)``."""

    __slots__ = ("_keys",)

    def __init__(self, keys: Sequence[tuple[str, bool]]) -> None:
        for p, _ in keys:
            path(p)
        self._keys = tuple(keys)

    @staticmethod
    def asc(*paths: str) -> Sort:
        return Sort([(p, False) for p in paths])

    @staticmethod
    def desc(*paths: str) -> Sort:
        return Sort([(p, True) for p in paths])

    def then(self, other: Sort) -> Sort:
        return Sort((*self._keys, *other._keys))

    __add__ = then

    def to_ast(self) -> list[ast.AstOrderItem]:
        return [ast.AstOrderItem(expr=path_expr(p), descending=d) for p, d in self._keys]

    def __repr__(self) -> str:
        return "Sort(" + ", ".join(("-" if d else "") + p for p, d in self._keys) + ")"


class Projection:
    """Fields to keep (``include``: a path is named after its last field) or to drop."""

    __slots__ = ("_exclude", "_paths")

    def __init__(self, exclude: bool, paths: Sequence[str]) -> None:
        for p in paths:
            path(p)
        self._exclude = exclude
        self._paths = tuple(paths)

    @staticmethod
    def include(*paths: str) -> Projection:
        return Projection(False, paths)

    @staticmethod
    def exclude(*paths: str) -> Projection:
        return Projection(True, paths)

    def to_ast(self) -> ast.AstSelect:
        items = []
        for p in self._paths:
            if self._exclude:
                items.append(ast.AstProjection(exclude=ast.AstPathProjection(path=path(p))))
            else:
                items.append(ast.AstProjection(expr=ast.AstExprProjection(expr=path_expr(p))))
        return ast.AstSelect(items=ast.AstSelectItems(items=items))


# ------------------------------------------------------------------------- statements

_FULL_SCAN_WRITE: Final = "allow_full_scan_write"


def _name(collection: str) -> ast.AstQualifiedName:
    return ast.AstQualifiedName(name=collection)


def _full_scan_write() -> ast.AstOptionItem:
    return ast.AstOptionItem(name=_FULL_SCAN_WRITE, value=ast.AstExpr(literal=ast.AstLiteral(bool_value=True)))


def find_statement(
    collection: str,
    filter: Filter,  # noqa: A002
    sort: Sort | None,
    projection: Projection | None,
    limit: int | None,
    skip: int | None,
    params: ParamSink,
) -> ast.AstStatement:
    """``FROM c [WHERE f] [SELECT p] [ORDER BY s] [LIMIT n] [OFFSET m]`` (README §4 rule 6)."""
    q = ast.AstQuery()
    getattr(q, "from").CopyFrom(ast.AstFromClause(source=ast.AstSource(collection=_name(collection))))
    if not filter.is_empty:
        q.where.CopyFrom(filter.to_ast(params))
    if projection is not None:
        q.select.CopyFrom(projection.to_ast())
    if sort is not None:
        q.order_by.extend(sort.to_ast())
    if limit is not None:
        q.limit.CopyFrom(int_literal(limit))
    if skip is not None:
        q.offset.CopyFrom(int_literal(skip))
    return ast.AstStatement(query=q)


def update_statement(
    collection: str,
    filter: Filter,  # noqa: A002
    update: Update,
    one: bool,
    filter_params: ParamSink,
    update_params: ParamSink,
) -> ast.AstStatement:
    """``UPDATE c <ops> [WHERE f] [LIMIT 1]``; the empty filter adds ``allow_full_scan_write``."""
    u = ast.AstUpdate(target=_name(collection), ops=update.to_ast(update_params))
    if filter.is_empty:
        u.options.append(_full_scan_write())
    else:
        u.where.CopyFrom(filter.to_ast(filter_params))
    if one:
        u.limit.CopyFrom(int_literal(1))
    return ast.AstStatement(update=u)


def delete_statement(collection: str, filter: Filter, one: bool, params: ParamSink) -> ast.AstStatement:  # noqa: A002
    d = ast.AstDelete(target=_name(collection))
    if filter.is_empty:
        d.options.append(_full_scan_write())
    else:
        d.where.CopyFrom(filter.to_ast(params))
    if one:
        d.limit.CopyFrom(int_literal(1))
    return ast.AstStatement(delete=d)


# ------------------------------------------------------------------------- bulk and indexes


@dataclass(frozen=True, slots=True)
class BulkOperation:
    """One operation of ``bulk_write``, addressed by ``_id`` (``BulkOperation`` of document.proto)."""

    kind: str
    id: Any = None
    document: Any = None
    update: Update | None = None
    if_rev: str | None = None

    @staticmethod
    def insert(document: Any) -> BulkOperation:
        return BulkOperation("insert", document=document)

    @staticmethod
    def replace(id: Any, document: Any, if_rev: str | None = None) -> BulkOperation:  # noqa: A002
        return BulkOperation("replace", id=id, document=document, if_rev=if_rev)

    @staticmethod
    def update_by_id(id: Any, update: Update, if_rev: str | None = None) -> BulkOperation:  # noqa: A002
        return BulkOperation("update", id=id, update=update, if_rev=if_rev)

    @staticmethod
    def upsert(document: Any) -> BulkOperation:
        return BulkOperation("upsert", document=document)

    @staticmethod
    def delete(id: Any, if_rev: str | None = None) -> BulkOperation:  # noqa: A002
        return BulkOperation("delete", id=id, if_rev=if_rev)


@dataclass(frozen=True, slots=True)
class IndexKey:
    """One key of an index: a dotted path, ascending unless ``descending``."""

    path: str
    descending: bool = False
