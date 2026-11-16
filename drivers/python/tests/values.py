# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Values, placeholders, matching and the builder DSL of the conformance suite
(drivers/conformance/README.md §4, §5)."""

from __future__ import annotations

import datetime as dt
import json
import math
import uuid
from collections.abc import Callable, Mapping
from decimal import Decimal
from typing import Any

from rustegon import Filter, Projection, Sort, Update, extjson
from rustegon.types import Binary, Counter, DatetimeMs, MaxKey, MinKey, ObjectId, Timestamp, Vector, datetime_to_millis

SYSTEM_FIELDS = ("_rev", "_createdAt", "_updatedAt")


class AnyValue:
    """``"$$any"``: matches any value, null included."""

    def __repr__(self) -> str:
        return "$$any"


ANY = AnyValue()


class TypeOf:
    """``{"$$type": name}``: any value of that data-model type."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"$$type:{self.name}"


def type_name(v: Any) -> str:
    """The data-model §2 type name of a Python value."""
    if v is None:
        return "null"
    if v is True or v is False:
        return "bool"
    table: list[tuple[type | tuple[type, ...], str]] = [
        (int, "int64"),
        (float, "float64"),
        (Decimal, "decimal128"),
        (str, "string"),
        ((bytes, Binary), "binary"),
        ((dt.datetime, DatetimeMs), "datetime"),
        (Timestamp, "timestamp"),
        (ObjectId, "objectId"),
        (uuid.UUID, "uuid"),
        (list, "array"),
        (dict, "object"),
        (Vector, "vector_f32"),
        (Counter, "counter"),
        (MinKey, "minKey"),
        (MaxKey, "maxKey"),
    ]
    for t, name in table:
        if isinstance(v, t):
            return name
    return type(v).__name__


def value(y: Any, ref: Callable[[str], Any], substitute: Callable[[str], str]) -> Any:
    """A YAML/JSON value of a test as a Python value: canonical extended JSON plus placeholders,
    ``$$ref`` and ``${…}`` substitutions."""
    if isinstance(y, str):
        if y == "$$any":
            return ANY
        if y.startswith("$$ref:"):
            return ref(y[len("$$ref:") :])
        return substitute(y)
    if isinstance(y, list):
        return [value(x, ref, substitute) for x in y]
    if isinstance(y, dict):
        if len(y) == 1:
            ((k, v),) = y.items()
            if k == "$$type":
                return TypeOf(v)
            if k.startswith("$"):
                return extjson.loads(json.dumps(y))
        return {k: value(v, ref, substitute) for k, v in y.items()}
    return y  # None, bool, int, float


def plain(y: Any) -> Any:
    """A value without placeholders (AST vectors, fake-server scripts)."""
    return value(y, lambda r: None, lambda s: s)


def _same_scalar(want: Any, got: Any) -> bool:
    if type(want) is not type(got):
        if isinstance(want, (dt.datetime, DatetimeMs)) and isinstance(got, (dt.datetime, DatetimeMs)):
            return _millis(want) == _millis(got)
        return False
    if isinstance(want, float):
        if math.isnan(want):
            return math.isnan(got)
        return bool(want == got and math.copysign(1, want) == math.copysign(1, got))
    if isinstance(want, Decimal):
        return str(want) == str(got)
    if isinstance(want, dt.datetime):
        return _millis(want) == _millis(got)
    return bool(want == got)


def _millis(v: dt.datetime | DatetimeMs) -> int:
    return v.millis if isinstance(v, DatetimeMs) else datetime_to_millis(v)


def mismatch(want: Any, got: Any, subset: bool, ordered: bool, field_order: bool, where: str = "") -> str | None:
    """``None`` when ``got`` matches ``want`` (README §5), else the first difference."""
    if want is ANY:
        return None
    if isinstance(want, TypeOf):
        return None if type_name(got) == want.name else f"{where}: expected a {want.name}, got {got!r}"
    if isinstance(want, dict):
        if not isinstance(got, dict):
            return f"{where}: expected a document, got {got!r}"
        actual = {k: v for k, v in got.items() if k not in SYSTEM_FIELDS or k in want}
        if not subset and set(actual) != set(want):
            return f"{where}: fields {list(actual)} != {list(want)}"
        if field_order and [k for k in actual if k in want] != list(want):
            return f"{where}: field order {list(actual)} != {list(want)}"
        for k, w in want.items():
            if k not in actual:
                return f"{where}.{k}: missing"
            d = mismatch(w, actual[k], subset, True, field_order, f"{where}.{k}")
            if d:
                return d
        return None
    if isinstance(want, list):
        if not isinstance(got, list):
            return f"{where}: expected an array, got {got!r}"
        if (ordered or not subset) and len(got) != len(want):
            return f"{where}: {len(got)} elements, expected {len(want)}: {got!r}"
        if ordered:
            for i, (w, g) in enumerate(zip(want, got, strict=True)):
                d = mismatch(w, g, subset, True, field_order, f"{where}[{i}]")
                if d:
                    return d
            return None
        free = list(range(len(got)))
        for i, w in enumerate(want):
            hit = next((j for j in free if mismatch(w, got[j], subset, True, field_order) is None), None)
            if hit is None:
                return f"{where}[{i}]: no match for {w!r} in {got!r}"
            free.remove(hit)
        return None
    if not _same_scalar(want, got):
        return f"{where}: expected {want!r}, got {got!r}"
    return None


# ------------------------------------------------------------------------- builder DSL


def dsl_filter(f: Any, v: Callable[[Any], Any]) -> Filter:
    if f == {}:
        return Filter.empty()
    ((op, a),) = f.items()
    simple = {
        "eq": Filter.eq,
        "ne": Filter.ne,
        "gt": Filter.gt,
        "gte": Filter.gte,
        "lt": Filter.lt,
        "lte": Filter.lte,
        "contains": Filter.contains,
    }
    lists = {
        "in": Filter.in_,
        "nin": Filter.nin,
        "containsAny": Filter.contains_any,
        "containsAll": Filter.contains_all,
    }
    if op in simple:
        return simple[op](a[0], v(a[1]))
    if op in lists:
        return lists[op](a[0], v(a[1]))
    if op == "exists":
        return Filter.exists(a[0], a[1])
    if op == "isNull":
        return Filter.is_null(a)
    if op == "elemMatch":
        return Filter.elem_match(a[0], dsl_filter(a[1], v))
    if op == "like":
        return Filter.like(a[0], a[1])
    if op == "regex":
        return Filter.regex(a[0], a[1])
    if op == "and":
        return Filter.and_(*(dsl_filter(x, v) for x in a))
    if op == "or":
        return Filter.or_(*(dsl_filter(x, v) for x in a))
    if op == "not":
        return Filter.not_(dsl_filter(a, v))
    if op == "id":
        return Filter.id(v(a))
    raise AssertionError(f"unknown filter {op}")


def dsl_update(ops: list[Mapping[str, Any]], v: Callable[[Any], Any]) -> Update:
    u = Update()
    for o in ops:
        ((op, a),) = o.items()
        if op in ("set", "inc", "mul", "min", "max", "push", "pull"):
            u = getattr(u, op)(a[0], v(a[1]))
        elif op == "addToSet":
            u = u.add_to_set(a[0], v(a[1]))
        elif op == "unset":
            u = u.unset(a)
        elif op == "pop":
            u = u.pop_first(a[0]) if a[1] == "first" else u.pop_last(a[0])
        elif op == "rename":
            u = u.rename(a[0], a[1])
        elif op == "currentDate":
            u = u.current_date(a)
        elif op == "replace":
            u = Update.replace_with(v(a))
        else:
            raise AssertionError(f"unknown update {op}")
    return u


def dsl_sort(keys: list[str]) -> Sort:
    s = Sort([])
    for k in keys:
        s = s + (Sort.desc(k[1:]) if k.startswith("-") else Sort.asc(k))
    return s


def dsl_projection(p: Mapping[str, list[str]]) -> Projection:
    if "include" in p:
        return Projection.include(*p["include"])
    return Projection.exclude(*p["exclude"])
