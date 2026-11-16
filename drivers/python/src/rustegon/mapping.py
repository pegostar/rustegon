# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Object mapping of dataclasses (python-driver.md §7, mapping/vectors.yaml, PD-174).

``get_collection(name, MyDataclass)`` maps documents to instances of a dataclass with the rules
of the .NET and Java mappers (PD-108, PD-111, PD-112), so data written by one driver reads back
in the others:

- the id is the member marked ``Annotated[..., RgnId()]`` or, without one, the member named
  ``id``; it is written first as ``_id`` and omitted when ``None``;
- a polymorphic root (a dataclass with dataclass subclasses) writes the discriminator ``_type``
  after ``_id``: the ``@discriminator("…")`` value or the class name;
- then the other members in declaration order, ``None`` written as null;
  ``RgnField("name")`` renames, ``RgnIgnore()`` skips, ``RgnRev()`` (``_rev``) and
  ``RgnCounter()`` are read only;
- reading ignores unknown and system fields; an absent field gives ``None``/0/0.0/False (or the
  member's default); null into a non-optional ``int``/``float``/``bool`` is an error;
- enums are stored by member name; datetimes as instants in ms (rounded down, offset dropped);
  ``Decimal`` keeps its scale; ``RgnVector(n)`` is a ``vector_f32`` of n elements;
  ``RgnGeoPoint()`` is the GeoJSON ``{"type": "Point", "coordinates": [lon, lat]}``.

Errors while reading or writing a mapped value raise ``ValueError`` naming the field.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import types
import typing
import uuid
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal
from typing import Any, Final, Generic, Protocol, TypeVar

from rustegon.types import Binary, Counter, DatetimeMs, ObjectId, Timestamp, Vector

__all__ = [
    "DocumentCodec",
    "RgnCounter",
    "RgnField",
    "RgnGeoPoint",
    "RgnId",
    "RgnIgnore",
    "RgnRev",
    "RgnVector",
    "codec_for",
    "discriminator",
]

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)
SYSTEM_FIELDS: Final = frozenset({"_rev", "_createdAt", "_updatedAt"})
DISCRIMINATOR_FIELD: Final = "_type"


@dataclasses.dataclass(frozen=True)
class RgnId:
    """Marks the id member (``_id``)."""


@dataclasses.dataclass(frozen=True)
class RgnField:
    """Stores the member under another field name."""

    name: str


@dataclasses.dataclass(frozen=True)
class RgnIgnore:
    """The member is neither written nor read."""


@dataclasses.dataclass(frozen=True)
class RgnRev:
    """Read-only: receives the document's ``_rev``."""


@dataclasses.dataclass(frozen=True)
class RgnCounter:
    """Read-only: receives a counter projection (``$counter``)."""


@dataclasses.dataclass(frozen=True)
class RgnVector:
    """A ``list[float]`` stored as a ``vector_f32`` of exactly ``dims`` elements."""

    dims: int


@dataclasses.dataclass(frozen=True)
class RgnGeoPoint:
    """A ``(lon, lat)`` pair stored as a GeoJSON point."""


def discriminator(value: str) -> Callable[[type[T]], type[T]]:
    """Class decorator: the ``_type`` value of a subtype (default: the class name)."""

    def apply(cls: type[T]) -> type[T]:
        cls.__rgn_discriminator__ = value  # type: ignore[attr-defined]
        return cls

    return apply


class DocumentCodec(Protocol[T]):
    """Converts between documents (``dict``) and the values of a collection."""

    def to_document(self, value: T) -> Mapping[str, Any]: ...

    def from_document(self, document: dict[str, Any]) -> T: ...


class _DictCodec:
    def to_document(self, value: Any) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise TypeError("documents of this collection are mappings (dict)")
        return value

    def from_document(self, document: dict[str, Any]) -> Any:
        return document


_DICT: Final = _DictCodec()
_CACHE: dict[type[Any], _ClassCodec[Any]] = {}


def codec_for(document_class: type[Any]) -> DocumentCodec[Any]:
    """The codec of ``dict`` (identity) or of a dataclass."""
    if document_class is dict or document_class is Mapping:
        return _DICT
    if not dataclasses.is_dataclass(document_class):
        raise TypeError(f"{document_class!r} is neither dict nor a dataclass")
    return _class_codec(document_class)


def _class_codec(cls: type[Any]) -> _ClassCodec[Any]:
    codec = _CACHE.get(cls)
    if codec is None:
        codec = _ClassCodec(cls)
        _CACHE[cls] = codec
        codec.build()
    return codec


# ------------------------------------------------------------------------- value converters

_Read = Callable[[Any, str], Any]
_Write = Callable[[Any, str], Any]


def _fail(where: str, what: str) -> ValueError:
    return ValueError(f"{where}: {what}")


def _strip(tp: Any) -> tuple[Any, tuple[Any, ...]]:
    if typing.get_origin(tp) is typing.Annotated:
        args = typing.get_args(tp)
        return args[0], tuple(args[1:])
    return tp, ()


def _optional(tp: Any) -> tuple[Any, bool]:
    origin = typing.get_origin(tp)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        if len(args) != len(typing.get_args(tp)):
            return (args[0] if len(args) == 1 else typing.Union[tuple(args)]), True  # noqa: UP007
    return tp, tp is Any


def _scalar(tp: Any) -> tuple[_Read, _Write] | None:
    def check(*kinds: type) -> tuple[_Read, _Write]:
        def read(v: Any, where: str) -> Any:
            if (isinstance(v, bool) and bool not in kinds) or not isinstance(v, kinds):
                raise _fail(where, f"expected {kinds[0].__name__}, got {type(v).__name__}")
            return v

        return read, read

    if tp is str:
        return check(str)
    if tp is bool:
        return check(bool)
    if tp is int:
        return check(int)
    if tp is float:

        def read_float(v: Any, where: str) -> Any:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise _fail(where, f"expected float, got {type(v).__name__}")
            return float(v)

        return read_float, read_float
    if tp is Decimal:
        return check(Decimal)
    if tp is _dt.datetime:

        def read_dt(v: Any, where: str) -> Any:
            if not isinstance(v, (_dt.datetime, DatetimeMs)):
                raise _fail(where, f"expected datetime, got {type(v).__name__}")
            return v

        return read_dt, read_dt
    for simple in (bytes, uuid.UUID, ObjectId, Binary, Timestamp, Vector):
        if tp is simple:
            return check(simple)
    return None


def _converter(tp: Any, markers: tuple[Any, ...]) -> tuple[_Read, _Write, bool]:
    """(read, write, nullable) of a member type."""
    inner, nullable = _optional(tp)
    vector = next((m for m in markers if isinstance(m, RgnVector)), None)
    geo = any(isinstance(m, RgnGeoPoint) for m in markers)
    if vector is not None:

        def read_vec(v: Any, where: str) -> Any:
            if not isinstance(v, Vector):
                raise _fail(where, "expected a vector")
            if len(v) != vector.dims:
                raise _fail(where, f"expected {vector.dims} dimensions, got {len(v)}")
            return list(v.values)

        def write_vec(v: Any, where: str) -> Any:
            vec = Vector(v)
            if len(vec) != vector.dims:
                raise _fail(where, f"expected {vector.dims} dimensions, got {len(vec)}")
            return vec

        return read_vec, write_vec, nullable
    if geo:

        def read_geo(v: Any, where: str) -> Any:
            ok = (
                isinstance(v, dict)
                and v.get("type") == "Point"
                and isinstance(v.get("coordinates"), list)
                and len(v["coordinates"]) == 2
                and all(isinstance(c, float) for c in v["coordinates"])
            )
            if not ok:
                raise _fail(where, "expected a GeoJSON point")
            return list(v["coordinates"])

        def write_geo(v: Any, where: str) -> Any:
            if len(v) != 2:
                raise _fail(where, "a point is [lon, lat]")
            return {"type": "Point", "coordinates": [float(v[0]), float(v[1])]}

        return read_geo, write_geo, nullable
    if inner is Any:
        return (lambda v, _w: v), (lambda v, _w: v), True
    scalar = _scalar(inner)
    if scalar is not None:
        return scalar[0], scalar[1], nullable
    if isinstance(inner, type) and issubclass(inner, enum.Enum):
        enum_type = inner

        def read_enum(v: Any, where: str) -> Any:
            if not isinstance(v, str) or v not in enum_type.__members__:
                raise _fail(where, f"{v!r} is not a member of {enum_type.__name__}")
            return enum_type[v]

        def write_enum(v: Any, where: str) -> Any:
            if not isinstance(v, enum_type):
                raise _fail(where, f"expected {enum_type.__name__}")
            return v.name

        return read_enum, write_enum, nullable
    if isinstance(inner, type) and dataclasses.is_dataclass(inner):
        nested = _class_codec(inner)
        return nested.read_value, nested.write_value, nullable
    origin, args = typing.get_origin(inner), typing.get_args(inner)
    if origin in (list, Sequence, tuple) and args and (origin is not tuple or args[-1] is Ellipsis or len(args) == 1):
        r, w, _ = _converter(args[0], ())
        build = tuple if origin is tuple else list

        def read_list(v: Any, where: str) -> Any:
            if not isinstance(v, list):
                raise _fail(where, "expected an array")
            return build(r(x, f"{where}[{i}]") for i, x in enumerate(v))

        def write_list(v: Any, where: str) -> Any:
            return [None if x is None else w(x, f"{where}[{i}]") for i, x in enumerate(v)]

        return read_list, write_list, nullable
    if origin in (dict, Mapping) and args and args[0] is str:
        r, w, _ = _converter(args[1], ())

        def read_map(v: Any, where: str) -> Any:
            if not isinstance(v, dict):
                raise _fail(where, "expected an object")
            return {k: r(x, f"{where}.{k}") for k, x in v.items()}

        def write_map(v: Any, where: str) -> Any:
            return {k: w(x, f"{where}.{k}") for k, x in v.items()}

        return read_map, write_map, nullable
    raise TypeError(f"no mapping for the member type {tp!r}")


# ------------------------------------------------------------------------- class codecs


@dataclasses.dataclass
class _Member:
    attr: str
    field: str
    read: _Read
    write: _Write
    nullable: bool
    read_only: bool
    absent: Any


class _ClassCodec(Generic[T]):
    """The codec of one dataclass (and of its subtypes when it is a polymorphic root)."""

    def __init__(self, cls: type[T]) -> None:
        self.cls = cls
        self.members: list[_Member] = []
        self.id_member: _Member | None = None
        self.subtypes: dict[str, type[Any]] = {}
        self.discriminator: str | None = None

    def build(self) -> None:
        cls = self.cls
        hints = typing.get_type_hints(cls, include_extras=True)
        fields = [f for f in dataclasses.fields(cls) if f.init or f.default is not dataclasses.MISSING]  # type: ignore[arg-type]
        explicit_id = [f for f in fields if any(isinstance(m, RgnId) for m in _strip(hints[f.name])[1])]
        for f in fields:
            tp, markers = _strip(hints[f.name])
            if any(isinstance(m, RgnIgnore) for m in markers):
                continue
            is_id = f in explicit_id or (not explicit_id and f.name == "id")
            rename = next((m.name for m in markers if isinstance(m, RgnField)), None)
            rev = any(isinstance(m, RgnRev) for m in markers)
            counter = any(isinstance(m, RgnCounter) for m in markers)
            name = "_id" if is_id else "_rev" if rev else rename or f.name
            read, write, nullable = _converter(tp, markers)
            if counter:
                read = _counter_reader
            if f.default is not dataclasses.MISSING:
                absent = f.default
            elif f.default_factory is not dataclasses.MISSING:
                absent = f.default_factory
            else:
                base = _optional(tp)[0]
                absent = {int: 0, float: 0.0, bool: False}.get(base) if not nullable else None
            m = _Member(f.name, name, read, write, nullable, rev or counter, absent)
            if is_id:
                self.id_member = m
            else:
                self.members.append(m)
        # A polymorphic root: every dataclass subclass, by discriminator value.
        stack = list(cls.__subclasses__())
        while stack:
            sub = stack.pop()
            stack.extend(sub.__subclasses__())
            if dataclasses.is_dataclass(sub):
                value = getattr(sub, "__dict__", {}).get("__rgn_discriminator__", sub.__name__)
                self.subtypes[value] = sub
        if (
            self.subtypes
            or cls.__dict__.get("__rgn_discriminator__")
            or any(dataclasses.is_dataclass(b) and b.__subclasses__() for b in cls.__mro__[1:])
        ):
            self.discriminator = cls.__dict__.get("__rgn_discriminator__", cls.__name__)

    # -- documents

    def to_document(self, value: T) -> dict[str, Any]:
        if type(value) is not self.cls:
            if isinstance(value, self.cls) and dataclasses.is_dataclass(value):
                return _class_codec(type(value)).to_document(value)
            raise TypeError(f"expected {self.cls.__name__}, got {type(value).__name__}")
        doc: dict[str, Any] = {}
        if self.id_member is not None:
            v = getattr(value, self.id_member.attr)
            if v is not None:
                doc["_id"] = self.id_member.write(v, self.id_member.attr)
        if self.discriminator is not None:
            doc[DISCRIMINATOR_FIELD] = self.discriminator
        for m in self.members:
            if m.read_only:
                continue
            v = getattr(value, m.attr)
            if v is None:
                doc[m.field] = None
            else:
                doc[m.field] = m.write(v, m.attr)
        return doc

    def from_document(self, document: dict[str, Any]) -> T:
        if self.subtypes or (self.discriminator is not None and DISCRIMINATOR_FIELD in document):
            tag = document.get(DISCRIMINATOR_FIELD)
            if tag is None:
                raise ValueError(f"{self.cls.__name__}: the document has no {DISCRIMINATOR_FIELD}")
            if tag != self.discriminator:
                sub = self.subtypes.get(tag) if isinstance(tag, str) else None
                if sub is None:
                    raise ValueError(f"{self.cls.__name__}: unknown {DISCRIMINATOR_FIELD} {tag!r}")
                result: T = _class_codec(sub).from_document(document)
                return result
            if dataclasses.is_dataclass(self.cls) and _is_abstract_root(self.cls):
                raise ValueError(f"{self.cls.__name__}: {tag!r} names an abstract root")
        kwargs: dict[str, Any] = {}
        members = [*([self.id_member] if self.id_member else []), *self.members]
        for m in members:
            if m.field in document:
                v = document[m.field]
                if v is None:
                    if not m.nullable:
                        raise ValueError(f"{m.attr}: null into a non-optional member")
                    kwargs[m.attr] = None
                else:
                    kwargs[m.attr] = m.read(v, m.attr)
            else:
                absent = m.absent
                kwargs[m.attr] = absent() if callable(absent) else absent
        return self.cls(**kwargs)

    # -- nested values

    def read_value(self, v: Any, where: str) -> Any:
        if not isinstance(v, dict):
            raise _fail(where, f"expected an object for {self.cls.__name__}")
        try:
            return self.from_document(v)
        except ValueError as e:
            raise _fail(where, str(e)) from e

    def write_value(self, v: Any, where: str) -> Any:
        return self.to_document(v)


def _is_abstract_root(cls: type[Any]) -> bool:
    return bool(getattr(cls, "__abstractmethods__", None))


def _counter_reader(v: Any, where: str) -> Any:
    if isinstance(v, Counter):
        return v.value
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    raise _fail(where, "expected a counter")
