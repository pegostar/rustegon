# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""RDoc v1 binary codec (data-model.md §4), byte-exact with the server's ``rustegon-doc``.

``encode_document`` / ``decode_document`` handle whole documents (header, canonical flag set);
``encode_value`` / ``decode_value`` the value encoding of ids and parameters
(``Value.rdoc_value``: type tag + payload). The decoder rejects every malformed input with an
``RDocError`` carrying the catalog code (``drivers/conformance/codec/invalid.yaml``) and never
loops or recurses without bound: containers are limited to depth 100.
"""

from __future__ import annotations

import datetime as _dt
import math
import struct
import uuid
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Final

import xxhash

from rustegon import _decimal128
from rustegon.errors import RDocError
from rustegon.types import (
    MAX_KEY,
    MIN_KEY,
    Binary,
    Counter,
    DatetimeMs,
    MaxKey,
    MinKey,
    ObjectId,
    Timestamp,
    Vector,
    datetime_to_millis,
    millis_to_datetime,
)

__all__ = ["decode_document", "decode_value", "encode_document", "encode_value", "name_hash16"]

MAGIC: Final = 0xD7
VERSION: Final = 0x01
FLAG_CANONICAL: Final = 0x01
HEADER_LEN: Final = 7
MAX_SIZE: Final = 16 * 1024 * 1024
MAX_DEPTH: Final = 100
MAX_NAME_BYTES: Final = 1024

T_NULL, T_BOOL, T_INT64, T_FLOAT64, T_DECIMAL, T_STRING, T_BINARY, T_DATETIME = range(1, 9)
T_TIMESTAMP, T_OBJECT_ID, T_UUID, T_ARRAY, T_OBJECT, T_VECTOR, T_COUNTER = range(9, 16)
T_MIN_KEY, T_MAX_KEY = 0x10, 0x11

_INT64_MIN: Final = -(1 << 63)
_INT64_MAX: Final = (1 << 63) - 1
_CANONICAL_NAN: Final = struct.pack("<Q", 0x7FF8000000000000)


def _malformed(message: str) -> RDocError:
    return RDocError(1001, message)


def name_hash16(name: bytes) -> int:
    """Low 16 bits of ``xxh3_64(name, seed 0)``: the index hash of a field name."""
    return xxhash.xxh3_64_intdigest(name) & 0xFFFF


def _check_name(name: str) -> bytes:
    if not isinstance(name, str):
        raise RDocError(1004, "field names are strings")
    try:
        raw = name.encode("utf-8")
    except UnicodeEncodeError as e:
        raise RDocError(1004, "a field name is not valid UTF-8") from e
    if not raw or len(raw) > MAX_NAME_BYTES:
        raise RDocError(1004, "a field name has 1 to 1024 bytes")
    if b"\x00" in raw:
        raise RDocError(1004, "a field name must not contain NUL")
    if raw[0] == 0x24:  # '$'
        raise RDocError(1004, f"field name {name!r} starts with '$'")
    return raw


# ---------------------------------------------------------------------------------- writer


def _varint(n: int, out: bytearray) -> None:
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)


def _zigzag(v: int) -> int:
    return ((v << 1) ^ (v >> 63)) & 0xFFFFFFFFFFFFFFFF


def _write_object(doc: Mapping[str, Any], out: bytearray, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise RDocError(1003, "nesting deeper than 100 levels")
    fields = bytearray()
    entries: list[tuple[int, bytes, int]] = []
    for name, value in doc.items():
        raw = _check_name(name)
        entries.append((name_hash16(raw), raw, len(fields)))
        _varint(len(raw), fields)
        fields += raw
        _write(value, fields, depth)
    entries.sort(key=lambda e: (e[0], e[1]))
    out.append(T_OBJECT)
    _varint(len(entries), out)
    _varint(len(fields), out)
    for h, _raw, offset in entries:
        out += struct.pack("<HI", h, offset)
    out += fields


def _write_array(items: Any, out: bytearray, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise RDocError(1003, "nesting deeper than 100 levels")
    elements = bytearray()
    offsets: list[int] = []
    for item in items:
        offsets.append(len(elements))
        _write(item, elements, depth)
    out.append(T_ARRAY)
    _varint(len(offsets), out)
    _varint(len(elements), out)
    for o in offsets:
        out += struct.pack("<I", o)
    out += elements


def _write(v: Any, out: bytearray, depth: int) -> None:
    """Appends the value encoding (tag + payload) of ``v``; ``depth`` = depth of its container."""
    if v is None:
        out.append(T_NULL)
    elif v is True or v is False:
        out += bytes((T_BOOL, 1 if v else 0))
    elif isinstance(v, int):
        if not _INT64_MIN <= v <= _INT64_MAX:
            raise _malformed("integer outside the int64 range (use decimal.Decimal)")
        out.append(T_INT64)
        _varint(_zigzag(v), out)
    elif isinstance(v, float):
        out.append(T_FLOAT64)
        out += _CANONICAL_NAN if math.isnan(v) else struct.pack("<d", v)
    elif isinstance(v, str):
        try:
            raw = v.encode("utf-8")
        except UnicodeEncodeError as e:
            raise _malformed("a string is not valid UTF-8 (lone surrogate)") from e
        out.append(T_STRING)
        _varint(len(raw), out)
        out += raw
    elif isinstance(v, Mapping):
        _write_object(v, out, depth + 1)
    elif isinstance(v, (list, tuple)):
        _write_array(v, out, depth + 1)
    elif isinstance(v, Decimal):
        try:
            out.append(T_DECIMAL)
            out += _decimal128.encode(v)
        except _decimal128.Decimal128Error as e:
            raise _malformed(str(e)) from e
    elif isinstance(v, (bytes, bytearray, memoryview)):
        data = bytes(v)
        out += bytes((T_BINARY, 0))
        _varint(len(data), out)
        out += data
    elif isinstance(v, Binary):
        out += bytes((T_BINARY, v.subtype))
        _varint(len(v.data), out)
        out += v.data
    elif isinstance(v, _dt.datetime):
        try:
            millis = datetime_to_millis(v)
        except ValueError as e:
            raise _malformed(str(e)) from e
        out.append(T_DATETIME)
        _varint(_zigzag(millis), out)
    elif isinstance(v, DatetimeMs):
        out.append(T_DATETIME)
        _varint(_zigzag(v.millis), out)
    elif isinstance(v, ObjectId):
        out.append(T_OBJECT_ID)
        out += v.binary
    elif isinstance(v, uuid.UUID):
        out.append(T_UUID)
        out += v.bytes
    elif isinstance(v, Timestamp):
        out.append(T_TIMESTAMP)
        out += struct.pack("<QI", v.wall, v.logical)
    elif isinstance(v, Vector):
        out.append(T_VECTOR)
        _varint(len(v), out)
        for f in v:
            out += struct.pack("<f", f)
    elif isinstance(v, MinKey):
        out.append(T_MIN_KEY)
    elif isinstance(v, MaxKey):
        out.append(T_MAX_KEY)
    elif isinstance(v, Counter):
        raise RDocError(1004, "a counter is read-only and never accepted as input")
    else:
        raise TypeError(f"no RDoc type for {type(v).__name__}")


def encode_value(value: Any) -> bytes:
    """The value encoding (type tag + payload, no header) of ``value``."""
    out = bytearray()
    _write(value, out, 0)
    return bytes(out)


def encode_document(document: Mapping[str, Any]) -> bytes:
    """The canonical RDoc of a document (header with the canonical flag)."""
    if not isinstance(document, Mapping):
        raise TypeError("a document is a mapping of field names to values")
    body = bytearray()
    _write_object(document, body, 1)
    total = HEADER_LEN + len(body)
    if total > MAX_SIZE:
        raise RDocError(1002, f"the document has {total} bytes (limit 16 MiB)")
    return bytes((MAGIC, VERSION, FLAG_CANONICAL)) + struct.pack("<I", total) + body


# ---------------------------------------------------------------------------------- reader


class _Reader:
    __slots__ = ("buf", "canonical", "pos")

    def __init__(self, buf: bytes, pos: int, canonical: bool) -> None:
        self.buf = buf
        self.pos = pos
        self.canonical = canonical

    def take(self, n: int, end: int) -> bytes:
        if n < 0 or self.pos + n > end:
            raise _malformed("value truncated")
        b = self.buf[self.pos : self.pos + n]
        self.pos += n
        return b

    def varint(self, end: int) -> int:
        result = 0
        for i in range(10):
            if self.pos >= end:
                raise _malformed("varint truncated")
            b = self.buf[self.pos]
            self.pos += 1
            if i == 9 and b > 1:
                raise _malformed("varint overflows u64")
            result |= (b & 0x7F) << (7 * i)
            if b < 0x80:
                if self.canonical and i > 0 and b == 0:
                    raise _malformed("non-minimal varint in a canonical document")
                return result
        raise _malformed("varint longer than 10 bytes")

    def length(self, end: int) -> int:
        n = self.varint(end)
        if self.pos + n > end:
            raise _malformed("length past the end of the value")
        return n

    def value(self, end: int, depth: int) -> Any:
        """Reads one value (tag + payload) ending at or before ``end``; ``depth`` = container depth."""
        tag = self.take(1, end)[0]
        if tag == T_NULL:
            return None
        if tag == T_BOOL:
            b = self.take(1, end)[0]
            if b > 1:
                raise _malformed("bool byte is not 0 or 1")
            return b == 1
        if tag in (T_INT64, T_DATETIME, T_COUNTER):
            z = self.varint(end)
            v = (z >> 1) ^ -(z & 1)
            if tag == T_INT64:
                return v
            if tag == T_COUNTER:
                return Counter(v)
            return millis_to_datetime(v)
        if tag == T_FLOAT64:
            raw = self.take(8, end)
            f: float = struct.unpack("<d", raw)[0]
            if math.isnan(f):
                if self.canonical and raw != _CANONICAL_NAN:
                    raise _malformed("NaN with a payload in a canonical document")
                return math.nan
            return f
        if tag == T_DECIMAL:
            raw = self.take(16, end)
            d = _decimal128.decode(raw)
            if self.canonical and _decimal128.encode(d) != raw:
                raise _malformed("non-canonical decimal128 in a canonical document")
            return d
        if tag == T_STRING:
            raw = self.take(self.length(end), end)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise _malformed("invalid UTF-8 in a string") from e
        if tag == T_BINARY:
            subtype = self.take(1, end)[0]
            data = self.take(self.length(end), end)
            if subtype == 0:
                return data
            if subtype == 4 and len(data) != 16:
                raise _malformed("binary subtype 4 must be 16 bytes")
            if subtype != 4 and subtype < 0x80:
                raise _malformed(f"reserved binary subtype {subtype:#04x}")
            return Binary(subtype, data)
        if tag == T_TIMESTAMP:
            wall, logical = struct.unpack("<QI", self.take(12, end))
            return Timestamp(wall, logical)
        if tag == T_OBJECT_ID:
            return ObjectId(self.take(12, end))
        if tag == T_UUID:
            return uuid.UUID(bytes=self.take(16, end))
        if tag == T_VECTOR:
            dims = self.varint(end)
            if dims > (end - self.pos) // 4:
                raise _malformed("vector truncated")
            values = struct.unpack(f"<{dims}f", self.take(4 * dims, end))
            if not all(math.isfinite(x) for x in values):
                raise RDocError(1040, "vector elements must be finite")
            return Vector(values)
        if tag == T_MIN_KEY:
            return MIN_KEY
        if tag == T_MAX_KEY:
            return MAX_KEY
        if tag == T_OBJECT:
            return self.object(end, depth + 1)
        if tag == T_ARRAY:
            return self.array(end, depth + 1)
        raise _malformed(f"unknown type tag {tag:#04x}")

    def object(self, end: int, depth: int) -> dict[str, Any]:
        if depth > MAX_DEPTH:
            raise RDocError(1003, "nesting deeper than 100 levels")
        n = self.varint(end)
        body_len = self.varint(end)
        if n > (end - self.pos) // 6:
            raise _malformed("field count exceeds the object body")
        index = [struct.unpack_from("<HI", self.buf, self.pos + 6 * i) for i in range(n)] if n else []
        self.pos += 6 * n
        start = self.pos
        body_end = start + body_len
        if body_end > end:
            raise _malformed("object body past the end of the value")
        doc: dict[str, Any] = {}
        starts: dict[int, tuple[int, bytes]] = {}
        for _ in range(n):
            if self.pos >= body_end:
                raise _malformed("field count exceeds the object body")
            offset = self.pos - start
            raw = self.take(self.length(body_end), body_end)
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise _malformed("invalid UTF-8 in a field name") from e
            _check_name(name)
            if name in doc:
                raise RDocError(1004, f"duplicate field name {name!r}")
            starts[offset] = (name_hash16(raw), raw)
            doc[name] = self.value(body_end, depth)
        if self.pos != body_end:
            raise _malformed("object body length does not match its fields")
        previous: tuple[int, bytes] | None = None
        seen: set[int] = set()
        for h, offset in index:
            entry = starts.get(offset)
            if entry is None or offset in seen:
                raise _malformed("index offset is not the start of a field")
            if entry[0] != h:
                raise _malformed("index hash does not match the field name")
            if previous is not None and entry <= previous:
                raise _malformed("index entries are not sorted by (hash, name)")
            seen.add(offset)
            previous = entry
        return doc

    def array(self, end: int, depth: int) -> list[Any]:
        if depth > MAX_DEPTH:
            raise RDocError(1003, "nesting deeper than 100 levels")
        n = self.varint(end)
        body_len = self.varint(end)
        if n > (end - self.pos) // 4:
            raise _malformed("element count exceeds the array")
        offsets = struct.unpack_from(f"<{n}I", self.buf, self.pos) if n else ()
        self.pos += 4 * n
        start = self.pos
        body_end = start + body_len
        if body_end > end:
            raise _malformed("array body past the end of the value")
        items: list[Any] = []
        for i in range(n):
            if offsets[i] != self.pos - start:
                raise _malformed("array offset does not match the element start")
            items.append(self.value(body_end, depth))
        if self.pos != body_end:
            raise _malformed("array body length does not match its elements")
        return items


def decode_value(raw: bytes) -> Any:
    """The value of a value encoding; trailing bytes are an error."""
    raw = bytes(raw)
    r = _Reader(raw, 0, False)
    v = r.value(len(raw), 0)
    if r.pos != len(raw):
        raise _malformed("trailing bytes after the value")
    return v


def decode_document(raw: bytes) -> dict[str, Any]:
    """The document of an RDoc; non-canonical encodings are accepted when the flag is clear."""
    raw = bytes(raw)
    if len(raw) < HEADER_LEN:
        raise _malformed("truncated RDoc header")
    if raw[0] != MAGIC:
        raise _malformed("not an RDoc (bad magic)")
    if raw[1] != VERSION:
        raise _malformed(f"unsupported RDoc version {raw[1]}")
    flags = raw[2]
    if flags & ~FLAG_CANONICAL:
        raise _malformed("unknown RDoc flag bits")
    (total,) = struct.unpack_from("<I", raw, 3)
    if total > MAX_SIZE:
        raise RDocError(1002, "the document exceeds 16 MiB")
    if total != len(raw):
        raise _malformed("total_len does not match the input length")
    r = _Reader(raw, HEADER_LEN, bool(flags & FLAG_CANONICAL))
    if r.take(1, len(raw))[0] != T_OBJECT:
        raise _malformed("the root of a document must be an object")
    doc = r.object(len(raw), 1)
    if r.pos != len(raw):
        raise _malformed("trailing bytes after the root object")
    return doc
