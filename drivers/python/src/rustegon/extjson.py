# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Canonical and extended JSON of RDoc values (data-model.md §2 notes), byte-exact with the server.

``dumps(value)`` prints canonical JSON (plain JSON wherever lossless, ``$`` wrappers otherwise),
``dumps(value, extended=True)`` the extended mode (every int64 as ``$int64``, every float64 as
``$float``); ``loads`` parses either mode into the Python values of ``rustegon.types`` and
``loads_document`` additionally requires an object. Invalid input raises ``RDocError`` with the
catalog code of ``drivers/conformance/codec/invalid.yaml``.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import math
import re
import struct
import uuid
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Final

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

__all__ = ["dumps", "format_float", "loads", "loads_document"]

_INT64_MIN: Final = -(1 << 63)
_INT64_MAX: Final = (1 << 63) - 1
_SAFE_INT: Final = 1 << 53
_MS_PER_DAY: Final = 86_400_000
_WRAPPERS: Final = frozenset(
    {
        "$int64",
        "$float",
        "$decimal",
        "$binary",
        "$date",
        "$ts",
        "$oid",
        "$uuid",
        "$vector",
        "$counter",
        "$minKey",
        "$maxKey",
    }
)
_INT: Final = re.compile(r"-?[0-9]+", re.ASCII)
_NUMBER: Final = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", re.ASCII)
_DATE: Final = re.compile(
    r"([+-][0-9]{6,}|[0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z",
    re.ASCII,
)
_TS: Final = re.compile(r"([0-9]+)\.([0-9]+)", re.ASCII)
_OID: Final = re.compile(r"[0-9a-fA-F]{24}", re.ASCII)
_UUID: Final = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.ASCII)
_HEX2: Final = re.compile(r"[0-9a-fA-F]{2}", re.ASCII)


def _malformed(message: str) -> RDocError:
    return RDocError(1001, message)


# ---------------------------------------------------------------------------------- calendar


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm)."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int) -> tuple[int, int, int]:
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return yoe + era * 400 + (m <= 2), m, d


def _days_in_month(y: int, m: int) -> int:
    if m == 2:
        return 29 if (y % 4 == 0 and y % 100 != 0) or y % 400 == 0 else 28
    return 30 if m in (4, 6, 9, 11) else 31


def _format_date(millis: int) -> str:
    days, ms = divmod(millis, _MS_PER_DAY)
    y, mo, d = _civil_from_days(days)
    hh, rest = divmod(ms, 3_600_000)
    mi, rest = divmod(rest, 60_000)
    ss, frac = divmod(rest, 1000)
    year = f"{y:04d}" if 0 <= y <= 9999 else f"{'+' if y > 0 else '-'}{abs(y):06d}"
    return f"{year}-{mo:02d}-{d:02d}T{hh:02d}:{mi:02d}:{ss:02d}.{frac:03d}Z"


def _parse_date(text: str) -> int:
    m = _DATE.fullmatch(text)
    if not m:
        raise _malformed(f"not a $date: {text!r}")
    y, mo, d, hh, mi, ss = (int(g) for g in m.groups()[:6])
    frac = int((m.group(7) or "0").ljust(3, "0"))
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo) and hh < 24 and mi < 60 and ss < 60):
        raise _malformed(f"not a valid date: {text!r}")
    millis = (_days_from_civil(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss) * 1000 + frac
    if not _INT64_MIN <= millis <= _INT64_MAX:
        raise _malformed("date outside the datetime range")
    return millis


# ---------------------------------------------------------------------------------- numbers


def _shortest(x: float, f32: bool) -> str:
    """Shortest round-trip decimal digits of ``x`` (as float32 when ``f32``) in Python syntax."""
    if not f32:
        return repr(x)
    for p in range(1, 10):
        s = f"{x:.{p - 1}e}"
        try:
            if struct.unpack("<f", struct.pack("<f", float(s)))[0] == x:
                return s
        except OverflowError:  # rounded up past the largest float32
            continue
    return repr(x)  # pragma: no cover - 9 digits always round-trip a float32


def format_float(x: float, f32: bool = False) -> str:
    """The number text of a finite float: shortest round trip, formatted like Rust's ``ryu``.

    ``1.0``, ``0.1``, ``1e300``, ``5e-324``, ``9.223372036854776e18``: plain decimal while the
    decimal point lies within 16 digits (and at most 5 leading zeros), scientific otherwise;
    the text always holds a ``.`` or an exponent so that it parses back as a float.
    """
    if x == 0:
        return "-0.0" if math.copysign(1.0, x) < 0 else "0.0"
    t = Decimal(_shortest(x, f32)).as_tuple()
    digits = "".join(map(str, t.digits)).rstrip("0")
    exp = int(t.exponent) + (len(t.digits) - len(digits))
    sign = "-" if t.sign else ""
    n = len(digits)
    kk = n + exp  # position of the decimal point
    if exp >= 0 and kk <= 16:
        return f"{sign}{digits}{'0' * exp}.0"
    if 0 < kk <= 16:
        return f"{sign}{digits[:kk]}.{digits[kk:]}"
    if -5 < kk <= 0:
        return f"{sign}0.{'0' * -kk}{digits}"
    if n == 1:
        return f"{sign}{digits}e{kk - 1}"
    return f"{sign}{digits[0]}.{digits[1:]}e{kk - 1}"


# ---------------------------------------------------------------------------------- writer


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(o, f"\\u{o:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _dump(v: Any, extended: bool, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True or v is False:
        out.append("true" if v else "false")
    elif isinstance(v, int):
        if not _INT64_MIN <= v <= _INT64_MAX:
            raise _malformed("integer outside the int64 range")
        out.append(f'{{"$int64":"{v}"}}' if extended or abs(v) > _SAFE_INT else str(v))
    elif isinstance(v, float):
        if math.isnan(v):
            out.append('{"$float":"NaN"}')
        elif math.isinf(v):
            out.append('{"$float":"Infinity"}' if v > 0 else '{"$float":"-Infinity"}')
        else:
            text = format_float(v)
            out.append(f'{{"$float":"{text}"}}' if extended else text)
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, Mapping):
        out.append("{")
        for i, (k, x) in enumerate(v.items()):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _dump(x, extended, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _dump(x, extended, out)
        out.append("]")
    elif isinstance(v, Decimal):
        out.append(f'{{"$decimal":"{v}"}}')
    elif isinstance(v, (bytes, bytearray, memoryview)):
        out.append(f'{{"$binary":{{"base64":"{base64.b64encode(bytes(v)).decode()}","subType":"00"}}}}')
    elif isinstance(v, Binary):
        b64 = base64.b64encode(v.data).decode()
        out.append(f'{{"$binary":{{"base64":"{b64}","subType":"{v.subtype:02x}"}}}}')
    elif isinstance(v, _dt.datetime):
        out.append(f'{{"$date":"{_format_date(datetime_to_millis(v))}"}}')
    elif isinstance(v, DatetimeMs):
        out.append(f'{{"$date":"{_format_date(v.millis)}"}}')
    elif isinstance(v, Timestamp):
        out.append(f'{{"$ts":"{v.wall}.{v.logical}"}}')
    elif isinstance(v, ObjectId):
        out.append(f'{{"$oid":"{v}"}}')
    elif isinstance(v, uuid.UUID):
        out.append(f'{{"$uuid":"{v}"}}')
    elif isinstance(v, Vector):
        out.append('{"$vector":[' + ",".join(format_float(f, True) for f in v) + "]}")
    elif isinstance(v, Counter):
        out.append(f'{{"$counter":{v.value}}}')
    elif isinstance(v, MinKey):
        out.append('{"$minKey":1}')
    elif isinstance(v, MaxKey):
        out.append('{"$maxKey":1}')
    else:
        raise TypeError(f"no extended-JSON form for {type(v).__name__}")


def dumps(value: Any, *, extended: bool = False) -> str:
    """Canonical (default) or extended JSON text of a value or document; compact, stable."""
    out: list[str] = []
    _dump(value, extended, out)
    return "".join(out)


# ---------------------------------------------------------------------------------- parser


class _Pairs(list[tuple[str, Any]]):
    """A JSON object as parsed: its members in order (duplicates still present)."""


def _parse_int(text: str) -> int | float:
    v = int(text)
    if _INT64_MIN <= v <= _INT64_MAX:
        return v
    f = float(text)  # beyond int64: the nearest float64, as MongoDB and JavaScript do
    if math.isinf(f):
        raise _malformed("number beyond the float64 range")
    return f


def _parse_float(text: str) -> float:
    f = float(text)
    if math.isinf(f):
        raise _malformed("number beyond the float64 range")
    return f


def _refuse_constant(name: str) -> Any:
    raise _malformed(f'{name} is not JSON (use {{"$float": "{name}"}})')


def _wrapper(key: str, raw: Any) -> Any:
    if key == "$int64":
        if not isinstance(raw, str) or not _INT.fullmatch(raw):
            raise _malformed("$int64 takes a decimal string")
        v = int(raw)
        if not _INT64_MIN <= v <= _INT64_MAX:
            raise _malformed("$int64 out of range")
        return v
    if key == "$float":
        if raw == "NaN":
            return math.nan
        if raw in ("Infinity", "-Infinity"):
            return float(raw)
        if not isinstance(raw, str) or not _NUMBER.fullmatch(raw):
            raise _malformed("$float takes NaN, Infinity, -Infinity or a number string")
        return _parse_float(raw)
    if key == "$decimal":
        if not isinstance(raw, str):
            raise _malformed("$decimal takes a string")
        try:
            return _decimal128.parse(raw)
        except _decimal128.Decimal128Error as e:
            raise _malformed(str(e)) from e
    if key == "$binary":
        if not isinstance(raw, _Pairs) or sorted(k for k, _ in raw) != ["base64", "subType"]:
            raise _malformed("$binary takes {base64, subType}")
        fields = dict(raw)
        b64, sub = fields["base64"], fields["subType"]
        if not isinstance(b64, str) or not isinstance(sub, str) or not _HEX2.fullmatch(sub):
            raise _malformed("$binary.subType is two hex digits")
        try:
            data = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise _malformed("invalid base64") from e
        if base64.b64encode(data).decode() != b64:
            raise _malformed("base64 must be padded with zero unused bits")
        subtype = int(sub, 16)
        if subtype == 0:
            return data
        try:
            return Binary(subtype, data)
        except ValueError as e:
            raise _malformed(str(e)) from e
    if key == "$date":
        if not isinstance(raw, str):
            raise _malformed("$date takes an ISO 8601 string")
        return millis_to_datetime(_parse_date(raw))
    if key == "$ts":
        m = _TS.fullmatch(raw) if isinstance(raw, str) else None
        if not m:
            raise _malformed('$ts takes "<wall>.<logical>"')
        try:
            return Timestamp(int(m.group(1)), int(m.group(2)))
        except ValueError as e:
            raise _malformed(str(e)) from e
    if key == "$oid":
        if not isinstance(raw, str) or not _OID.fullmatch(raw):
            raise _malformed("$oid takes 24 hex digits")
        return ObjectId(raw.lower())
    if key == "$uuid":
        if not isinstance(raw, str) or not _UUID.fullmatch(raw):
            raise _malformed("$uuid takes 8-4-4-4-12 hex digits")
        return uuid.UUID(raw)
    if key == "$vector":
        if not isinstance(raw, list) or isinstance(raw, _Pairs):
            raise _malformed("$vector takes an array of numbers")
        if any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in raw):
            raise _malformed("$vector takes an array of numbers")
        try:
            return Vector(raw)
        except ValueError as e:
            raise RDocError(1040, str(e)) from e
    if key in ("$minKey", "$maxKey"):
        if raw != 1 or isinstance(raw, bool):
            raise _malformed(f"{key} takes 1")
        return MIN_KEY if key == "$minKey" else MAX_KEY
    # $counter is a read-only projection: never accepted as input.
    raise RDocError(1004, f"{key} is not accepted as input")


def _convert(raw: Any, depth: int) -> Any:
    if isinstance(raw, _Pairs):
        if any(k.startswith("$") for k, _ in raw):
            if len(raw) == 1 and raw[0][0] in _WRAPPERS:
                return _wrapper(raw[0][0], raw[0][1])
            if any(k in _WRAPPERS for k, _ in raw):
                raise _malformed("a $ wrapper must be the only member of its object")
            name = next(k for k, _ in raw if k.startswith("$"))
            raise RDocError(1004, f"field name {name!r} starts with '$'")
        if depth + 1 > 100:
            raise RDocError(1003, "nesting deeper than 100 levels")
        doc: dict[str, Any] = {}
        for k, v in raw:
            if not k or "\x00" in k:
                raise RDocError(1004, "a field name is 1 to 1024 bytes without NUL")
            if k in doc:
                raise RDocError(1004, f"duplicate field name {k!r}")
            doc[k] = _convert(v, depth + 1)
        return doc
    if isinstance(raw, list):
        if depth + 1 > 100:
            raise RDocError(1003, "nesting deeper than 100 levels")
        return [_convert(x, depth + 1) for x in raw]
    return raw


def loads(text: str) -> Any:
    """The value of canonical or extended JSON text."""
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_Pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_refuse_constant,
        )
    except RDocError:
        raise
    except RecursionError as e:
        raise RDocError(1003, "nesting too deep") from e
    except ValueError as e:
        raise _malformed(f"invalid JSON: {e}") from e
    return _convert(raw, 0)


def loads_document(text: str) -> dict[str, Any]:
    """The document of JSON text whose root is an object."""
    v = loads(text)
    if not isinstance(v, dict):
        raise _malformed("the root of a document must be an object")
    return v
