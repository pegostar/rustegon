# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Python types of the RDoc values that have no exact built-in equivalent (data-model.md §2).

Built-in mapping (python-driver.md §7): ``None`` null, ``bool`` bool, ``int`` int64, ``float``
float64, ``decimal.Decimal`` decimal128, ``str`` string, ``bytes`` binary subtype 0,
``datetime.datetime`` (timezone-aware) datetime, ``uuid.UUID`` uuid, ``list``/``tuple`` array,
``dict`` object (insertion order is the field order). The classes below cover the rest.
"""

from __future__ import annotations

import datetime as _dt
import math
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "MAX_KEY",
    "MIN_KEY",
    "Binary",
    "Counter",
    "DatetimeMs",
    "MaxKey",
    "MinKey",
    "ObjectId",
    "Timestamp",
    "Vector",
]


class ObjectId:
    """A 12-byte object id: 4 B seconds (big-endian), 5 B per-process random, 3 B counter."""

    __slots__ = ("_bytes",)

    _lock: Final = threading.Lock()
    _random: bytes = os.urandom(5)
    _counter: int = int.from_bytes(os.urandom(3), "big")

    def __init__(self, value: str | bytes) -> None:
        if isinstance(value, str):
            if len(value) != 24:
                raise ValueError("an ObjectId is 24 hex digits")
            try:
                raw = bytes.fromhex(value)
            except ValueError as e:
                raise ValueError("an ObjectId is 24 hex digits") from e
        elif isinstance(value, bytes):
            raw = value
        else:
            raise TypeError("an ObjectId is built from 24 hex digits or 12 bytes")
        if len(raw) != 12:
            raise ValueError("an ObjectId has 12 bytes")
        self._bytes = raw

    @classmethod
    def generate(cls) -> ObjectId:
        """A new id; the counter is shared by every thread of the process."""
        with cls._lock:
            ObjectId._counter = (ObjectId._counter + 1) & 0xFFFFFF
            counter = ObjectId._counter
        seconds = int(time.time()) & 0xFFFFFFFF
        return cls(seconds.to_bytes(4, "big") + cls._random + counter.to_bytes(3, "big"))

    @property
    def binary(self) -> bytes:
        """The 12 bytes."""
        return self._bytes

    def __str__(self) -> str:
        return self._bytes.hex()

    def __repr__(self) -> str:
        return f"ObjectId('{self._bytes.hex()}')"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ObjectId) and other._bytes == self._bytes

    def __hash__(self) -> int:
        return hash(self._bytes)


@dataclass(frozen=True, slots=True)
class Binary:
    """Binary data with a subtype other than 0 (0 decodes to ``bytes``): 4 (16 bytes), 0x80–0xFF."""

    subtype: int
    data: bytes

    def __post_init__(self) -> None:
        if not (self.subtype in (0, 4) or 0x80 <= self.subtype <= 0xFF):
            raise ValueError(f"binary subtype {self.subtype:#04x} is reserved")
        if self.subtype == 4 and len(self.data) != 16:
            raise ValueError("binary subtype 4 (uuid) must be 16 bytes")


@dataclass(frozen=True, slots=True)
class Timestamp:
    """A hybrid logical clock timestamp (mostly system-generated)."""

    wall: int
    logical: int

    def __post_init__(self) -> None:
        if not (0 <= self.wall < 1 << 64 and 0 <= self.logical < 1 << 32):
            raise ValueError("a timestamp is a u64 wall time and a u32 logical counter")


def _f32(x: float) -> float:
    """``x`` rounded to the nearest float32 (OverflowError beyond its range)."""
    return float(struct.unpack("<f", struct.pack("<f", x))[0])


class Vector:
    """A ``vector_f32``: finite float32 elements (stored widened to Python floats)."""

    __slots__ = ("_values",)

    def __init__(self, values: Any) -> None:
        out: list[float] = []
        for v in values:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise TypeError("vector elements are numbers")
            try:
                f = _f32(float(v))
            except OverflowError as e:
                raise ValueError("vector elements must be finite float32 values") from e
            if not math.isfinite(f):
                raise ValueError("vector elements must be finite float32 values")
            out.append(f)
        self._values = tuple(out)

    @property
    def values(self) -> tuple[float, ...]:
        """The elements."""
        return self._values

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Any:
        return iter(self._values)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Vector) or len(other._values) != len(self._values):
            return False
        # Bitwise equality: -0.0 and 0.0 are different elements of a stored vector.
        return all(
            struct.pack("<f", a) == struct.pack("<f", b) for a, b in zip(self._values, other._values, strict=True)
        )

    def __hash__(self) -> int:
        return hash(self._values)

    def __repr__(self) -> str:
        return f"Vector({list(self._values)!r})"


@dataclass(frozen=True, slots=True)
class Counter:
    """The read-only projection of a document counter (never accepted as input)."""

    value: int


class MinKey:
    """The lowest value of the total order (range bounds)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "MIN_KEY"


class MaxKey:
    """The highest value of the total order (range bounds)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "MAX_KEY"


MIN_KEY: Final = MinKey()
MAX_KEY: Final = MaxKey()


@dataclass(frozen=True, slots=True)
class DatetimeMs:
    """A datetime outside the years 1–9999 of ``datetime.datetime``: milliseconds since the epoch.

    RDoc datetimes span ±292 million years; values that ``datetime.datetime`` can hold decode to
    an aware ``datetime`` in UTC, the others to this class (python-driver.md §7).
    """

    millis: int

    def __post_init__(self) -> None:
        if not -(1 << 63) <= self.millis < 1 << 63:
            raise ValueError("a datetime is a signed 64-bit count of milliseconds")


_EPOCH: Final = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)


def datetime_to_millis(value: _dt.datetime) -> int:
    """Milliseconds since the epoch, rounded down (also before 1970); the offset is dropped."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetimes are ambiguous: give a timezone (e.g. datetime.UTC)")
    return (value - _EPOCH) // _dt.timedelta(milliseconds=1)


def millis_to_datetime(millis: int) -> _dt.datetime | DatetimeMs:
    """The aware UTC datetime of ``millis``, or ``DatetimeMs`` outside the years 1–9999."""
    try:
        return _EPOCH + _dt.timedelta(milliseconds=millis)
    except OverflowError:
        return DatetimeMs(millis)
