# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""IEEE 754-2008 decimal128, binary integer decimal (BID) encoding (data-model.md §2, §4).

``decimal.Decimal`` keeps the cohort (``12.50`` stays ``12.50``) and its ``str`` is IEEE
"to-scientific-string", so it is the Python type of decimal128; this module converts it to and
from the 16 bytes (u128 little-endian) of RDoc.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Final

MAX_COEFFICIENT: Final = 10**34 - 1
EXP_MIN: Final = -6176
EXP_MAX: Final = 6111
_BIAS: Final = 6176
_SMALL_COEFF_MASK: Final = (1 << 113) - 1
_NAN: Final = 0x7C << 120
_INF: Final = 0x78 << 120
_SIGN: Final = 1 << 127

# IEEE 754 decimal character sequence (no whitespace, no underscores: stricter than Decimal()).
_SYNTAX: Final = re.compile(
    r"[+-]?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|[Ii][Nn][Ff](?:[Ii][Nn][Ii][Tt][Yy])?|[Nn][Aa][Nn])",
    re.ASCII,
)


class Decimal128Error(ValueError):
    """A decimal that decimal128 cannot hold exactly."""


def parse(text: str) -> Decimal:
    """The decimal of an IEEE decimal string; refuses what decimal128 cannot hold exactly."""
    if not _SYNTAX.fullmatch(text):
        raise Decimal128Error(f"not a decimal: {text!r}")
    d = Decimal(text)
    encode(d)  # range and precision check
    return d


def encode(value: Decimal) -> bytes:
    """The canonical BID bytes of ``value`` (exact: never rounds)."""
    if value.is_nan():
        if value.is_snan():
            raise Decimal128Error("signalling NaN is not a decimal128 value")
        return _NAN.to_bytes(16, "little")
    sign = _SIGN if value.is_signed() else 0
    if value.is_infinite():
        return (sign | _INF).to_bytes(16, "little")
    t = value.as_tuple()
    coefficient = int("".join(map(str, t.digits)) or "0")
    if not isinstance(t.exponent, int):  # pragma: no cover - finite values have an int exponent
        raise Decimal128Error("unexpected special value")
    exponent: int = t.exponent
    # Exact only: drop trailing zeros while the coefficient is too long, then bring the
    # exponent into range by adding or removing zeros (IEEE clamping; data-model.md §2 notes).
    while coefficient > MAX_COEFFICIENT and coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    if coefficient > MAX_COEFFICIENT:
        raise Decimal128Error("more than 34 significant digits")
    if coefficient == 0:
        exponent = min(max(exponent, EXP_MIN), EXP_MAX)
    while exponent > EXP_MAX:
        coefficient *= 10
        exponent -= 1
        if coefficient > MAX_COEFFICIENT:
            raise Decimal128Error("exponent out of the decimal128 range")
    while exponent < EXP_MIN:
        if coefficient % 10 != 0:
            raise Decimal128Error("exponent out of the decimal128 range")
        coefficient //= 10
        exponent += 1
    bits = sign | ((exponent + _BIAS) << 113) | coefficient
    return bits.to_bytes(16, "little")


def decode(raw: bytes) -> Decimal:
    """The decimal of 16 BID bytes; non-canonical encodings are normalised (IEEE rules)."""
    bits = int.from_bytes(raw, "little")
    negative = bool(bits & _SIGN)
    top5 = (bits >> 122) & 0x1F
    if top5 == 0x1F:
        return Decimal("NaN")
    if top5 == 0x1E:
        return Decimal("-Infinity" if negative else "Infinity")
    if (bits >> 125) & 0x3 == 0x3:
        # Large-coefficient form: the coefficient is >= 2^113 > 10^34 - 1, i.e. non-canonical: 0.
        biased = (bits >> 111) & 0x3FFF
        coefficient = 0
    else:
        biased = (bits >> 113) & 0x3FFF
        coefficient = bits & _SMALL_COEFF_MASK
        if coefficient > MAX_COEFFICIENT:
            coefficient = 0
    exponent = min(biased, EXP_MAX + _BIAS) - _BIAS
    digits = tuple(int(c) for c in str(coefficient))
    return Decimal((1 if negative else 0, digits, exponent))
