# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""TC-DRV-PY-001…004: the RDoc codec and extended JSON against drivers/conformance/codec/*.yaml.

The same checks back the conformance runner operations ``checkValueVectors``,
``checkDocumentVectors`` and ``checkInvalidVectors`` (README §3, §7).
"""

from __future__ import annotations

import datetime as dt
import math
import uuid
from decimal import Decimal

import pytest

from rustegon import extjson, rdoc
from rustegon.errors import RDocError
from rustegon.types import Binary, DatetimeMs, ObjectId, Vector
from tests.vectors import check_document_vectors, check_invalid_vectors, check_value_vectors


def test_tc_drv_py_001_conformance_value_vectors() -> None:
    assert check_value_vectors() == []


def test_tc_drv_py_001_conformance_document_vectors() -> None:
    assert check_document_vectors() == []


def test_tc_drv_py_003_conformance_invalid_inputs() -> None:
    assert check_invalid_vectors() == []


def test_tc_drv_py_002_python_values_round_trip() -> None:
    doc = {
        "_id": ObjectId("65a1b2c3d4e5f60718293a4b"),
        "n": None,
        "b": True,
        "i": -(1 << 63),
        "f": -0.0,
        "nan": math.nan,
        "d": Decimal("12.50"),
        "s": "héllo \x00 😀",
        "bin": b"\x01\x02",
        "ubin": Binary(0x80, b"\xff"),
        "dt": dt.datetime(2026, 1, 1, 0, 0, 0, 123000, tzinfo=dt.UTC),
        "far": DatetimeMs(-(1 << 63)),
        "u": uuid.UUID("01234567-89ab-cdef-0123-456789abcdef"),
        "v": Vector([0.5, -1.0]),
        "arr": [1, [2, [3]], {}],
        "obj": {"z": 1, "a": {"k": []}},
    }
    back = rdoc.decode_document(rdoc.encode_document(doc))
    assert list(back) == list(doc)
    assert extjson.dumps(back) == extjson.dumps(doc)
    assert extjson.loads_document(extjson.dumps(doc, extended=True)) == back | {"nan": back["nan"]}


def test_tc_drv_py_002_datetimes_round_down_and_need_a_timezone() -> None:
    before_epoch = dt.datetime(1969, 12, 31, 23, 59, 59, 999500, tzinfo=dt.UTC)
    assert extjson.dumps(before_epoch) == '{"$date":"1969-12-31T23:59:59.999Z"}'
    offset = dt.datetime(2026, 1, 2, 3, 4, 5, 999000, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    assert extjson.dumps(offset) == '{"$date":"2026-01-02T01:04:05.999Z"}'
    with pytest.raises(RDocError) as e:
        rdoc.encode_value(dt.datetime(2026, 1, 1))  # naive
    assert e.value.code == 1001


def test_tc_drv_py_004_encoder_refuses_what_the_server_refuses() -> None:
    with pytest.raises(RDocError) as e:
        rdoc.encode_document({"a": {"$set": 1}})
    assert e.value.code == 1004
    with pytest.raises(RDocError) as e:
        rdoc.encode_value(1 << 63)
    assert e.value.code == 1001
    deep: dict[str, object] = {}
    cur = deep
    for _ in range(100):
        nxt: dict[str, object] = {}
        cur["a"] = nxt
        cur = nxt
    with pytest.raises(RDocError) as e:
        rdoc.encode_document(deep)
    assert e.value.code == 1003
    with pytest.raises(RDocError) as e:
        rdoc.encode_document({"big": b"\x00" * (16 * 1024 * 1024)})
    assert e.value.code == 1002
    assert isinstance(e.value, ValueError)  # an argument error raised before any I/O
    with pytest.raises(TypeError):
        rdoc.encode_value(object())
