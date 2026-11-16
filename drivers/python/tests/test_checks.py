# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""TC-DRV-PY-005…008, 021…023: builder -> AST vectors, error table, SCRAM, connection strings and
object mapping against the shared files of drivers/conformance (the same checks back the runner
operations of README §7)."""

from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import struct
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

import pytest

from rustegon import ClientSettings, Credential, extjson, rdoc
from rustegon.mapping import RgnCounter, RgnField, RgnGeoPoint, RgnId, RgnRev, RgnVector, codec_for, discriminator
from tests import checks
from tests.vectors import load


@pytest.mark.parametrize("file", ["ast/filters.json", "ast/updates.json", "ast/statements.json"])
def test_tc_drv_py_005_builder_ast_vectors(file: str) -> None:
    assert checks.check_ast_vectors(file) == []


def test_tc_drv_py_006_error_table_and_hierarchy() -> None:
    assert checks.check_error_mapping() == []


def test_tc_drv_py_007_scram_and_saslprep_vectors() -> None:
    assert checks.check_scram_vectors() == []


def test_tc_drv_py_008_connection_string_cases() -> None:
    assert checks.check_connection_strings() == []


# ------------------------------------------------------------------------- ADR-034 TLS default


def test_tc_drv_py_008_plain_text_by_default() -> None:
    s = ClientSettings.from_connection_string("rustegon://admin:pwd@localhost:7700/shop")
    assert s.tls is False
    assert s.credential is not None and s.credential.user == "admin"
    assert "pwd" not in repr(s)
    assert ClientSettings().tls is False


@pytest.mark.parametrize(
    "query",
    ["tlsCaFile=ca.crt", "tlsServerName=n1", "tlsCertificateFile=c.crt&tlsKeyFile=c.key", "authMechanism=X509"],
)
def test_tc_drv_py_008_tls_options_turn_tls_on(query: str) -> None:
    assert ClientSettings.from_connection_string(f"rustegon://db1/?{query}").tls is True


@pytest.mark.parametrize(
    "query",
    [
        "tls=false&tlsCaFile=ca.crt",
        "tls=false&tlsCertificateFile=c.crt&tlsKeyFile=c.key",
        "tls=false&authMechanism=X509",
    ],
)
def test_tc_drv_py_008_tls_false_with_tls_options_is_an_error(query: str) -> None:
    with pytest.raises(ValueError, match=r"(ADR-034|needs TLS)"):
        ClientSettings.from_connection_string(f"rustegon://db1/?{query}")


def test_tc_drv_py_008_settings_follow_the_same_rule() -> None:
    assert ClientSettings(tls_ca_file="ca.crt").tls is True
    assert ClientSettings(credential=Credential.x509("c.crt", "c.key")).tls is True
    with pytest.raises(ValueError, match="ADR-034"):
        ClientSettings(tls=False, tls_server_name="n1")


# ------------------------------------------------------------------------- object mapping


class MapStatus(enum.Enum):
    Draft = "draft"
    Paid = "paid"


@dataclasses.dataclass
class MapItem:
    name: str | None = None
    id: str | None = None
    count: int = 0
    ratio: float = 0.0
    price: Decimal | None = None
    tags: list[str] | None = None
    note: str | None = None
    status: MapStatus | None = None
    postal_code: Annotated[str | None, RgnField("zip")] = None
    rev: Annotated[str | None, RgnRev()] = None
    views: Annotated[int, RgnCounter()] = 0
    when: dt.datetime | None = None


@dataclasses.dataclass
class MapGeo:
    key: Annotated[str | None, RgnId()] = None
    embedding: Annotated[list[float] | None, RgnVector(3)] = None
    location: Annotated[list[float] | None, RgnGeoPoint()] = None


@dataclasses.dataclass
class MapShape:
    pass


@discriminator("circle")
@dataclasses.dataclass
class MapCircle(MapShape):
    id: str | None = None
    radius: float = 0.0


@dataclasses.dataclass
class MapSquare(MapShape):
    side: float = 0.0


@dataclasses.dataclass
class MapDrawing:
    id: str | None = None
    main: MapShape | None = None
    shapes: list[MapShape] | None = None


MODELS: dict[str, type[Any]] = {
    "MapItem": MapItem,
    "MapGeo": MapGeo,
    "MapShape": MapShape,
    "MapDrawing": MapDrawing,
}

# The vectors' "build" values, constructed in code (the vector name selects one).
F32_TENTH = struct.unpack("<f", struct.pack("<f", 0.1))[0]  # 0.1f widened to float64
BUILT: dict[str, Any] = {
    "null_id_omitted_read_only_not_written": MapItem(name="n", rev="r1", views=99),
    "datetime_rounded_down_to_ms": MapItem(id="t1", when=dt.datetime(2026, 11, 12, 10, 15, 30, 123456, tzinfo=dt.UTC)),
    "datetime_rounded_down_before_1970": MapItem(
        id="t2", when=dt.datetime(1969, 12, 31, 23, 59, 59, 999500, tzinfo=dt.UTC)
    ),
    "datetime_offset_dropped": MapItem(
        id="t3", when=dt.datetime(2026, 1, 2, 3, 4, 5, 999000, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    ),
    "float_widened_to_float64": MapItem(id="f1", ratio=F32_TENTH),
}
# Python has no int32: an int64 into an int member is accepted (DIVERGENCES.md §5).
NOT_APPLICABLE = {"item_int_overflow"}


def _encode(model: type[Any], value: Any) -> str:
    doc = codec_for(model).to_document(value)
    text = extjson.dumps(doc)
    # The RDoc bytes of the mapped document equal those of the parsed text.
    assert rdoc.encode_document(doc) == rdoc.encode_document(extjson.loads_document(text))
    return text


def test_tc_drv_py_023_mapping_round_trips() -> None:
    failures = []
    for v in load("mapping/vectors.yaml")["roundTrip"]:
        model = MODELS[v["model"]]
        codec = codec_for(model)
        for source in (v.get("input", v["json"]), v["json"]):
            got = _encode(model, codec.from_document(extjson.loads_document(source)))
            if got != v["json"]:
                failures.append(f"{v['name']}: {got}")
    assert failures == []


def test_tc_drv_py_023_mapping_built_values() -> None:
    vectors = load("mapping/vectors.yaml")["build"]
    assert {v["name"] for v in vectors} == set(BUILT)
    for v in vectors:
        assert _encode(MODELS[v["model"]], BUILT[v["name"]]) == v["json"], v["name"]


def test_tc_drv_py_023_mapping_refuses_invalid_documents() -> None:
    for v in load("mapping/vectors.yaml")["invalid"]:
        if v["name"] in NOT_APPLICABLE:
            continue
        with pytest.raises(ValueError):
            codec_for(MODELS[v["model"]]).from_document(extjson.loads_document(v["input"]))


def test_tc_drv_py_010_generated_sources_are_current() -> None:
    """The checked-in stubs and error table match proto/ and errors.json (PD-171)."""
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate.py"
    r = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
