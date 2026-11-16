# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Checks of the shared data files of drivers/conformance (README §3, §4, §7, connstring.yaml,
scram/vectors.yaml, generated/errors.json). Each returns the list of failures (empty = pass);
the unit tests and the conformance runner operations call the same functions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from rustegon import extjson, rdoc
from rustegon.errors import RDocError

CONFORMANCE = Path(__file__).resolve().parents[2] / "conformance"
REPO = CONFORMANCE.parents[1]


def load(relative: str) -> Any:
    """A YAML or JSON file of the suite."""
    text = (CONFORMANCE / relative).read_text(encoding="utf-8")
    return json.loads(text) if relative.endswith(".json") else yaml.safe_load(text)


def check_value_vectors() -> list[str]:
    failures: list[str] = []
    data = load("codec/values.yaml")
    for v in data["values"]:
        name = v["name"]
        try:
            decoded = rdoc.decode_value(bytes.fromhex(v["hex"]))
            if extjson.dumps(decoded) != v["ext_json"]:
                failures.append(f"{name}: decode -> {extjson.dumps(decoded)}")
            if extjson.dumps(decoded, extended=True) != v["extended_json"]:
                failures.append(f"{name}: extended -> {extjson.dumps(decoded, extended=True)}")
            if v.get("decode_only"):
                continue
            for text in (v["input"], v["ext_json"], v["extended_json"]):
                parsed = extjson.loads(text)
                if rdoc.encode_value(parsed).hex() != v["hex"]:
                    failures.append(f"{name}: encode {text} -> {rdoc.encode_value(parsed).hex()}")
        except (RDocError, ValueError, TypeError) as e:
            failures.append(f"{name}: {e!r}")
    for v in data.get("noncanonical", []):
        try:
            decoded = rdoc.decode_value(bytes.fromhex(v["hex"]))
            if rdoc.encode_value(decoded).hex() != v["canonical_hex"]:
                failures.append(f"{v['name']}: re-encoded {rdoc.encode_value(decoded).hex()}")
            if extjson.dumps(decoded) != v["ext_json"]:
                failures.append(f"{v['name']}: json {extjson.dumps(decoded)}")
        except (RDocError, ValueError) as e:
            failures.append(f"{v['name']}: {e!r}")
    return failures


def check_document_vectors() -> list[str]:
    failures: list[str] = []
    data = load("codec/documents.yaml")
    for d in data["documents"]:
        name = d["name"]
        try:
            decoded = rdoc.decode_document(bytes.fromhex(d["hex"]))
            if extjson.dumps(decoded) != d["ext_json"]:
                failures.append(f"{name}: decode -> {extjson.dumps(decoded)[:200]}")
            if not d.get("decode_only"):
                encoded = rdoc.encode_document(extjson.loads_document(d["ext_json"])).hex()
                if encoded != d["hex"]:
                    failures.append(f"{name}: encode -> {encoded[:200]}")
            for h in d.get("name_hash16") or []:
                got = f"{rdoc.name_hash16(h['name'].encode('utf-8')):04x}"
                if got != h["hash"]:
                    failures.append(f"{name}: hash of {h['name']!r} = {got}")
        except (RDocError, ValueError, TypeError) as e:
            failures.append(f"{name}: {e!r}")
    for d in data.get("noncanonical", []):
        try:
            decoded = rdoc.decode_document(bytes.fromhex(d["hex"]))
            if rdoc.encode_document(decoded).hex() != d["canonical_hex"]:
                failures.append(f"{d['name']}: re-encoded {rdoc.encode_document(decoded).hex()}")
            if "ext_json" in d and extjson.dumps(decoded) != d["ext_json"]:
                failures.append(f"{d['name']}: json {extjson.dumps(decoded)}")
        except (RDocError, ValueError) as e:
            failures.append(f"{d['name']}: {e!r}")
    return failures


def check_invalid_vectors() -> list[str]:
    failures: list[str] = []
    data = load("codec/invalid.yaml")
    cases: list[tuple[str, int, Any]] = []
    for d in data["documents"]:
        cases.append((d["name"], d["code"], lambda h=d["hex"]: rdoc.decode_document(bytes.fromhex(h))))
    for v in data["values"]:
        cases.append((v["name"], v["code"], lambda h=v["hex"]: rdoc.decode_value(bytes.fromhex(h))))
    for j in data["json"]:
        fn = extjson.loads_document if j["kind"] == "document" else extjson.loads
        cases.append((j["name"], j["code"], lambda t=j["json"], f=fn: f(t)))
    for name, code, run in cases:
        try:
            run()
            failures.append(f"{name}: accepted")
        except RDocError as e:
            if e.code != code:
                failures.append(f"{name}: RGN-{e.code}, expected RGN-{code} ({e})")
        except Exception as e:
            failures.append(f"{name}: unexpected {e!r}")
    return failures
