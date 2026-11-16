# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Checks of the shared data files beyond the codec: builder -> AST vectors (README §4),
connstring.yaml, scram/vectors.yaml and generated/errors.json. Each returns its failures."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from google.protobuf.json_format import MessageToDict

from rustegon import ClientSettings, Update, errors
from rustegon._ops import map_status
from rustegon._pb import error_pb2
from rustegon._scram import ScramClient, ScramError, saslprep
from rustegon.builders import ParamSink, delete_statement, find_statement, update_statement
from rustegon.settings import SCRAM_SHA_256
from tests.values import dsl_filter, dsl_projection, dsl_sort, dsl_update, plain
from tests.vectors import load

# ------------------------------------------------------------------------- AST vectors (§4)


def _statement(collection: str, case: Mapping[str, Any], params: dict[str, Any]) -> Any:
    op, args = case["op"], case["args"]
    f = dsl_filter(args["filter"], plain)
    fp, up = ParamSink("f", params), ParamSink("u", params)
    if op == "find":
        return find_statement(
            collection,
            f,
            dsl_sort(args["sort"]) if "sort" in args else None,
            dsl_projection(args["projection"]) if "projection" in args else None,
            args.get("limit"),
            args.get("skip"),
            fp,
        )
    if op in ("updateOne", "updateMany"):
        return update_statement(collection, f, dsl_update(args["update"], plain), op == "updateOne", fp, up)
    if op == "replaceOne":
        return update_statement(collection, f, Update.replace_with(plain(args["replacement"])), True, fp, up)
    return delete_statement(collection, f, op == "deleteOne", fp)


def check_ast_vectors(relative: str) -> list[str]:
    data = load(relative)
    collection = data["collection"]
    kind = Path(relative).name
    failures: list[str] = []
    for case in data["cases"]:
        params: dict[str, Any] = {}
        diffs: list[str] = []
        try:
            if kind == "filters.json":
                st = find_statement(
                    collection, dsl_filter(case["filter"], plain), None, None, None, None, ParamSink("f", params)
                )
                if MessageToDict(st) != case["statement"]:
                    diffs.append(f"statement {MessageToDict(st)}")
                if MessageToDict(st.query.where) != case["where"]:
                    diffs.append("where")
            elif kind == "updates.json":
                ops = [MessageToDict(o) for o in dsl_update(case["update"], plain).to_ast(ParamSink("u", params))]
                if ops != case["operations"]:
                    diffs.append(f"operations {ops}")
            else:
                st = _statement(collection, case, params)
                if MessageToDict(st) != case["statement"]:
                    diffs.append(f"statement {MessageToDict(st)}")
            want = {k: p["hex"] for k, p in case["params"].items()}
            got = {k: p.rdoc_value.hex() for k, p in params.items()}
            if want != got:
                diffs.append(f"params {got}, expected {want}")
        except Exception as e:
            diffs.append(repr(e))
        if diffs:
            failures.append(f"{case['name']}: {'; '.join(diffs)}")
    return failures


# ------------------------------------------------------------------------- connection strings


def _ms(x: float | None) -> int | None:
    return None if x is None else round(x * 1000)


def settings_view(s: ClientSettings) -> dict[str, Any]:
    """The settings in connstring.yaml's vocabulary."""
    cred = s.credential
    return {
        "hosts": [{"host": h, "port": p} for h, p in s.hosts],
        "user": cred.user if cred is not None and cred.user is not None else s.user,
        "password": cred.secret if cred is not None and cred.mechanism == SCRAM_SHA_256 else None,
        "database": s.database,
        "tls": s.tls,
        "tlsCaFile": s.tls_ca_file,
        "tlsServerName": s.tls_server_name,
        "tlsCertificateFile": s.tls_certificate_file,
        "tlsKeyFile": s.tls_key_file,
        "authMechanism": s.auth_mechanism,
        "applicationName": s.application_name,
        "connectTimeoutMs": _ms(s.connect_timeout),
        "operationTimeoutMs": _ms(s.operation_timeout),
        "readConsistency": s.read_consistency.value if s.read_consistency else None,
        "maxStalenessMs": _ms(s.max_staleness),
        "writeConcern": s.write_concern.value if s.write_concern else None,
        "retryReads": s.retry_reads,
        "retryWrites": s.retry_writes,
        "maxRetries": s.max_retries,
        "connectionsPerEndpoint": s.connections_per_endpoint,
    }


def check_connection_strings() -> list[str]:
    data = load("connstring.yaml")
    failures: list[str] = []
    for case in data["cases"]:
        name, uri = case["name"], case["uri"]
        try:
            s = ClientSettings.from_connection_string(uri)
        except ValueError as e:
            if case["valid"]:
                failures.append(f"{name}: rejected ({e})")
            else:
                userinfo = uri.partition("://")[2].partition("/")[0].rpartition("@")
                secret = userinfo[0].partition(":")[2] if userinfo[1] else ""
                # One-letter passwords of the suite ("p") occur in any English message.
                if len(secret) > 2 and secret in str(e):
                    failures.append(f"{name}: the error quotes the password")
            continue
        except Exception as e:
            failures.append(f"{name}: {e!r} instead of ValueError")
            continue
        if not case["valid"]:
            failures.append(f"{name}: accepted")
            continue
        expect = case.get("expect", {})
        want = {**data["defaults"], **expect}
        got = settings_view(s)
        diff = {k: (got[k], w) for k, w in want.items() if got.get(k) != w}
        if diff:
            failures.append(f"{name}: {diff}")
    return failures


# ------------------------------------------------------------------------- SCRAM


def check_scram_vectors() -> list[str]:
    data = load("scram/vectors.yaml")
    failures: list[str] = []
    for c in data["saslprep"]:
        try:
            out = saslprep(c["input"])
        except ValueError:
            if not c.get("error"):
                failures.append(f"saslprep {c['name']}: refused")
            continue
        if c.get("error"):
            failures.append(f"saslprep {c['name']}: accepted")
        elif out != c["output"]:
            failures.append(f"saslprep {c['name']}: {out!r}")
    for x in data["exchanges"]:
        scram = ScramClient(x["user"], x["password"], nonce=x["clientNonce"])
        if scram.client_first() != x["clientFirst"]:
            failures.append(f"{x['name']}: client-first {scram.client_first()}")
        final = scram.client_final(x["serverFirst"])
        if final != x["clientFinal"]:
            failures.append(f"{x['name']}: client-final {final}")
        if scram.salted_password.hex() != x["saltedPasswordHex"]:
            failures.append(f"{x['name']}: salted password")
        try:
            scram.verify_server_final(x["serverFinal"])
        except ScramError:
            failures.append(f"{x['name']}: valid server-final refused")
        sig = x["serverFinal"]
        tampered = sig[:3] + ("A" if sig[3] != "A" else "B") + sig[4:]
        try:
            scram.verify_server_final(tampered)
            failures.append(f"{x['name']}: tampered server-final accepted")
        except ScramError:
            pass
    return failures


# ------------------------------------------------------------------------- error mapping


def _varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _field(n: int, payload: bytes) -> bytes:
    return _varint(n << 3 | 2) + _varint(len(payload)) + payload


def status_bytes(code: int, detail: bytes) -> bytes:
    """A ``google.rpc.Status`` with one ``Any(ErrorDetail)``, as the server's ``to_status`` sends it."""
    any_ = _field(1, b"type.googleapis.com/rustegon.v1.ErrorDetail") + _field(2, detail)
    return _varint(1 << 3) + _varint(code) + _field(2, b"msg") + _field(3, any_)


def check_error_mapping() -> list[str]:
    data = load("generated/errors.json")
    failures: list[str] = []
    ids = {c["id"]: c for c in data["classes"]}
    for cid, cls in errors.CLASSES.items():
        parent = ids[cid]["parent"]
        want = Exception if parent is None else errors.CLASSES[parent]
        if want not in cls.__bases__:
            failures.append(f"{cls.__name__} does not derive from {want.__name__}")
    for c in data["codes"]:
        for retryable in (True, False):
            d = error_pb2.ErrorDetail(code=c["code"], name=c["name"], retryable=retryable, trace_id="t")
            e = map_status(c["grpc"], "", status_bytes(c["grpcCode"], d.SerializeToString()))
            if type(e) is not errors.CLASSES[c["exception"]["id"]]:
                failures.append(f"RGN-{c['code']} -> {type(e).__name__}, expected {c['exception']['id']}")
            if (e.code, e.retryable, e.trace_id, e.name) != (c["code"], retryable, "t", c["name"]):
                failures.append(f"RGN-{c['code']}: fields {e.code} {e.retryable} {e.trace_id} {e.name}")
    future = error_pb2.ErrorDetail(code=424242, name="Future").SerializeToString()
    unknown = map_status("UNKNOWN", "", status_bytes(2, future))
    if type(unknown) is not errors.CLASSES[data["unknown"]["id"]] or unknown.code != 424242:
        failures.append(f"unknown code -> {type(unknown).__name__}")
    for t in data["transport"]:
        status = "ABORTED" if t["grpc"] == "default" else t["grpc"]
        e = map_status(status, "", None)
        if (type(e), e.code, e.retryable) != (errors.CLASSES[t["exception"]["id"]], t["code"], t["retryable"]):
            failures.append(f"transport {t['grpc']} -> {type(e).__name__} {e.code} {e.retryable}")
    return failures
