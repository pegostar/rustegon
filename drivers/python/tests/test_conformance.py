# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""The conformance runner of the Python driver (TC-DRV-PY-011…020, TC-DRV-CONF-*; FR-DRV-003,
AC-DRV-003): every test file of drivers/conformance runs per README §5-§7 against the
``rustegond`` fixture (PD-072): a fresh database per file; collections, indexes, data and users
per test; then the operations and the ``outcome``. The results go to
``RUSTEGON_CONFORMANCE_RESULTS`` (default ``build/conformance-results.json``, README §6); the last
test checks that every ``r1`` operation of model.yaml is covered by a passed test."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import os
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from rustegon import (
    AsyncCursor,
    AsyncRustegonClient,
    AsyncTransaction,
    ClientSession,
    Credential,
    IndexKey,
    Sort,
    __version__,
    extjson,
)
from rustegon._ops import NO_CONTEXT, Kind
from rustegon._pb import admin_pb2, common_pb2
from rustegon.types import DatetimeMs, ObjectId
from tests import checks, server
from tests.fake_server import run_retry_scenarios
from tests.oprunner import ApplicationError, OpRunner, _validator
from tests.values import SYSTEM_FIELDS, mismatch
from tests.vectors import CONFORMANCE, check_document_vectors, check_invalid_vectors, check_value_vectors, load

pytestmark = [pytest.mark.conformance]

FILES = {
    "011_crud": ["crud/find-by-id.yaml", "crud/insert.yaml", "crud/replace-delete.yaml", "crud/update.yaml"],
    "012_find_and_cursors": ["query/filters.yaml", "query/find-options.yaml", "cursor/cursor.yaml"],
    "013_rgql": ["query/rgql.yaml"],
    "014_bulk": ["bulk/bulk.yaml"],
    "015_schema": ["schema/collections.yaml"],
    "016_transactions": ["txn/transactions.yaml"],
    "018_auth": ["auth/auth.yaml"],
    "020_client_and_errors": ["client/vectors.yaml", "errors/errors.yaml"],
}
CAPABILITIES = {"admin", "api-key", "x509-client-cert", "slow", "fixture-connection-string"}
RESULTS: dict[str, dict[str, Any]] = {}
COVERS: dict[str, list[str]] = {}
_state: dict[str, Any] = {"serverVersion": "", "apiKey": None}


def _none(failures: list[str]) -> None:
    if failures:
        raise AssertionError(f"{len(failures)} failures:\n" + "\n".join(failures))


def _grant(text: str) -> common_pb2.RoleGrant:
    """``role@db`` / ``role@db.coll`` / ``role`` -> RoleGrant (PD-051)."""
    role, at, scope = text.partition("@")
    if not at:
        return common_pb2.RoleGrant(role=role)
    return common_pb2.RoleGrant(role=role, resource=("collection:" if "." in scope else "database:") + scope)


class FileRun:
    """One test file: its database and administrator client, created on first need."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        root = load(rel)
        self.tests: list[dict[str, Any]] = root["tests"]
        self.file_setup = root.get("setup")
        self.text = (CONFORMANCE / rel).read_text(encoding="utf-8")
        self.server: server.TestServer | None = None
        self.database = ""
        self.admin: AsyncRustegonClient | None = None

    async def test(self, t: Mapping[str, Any], last: bool) -> None:
        tid = t["id"]
        COVERS[tid] = list(t.get("covers", []))
        result: dict[str, Any] = {"id": tid}
        RESULTS[tid] = result
        runner: OpRunner | None = None
        try:
            for cap in t.get("requires", []):
                if cap not in CAPABILITIES:
                    pytest.skip(f"requires {cap}")
            setup = t.get("setup", self.file_setup)
            ops = t["operations"]
            needs_server = setup is not None or any(o["object"] != "runner" for o in ops)
            if needs_server:
                await self._open()
            # A runner-only test needs no client: the placeholder is never called.
            client = self.admin or AsyncRustegonClient("rustegon://localhost")
            runner = OpRunner(client, self.database, _default_collection(setup), _Env(self))
            users = await self._set_up(setup, t, runner) if needs_server else []
            try:
                for op in ops:
                    await runner.run(op)
                if isinstance(t.get("outcome"), dict):
                    result["outcome"] = await self._check_outcome(t["outcome"], runner)
            finally:
                await runner.close_opened()
                for u in users:
                    await self._drop_user(u)
            result["status"] = "passed"
        except pytest.skip.Exception as e:
            result["status"], result["reason"] = "skipped", str(e)
            raise
        except BaseException as e:
            result["status"], result["reason"] = "failed", str(e)
            raise
        finally:
            if runner is not None:
                result["observations"] = runner.observations
            result["text"] = self.text
            if last:
                await self._close()

    async def _open(self) -> None:
        if self.admin is not None:
            return
        self.server = server.shared()
        category, _, file = self.rel.partition("/")
        stem = file.rsplit(".", 1)[0].replace("-", "_")
        self.database = f"conf_{category}_{stem}_{secrets.token_hex(4)}"
        self.admin = AsyncRustegonClient(self.server.admin_settings(database=self.database))
        _state["serverVersion"] = (await self.admin.server_info()).server_version
        await self.admin.create_database(self.database)

    async def _close(self) -> None:
        if self.admin is not None:
            try:
                await self.admin.drop_database(self.database, if_exists=True)
            finally:
                await self.admin.close()
                self.admin = None

    async def _admin_call(self, method: str, request: Any) -> Any:
        assert self.admin is not None
        return await self.admin._ops.unary(lambda s: getattr(s.admin, method), request, Kind.NONE, NO_CONTEXT)

    async def _drop_user(self, name: str) -> None:
        with contextlib.suppress(Exception):  # not there
            await self._admin_call("DropUser", admin_pb2.DropUserRequest(name=name))

    async def _set_up(self, setup: Mapping[str, Any] | None, t: Mapping[str, Any], runner: OpRunner) -> list[str]:
        assert self.admin is not None
        db = self.admin.get_database(self.database)
        for c in await db.list_collection_names():
            await db.drop_collection(c, if_exists=True)
        users: list[str] = []
        if "x509-client-cert" in t.get("requires", []):
            name = f"x509:CN={server.X509_USER}"
            await self._drop_user(name)
            await self._admin_call(
                "CreateUser", admin_pb2.CreateUserRequest(name=name, roles=[_grant(f"read_write@{self.database}")])
            )
            users.append(name)
        if setup is None:
            return users
        for c in setup.get("collections", []):
            v = _validator(c["validator"]) if "validator" in c else None
            await db.create_collection(c["name"], validator=v)
        for ix in setup.get("indexes", []):
            keys = [IndexKey(k["path"], bool(k.get("descending"))) for k in ix["keys"]]
            await db.get_collection(ix["collection"]).create_index(ix["name"], keys, unique=bool(ix.get("unique")))
        for coll, docs in (setup.get("data") or {}).items():
            if docs:
                await db.get_collection(coll).insert_many([runner.v(d) for d in docs])
        for u in setup.get("users", []):
            await self._drop_user(u["name"])
            await self._admin_call(
                "CreateUser",
                admin_pb2.CreateUserRequest(
                    name=u["name"],
                    password=u["password"],
                    must_change_password=bool(u.get("mustChangePassword")),
                    roles=[_grant(self.substitute(r)) for r in u["roles"]],
                ),
            )
            users.append(u["name"])
        return users

    async def _check_outcome(self, outcome: Mapping[str, Any], runner: OpRunner) -> dict[str, Any]:
        assert self.admin is not None
        actual: dict[str, Any] = {}
        for coll, want in outcome.items():
            docs = (
                await self.admin.get_database(self.database).get_collection(coll).find().sort(Sort.asc("_id")).to_list()
            )
            actual[coll] = docs
            d = mismatch(runner.v(want), docs, False, True, False)
            if d is not None:
                raise AssertionError(f"outcome {coll}: {d}")
        return actual

    def substitute(self, s: str) -> str:
        if "${" not in s:
            return s
        values = {"database": self.database}
        srv = self.server
        if srv is not None:
            values |= {
                "host": srv.host,
                "port": str(srv.port),
                "adminUser": server.ADMIN_USER,
                "adminPassword": srv.admin_password,
                "adminUserEncoded": quote(server.ADMIN_USER, safe=""),
                "adminPasswordEncoded": quote(srv.admin_password, safe=""),
                "caFile": str(srv.ca_file),
                "caFileEncoded": quote(str(srv.ca_file), safe=""),
                "clientCertFile": str(srv.client_cert_file),
                "clientKeyFile": str(srv.client_key_file),
            }
        for k, v in values.items():
            s = s.replace("${" + k + "}", v)
        return s

    async def api_key(self) -> str:
        if _state["apiKey"] is None:
            r = await self._admin_call(
                "CreateApiKey",
                admin_pb2.CreateApiKeyRequest(
                    description="python driver conformance",
                    roles=[common_pb2.RoleGrant(role="root", resource="cluster")],
                ),
            )
            _state["apiKey"] = r.secret
        key: str = _state["apiKey"]
        return key


def _default_collection(setup: Mapping[str, Any] | None) -> str:
    if setup and setup.get("collections"):
        name: str = setup["collections"][0]["name"]
        return name
    return "items"


class _Env:
    def __init__(self, run: FileRun) -> None:
        self.run = run

    def substitute(self, s: str) -> str:
        return self.run.substitute(s)

    async def open(self, args: Mapping[str, Any]) -> AsyncRustegonClient:
        srv = self.run.server
        assert srv is not None
        cred = args["credential"]
        if "scram" in cred:
            credential = Credential.scram(
                self.substitute(cred["scram"]["user"]), self.substitute(cred["scram"]["password"])
            )
        elif "apiKey" in cred:
            key = cred["apiKey"]
            credential = Credential.api_key(await self.run.api_key() if key == "${apiKey}" else self.substitute(key))
        else:
            x = cred["x509"]
            credential = Credential.x509(self.substitute(x["certificateFile"]), self.substitute(x["keyFile"]))
        return AsyncRustegonClient(
            srv.settings(
                credential,
                database=self.run.database,
                allow_password_change_only=bool(args.get("allowPasswordChangeOnly")),
            )
        )

    async def runner(self, name: str, args: Mapping[str, Any], runner: OpRunner) -> Any:
        file = args.get("file", "")
        if name == "sleep":
            await asyncio.sleep(args["ms"] / 1000)
        elif name == "throwApplicationError":
            raise ApplicationError
        elif name == "assertLastErrorHasTraceId":
            e = runner.last_error
            if not getattr(e, "trace_id", ""):
                raise AssertionError(f"the last error has no trace id: {e!r}")
        elif name == "checkAstVectors":
            _none(checks.check_ast_vectors(file))
        elif name == "runRetryScenarios":
            _none(await run_retry_scenarios(file))
        elif name == "checkValueVectors":
            _none(check_value_vectors())
        elif name == "checkDocumentVectors":
            _none(check_document_vectors())
        elif name == "checkInvalidVectors":
            _none(check_invalid_vectors())
        elif name == "checkErrorMapping":
            _none(checks.check_error_mapping())
        elif name == "checkConnectionStrings":
            _none(checks.check_connection_strings())
        elif name == "checkScramVectors":
            _none(checks.check_scram_vectors())
        else:
            raise AssertionError(f"runner.{name}")
        return None


# ------------------------------------------------------------------------- tests

_RUNS = {rel: FileRun(rel) for files in FILES.values() for rel in files}
_CASES = [
    pytest.param(group, rel, i, id=t["id"])
    for group, files in FILES.items()
    for rel in files
    for i, t in enumerate(_RUNS[rel].tests)
]


@pytest.mark.parametrize(("group", "rel", "index"), _CASES)
async def test_tc_drv_py_conformance(group: str, rel: str, index: int) -> None:
    run = _RUNS[rel]
    await run.test(run.tests[index], index == len(run.tests) - 1)


def test_tc_drv_py_020_every_r1_operation_is_covered_and_results_are_written() -> None:
    if not RESULTS:
        pytest.skip("the conformance tests did not run")
    write_results()
    covered = {op for tid, r in RESULTS.items() if r.get("status") == "passed" for op in COVERS.get(tid, [])}
    r1 = [op["id"] for op in load("model.yaml")["operations"] if op["status"] == "r1"]
    missing = [op for op in r1 if op not in covered]
    print(f"conformance: {len(RESULTS)} tests, r1 operations covered {len(r1) - len(missing)}/{len(r1)}")
    assert missing == [], f"r1 operations without a passed test: {missing}"


# ------------------------------------------------------------------------- results file (README §6)


def results_path() -> Path:
    env = os.environ.get("RUSTEGON_CONFORMANCE_RESULTS")
    return Path(env) if env else Path(__file__).resolve().parents[1] / "build" / "conformance-results.json"


def write_results() -> None:
    """Canonical extended JSON, sorted keys, volatile values as tokens."""
    parts = []
    for tid in sorted(RESULTS):
        entry = dict(RESULTS[tid])
        text = entry.pop("text", "")
        parts.append(_Tokens(text).json(entry))
    head = (
        f'{{"driver":"python","driverVersion":{extjson.dumps(__version__)},'
        f'"serverVersion":{extjson.dumps(_state["serverVersion"])},"results":['
    )
    path = results_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(head + ",".join(parts) + "]}\n", encoding="utf-8")


class _Tokens:
    """Token replacement of one test's values: generated ObjectIds, server datetimes, handles."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.oids: dict[str, str] = {}

    def json(self, v: Any) -> str:
        if isinstance(v, dict):
            items = sorted((k, x) for k, x in v.items() if k not in SYSTEM_FIELDS)
            return "{" + ",".join(f"{extjson.dumps(k)}:{self.json(x)}" for k, x in items) + "}"
        if isinstance(v, list):
            return "[" + ",".join(self.json(x) for x in v) + "]"
        if isinstance(v, ObjectId) and str(v) not in self.text:
            return '"' + self.oids.setdefault(str(v), f"<oid:{len(self.oids) + 1}>") + '"'
        if isinstance(v, (dt.datetime, DatetimeMs)):
            iso = extjson.dumps(v)
            inner = iso[iso.index(':"') + 2 : iso.rindex('"')]
            return iso if inner in self.text else '"<datetime>"'
        if isinstance(v, (AsyncRustegonClient, AsyncCursor, ClientSession, AsyncTransaction)):
            return '"<handle>"'
        try:
            return extjson.dumps(v)
        except (TypeError, ValueError):
            return extjson.dumps(str(v))
