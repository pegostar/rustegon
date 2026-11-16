# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""The in-process fake gRPC server of retry.yaml (drivers/conformance/README.md §8, PD-073) and
the runner operation ``runRetryScenarios``: every scenario runs against a fresh fake server with
a fresh client, then the outcome, call counts, request ids, deadlines and backoff delays are
checked against the scenario (rules R1-R8 of the file header)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

import grpc
import grpc.aio
from google.protobuf import json_format, message_factory
from google.protobuf.descriptor import Descriptor, MethodDescriptor

from rustegon import AsyncRustegonClient, ClientSettings, Credential, rdoc
from rustegon._error_table import CODES
from rustegon._pb import (
    admin_pb2,
    auth_pb2,
    document_pb2,
    error_pb2,
    query_pb2,
    schema_pb2,
    session_pb2,
    transaction_pb2,
)
from tests.checks import status_bytes
from tests.oprunner import ApplicationError, OpRunner
from tests.values import plain
from tests.vectors import load

SCRAM_USER = "fake"
SCRAM_PASSWORD = "fake-password-123"
DELAY_TOLERANCE_MS = 250  # retry.yaml header
_MODULES = (admin_pb2, auth_pb2, document_pb2, query_pb2, schema_pb2, session_pb2, transaction_pb2)
_DEFAULTS: dict[str, dict[str, Any]] = {
    "SessionService.GetServerInfo": {"ok": {"serverVersion": "0.0.0-fake", "protocolVersion": "1.0", "features": []}},
    "TransactionService.Begin": {"ok": {"txnId": "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60", "heartbeatIntervalMs": 1000}},
    "TransactionService.Status": {"ok": {"state": "TRANSACTION_STATE_COMMITTED"}},
    "QueryService.Execute": {"ok": {"batches": [{}]}},
}


@dataclass
class Call:
    rpc: str
    request_id: str | None
    deadline: bool
    arrival: float
    reply: float = 0.0
    failed: bool = False


def _to_message(desc: Descriptor, j: Any) -> Any:
    """Protobuf JSON where documents and values are canonical extended JSON (retry.yaml header)."""
    out: dict[str, Any] = {}
    for key, v in j.items():
        f = desc.fields_by_camelcase_name.get(key) or desc.fields_by_name[key]
        mt = f.message_type
        if mt is None:
            out[key] = v
            continue

        def one(x: Any, mt: Descriptor = mt) -> Any:
            if mt.full_name == "rustegon.v1.Document":
                return {"rdoc": base64.b64encode(rdoc.encode_document(plain(x))).decode()}
            if mt.full_name == "rustegon.v1.Value":
                return {"rdocValue": base64.b64encode(rdoc.encode_value(plain(x))).decode()}
            return _to_message(mt, x)

        out[key] = [one(x) for x in v] if isinstance(v, list) else one(v)
    return out


class _Scram:
    """Server side of SCRAM-SHA-256 for the fixed fake user (RFC 5802/7677)."""

    def __init__(self) -> None:
        self.salt = os.urandom(16)
        self.iterations = 4096
        self.nonce = base64.b64encode(os.urandom(18)).decode()

    def first(self, client_first: str) -> tuple[str, str]:
        bare = client_first.split(",", 2)[2]
        attrs = dict(a.split("=", 1) for a in bare.split(","))
        server_first = f"r={attrs['r']}{self.nonce},s={base64.b64encode(self.salt).decode()},i={self.iterations}"
        return bare, server_first

    def final(self, bare: str, server_first: str, client_final: str) -> str | None:
        without_proof, _, proof = client_final.rpartition(",p=")
        sp = hashlib.pbkdf2_hmac("sha256", SCRAM_PASSWORD.encode(), self.salt, self.iterations)
        client_key = hmac.new(sp, b"Client Key", "sha256").digest()
        message = f"{bare},{server_first},{without_proof}".encode()
        signature = hmac.new(hashlib.sha256(client_key).digest(), message, "sha256").digest()
        expected = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        if not hmac.compare_digest(base64.b64decode(proof), expected):
            return None
        server_key = hmac.new(sp, b"Server Key", "sha256").digest()
        return "v=" + base64.b64encode(hmac.new(server_key, message, "sha256").digest()).decode()


class FakeServer:
    """Serves every rustegon.v1 RPC on 127.0.0.1 (plain text); scripted replies per RPC."""

    def __init__(self, script: Mapping[str, list[dict[str, Any]]]) -> None:
        self.script = {k: list(v) for k, v in script.items()}
        self.calls: list[Call] = []
        self._used: dict[str, int] = {}
        self._server = grpc.aio.server()
        handlers: dict[str, dict[str, grpc.RpcMethodHandler[Any, Any]]] = {}
        for module in _MODULES:
            for service in module.DESCRIPTOR.services_by_name.values():
                methods = handlers.setdefault(service.full_name, {})
                for m in service.methods:
                    methods[m.name] = self._handler(service.name, m)
        self._server.add_generic_rpc_handlers(
            tuple(grpc.method_handlers_generic_handler(s, h) for s, h in handlers.items())
        )
        self.port = self._server.add_insecure_port("127.0.0.1:0")

    async def __aenter__(self) -> FakeServer:
        await self._server.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._server.stop(None)

    def count(self, rpc: str) -> int:
        return sum(1 for c in self.calls if c.rpc == rpc)

    def _reply(self, rpc: str, request: Any) -> dict[str, Any]:
        replies = self.script.get(rpc)
        if replies:
            n = self._used.get(rpc, 0)
            self._used[rpc] = n + 1
            return replies[min(n, len(replies) - 1)]  # the last reply repeats
        if rpc in _DEFAULTS:
            return _DEFAULTS[rpc]
        if rpc == "DocumentService.Insert":
            ids = [rdoc.decode_document(d.rdoc).get("_id") for d in request.documents]
            return {"ok": {"results": [{"id": i} for i in ids]}}
        return {"ok": {}}

    def _record(self, rpc: str, context: grpc.aio.ServicerContext[Any, Any]) -> Call:
        md = dict(context.invocation_metadata() or ())
        rid = md.get("rgn-request-id")
        call = Call(rpc, rid if isinstance(rid, str) else None, context.time_remaining() is not None, time.monotonic())
        self.calls.append(call)
        return call

    async def _answer(
        self, call: Call, reply: dict[str, Any], context: grpc.aio.ServicerContext[Any, Any]
    ) -> dict[str, Any]:
        """Waits ``delayMs`` and aborts on ``error``/``transport``; returns the ``ok`` JSON."""
        if "delayMs" in reply:
            await asyncio.sleep(reply["delayMs"] / 1000)
        call.reply = time.monotonic()
        if "transport" in reply:
            call.failed = True
            await context.abort(grpc.StatusCode[reply["transport"]], "scripted transport failure")
        if "error" in reply:
            call.failed = True
            e = reply["error"]
            code = e["code"]
            d = error_pb2.ErrorDetail(code=code, name=CODES[code][0], retryable=e["retryable"], trace_id="fake")
            if "committed" in e:
                d.committed = e["committed"]
            if "retryAfterMs" in e:
                d.retry_after_ms = e["retryAfterMs"]
            for k, v in (e.get("details") or {}).items():
                d.details[k] = v
            status = grpc.StatusCode[CODES[code][2]]
            details = status_bytes(status.value[0], d.SerializeToString())
            await context.abort(status, d.name, trailing_metadata=(("grpc-status-details-bin", details),))
        return dict(reply["ok"])

    def _handler(self, service: str, m: MethodDescriptor) -> grpc.RpcMethodHandler[Any, Any]:
        rpc = f"{service}.{m.name}"
        req = message_factory.GetMessageClass(m.input_type)
        resp = message_factory.GetMessageClass(m.output_type)

        def make(j: dict[str, Any]) -> Any:
            return json_format.ParseDict(_to_message(resp.DESCRIPTOR, j), resp())  # type: ignore[arg-type]

        if rpc == "AuthService.Authenticate":

            async def authenticate(requests: AsyncIterator[Any], context: grpc.aio.ServicerContext[Any, Any]) -> Any:
                call = self._record(rpc, context)
                scram = _Scram()
                first = await anext(requests)
                bare, server_first = scram.first(first.payload.decode())
                yield auth_pb2.AuthenticateResponse(challenge=server_first.encode())
                final = await anext(requests)
                verifier = scram.final(bare, server_first, final.payload.decode())
                call.reply = time.monotonic()
                if verifier is None:
                    call.failed = True
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bad proof")
                token = base64.urlsafe_b64encode(os.urandom(32)).decode()
                success = auth_pb2.AuthSuccess(server_final=verifier.encode(), session_token=token, user=SCRAM_USER)
                yield auth_pb2.AuthenticateResponse(success=success)

            return grpc.stream_stream_rpc_method_handler(authenticate, req.FromString, resp.SerializeToString)

        if m.server_streaming:  # QueryService.Execute: one streamed response per scripted batch

            async def stream(request: Any, context: grpc.aio.ServicerContext[Any, Any]) -> Any:
                call = self._record(rpc, context)
                ok = await self._answer(call, self._reply(rpc, request), context)
                for batch in ok.get("batches", []):
                    yield make({"batch": batch})

            return grpc.unary_stream_rpc_method_handler(stream, req.FromString, resp.SerializeToString)

        async def unary(request: Any, context: grpc.aio.ServicerContext[Any, Any]) -> Any:
            call = self._record(rpc, context)
            return make(await self._answer(call, self._reply(rpc, request), context))

        return grpc.unary_unary_rpc_method_handler(unary, req.FromString, resp.SerializeToString)


# ------------------------------------------------------------------------- scenarios


class _Env:
    def substitute(self, s: str) -> str:
        return s

    async def open(self, args: Mapping[str, Any]) -> AsyncRustegonClient:
        raise AssertionError("retry scenarios do not open clients")

    async def runner(self, name: str, args: Mapping[str, Any], runner: OpRunner) -> Any:
        if name == "throwApplicationError":
            raise ApplicationError
        raise AssertionError(f"runner.{name} in a retry scenario")


async def run_retry_scenarios(relative: str = "retry.yaml") -> list[str]:
    """Runs every scenario; the failures, one line each."""
    root = load(relative)
    failures: list[str] = []
    for s in root["scenarios"]:
        try:
            d = await _scenario(s, root["defaults"])
        except Exception as e:
            d = f"{e!r}"
        if d is not None:
            failures.append(f"{s['name']}: {d}")
    return failures


async def _scenario(s: Mapping[str, Any], defaults: Mapping[str, Any]) -> str | None:
    settings = {**defaults["settings"], **(s.get("settings") or {})}
    expect = s["expect"]
    async with FakeServer(s.get("server") or {}) as server:
        credential = (
            Credential.scram(SCRAM_USER, SCRAM_PASSWORD)
            if s.get("credential") == "scram"
            else Credential.api_key("rgn_fake_key")
        )
        client = AsyncRustegonClient(
            ClientSettings(
                hosts=[("127.0.0.1", server.port)],
                database="fake",
                credential=credential,
                retry_reads=settings["retryReads"],
                retry_writes=settings["retryWrites"],
                max_retries=settings["maxRetries"],
                operation_timeout=settings["operationTimeoutMs"] / 1000,
            )
        )
        op = dict(s["operation"])
        op["expect"] = expect["outcome"]
        if "result" in expect["outcome"]:
            op["match"] = "subset"
        runner = OpRunner(client, "fake", "c", _Env())
        try:
            await runner.run(op)
        except AssertionError as e:
            return f"outcome: {e}"
        finally:
            await runner.close_opened()
            await client.close()
        return _calls(server, expect, defaults["backoff"])


def _calls(server: FakeServer, expect: Mapping[str, Any], backoff: Mapping[str, Any]) -> str | None:
    for rpc, n in (expect.get("calls") or {}).items():
        if server.count(rpc) != n:
            return f"{rpc} called {server.count(rpc)} times, expected {n}"
    for rpc in expect.get("sameRequestId") or []:
        ids = {c.request_id or "" for c in server.calls if c.rpc == rpc}
        if len(ids) != 1 or "" in ids:
            return f"{rpc} request ids {ids}, expected one non-empty id"
    if expect.get("grpcTimeoutSent"):
        missing = [c.rpc for c in server.calls if not c.deadline]
        if missing:
            return f"{missing} without grpc-timeout"
    gaps = _gaps(server.calls)
    for d in expect.get("delays") or []:
        n = d["retry"]
        if len(gaps) < n:
            return f"no retry {n} (gaps {gaps})"
        gap = gaps[n - 1]
        if "minMs" in d:
            if gap < d["minMs"]:
                return f"retry {n} after {gap} ms, expected >= {d['minMs']}"
        else:
            most = min(backoff["capMs"], backoff["baseMs"] << (n - 1)) + DELAY_TOLERANCE_MS
            if gap > most:
                return f"retry {n} after {gap} ms, expected <= {most}"
    return None


def _gaps(calls: list[Call]) -> list[int]:
    """For each failed reply (best-effort rollbacks excluded), ms until the next call of the same RPC."""
    out = []
    for i, c in enumerate(calls):
        if not c.failed or c.rpc == "TransactionService.Rollback":
            continue
        nxt = next((x for x in calls[i + 1 :] if x.rpc == c.rpc), None)
        if nxt is not None:
            out.append(int((nxt.arrival - c.reply) * 1000))
    return out
