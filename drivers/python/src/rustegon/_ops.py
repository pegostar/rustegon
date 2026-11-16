# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Calls to the server: channels, authentication, request metadata, error mapping and the
retry policy of ``drivers/conformance/retry.yaml`` (python-driver.md §8, PD-073, PD-097):

- R1 a failure is retried only when its ``ErrorDetail.retryable`` (or the transport fallback)
  says so, at most ``max_retries`` times, after a full-jitter backoff (base 10 ms, x2, cap 1 s)
  that is at least the server's ``retry_after_ms``;
- R2 reads when ``retry_reads``, writes when ``retry_writes``; every attempt reuses the first
  attempt's ``rgn-request-id`` so the server deduplicates; nothing inside a transaction;
- R3 a stream that delivered a batch and ``NONE`` calls (GetMore, KillCursor, DDL, transaction
  control, admin) are never retried;
- R4 the caller's own deadline maps to RGN-5006, not retryable;
- R5 RGN-4005 on a session token: one fresh login and one resend, outside the retry budget;
- R8 the timeout is one deadline for the whole operation, attempts and backoff included.

Concurrency: everything runs on the event loop that first used the client (grpc.aio channels
are bound to it). Handshakes are serialized by an ``asyncio.Lock``; the CPU-bound PBKDF2 of
SCRAM runs in a worker thread so the loop never blocks.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import os
import random
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, TypeVar

import grpc
import grpc.aio

from rustegon import errors
from rustegon._pb import (
    admin_pb2_grpc,
    auth_pb2,
    auth_pb2_grpc,
    common_pb2,
    document_pb2_grpc,
    error_pb2,
    query_pb2,
    query_pb2_grpc,
    schema_pb2_grpc,
    session_pb2_grpc,
    transaction_pb2_grpc,
)
from rustegon._scram import ScramClient, ScramError
from rustegon._version import __version__
from rustegon.settings import APIKEY, SCRAM_SHA_256, X509, ClientSettings, ReadConsistency, WriteConcern

if TYPE_CHECKING:
    from rustegon.session import ClientSession

_LOG: Final = logging.getLogger("rustegon")
BACKOFF_BASE_MS: Final = 10
BACKOFF_CAP_MS: Final = 1000
DRIVER_NAME: Final = "rustegon-python"
_MAX_MESSAGE: Final = 64 * 1024 * 1024
_LOGOUT_TIMEOUT: Final = 2.0
_STATUS_DETAILS: Final = "grpc-status-details-bin"
_ERROR_DETAIL_TYPE: Final = "/rustegon.v1.ErrorDetail"

T = TypeVar("T")


class Kind(enum.Enum):
    """How an operation may be retried (R2/R3, R7)."""

    READ = "read"
    WRITE = "write"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class OpContext:
    """Per-handle overrides (PD-172): session, timeout, consistency, concern, transaction."""

    txn_id: str | None = None
    session: ClientSession | None = None
    timeout: float | None = None
    read_consistency: ReadConsistency | None = None
    max_staleness: float | None = None
    write_concern: WriteConcern | None = None

    def with_(self, **changes: Any) -> OpContext:
        return replace(self, **changes)


NO_CONTEXT: Final = OpContext()


def uuid7() -> str:
    """A UUIDv7 (48-bit Unix ms timestamp, random rest): the ``rgn-request-id`` of a call."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80 | 0x7 << 76 | (rand >> 68 & 0xFFF) << 64
    value |= 0b10 << 62 | rand & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


def backoff_ms(n: int, retry_after_ms: int | None = None) -> int:
    """Full-jitter backoff of the n-th retry (1-based): uniform in [0, min(cap, base*2^(n-1))]."""
    ceiling = BACKOFF_CAP_MS if n > 8 else min(BACKOFF_CAP_MS, BACKOFF_BASE_MS << (n - 1))
    wait = random.randint(0, ceiling)  # noqa: S311 - jitter, not cryptography
    return wait if retry_after_ms is None else max(wait, retry_after_ms)


# ------------------------------------------------------------------------- error mapping


def _fields(raw: bytes) -> list[tuple[int, int, Any]]:
    """Minimal protobuf wire decoding: (field, wire type, value) of varint and bytes fields."""
    out: list[tuple[int, int, Any]] = []
    pos = 0

    def varint() -> int:
        nonlocal pos
        result = shift = 0
        while True:
            if pos >= len(raw) or shift > 63:
                raise ValueError("truncated varint")
            b = raw[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                return result

    while pos < len(raw):
        tag = varint()
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            out.append((field, wire, varint()))
        elif wire == 2:
            n = varint()
            if pos + n > len(raw):
                raise ValueError("truncated field")
            out.append((field, wire, raw[pos : pos + n]))
            pos += n
        elif wire == 5:
            pos += 4
        elif wire == 1:
            pos += 8
        else:
            raise ValueError("unsupported wire type")
    return out


def error_detail(status_details: bytes | None) -> error_pb2.ErrorDetail | None:
    """The ``ErrorDetail`` packed in a ``google.rpc.Status`` trailer, if present and well formed."""
    if not status_details:
        return None
    try:
        for field, wire, value in _fields(status_details):
            if field != 3 or wire != 2:  # google.rpc.Status.details: repeated Any
                continue
            any_fields = {f: v for f, w, v in _fields(value) if w == 2}
            type_url = bytes(any_fields.get(1, b"")).decode("utf-8", "replace")
            if type_url.endswith(_ERROR_DETAIL_TYPE) and 2 in any_fields:
                return error_pb2.ErrorDetail.FromString(bytes(any_fields[2]))
    except ValueError:
        return None  # malformed trailer: the status code still classifies the failure
    except Exception:  # noqa: BLE001 - protobuf DecodeError has no stable public base
        return None
    return None


def from_detail(message: str, d: error_pb2.ErrorDetail) -> errors.RustegonException:
    """The exception of an ``ErrorDetail``: class by code, flags from the response."""
    return errors.create(
        message,
        d.code,
        name=d.name,
        retryable=d.retryable,
        committed=d.committed if d.HasField("committed") else None,
        details=dict(d.details),
        trace_id=d.trace_id,
        retry_after_ms=d.retry_after_ms if d.HasField("retry_after_ms") else None,
    )


def map_status(status_name: str, message: str, details: bytes | None) -> errors.RustegonException:
    """The exception of a failed call (status name + optional ``grpc-status-details-bin``)."""
    d = error_detail(details)
    if d is not None:
        return from_detail(message or d.name, d)
    return errors.transport(status_name, message or status_name)


def _trailer(metadata: Any, key: str) -> Any:
    for k, v in metadata or ():
        if k == key:
            return v
    return None


def map_rpc_error(e: grpc.aio.AioRpcError) -> errors.RustegonException:
    details = _trailer(e.trailing_metadata(), _STATUS_DETAILS)
    return map_status(e.code().name, e.details() or "", details if isinstance(details, bytes) else None)


# ------------------------------------------------------------------------- channels


class _Channels:
    """``connections_per_endpoint`` channels per endpoint, round robin (multi-endpoint selection
    is deferred to M5: R1 nodes are single, ``Behavior.MultiEndpoint``)."""

    def __init__(self, settings: ClientSettings) -> None:
        self._settings = settings
        self._channels: list[grpc.aio.Channel] = []
        self._next = 0

    def _credentials(self) -> grpc.ChannelCredentials:
        s = self._settings
        cred = s.credential
        cert_file = (cred.certificate_file if cred and cred.certificate_file else None) or s.tls_certificate_file
        key_file = (cred.key_file if cred and cred.key_file else None) or s.tls_key_file
        return grpc.ssl_channel_credentials(
            root_certificates=Path(s.tls_ca_file).read_bytes() if s.tls_ca_file else None,
            private_key=Path(key_file).read_bytes() if key_file else None,
            certificate_chain=Path(cert_file).read_bytes() if cert_file else None,
        )

    def _open(self) -> None:
        s = self._settings
        user_agent = f"{DRIVER_NAME}/{__version__}"
        if s.application_name:
            user_agent += f" ({s.application_name})"
        credentials = self._credentials() if s.tls else None
        for host, port in s.hosts:
            target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            for _ in range(s.connections_per_endpoint):
                options: list[tuple[str, Any]] = [
                    ("grpc.primary_user_agent", user_agent),
                    ("grpc.keepalive_time_ms", 30_000),
                    ("grpc.max_receive_message_length", _MAX_MESSAGE),
                    ("grpc.max_send_message_length", _MAX_MESSAGE),
                    # One connection per channel: the pool, not gRPC, spreads the load.
                    ("grpc.use_local_subchannel_pool", 1),
                ]
                if s.tls_server_name:
                    options.append(("grpc.ssl_target_name_override", s.tls_server_name))
                if credentials is not None:
                    self._channels.append(grpc.aio.secure_channel(target, credentials, options))
                else:
                    self._channels.append(grpc.aio.insecure_channel(target, options))

    async def next(self) -> grpc.aio.Channel:
        """A channel connected within ``connect_timeout`` (PD-081), else RGN-3002."""
        if not self._channels:
            self._open()
        ch = self._channels[self._next % len(self._channels)]
        self._next += 1
        if ch.get_state(try_to_connect=True) != grpc.ChannelConnectivity.READY:
            try:
                await asyncio.wait_for(ch.channel_ready(), self._settings.connect_timeout)
            except TimeoutError:
                raise errors.local(
                    3002, f"no connection within the connect timeout ({self._settings.connect_timeout} s)"
                ) from None
        return ch

    def any(self) -> grpc.aio.Channel | None:
        return self._channels[0] if self._channels else None

    async def close(self) -> None:
        for ch in self._channels:
            await ch.close(None)
        self._channels.clear()


# ------------------------------------------------------------------------- authentication


class _Auth:
    """Obtains and caches the ``authorization`` value (protocol.md §8): SCRAM-SHA-256 and X.509
    run ``Authenticate`` once and use ``Bearer <session token>``; an API key is sent as is."""

    def __init__(self, settings: ClientSettings) -> None:
        self._settings = settings
        self._credential = settings.credential
        self._lock: asyncio.Lock | None = None
        self.authorization: str | None = None
        self.password_change_required = False

    @property
    def uses_session(self) -> bool:
        return self._credential is not None and self._credential.mechanism != APIKEY

    @property
    def mechanism(self) -> str | None:
        return self._credential.mechanism if self._credential else None

    def invalidate(self, failed: str | None) -> None:
        if failed is not None and failed == self.authorization:
            self.authorization = None

    def password_changed(self, new_password: str) -> None:
        if self._credential is not None:
            self._credential = replace(self._credential, secret=new_password)
        self.authorization = None
        self.password_change_required = False

    async def get(self, channel: grpc.aio.Channel, timeout: float, password_change_call: bool) -> str | None:
        value = self.authorization
        if value is None and self._credential is not None:
            if self._lock is None:
                self._lock = asyncio.Lock()
            async with self._lock:
                value = self.authorization
                if value is None:
                    value = await self._authenticate(channel, timeout)
                    self.authorization = value
        if self.password_change_required and not password_change_call and not self._settings.allow_password_change_only:
            raise errors.PasswordChangeRequiredException(
                "the password must be changed before any other operation",
                code=4002,
                name="PermissionDenied",
                details={"reason": "must_change_password"},
            )
        return value

    async def _authenticate(self, channel: grpc.aio.Channel, timeout: float) -> str:
        cred = self._credential
        if cred is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no credential")
        if cred.mechanism == APIKEY:
            return f"ApiKey {cred.secret}"
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        info = auth_pb2.ClientInfo(
            driver_name=DRIVER_NAME, driver_version=__version__, application=self._settings.application_name or ""
        )
        # A bidirectional stream driven with write()/read(): no request iterator.
        call = stub.Authenticate(timeout=timeout)  # type: ignore[call-arg]
        try:
            if cred.mechanism == X509:
                await call.write(auth_pb2.AuthenticateRequest(mechanism=auth_pb2.AUTH_MECHANISM_X509, client_info=info))
                success = await self._success(call)
            elif cred.mechanism == SCRAM_SHA_256:
                if cred.secret is None:
                    raise ValueError("the SCRAM credential has no password")
                scram = await asyncio.to_thread(ScramClient, cred.user or "", cred.secret)
                await call.write(
                    auth_pb2.AuthenticateRequest(
                        mechanism=auth_pb2.AUTH_MECHANISM_SCRAM_SHA_256,
                        payload=scram.client_first().encode(),
                        client_info=info,
                    )
                )
                challenge = await self._read(call)
                if challenge.WhichOneof("step") != "challenge":
                    raise _failed("no SCRAM challenge")
                final = await asyncio.to_thread(scram.client_final, challenge.challenge.decode("utf-8"))
                await call.write(auth_pb2.AuthenticateRequest(payload=final.encode()))
                success = await self._success(call)
                scram.verify_server_final(success.server_final.decode("utf-8"))
            else:  # pragma: no cover - mechanisms are validated by the settings
                raise ValueError(f"unknown mechanism {cred.mechanism}")
            await call.done_writing()
        except ScramError as e:
            call.cancel()
            raise _failed(str(e)) from e
        except grpc.aio.AioRpcError as e:
            raise map_rpc_error(e) from None
        except BaseException:
            call.cancel()
            raise
        self.password_change_required = success.must_change_password
        _LOG.debug("authenticated (password change required: %s)", success.must_change_password)
        return f"Bearer {success.session_token}"

    @staticmethod
    async def _read(call: Any) -> auth_pb2.AuthenticateResponse:
        r = await call.read()
        if r is grpc.aio.EOF:  # type: ignore[attr-defined]
            raise _failed("the server ended the authentication stream early")
        if not isinstance(r, auth_pb2.AuthenticateResponse):  # pragma: no cover - typed stream
            raise _failed("unexpected authentication message")
        return r

    async def _success(self, call: Any) -> auth_pb2.AuthSuccess:
        r = await self._read(call)
        if r.WhichOneof("step") != "success":
            raise _failed("no authentication success")
        return r.success


def _failed(reason: str) -> errors.RustegonException:
    return errors.create(f"authentication failed ({reason})", 4001, name="Unauthenticated")


# ------------------------------------------------------------------------- operations


class Stubs:
    """The service stubs of one channel."""

    def __init__(self, channel: grpc.aio.Channel) -> None:
        self.document = document_pb2_grpc.DocumentServiceStub(channel)
        self.query = query_pb2_grpc.QueryServiceStub(channel)
        self.schema = schema_pb2_grpc.SchemaServiceStub(channel)
        self.session = session_pb2_grpc.SessionServiceStub(channel)
        self.transaction = transaction_pb2_grpc.TransactionServiceStub(channel)
        self.admin = admin_pb2_grpc.AdminServiceStub(channel)
        self.auth = auth_pb2_grpc.AuthServiceStub(channel)


Attempt = Callable[[Stubs, list[tuple[str, str]], float, list[bool]], Awaitable[T]]


class Operations:
    """Runs the client's calls (one instance per client)."""

    def __init__(self, settings: ClientSettings) -> None:
        self.settings = settings
        self._channels = _Channels(settings)
        self.auth = _Auth(settings)
        self.closed = False

    def ensure_open(self) -> None:
        if self.closed:
            raise RuntimeError("the client is closed")

    async def unary(self, call: Callable[[Stubs], Any], request: Any, kind: Kind, ctx: OpContext) -> Any:
        """A unary call: ``call(stubs)`` selects the stub method, e.g. ``lambda s: s.document.Get``."""

        async def attempt(stubs: Stubs, metadata: list[tuple[str, str]], timeout: float, _d: list[bool]) -> Any:
            return await self._observe(call(stubs)(request, metadata=metadata, timeout=timeout), ctx)

        return await self.run(kind, ctx, attempt)

    async def password_change(self, call: Callable[[Stubs], Any], request: Any) -> Any:
        """``AdminService.ChangePassword``: allowed while a password change is pending (PD-076)."""

        async def attempt(stubs: Stubs, metadata: list[tuple[str, str]], timeout: float, _d: list[bool]) -> Any:
            return await call(stubs)(request, metadata=metadata, timeout=timeout)

        return await self.run(Kind.NONE, NO_CONTEXT, attempt, password_change_call=True)

    async def commit(self, request: Any, ctx: OpContext) -> Any:
        """``TransactionService.Commit`` (never retried alone). A failure without ``ErrorDetail``
        after the request reached the transport may hide a commit that took effect, exactly like a
        coordinator dying before its ack: it is reported as RGN-2006 and resolved with ``Status``,
        never by re-running (PD-122, transaction-management.md §7)."""

        async def attempt(stubs: Stubs, metadata: list[tuple[str, str]], timeout: float, _d: list[bool]) -> Any:
            try:
                return await stubs.transaction.Commit(request, metadata=metadata, timeout=timeout)
            except grpc.aio.AioRpcError as e:
                if error_detail(_trailer(e.trailing_metadata(), _STATUS_DETAILS)) is not None:
                    raise
                raise errors.local(
                    2006, f"commit failed in transport ({e.code().name}); its outcome is unknown"
                ) from None

        return await self.run(Kind.NONE, ctx, attempt)

    async def execute(
        self, request: query_pb2.ExecuteRequest, kind: Kind, ctx: OpContext
    ) -> list[query_pb2.ResultBatch]:
        """``QueryService.Execute`` read to the end of the stream (one batch; the rest by GetMore)."""

        async def attempt(stubs: Stubs, metadata: list[tuple[str, str]], timeout: float, delivered: list[bool]) -> Any:
            batches: list[query_pb2.ResultBatch] = []
            call = stubs.query.Execute(request, metadata=metadata, timeout=timeout)
            stream: AsyncIterator[query_pb2.ExecuteResponse] = call.__aiter__()
            async for response in stream:
                batches.append(response.batch)
                delivered[0] = True
            await self._causality(call, ctx)
            return batches

        result: list[query_pb2.ResultBatch] = await self.run(kind, ctx, attempt)
        return result

    async def _observe(self, call: Any, ctx: OpContext) -> Any:
        response = await call
        await self._causality(call, ctx)
        return response

    @staticmethod
    async def _causality(call: Any, ctx: OpContext) -> None:
        """Sessions echo the last ``rgn-causality-token`` seen in headers or trailers (PD-069)."""
        session = ctx.session
        if session is None or not session.causal_consistency:
            return
        for md in (await call.initial_metadata(), await call.trailing_metadata()):
            token = _trailer(md, "rgn-causality-token")
            if isinstance(token, str) and token:
                session.observe(token)

    async def run(self, kind: Kind, ctx: OpContext, attempt: Attempt[T], *, password_change_call: bool = False) -> T:
        self.ensure_open()
        if ctx.session is not None:
            ctx.session.ensure_open()
        request_id = uuid7()
        timeout = ctx.timeout if ctx.timeout is not None else self.settings.operation_timeout
        deadline = time.monotonic() + timeout  # R8: one deadline for every attempt and backoff
        reauthenticated = False
        retries = 0
        while True:
            delivered = [False]
            authorization: str | None = None
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise errors.local(5006, "the operation timeout passed")
                channel = await self._channels.next()
                authorization = await self.auth.get(channel, remaining, password_change_call)
                metadata = [("rgn-request-id", request_id)]
                if authorization is not None:
                    metadata.append(("authorization", authorization))
                if ctx.session is not None and ctx.session.causal_consistency and ctx.session.causality_token:
                    metadata.append(("rgn-causality-token", ctx.session.causality_token))
                return await attempt(Stubs(channel), metadata, max(deadline - time.monotonic(), 0.001), delivered)
            except grpc.aio.AioRpcError as e:
                failure = map_rpc_error(e)
            except errors.PasswordChangeRequiredException:
                raise
            except errors.RustegonException as e:
                failure = e  # connect timeout or a failed handshake: classified like any failure
            if failure.code == 4005 and not reauthenticated and authorization is not None and self.auth.uses_session:
                _LOG.debug("session expired; re-authenticating")  # R5, outside the budget
                reauthenticated = True
                self.auth.invalidate(authorization)
                continue
            if (
                not failure.retryable
                or delivered[0]
                or retries >= self.settings.max_retries
                or not self._retry_allowed(kind, ctx)
            ):
                raise failure
            retries += 1
            wait = backoff_ms(retries, failure.retry_after_ms) / 1000
            if deadline - time.monotonic() <= wait:
                raise failure
            await asyncio.sleep(wait)

    def _retry_allowed(self, kind: Kind, ctx: OpContext) -> bool:
        if ctx.txn_id is not None:
            return False
        if kind is Kind.READ:
            return self.settings.retry_reads
        if kind is Kind.WRITE:
            return self.settings.retry_writes
        return False

    def read_consistency(self, ctx: OpContext) -> common_pb2.ReadConsistency | None:
        """The read consistency of a call outside a transaction; ``None`` = server default."""
        level = ctx.read_consistency or self.settings.read_consistency
        if level is None or ctx.txn_id is not None:
            return None
        staleness = ctx.max_staleness if ctx.read_consistency is not None else self.settings.max_staleness
        rc = common_pb2.ReadConsistency(
            level=common_pb2.ReadConsistencyLevel.Value(f"READ_CONSISTENCY_LEVEL_{level.name}")
        )
        if staleness is not None:
            rc.max_staleness_ms = min(2**32 - 1, round(staleness * 1000))
        return rc

    def write_concern(self, ctx: OpContext) -> common_pb2.WriteConcern.ValueType:
        """The write concern of a write outside a transaction (UNSPECIFIED = server default)."""
        wc = ctx.write_concern or self.settings.write_concern
        if wc is None or ctx.txn_id is not None:
            return common_pb2.WRITE_CONCERN_UNSPECIFIED
        return common_pb2.WriteConcern.Value(f"WRITE_CONCERN_{wc.name}")

    async def close(self) -> None:
        """Best-effort ``Logout``, then the channels; idempotent."""
        if self.closed:
            return
        self.closed = True
        channel = self._channels.any()
        if channel is not None and self.auth.authorization is not None and self.auth.uses_session:
            try:
                await auth_pb2_grpc.AuthServiceStub(channel).Logout(
                    auth_pb2.LogoutRequest(),
                    metadata=[("authorization", self.auth.authorization), ("rgn-request-id", uuid7())],
                    timeout=_LOGOUT_TIMEOUT,
                )
            except grpc.aio.AioRpcError as e:
                _LOG.debug("logout at close failed: %s", e.code().name)
        await self._channels.close()
