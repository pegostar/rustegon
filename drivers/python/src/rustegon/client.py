# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""The asyncio client (python-driver.md §4–§6): ``AsyncRustegonClient`` and its database,
collection, find, cursor and transaction handles. Every I/O method is a coroutine; the blocking
facade of ``rustegon.sync`` runs these on a private event loop (PD-170).

R1 scope (PD-069, ``drivers/conformance/model.yaml``): databases, collections and indexes, CRUD by
id and by filter, finds with sort/limit/skip/projection/batch size, cursors, RGQL with
parameters, bulk writes by id, sessions as causality-token pass-through, interactive
transactions and ``with_transaction``, ``change_password``.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import json
import logging
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Final, Generic, TypeVar, overload

from rustegon import errors, rdoc
from rustegon._ops import NO_CONTEXT, Kind, OpContext, Operations, Stubs, backoff_ms, from_detail
from rustegon._pb import (
    admin_pb2,
    common_pb2,
    document_pb2,
    query_ast_pb2,
    query_pb2,
    schema_pb2,
    session_pb2,
    transaction_pb2,
)
from rustegon.builders import (
    BulkOperation,
    Filter,
    IndexKey,
    ParamSink,
    Projection,
    Sort,
    Update,
    delete_statement,
    dotted,
    find_statement,
    path,
    update_statement,
)
from rustegon.mapping import DocumentCodec, codec_for
from rustegon.session import ClientSession
from rustegon.settings import ClientSettings, ReadConsistency, WriteConcern

__all__ = [
    "AsyncCollection",
    "AsyncCursor",
    "AsyncDatabase",
    "AsyncFind",
    "AsyncRustegonClient",
    "AsyncTransaction",
    "BulkWriteError",
    "BulkWriteResult",
    "DeleteResult",
    "IndexInfo",
    "IndexState",
    "InsertManyResult",
    "InsertOneResult",
    "IsolationLevel",
    "ServerInfo",
    "TransactionOptions",
    "UpdateResult",
    "Validator",
]

_LOG: Final = logging.getLogger("rustegon")
_INDEX_POLL: Final = 0.05
T = TypeVar("T")
D = TypeVar("D")
R = TypeVar("R")


# ------------------------------------------------------------------------- results and options


@dataclass(frozen=True, slots=True)
class ServerInfo:
    server_version: str
    protocol_version: str
    features: tuple[str, ...]
    node_addresses: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InsertOneResult:
    inserted_id: Any


@dataclass(frozen=True, slots=True)
class InsertManyResult:
    inserted_ids: list[Any]


@dataclass(frozen=True, slots=True)
class UpdateResult:
    """By-id writes report the server's matched/modified; statements report ``docs_affected`` as both."""

    matched_count: int
    modified_count: int
    upserted_id: Any = None


@dataclass(frozen=True, slots=True)
class DeleteResult:
    deleted_count: int


@dataclass(frozen=True, slots=True)
class BulkWriteError:
    """A failed operation of an outside-transaction bulk write (it does not raise)."""

    index: int
    error: errors.RustegonException
    message: str


@dataclass(frozen=True, slots=True)
class BulkWriteResult:
    inserted_count: int
    matched_count: int
    modified_count: int
    deleted_count: int
    errors: list[BulkWriteError] = field(default_factory=list)


class IndexState(enum.Enum):
    BUILDING = "building"
    READY = "ready"
    FAILED = "failed"
    HIDDEN = "hidden"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IndexInfo:
    name: str
    keys: list[IndexKey]
    unique: bool
    state: IndexState


class IsolationLevel(enum.Enum):
    SERIALIZABLE = "serializable"
    SNAPSHOT = "snapshot"
    READ_COMMITTED = "read_committed"


@dataclass(frozen=True, slots=True)
class TransactionOptions:
    """``max_retry_time`` (seconds) bounds the retries of ``with_transaction`` (transactions.md §5)."""

    isolation: IsolationLevel | None = None
    read_only: bool = False
    max_retry_time: float = 120.0


@dataclass(frozen=True, slots=True)
class Validator:
    """A JSON-Schema validator: ``level`` ``off``/``strict``, ``action`` ``error``/``warn``."""

    json_schema: Mapping[str, Any] | str
    level: str | None = None
    action: str | None = None

    def to_proto(self) -> schema_pb2.Validator:
        schema = self.json_schema if isinstance(self.json_schema, str) else json.dumps(self.json_schema)
        v = schema_pb2.Validator(definition_json='{"$jsonSchema":' + schema + "}")
        if self.level is not None:
            v.level = schema_pb2.ValidationLevel.Value(f"VALIDATION_LEVEL_{self.level.upper()}")
        if self.action is not None:
            v.action = schema_pb2.ValidationAction.Value(f"VALIDATION_ACTION_{self.action.upper()}")
        return v


_STATES: Final = {
    schema_pb2.INDEX_STATE_BUILDING: IndexState.BUILDING,
    schema_pb2.INDEX_STATE_READY: IndexState.READY,
    schema_pb2.INDEX_STATE_FAILED: IndexState.FAILED,
    schema_pb2.INDEX_STATE_HIDDEN: IndexState.HIDDEN,
}


def _index_info(i: schema_pb2.IndexInfo) -> IndexInfo:
    keys = [IndexKey(dotted(k.path), k.descending) for k in i.definition.keys]
    unique = i.definition.index_type == query_ast_pb2.AST_INDEX_TYPE_UNIQUE
    return IndexInfo(i.definition.name, keys, unique, _STATES.get(i.state, IndexState.UNKNOWN))


def _value(v: Any) -> common_pb2.Value:
    return common_pb2.Value(rdoc_value=rdoc.encode_value(v))


def _decode_value(v: common_pb2.Value) -> Any:
    return rdoc.decode_value(v.rdoc_value)


def _context_with(ctx: OpContext, **options: Any) -> OpContext:
    """Validates and applies ``with_options`` arguments (PD-172)."""
    changes: dict[str, Any] = {}
    for key, value in options.items():
        if value is None:
            continue
        if key == "timeout":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError("timeout must be a positive number of seconds")
            changes["timeout"] = float(value)
        elif key == "session":
            if not isinstance(value, ClientSession):
                raise TypeError("session must be a ClientSession")
            changes["session"] = value
        elif key == "read_consistency":
            changes["read_consistency"] = ReadConsistency(value)
        elif key == "max_staleness":
            if value <= 0:
                raise ValueError("max_staleness must be positive")
            changes["max_staleness"] = float(value)
        elif key == "write_concern":
            changes["write_concern"] = WriteConcern(value)
        else:  # pragma: no cover - keyword-only parameters
            raise TypeError(key)
    rc = changes.get("read_consistency", ctx.read_consistency)
    if rc is ReadConsistency.BOUNDED_STALENESS and changes.get("max_staleness", ctx.max_staleness) is None:
        raise ValueError("bounded_staleness needs max_staleness")
    return ctx.with_(**changes)


# ------------------------------------------------------------------------- client


class AsyncRustegonClient:
    """A long-lived, concurrency-safe client owning the connections (``Client.Create``).

    No I/O happens in the constructor; the first operation connects and logs in. A client is
    bound to the event loop that first uses it.
    """

    def __init__(self, settings: ClientSettings | str, **overrides: Any) -> None:
        if isinstance(settings, str):
            settings = ClientSettings.from_connection_string(settings, **overrides)
        elif overrides:
            settings = settings.replace(**overrides)
        cred = settings.credential
        if cred is None and settings.user is not None:
            raise ValueError(
                f"the connection string names user {settings.user!r} without a password: "
                "pass credential=Credential.scram(user, password)"
            )
        x509 = cred is not None and cred.mechanism == "X509"
        if (
            x509
            and cred is not None
            and not (settings.tls and (cred.certificate_file or settings.tls_certificate_file))
        ):
            raise ValueError("an X.509 credential needs TLS and a client certificate")
        self.settings = settings
        self._ops = Operations(settings)

    async def __aenter__(self) -> AsyncRustegonClient:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        await self.close()

    async def ping(self) -> None:
        await self._ops.unary(lambda s: s.session.Ping, session_pb2.PingRequest(), Kind.READ, NO_CONTEXT)

    async def server_info(self) -> ServerInfo:
        """Server version, protocol version and feature flags (``Client.GetServerInfo``)."""
        r = await self._ops.unary(
            lambda s: s.session.GetServerInfo, session_pb2.GetServerInfoRequest(), Kind.READ, NO_CONTEXT
        )
        return ServerInfo(r.server_version, r.protocol_version, tuple(r.features), tuple(r.node_addresses))

    def get_database(self, name: str | None = None) -> AsyncDatabase:
        """A database handle (no I/O); the default database of the settings when ``name`` is omitted."""
        name = name or self.settings.database
        if not name:
            raise ValueError("no database name and no default database in the settings")
        return AsyncDatabase(self, name, NO_CONTEXT)

    async def list_database_names(self) -> list[str]:
        r = await self._ops.unary(
            lambda s: s.schema.ListDatabases, schema_pb2.ListDatabasesRequest(), Kind.READ, NO_CONTEXT
        )
        return sorted(d.name for d in r.databases)

    async def create_database(self, name: str, *, if_not_exists: bool = False) -> bool:
        r = await self._ops.unary(
            lambda s: s.schema.CreateDatabase,
            schema_pb2.CreateDatabaseRequest(name=name, if_not_exists=if_not_exists),
            Kind.NONE,
            NO_CONTEXT,
        )
        return bool(r.created)

    async def drop_database(self, name: str, *, if_exists: bool = False) -> bool:
        r = await self._ops.unary(
            lambda s: s.schema.DropDatabase,
            schema_pb2.DropDatabaseRequest(name=name, if_exists=if_exists),
            Kind.NONE,
            NO_CONTEXT,
        )
        return bool(r.dropped)

    def start_session(self, *, causal_consistency: bool = True) -> ClientSession:
        """A session (no server call in R1: causality-token pass-through, PD-069)."""
        self._ops.ensure_open()
        return ClientSession(causal_consistency)

    async def begin_transaction(self, options: TransactionOptions | None = None) -> AsyncTransaction:
        """Starts an interactive transaction (manual mode); ``async with`` rolls back if not committed."""
        options = options or TransactionOptions()
        r = transaction_pb2.BeginRequest(read_only=options.read_only, write_concern=self._ops.write_concern(NO_CONTEXT))
        if options.isolation is not None:
            r.isolation = query_ast_pb2.AstIsolation.Value(f"AST_ISOLATION_{options.isolation.name}")
        consistency = self._ops.read_consistency(NO_CONTEXT)
        if options.read_only and consistency is not None:  # accepted on read-only transactions only
            r.consistency.CopyFrom(consistency)
        resp = await self._ops.unary(lambda s: s.transaction.Begin, r, Kind.NONE, NO_CONTEXT)
        return AsyncTransaction(self, resp.txn_id, resp.heartbeat_interval_ms / 1000)

    async def with_transaction(
        self,
        callback: Callable[[AsyncTransaction], Awaitable[T]],
        options: TransactionOptions | None = None,
    ) -> T:
        """Runs ``callback`` in a transaction and commits, retrying per transactions.md §5.

        Retryable errors of the callback or of the commit roll back (best effort), back off and
        re-run the callback until ``max_retry_time``; RGN-2006 is resolved with ``Status`` (never
        by re-running while the outcome is unknown); other errors and exceptions of the callback
        roll back and propagate.
        """
        options = options or TransactionOptions()
        deadline = time.monotonic() + options.max_retry_time
        attempt = 0
        while True:
            txn = await self.begin_transaction(options)
            failure: errors.RustegonException
            try:
                result = await callback(txn)
                try:
                    await txn.commit()
                    return result
                except errors.CommitOutcomeUnknownException as unknown:
                    if await self._resolve_commit(txn, unknown, deadline):
                        return result
                    failure = unknown  # ABORTED: nothing was written, re-running is safe
            except errors.CommitOutcomeUnknownException:
                raise  # still unknown at the deadline: never roll back or re-run
            except errors.RustegonException as e:
                await txn.rollback_quietly()
                if not e.retryable or time.monotonic() >= deadline:
                    raise
                failure = e
            except BaseException:
                await txn.rollback_quietly()
                raise
            finally:
                txn.stop_heartbeat()
            if time.monotonic() >= deadline:
                raise failure
            attempt += 1
            _LOG.debug("transaction attempt %d failed with RGN-%d; retrying", attempt, failure.code)
            await asyncio.sleep(backoff_ms(attempt) / 1000)

    @staticmethod
    async def _resolve_commit(
        txn: AsyncTransaction, unknown: errors.CommitOutcomeUnknownException, deadline: float
    ) -> bool:
        poll = 0
        while True:
            poll += 1
            try:
                outcome = await txn.resolve()
            except errors.RustegonException as e:
                # A failed poll leaves the outcome unknown: keep polling, never re-run.
                _LOG.debug("transaction status poll failed with RGN-%d", e.code)
                outcome = "unknown"
            if outcome == "committed":
                return True
            if outcome == "aborted":
                return False
            if time.monotonic() >= deadline:
                raise unknown
            await asyncio.sleep(backoff_ms(poll) / 1000)

    @property
    def password_change_required(self) -> bool:
        """Whether the last login reported ``must_change_password`` (PD-076)."""
        return self._ops.auth.password_change_required

    async def change_password(self, current_password: str, new_password: str) -> None:
        """Changes the password of the SCRAM user; later logins use the new one (PD-076)."""
        if self._ops.auth.mechanism != "SCRAM-SHA-256":
            raise RuntimeError("change_password needs a SCRAM credential")
        await self._ops.password_change(
            lambda s: s.admin.ChangePassword,
            admin_pb2.ChangePasswordRequest(current_password=current_password, new_password=new_password),
        )
        self._ops.auth.password_changed(new_password)

    async def close(self) -> None:
        """Logs out (best effort) and closes the connections; idempotent."""
        await self._ops.close()


# ------------------------------------------------------------------------- database


class AsyncDatabase:
    """A database handle (no I/O)."""

    def __init__(self, client: AsyncRustegonClient, name: str, ctx: OpContext) -> None:
        self.client = client
        self.name = name
        self._ctx = ctx

    @property
    def _ops(self) -> Operations:
        return self.client._ops

    def with_options(
        self,
        *,
        session: ClientSession | None = None,
        timeout: float | None = None,
        read_consistency: ReadConsistency | str | None = None,
        max_staleness: float | None = None,
        write_concern: WriteConcern | str | None = None,
    ) -> AsyncDatabase:
        """A handle whose operations use these overrides (PD-172)."""
        ctx = _context_with(
            self._ctx,
            session=session,
            timeout=timeout,
            read_consistency=read_consistency,
            max_staleness=max_staleness,
            write_concern=write_concern,
        )
        return AsyncDatabase(self.client, self.name, ctx)

    @overload
    def get_collection(self, name: str) -> AsyncCollection[dict[str, Any]]: ...

    @overload
    def get_collection(self, name: str, document_class: type[D]) -> AsyncCollection[D]: ...

    def get_collection(self, name: str, document_class: type[Any] = dict) -> AsyncCollection[Any]:
        """A collection handle (no I/O) whose documents are ``dict`` or a mapped dataclass."""
        return AsyncCollection(self, name, codec_for(document_class), self._ctx)

    async def query(
        self,
        rgql: str,
        params: Mapping[str, Any] | None = None,
        *,
        batch_size: int | None = None,
        document_class: type[Any] = dict,
    ) -> AsyncCursor[Any]:
        """Runs RGQL text with named parameters (sent as values, never interpolated)."""
        return await self._query(rgql, params, batch_size, document_class, self._ctx)

    async def _query(
        self,
        rgql: str,
        params: Mapping[str, Any] | None,
        batch_size: int | None,
        document_class: type[Any],
        ctx: OpContext,
    ) -> AsyncCursor[Any]:
        if not isinstance(rgql, str) or not rgql:
            raise ValueError("rgql must be a non-empty string")
        values = {k: _value(v) for k, v in (params or {}).items()}
        # RGQL text may write (PD-097, retry.yaml R7): retried as a write.
        return await self._open(None, rgql, values, batch_size, Kind.WRITE, ctx, codec_for(document_class))

    async def _open(
        self,
        statement: query_ast_pb2.AstStatement | None,
        rgql: str | None,
        params: dict[str, common_pb2.Value],
        batch_size: int | None,
        kind: Kind,
        ctx: OpContext,
        codec: DocumentCodec[Any],
    ) -> AsyncCursor[Any]:
        batches = await self._execute(statement, rgql, params, batch_size, kind, ctx)
        return AsyncCursor(self._ops, ctx, codec, batch_size, batches)

    async def _execute_write(
        self, statement: query_ast_pb2.AstStatement, params: dict[str, common_pb2.Value], ctx: OpContext
    ) -> int:
        batches = await self._execute(statement, None, params, None, Kind.WRITE, ctx)
        return int(batches[-1].stats.docs_affected) if batches else 0

    async def _execute(
        self,
        statement: query_ast_pb2.AstStatement | None,
        rgql: str | None,
        params: dict[str, common_pb2.Value],
        batch_size: int | None,
        kind: Kind,
        ctx: OpContext,
    ) -> list[query_pb2.ResultBatch]:
        o = query_pb2.ExecOptions(max_batches=1, write_concern=self._ops.write_concern(ctx))
        if batch_size is not None:
            o.batch_size = batch_size
        consistency = self._ops.read_consistency(ctx)
        if consistency is not None:
            o.consistency.CopyFrom(consistency)
        r = query_pb2.ExecuteRequest(database=self.name, options=o)
        for k, v in params.items():
            r.params[k].CopyFrom(v)
        if statement is not None:
            r.ast.CopyFrom(statement)
        else:
            r.rgql = rgql or ""
        if ctx.txn_id is not None:
            r.txn_id = ctx.txn_id
        return await self._ops.execute(r, kind, ctx)

    async def create_collection(
        self, name: str, *, if_not_exists: bool = False, validator: Validator | None = None
    ) -> bool:
        r = schema_pb2.CreateCollectionRequest(database=self.name, name=name, if_not_exists=if_not_exists)
        if validator is not None:
            r.validator.CopyFrom(validator.to_proto())
        resp = await self._ops.unary(lambda s: s.schema.CreateCollection, r, Kind.NONE, self._ctx)
        return bool(resp.created)

    async def drop_collection(self, name: str, *, if_exists: bool = False) -> bool:
        r = schema_pb2.DropCollectionRequest(database=self.name, name=name, if_exists=if_exists)
        resp = await self._ops.unary(lambda s: s.schema.DropCollection, r, Kind.NONE, self._ctx)
        return bool(resp.dropped)

    async def list_collection_names(self) -> list[str]:
        r = schema_pb2.ListCollectionsRequest(database=self.name)
        resp = await self._ops.unary(lambda s: s.schema.ListCollections, r, Kind.READ, self._ctx)
        return sorted(c.name for c in resp.collections)

    def __repr__(self) -> str:
        return f"AsyncDatabase({self.name!r})"


# ------------------------------------------------------------------------- collection


class AsyncCollection(Generic[T]):
    """A collection handle (no I/O); documents are ``dict`` or a mapped type (``document_class``)."""

    def __init__(self, database: AsyncDatabase, name: str, codec: DocumentCodec[T], ctx: OpContext) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("a collection name must not be empty")
        self.database = database
        self.name = name
        self._codec = codec
        self._ctx = ctx

    @property
    def _ops(self) -> Operations:
        return self.database.client._ops

    def with_options(
        self,
        *,
        session: ClientSession | None = None,
        timeout: float | None = None,
        read_consistency: ReadConsistency | str | None = None,
        max_staleness: float | None = None,
        write_concern: WriteConcern | str | None = None,
    ) -> AsyncCollection[T]:
        """A handle whose operations use these overrides (PD-172)."""
        ctx = _context_with(
            self._ctx,
            session=session,
            timeout=timeout,
            read_consistency=read_consistency,
            max_staleness=max_staleness,
            write_concern=write_concern,
        )
        return AsyncCollection(self.database, self.name, self._codec, ctx)

    def _document(self, value: T) -> common_pb2.Document:
        if value is None:
            raise ValueError("a document is required")
        return common_pb2.Document(rdoc=rdoc.encode_document(self._codec.to_document(value)))

    def _decode(self, d: common_pb2.Document) -> T:
        return self._codec.from_document(rdoc.decode_document(d.rdoc))

    def _write_options(self) -> document_pb2.WriteOptions:
        return document_pb2.WriteOptions(write_concern=self._ops.write_concern(self._ctx))

    async def insert_one(self, document: T) -> InsertOneResult:
        """Inserts one document; the server generates an ObjectId ``_id`` when it has none."""
        return InsertOneResult((await self._insert([document]))[0])

    async def insert_many(self, documents: Iterable[T]) -> InsertManyResult:
        """Inserts documents atomically (all or none); the ids in input order."""
        return InsertManyResult(await self._insert(list(documents)))

    async def _insert(self, documents: list[T]) -> list[Any]:
        if not documents:
            raise ValueError("nothing to insert")
        r = document_pb2.InsertRequest(
            database=self.database.name,
            collection=self.name,
            documents=[self._document(d) for d in documents],
            options=self._write_options(),
        )
        if self._ctx.txn_id is not None:
            r.txn_id = self._ctx.txn_id
        resp = await self._ops.unary(lambda s: s.document.Insert, r, Kind.WRITE, self._ctx)
        return [_decode_value(w.id) for w in resp.results]

    async def find_by_id(self, id: Any) -> T | None:  # noqa: A002 - mirrors the model
        """The document with this ``_id``, or ``None``."""
        r = document_pb2.GetRequest(database=self.database.name, collection=self.name, id=_value(id))
        if self._ctx.txn_id is not None:
            r.txn_id = self._ctx.txn_id
        consistency = self._ops.read_consistency(self._ctx)
        if consistency is not None:
            r.consistency.CopyFrom(consistency)
        resp = await self._ops.unary(lambda s: s.document.Get, r, Kind.READ, self._ctx)
        return self._decode(resp.document) if resp.HasField("document") else None

    def find(self, filter: Filter | None = None) -> AsyncFind[T]:  # noqa: A002
        """A fluent find; runs when iterated, ``to_list()``, ``first()`` or ``cursor()``."""
        return AsyncFind(self, filter or Filter.empty())

    async def update_one(self, filter: Filter, update: Update, *, if_rev: str | None = None) -> UpdateResult:  # noqa: A002
        """Updates one document: by id (``DocumentService.Update``) or the matching document
        with the lowest ``_id`` (``UPDATE … LIMIT 1``, PD-070)."""
        if filter.is_id:
            params = ParamSink("u")
            r = document_pb2.UpdateRequest(
                database=self.database.name,
                collection=self.name,
                id=_value(filter.id_value),
                operations=update.to_ast(params),
                options=self._write_options(),
            )
            for k, v in params.params.items():
                r.params[k].CopyFrom(v)
            if if_rev is not None:
                r.if_rev = if_rev
            if self._ctx.txn_id is not None:
                r.txn_id = self._ctx.txn_id
            resp = await self._ops.unary(lambda s: s.document.Update, r, Kind.WRITE, self._ctx)
            return UpdateResult(1 if resp.matched else 0, 1 if resp.modified else 0)
        return await self._statement_update(filter, update, True, if_rev)

    async def update_many(self, filter: Filter, update: Update) -> UpdateResult:  # noqa: A002
        """Updates every matching document (the empty filter adds ``allow_full_scan_write``)."""
        return await self._statement_update(filter, update, False, None)

    async def _statement_update(self, filter: Filter, update: Update, one: bool, if_rev: str | None) -> UpdateResult:  # noqa: A002
        if if_rev is not None:
            raise ValueError("if_rev needs a Filter.id filter")
        params: dict[str, common_pb2.Value] = {}
        st = update_statement(self.name, filter, update, one, ParamSink("f", params), ParamSink("u", params))
        n = await self.database._execute_write(st, params, self._ctx)
        return UpdateResult(n, n)

    async def replace_one(
        self,
        filter: Filter,  # noqa: A002
        replacement: T,
        *,
        upsert: bool = False,
        if_rev: str | None = None,
    ) -> UpdateResult:
        """Replaces one document; ``upsert`` needs ``Filter.id`` (``DocumentService.Upsert``)."""
        if upsert or filter.is_id:
            if not filter.is_id:
                raise ValueError("upsert needs a Filter.id filter")
            return await self._replace_by_id(filter.id_value, replacement, upsert, if_rev)
        if if_rev is not None:
            raise ValueError("if_rev needs a Filter.id filter")
        params: dict[str, common_pb2.Value] = {}
        st = update_statement(
            self.name,
            filter,
            Update.replace_with(self._codec.to_document(replacement)),
            True,
            ParamSink("f", params),
            ParamSink("u", params),
        )
        n = await self.database._execute_write(st, params, self._ctx)
        return UpdateResult(n, n)

    async def _replace_by_id(self, id: Any, replacement: T, upsert: bool, if_rev: str | None) -> UpdateResult:  # noqa: A002
        if upsert:
            doc = {"_id": id}
            doc.update((k, v) for k, v in self._codec.to_document(replacement).items() if k != "_id")
            u = document_pb2.UpsertRequest(
                database=self.database.name,
                collection=self.name,
                document=common_pb2.Document(rdoc=rdoc.encode_document(doc)),
                options=self._write_options(),
            )
            if if_rev is not None:
                u.if_rev = if_rev
            if self._ctx.txn_id is not None:
                u.txn_id = self._ctx.txn_id
            ur = await self._ops.unary(lambda s: s.document.Upsert, u, Kind.WRITE, self._ctx)
            return UpdateResult(0, 0, id) if ur.inserted else UpdateResult(1, 1)
        r = document_pb2.ReplaceRequest(
            database=self.database.name,
            collection=self.name,
            id=_value(id),
            document=self._document(replacement),
            options=self._write_options(),
        )
        if if_rev is not None:
            r.if_rev = if_rev
        if self._ctx.txn_id is not None:
            r.txn_id = self._ctx.txn_id
        resp = await self._ops.unary(lambda s: s.document.Replace, r, Kind.WRITE, self._ctx)
        return UpdateResult(1, 1) if resp.matched else UpdateResult(0, 0)

    async def delete_one(self, filter: Filter, *, if_rev: str | None = None) -> DeleteResult:  # noqa: A002
        """Deletes one document: by id, or the matching document with the lowest ``_id``."""
        if filter.is_id:
            r = document_pb2.DeleteRequest(
                database=self.database.name,
                collection=self.name,
                id=_value(filter.id_value),
                options=self._write_options(),
            )
            if if_rev is not None:
                r.if_rev = if_rev
            if self._ctx.txn_id is not None:
                r.txn_id = self._ctx.txn_id
            resp = await self._ops.unary(lambda s: s.document.Delete, r, Kind.WRITE, self._ctx)
            return DeleteResult(1 if resp.deleted else 0)
        return await self._statement_delete(filter, True, if_rev)

    async def delete_many(self, filter: Filter) -> DeleteResult:  # noqa: A002
        return await self._statement_delete(filter, False, None)

    async def _statement_delete(self, filter: Filter, one: bool, if_rev: str | None) -> DeleteResult:  # noqa: A002
        if if_rev is not None:
            raise ValueError("if_rev needs a Filter.id filter")
        sink = ParamSink("f")
        n = await self.database._execute_write(delete_statement(self.name, filter, one, sink), sink.params, self._ctx)
        return DeleteResult(n)

    async def bulk_write(self, operations: Sequence[BulkOperation], *, ordered: bool = True) -> BulkWriteResult:
        """By-id operations in one call. Outside a transaction failed operations are reported in
        ``errors`` (they roll back alone); inside one any failure raises (PD-071)."""
        params = ParamSink("u")
        r = document_pb2.BulkWriteRequest(
            database=self.database.name, collection=self.name, ordered=ordered, options=self._write_options()
        )
        for op in operations:
            b = document_pb2.BulkOperation()
            if op.kind == "insert":
                b.insert.document.CopyFrom(self._document(op.document))
            elif op.kind == "upsert":
                b.upsert.document.CopyFrom(self._document(op.document))
            elif op.kind == "replace":
                b.replace.id.CopyFrom(_value(op.id))
                b.replace.document.CopyFrom(self._document(op.document))
                if op.if_rev is not None:
                    b.replace.if_rev = op.if_rev
            elif op.kind == "update":
                if op.update is None:
                    raise ValueError("a bulk update needs an Update")
                b.update.id.CopyFrom(_value(op.id))
                b.update.operations.extend(op.update.to_ast(params))
                if op.if_rev is not None:
                    b.update.if_rev = op.if_rev
            elif op.kind == "delete":
                b.delete.id.CopyFrom(_value(op.id))
                if op.if_rev is not None:
                    b.delete.if_rev = op.if_rev
            else:
                raise ValueError(f"unknown bulk operation {op.kind!r}")
            r.operations.append(b)
        for k, v in params.params.items():
            r.params[k].CopyFrom(v)
        if self._ctx.txn_id is not None:
            r.txn_id = self._ctx.txn_id
        resp = await self._ops.unary(lambda s: s.document.BulkWrite, r, Kind.WRITE, self._ctx)
        errs = [
            BulkWriteError(e.index, from_detail(e.message or e.error.name, e.error), e.message) for e in resp.errors
        ]
        return BulkWriteResult(int(resp.inserted), int(resp.matched), int(resp.modified), int(resp.deleted), errs)

    async def create_index(self, name: str, keys: Sequence[IndexKey | str], *, unique: bool = False) -> IndexInfo:
        """Creates an index and waits until it is ready (bounded by the operation timeout)."""
        if not keys:
            raise ValueError("an index needs at least one key")
        definition = query_ast_pb2.AstCreateIndex(
            index_type=query_ast_pb2.AST_INDEX_TYPE_UNIQUE if unique else query_ast_pb2.AST_INDEX_TYPE_STANDARD,
            name=name,
            on=query_ast_pb2.AstQualifiedName(name=self.name),
        )
        for k in keys:
            key = IndexKey(k) if isinstance(k, str) else k
            definition.keys.append(query_ast_pb2.AstIndexKey(path=path(key.path), descending=key.descending))
        r = schema_pb2.CreateIndexRequest(database=self.database.name, definition=definition)
        info = _index_info((await self._ops.unary(lambda s: s.schema.CreateIndex, r, Kind.NONE, self._ctx)).index)
        timeout = self._ctx.timeout if self._ctx.timeout is not None else self._ops.settings.operation_timeout
        deadline = time.monotonic() + timeout
        state = info.state
        while state is IndexState.BUILDING:
            if time.monotonic() > deadline:
                raise errors.local(5006, f"index {name} still building after {timeout} s")
            await asyncio.sleep(_INDEX_POLL)
            p = schema_pb2.IndexBuildProgressRequest(database=self.database.name, collection=self.name, name=name)
            progress = await self._ops.unary(lambda s: s.schema.IndexBuildProgress, p, Kind.READ, self._ctx)
            state = _STATES.get(progress.state, IndexState.UNKNOWN)
        return IndexInfo(info.name, info.keys, info.unique, state)

    async def drop_index(self, name: str, *, if_exists: bool = False) -> bool:
        r = schema_pb2.DropIndexRequest(
            database=self.database.name, collection=self.name, name=name, if_exists=if_exists
        )
        return bool((await self._ops.unary(lambda s: s.schema.DropIndex, r, Kind.NONE, self._ctx)).dropped)

    async def list_indexes(self) -> list[IndexInfo]:
        r = schema_pb2.ListIndexesRequest(database=self.database.name, collection=self.name)
        resp = await self._ops.unary(lambda s: s.schema.ListIndexes, r, Kind.READ, self._ctx)
        return sorted((_index_info(i) for i in resp.indexes), key=lambda i: i.name)

    def __repr__(self) -> str:
        return f"AsyncCollection({self.database.name}.{self.name})"


# ------------------------------------------------------------------------- find and cursor


class AsyncFind(Generic[T]):
    """A fluent find (``Collection.Find``); executes on ``to_list``, ``first``, ``cursor`` or
    ``async for``."""

    def __init__(self, collection: AsyncCollection[T], filter: Filter) -> None:  # noqa: A002
        if not isinstance(filter, Filter):
            raise TypeError("find takes a Filter")
        self._collection = collection
        self._filter = filter
        self._sort: Sort | None = None
        self._projection: Projection | None = None
        self._limit: int | None = None
        self._skip: int | None = None
        self._batch_size: int | None = None

    def sort(self, order: Sort) -> AsyncFind[T]:
        self._sort = order
        return self

    def limit(self, n: int) -> AsyncFind[T]:
        if n < 0:
            raise ValueError("limit must not be negative")
        self._limit = n
        return self

    def skip(self, n: int) -> AsyncFind[T]:
        if n < 0:
            raise ValueError("skip must not be negative")
        self._skip = n
        return self

    def project(self, projection: Projection) -> AsyncFind[T]:
        self._projection = projection
        return self

    def batch_size(self, n: int) -> AsyncFind[T]:
        if n < 1:
            raise ValueError("batch_size must be positive")
        self._batch_size = n
        return self

    async def _open(self, limit: int | None) -> AsyncCursor[T]:
        sink = ParamSink("f")
        c = self._collection
        st = find_statement(c.name, self._filter, self._sort, self._projection, limit, self._skip, sink)
        return await c.database._open(st, None, sink.params, self._batch_size, Kind.READ, c._ctx, c._codec)

    async def cursor(self) -> AsyncCursor[T]:
        """Runs the find and returns its cursor (close it, or use ``async with``)."""
        return await self._open(self._limit)

    async def to_list(self) -> list[T]:
        async with await self.cursor() as cur:
            return [d async for d in cur]

    async def first(self) -> T | None:
        """The first row (``LIMIT 1``), or ``None``."""
        async with await self._open(1 if self._limit is None else min(self._limit, 1)) as cur:
            return await cur.try_next()

    async def __aiter__(self) -> AsyncIterator[T]:
        async with await self.cursor() as cur:
            async for d in cur:
                yield d


class AsyncCursor(Generic[T]):
    """Rows of a find or a query, fetched in batches (``GetMore``); ``async for`` and ``async with``."""

    def __init__(
        self,
        ops: Operations,
        ctx: OpContext,
        codec: DocumentCodec[T],
        batch_size: int | None,
        first: Iterable[query_pb2.ResultBatch],
    ) -> None:
        self._ops = ops
        self._ctx = ctx
        self._codec = codec
        self._batch_size = batch_size
        self._buffer: deque[common_pb2.Document] = deque()
        self._cursor_id: str | None = None
        self._closed = False
        for b in first:
            self._take(b)

    def _take(self, b: query_pb2.ResultBatch) -> None:
        self._buffer.extend(b.docs)
        self._cursor_id = b.cursor_id if b.HasField("cursor_id") else None

    async def try_next(self) -> T | None:
        """The next row, or ``None`` at the end (``Cursor.Next``)."""
        while not self._buffer and self._cursor_id is not None and not self._closed:
            r = query_pb2.GetMoreRequest(cursor_id=self._cursor_id)
            if self._batch_size is not None:
                r.batch_size = self._batch_size
            resp = await self._ops.unary(lambda s: s.query.GetMore, r, Kind.NONE, self._ctx)
            self._take(resp.batch)
        if self._closed or not self._buffer:
            return None
        return self._codec.from_document(rdoc.decode_document(self._buffer.popleft().rdoc))

    def __aiter__(self) -> AsyncCursor[T]:
        return self

    async def __anext__(self) -> T:
        if self._closed or (not self._buffer and self._cursor_id is None):
            raise StopAsyncIteration
        row = await self.try_next()
        if row is None and not self._buffer and self._cursor_id is None:
            raise StopAsyncIteration
        return row  # type: ignore[return-value] # a decoded row is never None

    async def to_list(self) -> list[T]:
        async with self:
            return [d async for d in self]

    async def close(self) -> None:
        """Releases the server cursor (``KillCursor``); idempotent."""
        if self._closed:
            return
        self._closed = True
        self._buffer.clear()
        cursor_id, self._cursor_id = self._cursor_id, None
        if cursor_id is not None:
            with contextlib.suppress(errors.RustegonException, RuntimeError):
                await self._ops.unary(
                    lambda s: s.query.KillCursor, query_pb2.KillCursorRequest(cursor_id=cursor_id), Kind.NONE, self._ctx
                )

    async def __aenter__(self) -> AsyncCursor[T]:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        await self.close()


# ------------------------------------------------------------------------- transactions


class AsyncTransaction:
    """An interactive transaction (manual mode or inside ``with_transaction``).

    Operations through ``get_collection`` / ``query`` carry its ``txn_id``. While it is open the
    driver sends ``Heartbeat`` every ``heartbeat_interval_ms`` (``Behavior.TransactionHeartbeat``).
    """

    def __init__(self, client: AsyncRustegonClient, txn_id: str, heartbeat_interval: float) -> None:
        self.client = client
        self.id = txn_id
        self._ctx = OpContext(txn_id=txn_id)
        self._state = "active"
        self._heartbeat: asyncio.Task[None] | None = None
        if heartbeat_interval > 0:
            self._heartbeat = asyncio.get_running_loop().create_task(self._beat(heartbeat_interval))

    async def _beat(self, interval: float) -> None:
        ctx = self._ctx.with_(timeout=max(1.0, interval))
        while True:
            await asyncio.sleep(interval)
            try:
                await self.client._ops.unary(
                    lambda s: s.transaction.Heartbeat,
                    transaction_pb2.HeartbeatRequest(txn_id=self.id),
                    Kind.NONE,
                    ctx,
                )
            except (errors.RustegonException, RuntimeError) as e:
                _LOG.debug("heartbeat of a transaction failed: %s", e)

    def stop_heartbeat(self) -> None:
        if self._heartbeat is not None:
            self._heartbeat.cancel()
            self._heartbeat = None

    @overload
    def get_collection(self, name: str) -> AsyncCollection[dict[str, Any]]: ...

    @overload
    def get_collection(self, name: str, document_class: type[D]) -> AsyncCollection[D]: ...

    def get_collection(self, name: str, document_class: type[Any] = dict) -> AsyncCollection[Any]:
        """``"coll"`` (default database) or ``"db.coll"``: a handle bound to this transaction."""
        db_name, dot, coll = name.partition(".")
        database = self.client.get_database(db_name if dot else None)
        db = AsyncDatabase(self.client, database.name, self._ctx)
        return AsyncCollection(db, coll if dot else name, codec_for(document_class), self._ctx)

    async def query(
        self, rgql: str, params: Mapping[str, Any] | None = None, *, document_class: type[Any] = dict
    ) -> AsyncCursor[Any]:
        """RGQL inside the transaction (default database)."""
        db = self.client.get_database()
        return await db._query(rgql, params, None, document_class, self._ctx)

    async def commit(self) -> None:
        """Commits; RGN-2006 raises ``CommitOutcomeUnknownException`` whose ``resolve()`` asks ``Status``."""
        try:
            await self.client._ops.commit(transaction_pb2.CommitRequest(txn_id=self.id), self._ctx)
        except errors.CommitOutcomeUnknownException as e:
            self._state = "unknown"
            self.stop_heartbeat()
            e._resolver = self.resolve
            raise
        self._state = "committed"
        self.stop_heartbeat()

    async def rollback(self) -> None:
        self.stop_heartbeat()
        await self.client._ops.unary(
            lambda s: s.transaction.Rollback, transaction_pb2.RollbackRequest(txn_id=self.id), Kind.NONE, self._ctx
        )
        self._state = "rolled_back"

    async def rollback_quietly(self) -> None:
        """Best effort (transactions.md §5): the server aborts the transaction anyway."""
        try:
            await self.rollback()
        except (errors.RustegonException, RuntimeError) as e:
            _LOG.debug("rollback after a failed attempt failed: %s", e)

    async def resolve(self) -> str:
        """``committed``, ``aborted`` or ``unknown`` (``TransactionService.Status``)."""
        r = await self.client._ops.unary(
            lambda s: s.transaction.Status, transaction_pb2.StatusRequest(txn_id=self.id), Kind.NONE, self._ctx
        )
        if r.state == transaction_pb2.TRANSACTION_STATE_COMMITTED:
            return "committed"
        if r.state == transaction_pb2.TRANSACTION_STATE_ABORTED:
            return "aborted"
        return "unknown"

    async def close(self) -> None:
        """Rolls back when neither committed nor rolled back; idempotent."""
        self.stop_heartbeat()
        if self._state == "active":
            await self.rollback_quietly()

    async def __aenter__(self) -> AsyncTransaction:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        await self.close()


def _unused(_s: Stubs) -> None:  # pragma: no cover - keeps the Stubs import for type checkers
    return None
