# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""The blocking facade (PD-170): ``RustegonClient`` and its handles mirror the asyncio API with
plain methods. Each client runs the asyncio core on a private event loop in a daemon thread;
a call submits the coroutine there and waits for its result, so the facade is thread-safe and
needs no running event loop. Do not call it from inside that client's own callbacks' event loop
(``with_transaction`` callbacks run in a worker thread and may use the facade freely).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine, Iterable, Iterator, Mapping, Sequence
from types import TracebackType
from typing import Any, Generic, TypeVar, overload

from rustegon.builders import BulkOperation, Filter, IndexKey, Projection, Sort, Update
from rustegon.client import (
    AsyncCollection,
    AsyncCursor,
    AsyncDatabase,
    AsyncFind,
    AsyncRustegonClient,
    AsyncTransaction,
    BulkWriteResult,
    DeleteResult,
    IndexInfo,
    InsertManyResult,
    InsertOneResult,
    ServerInfo,
    TransactionOptions,
    UpdateResult,
    Validator,
)
from rustegon.session import ClientSession
from rustegon.settings import ClientSettings, ReadConsistency, WriteConcern

__all__ = ["Collection", "Cursor", "Database", "Find", "RustegonClient", "Transaction"]

T = TypeVar("T")
D = TypeVar("D")


class _Loop:
    """A private event loop in a daemon thread."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="rustegon-client", daemon=True)
        self.thread.start()

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        if threading.current_thread() is self.thread:
            coro.close()
            raise RuntimeError("the blocking API cannot be used on the client's own event loop")
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result()

    def stop(self) -> None:
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=10)
        if not self.loop.is_running():
            self.loop.close()


class RustegonClient:
    """The blocking client (same settings and semantics as ``AsyncRustegonClient``)."""

    def __init__(self, settings: ClientSettings | str, **overrides: Any) -> None:
        self._async = AsyncRustegonClient(settings, **overrides)
        self.settings = self._async.settings
        self._loop = _Loop()

    def _run(self, coro: Coroutine[Any, Any, T]) -> T:
        return self._loop.run(coro)

    def __enter__(self) -> RustegonClient:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def ping(self) -> None:
        self._run(self._async.ping())

    def server_info(self) -> ServerInfo:
        return self._run(self._async.server_info())

    def get_database(self, name: str | None = None) -> Database:
        return Database(self, self._async.get_database(name))

    def list_database_names(self) -> list[str]:
        return self._run(self._async.list_database_names())

    def create_database(self, name: str, *, if_not_exists: bool = False) -> bool:
        return self._run(self._async.create_database(name, if_not_exists=if_not_exists))

    def drop_database(self, name: str, *, if_exists: bool = False) -> bool:
        return self._run(self._async.drop_database(name, if_exists=if_exists))

    def start_session(self, *, causal_consistency: bool = True) -> ClientSession:
        return self._async.start_session(causal_consistency=causal_consistency)

    def begin_transaction(self, options: TransactionOptions | None = None) -> Transaction:
        return Transaction(self, self._run(self._async.begin_transaction(options)))

    def with_transaction(self, callback: Callable[[Transaction], T], options: TransactionOptions | None = None) -> T:
        """Runs the blocking ``callback`` (in a worker thread) with the retry loop of the core."""

        async def run(txn: AsyncTransaction) -> T:
            return await asyncio.to_thread(callback, Transaction(self, txn))

        return self._run(self._async.with_transaction(run, options))

    @property
    def password_change_required(self) -> bool:
        return self._async.password_change_required

    def change_password(self, current_password: str, new_password: str) -> None:
        self._run(self._async.change_password(current_password, new_password))

    def close(self) -> None:
        """Logs out, closes the connections and stops the client's thread; idempotent."""
        if self._loop.loop.is_closed():
            return
        try:
            self._run(self._async.close())
        finally:
            self._loop.stop()


class Database:
    def __init__(self, client: RustegonClient, inner: AsyncDatabase) -> None:
        self.client = client
        self._inner = inner
        self.name = inner.name

    def with_options(self, **options: Any) -> Database:
        """See ``AsyncDatabase.with_options``: session, timeout, read_consistency, max_staleness, write_concern."""
        return Database(self.client, self._inner.with_options(**options))

    @overload
    def get_collection(self, name: str) -> Collection[dict[str, Any]]: ...

    @overload
    def get_collection(self, name: str, document_class: type[D]) -> Collection[D]: ...

    def get_collection(self, name: str, document_class: type[Any] = dict) -> Collection[Any]:
        return Collection(self.client, self._inner.get_collection(name, document_class))

    def query(
        self,
        rgql: str,
        params: Mapping[str, Any] | None = None,
        *,
        batch_size: int | None = None,
        document_class: type[Any] = dict,
    ) -> Cursor[Any]:
        return Cursor(
            self.client,
            self.client._run(self._inner.query(rgql, params, batch_size=batch_size, document_class=document_class)),
        )

    def create_collection(self, name: str, *, if_not_exists: bool = False, validator: Validator | None = None) -> bool:
        return self.client._run(self._inner.create_collection(name, if_not_exists=if_not_exists, validator=validator))

    def drop_collection(self, name: str, *, if_exists: bool = False) -> bool:
        return self.client._run(self._inner.drop_collection(name, if_exists=if_exists))

    def list_collection_names(self) -> list[str]:
        return self.client._run(self._inner.list_collection_names())


class Collection(Generic[T]):
    def __init__(self, client: RustegonClient, inner: AsyncCollection[T]) -> None:
        self.client = client
        self._inner = inner
        self.name = inner.name

    def with_options(
        self,
        *,
        session: ClientSession | None = None,
        timeout: float | None = None,
        read_consistency: ReadConsistency | str | None = None,
        max_staleness: float | None = None,
        write_concern: WriteConcern | str | None = None,
    ) -> Collection[T]:
        inner = self._inner.with_options(
            session=session,
            timeout=timeout,
            read_consistency=read_consistency,
            max_staleness=max_staleness,
            write_concern=write_concern,
        )
        return Collection(self.client, inner)

    def insert_one(self, document: T) -> InsertOneResult:
        return self.client._run(self._inner.insert_one(document))

    def insert_many(self, documents: Iterable[T]) -> InsertManyResult:
        return self.client._run(self._inner.insert_many(list(documents)))

    def find_by_id(self, id: Any) -> T | None:  # noqa: A002
        return self.client._run(self._inner.find_by_id(id))

    def find(self, filter: Filter | None = None) -> Find[T]:  # noqa: A002
        return Find(self.client, self._inner.find(filter))

    def update_one(self, filter: Filter, update: Update, *, if_rev: str | None = None) -> UpdateResult:  # noqa: A002
        return self.client._run(self._inner.update_one(filter, update, if_rev=if_rev))

    def update_many(self, filter: Filter, update: Update) -> UpdateResult:  # noqa: A002
        return self.client._run(self._inner.update_many(filter, update))

    def replace_one(
        self,
        filter: Filter,  # noqa: A002
        replacement: T,
        *,
        upsert: bool = False,
        if_rev: str | None = None,
    ) -> UpdateResult:
        return self.client._run(self._inner.replace_one(filter, replacement, upsert=upsert, if_rev=if_rev))

    def delete_one(self, filter: Filter, *, if_rev: str | None = None) -> DeleteResult:  # noqa: A002
        return self.client._run(self._inner.delete_one(filter, if_rev=if_rev))

    def delete_many(self, filter: Filter) -> DeleteResult:  # noqa: A002
        return self.client._run(self._inner.delete_many(filter))

    def bulk_write(self, operations: Sequence[BulkOperation], *, ordered: bool = True) -> BulkWriteResult:
        return self.client._run(self._inner.bulk_write(operations, ordered=ordered))

    def create_index(self, name: str, keys: Sequence[IndexKey | str], *, unique: bool = False) -> IndexInfo:
        return self.client._run(self._inner.create_index(name, keys, unique=unique))

    def drop_index(self, name: str, *, if_exists: bool = False) -> bool:
        return self.client._run(self._inner.drop_index(name, if_exists=if_exists))

    def list_indexes(self) -> list[IndexInfo]:
        return self.client._run(self._inner.list_indexes())


class Find(Generic[T]):
    """A fluent find; iterate it, or call ``to_list``, ``first`` or ``cursor``."""

    def __init__(self, client: RustegonClient, inner: AsyncFind[T]) -> None:
        self.client = client
        self._inner = inner

    def sort(self, order: Sort) -> Find[T]:
        self._inner.sort(order)
        return self

    def limit(self, n: int) -> Find[T]:
        self._inner.limit(n)
        return self

    def skip(self, n: int) -> Find[T]:
        self._inner.skip(n)
        return self

    def project(self, projection: Projection) -> Find[T]:
        self._inner.project(projection)
        return self

    def batch_size(self, n: int) -> Find[T]:
        self._inner.batch_size(n)
        return self

    def cursor(self) -> Cursor[T]:
        return Cursor(self.client, self.client._run(self._inner.cursor()))

    def to_list(self) -> list[T]:
        return self.client._run(self._inner.to_list())

    def first(self) -> T | None:
        return self.client._run(self._inner.first())

    def __iter__(self) -> Iterator[T]:
        with self.cursor() as cur:
            yield from cur


class Cursor(Generic[T]):
    """A blocking cursor: an iterator and a context manager."""

    def __init__(self, client: RustegonClient, inner: AsyncCursor[T]) -> None:
        self.client = client
        self._inner = inner

    def try_next(self) -> T | None:
        """The next row, or ``None`` at the end."""
        return self.client._run(self._inner.try_next())

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        async def step() -> tuple[bool, Any]:
            try:
                return True, await self._inner.__anext__()
            except StopAsyncIteration:
                return False, None

        ok, row = self.client._run(step())
        if not ok:
            raise StopIteration
        return row  # type: ignore[no-any-return]

    def to_list(self) -> list[T]:
        return self.client._run(self._inner.to_list())

    def close(self) -> None:
        self.client._run(self._inner.close())

    def __enter__(self) -> Cursor[T]:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


class Transaction:
    """A blocking interactive transaction; ``with`` rolls back if not committed."""

    def __init__(self, client: RustegonClient, inner: AsyncTransaction) -> None:
        self.client = client
        self._inner = inner
        self.id = inner.id

    @overload
    def get_collection(self, name: str) -> Collection[dict[str, Any]]: ...

    @overload
    def get_collection(self, name: str, document_class: type[D]) -> Collection[D]: ...

    def get_collection(self, name: str, document_class: type[Any] = dict) -> Collection[Any]:
        return Collection(self.client, self._inner.get_collection(name, document_class))

    def query(
        self, rgql: str, params: Mapping[str, Any] | None = None, *, document_class: type[Any] = dict
    ) -> Cursor[Any]:
        return Cursor(self.client, self.client._run(self._inner.query(rgql, params, document_class=document_class)))

    def commit(self) -> None:
        self.client._run(self._inner.commit())

    def rollback(self) -> None:
        self.client._run(self._inner.rollback())

    def resolve(self) -> str:
        return self.client._run(self._inner.resolve())

    def close(self) -> None:
        self.client._run(self._inner.close())

    def __enter__(self) -> Transaction:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()
