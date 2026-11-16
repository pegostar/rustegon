# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Runs the operations of conformance tests (drivers/conformance/README.md §5) against an
``AsyncRustegonClient``: dispatch by object and name, argument conversion, results as plain
values, expectations (``result`` exact/subset, ``error`` class/code/name/flags), ``saveAs`` and
``$$ref``. What depends on the fixture (opening clients, runner operations) comes from ``Env``.
Shared by the conformance runner and the fake-server retry scenarios."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from rustegon import (
    AsyncCollection,
    AsyncCursor,
    AsyncDatabase,
    AsyncRustegonClient,
    AsyncTransaction,
    BulkOperation,
    ClientSession,
    IndexKey,
    IsolationLevel,
    TransactionOptions,
    UpdateResult,
    Validator,
    errors,
)
from tests.values import dsl_filter, dsl_projection, dsl_sort, dsl_update, mismatch, value


class Env(Protocol):
    def substitute(self, s: str) -> str: ...

    async def open(self, args: Mapping[str, Any]) -> AsyncRustegonClient: ...

    async def runner(self, name: str, args: Mapping[str, Any], runner: OpRunner) -> Any: ...


class ApplicationError(Exception):
    """The exception of ``runner.throwApplicationError``."""

    def __init__(self) -> None:
        super().__init__("application error thrown by the callback")


# errors-map.yaml class ids, most specific first; Argument and InvalidState are the Python
# conventions of errors.py (ValueError/TypeError, RuntimeError).
CLASSES: list[tuple[str, type[BaseException] | tuple[type[BaseException], ...]]] = [
    ("PasswordChangeRequired", errors.PasswordChangeRequiredException),
    ("QuerySyntax", errors.QuerySyntaxException),
    ("Client", errors.RustegonClientException),
    ("DuplicateKey", errors.DuplicateKeyException),
    ("DocumentValidation", errors.DocumentValidationException),
    ("TransactionConflict", errors.TransactionConflictException),
    ("TransactionAborted", errors.TransactionAbortedException),
    ("CommitOutcomeUnknown", errors.CommitOutcomeUnknownException),
    ("Authentication", errors.AuthenticationException),
    ("Authorization", errors.AuthorizationException),
    ("Unavailable", errors.UnavailableException),
    ("RateLimited", errors.RateLimitedException),
    ("Timeout", errors.RustegonTimeoutException),
    ("Server", errors.RustegonServerException),
    ("Base", errors.RustegonException),
    ("Argument", (ValueError, TypeError)),
    ("InvalidState", RuntimeError),
]
_BY_ID = dict(CLASSES)


def class_id(e: BaseException) -> str:
    if isinstance(e, ApplicationError):
        return "ApplicationError"
    return next((cid for cid, cls in CLASSES if isinstance(e, cls)), type(e).__name__)


def error_mismatch(want: Mapping[str, Any], e: BaseException) -> str | None:
    """``None`` when ``e`` satisfies the expected error, else the difference."""
    if want.get("applicationError"):
        return None if isinstance(e, ApplicationError) else f"expected the application error, got {e!r}"
    cid = want.get("exception")
    if cid is not None:
        cls = _BY_ID.get(cid)
        if cls is None:
            return f"unknown exception class id {cid}"
        if not isinstance(e, cls):
            return f"expected {cid}, got {e!r}"
    r = e if isinstance(e, errors.RustegonException) else None
    if "code" in want and (r is None or r.code != want["code"]):
        return f"expected code {want['code']}, got {e!r}"
    if "name" in want and (r is None or r.name != want["name"]):
        return f"expected name {want['name']}, got {e!r}"
    if "retryable" in want and (r is None or r.retryable != want["retryable"]):
        return f"expected retryable={want['retryable']}, got {e!r}"
    if "committed" in want and (r is None or r.committed != want["committed"]):
        return f"expected committed={want['committed']}, got {e!r}"
    return None


def _update_result(r: UpdateResult) -> dict[str, Any]:
    d: dict[str, Any] = {"matchedCount": r.matched_count, "modifiedCount": r.modified_count}
    if r.upserted_id is not None:
        d["upsertedId"] = r.upserted_id
    return d


def _validator(m: Mapping[str, Any]) -> Validator:
    return Validator(m["jsonSchema"], m.get("level"), m.get("action"))


def _keys(keys: list[Mapping[str, Any]]) -> list[IndexKey]:
    return [IndexKey(k["path"], bool(k.get("descending"))) for k in keys]


class OpRunner:
    def __init__(self, client: AsyncRustegonClient, database: str, default_collection: str, env: Env) -> None:
        self.client = client
        self.database = database
        self.default_collection = default_collection
        self.env = env
        self.saved: dict[str, Any] = {}
        self.observations: list[dict[str, Any]] = []
        self.last_error: BaseException | None = None
        self._transactions: list[AsyncTransaction] = []
        self._opened: list[Any] = []
        self._index = 0
        self._depth = 0

    async def close_opened(self) -> None:
        """Closes the clients, sessions, cursors and transactions the operations opened."""
        for c in reversed(self._opened):
            try:
                r = c.close()
                if r is not None:
                    await r
            except Exception:
                pass
        self._opened.clear()

    def v(self, y: Any) -> Any:
        return value(y, self._ref, self.env.substitute)

    def _ref(self, spec: str) -> Any:
        name, *parts = spec.split(".")
        if name not in self.saved:
            raise AssertionError(f"$$ref to an unsaved name: {spec}")
        x = self.saved[name]
        for p in parts:
            x = x[p]
        return x

    async def run(self, op: Mapping[str, Any]) -> None:
        """Runs one operation and checks its expectation; an exception of an operation without
        ``expect`` propagates (inside a ``with_transaction`` callback that is how a failure reaches
        the helper)."""
        # Only top-level operations are observed, numbered by position (README §6).
        at = self._index if self._depth == 0 else -1
        if self._depth == 0:
            self._index += 1
        self._depth += 1
        try:
            await self._run(op, at)
        finally:
            self._depth -= 1

    async def _run(self, op: Mapping[str, Any], at: int) -> None:
        where = f"op {at}" if at >= 0 else "callback op"
        expect = op.get("expect")
        try:
            result = await self._invoke(op)
        except AssertionError:
            raise
        except Exception as e:
            self.last_error = e
            if at >= 0:
                self.observations.append(self._observation(at, None, e))
            if expect is None or "error" not in expect:
                raise
            d = error_mismatch(expect["error"], e)
            if d is not None:
                raise AssertionError(f"{where} ({op['name']}): {d}") from e
            return
        if at >= 0:
            self.observations.append(self._observation(at, self._observed(op["name"], result), None))
        if "saveAs" in op:
            self.saved[op["saveAs"]] = result
        if expect is None:
            return
        if "error" in expect:
            raise AssertionError(f"{where} ({op['name']}): expected an error, got {result!r}")
        d = mismatch(
            self.v(expect.get("result")),
            result,
            op.get("match") == "subset",
            op.get("ordered", True) is not False,
            op.get("fieldOrder") is True,
        )
        if d is not None:
            raise AssertionError(f"{where} ({op['name']}): {d}")

    def _observed(self, name: str, result: Any) -> Any:
        """README §6: session tokens are volatile; ``listDatabaseNames`` keeps this file's
        databases with ``${database}`` written as ``<database>``."""
        if name == "causalityToken" and result is not None:
            return "<volatile>"
        if name == "listDatabaseNames" and isinstance(result, list):
            return ["<database>" + n[len(self.database) :] for n in result if n.startswith(self.database)]
        return result

    @staticmethod
    def _observation(at: int, result: Any, e: BaseException | None) -> dict[str, Any]:
        if e is None:
            return {"op": at, "result": result}
        err: dict[str, Any] = {}
        if isinstance(e, errors.RustegonException):
            err["code"] = e.code
            err["retryable"] = e.retryable
        err["exception"] = class_id(e)
        return {"op": at, "error": err}

    # ------------------------------------------------------------------ dispatch

    async def _invoke(self, op: Mapping[str, Any]) -> Any:
        obj, name = op["object"], op["name"]
        args: Mapping[str, Any] = op.get("args") or {}
        if obj == "runner":
            return await self.env.runner(name, args, self)
        target: Any
        if obj in ("client", "collection"):
            target = self.client
        elif obj == "database":
            target = self.client.get_database(self.database)
        elif obj == "transaction":
            target = self._transactions[-1] if self._transactions else None
        elif obj in self.saved:
            target = self.saved[obj]
        else:
            raise AssertionError(f"unknown object {obj}")
        if isinstance(target, AsyncRustegonClient) and (obj == "collection" or "collection" in op):
            coll = target.get_database(self.database).get_collection(op.get("collection", self.default_collection))
            if "session" in op:
                coll = coll.with_options(session=self.saved[op["session"]])
            return await self._collection_op(coll, name, args, op)
        if isinstance(target, AsyncTransaction) and "collection" in op:
            return await self._collection_op(
                target.get_collection(f"{self.database}.{op['collection']}"), name, args, op
            )
        if isinstance(target, AsyncRustegonClient):
            return await self._client_op(target, name, args)
        if isinstance(target, AsyncDatabase):
            return await self._database_op(target, name, args)
        if isinstance(target, AsyncTransaction):
            return await self._transaction_op(target, name, args)
        if isinstance(target, AsyncCursor):
            if name == "next":
                return await target.try_next()
            if name == "close":
                await target.close()
                return None
        if isinstance(target, ClientSession):
            if name == "causalityToken":
                return target.causality_token
            if name == "close":
                target.close()
                return None
        if target is None:
            raise AssertionError(f"no object {obj}")
        raise AssertionError(f"cannot call {name} on {target!r}")

    def _str(self, args: Mapping[str, Any], key: str) -> str:
        return self.env.substitute(args[key])

    async def _connected(self, client: AsyncRustegonClient) -> AsyncRustegonClient:
        try:
            await client.server_info()  # creating a client is lazy: log in now
        except BaseException:
            await client.close()
            raise
        self._opened.append(client)
        return client

    async def _client_op(self, c: AsyncRustegonClient, name: str, args: Mapping[str, Any]) -> Any:
        if name == "open":
            return await self._connected(await self.env.open(args))
        if name == "openFromConnectionString":
            return await self._connected(AsyncRustegonClient(self._str(args, "uri")))
        if name == "getServerInfo":
            i = await c.server_info()
            return {
                "serverVersion": i.server_version,
                "protocolVersion": i.protocol_version,
                "features": list(i.features),
            }
        if name == "listDatabaseNames":
            return await c.list_database_names()
        if name == "createDatabase":
            return {
                "created": await c.create_database(self._str(args, "name"), if_not_exists=bool(args.get("ifNotExists")))
            }
        if name == "dropDatabase":
            return {"dropped": await c.drop_database(self._str(args, "name"), if_exists=bool(args.get("ifExists")))}
        if name == "startSession":
            s = c.start_session(causal_consistency=args.get("causalConsistency", True) is not False)
            self._opened.append(s)
            return s
        if name == "beginTransaction":
            t = await c.begin_transaction(self._txn_options(args))
            self._opened.append(t)
            return t
        if name == "withTransaction":
            callback = args["callback"]

            async def body(txn: AsyncTransaction) -> None:
                self._transactions.append(txn)
                try:
                    for step in callback:
                        await self.run(step)
                finally:
                    self._transactions.pop()

            await c.with_transaction(body, self._txn_options(args))
            return None
        if name == "manualTransaction":
            async with await c.begin_transaction(self._txn_options(args)) as txn:
                self._transactions.append(txn)
                try:
                    for step in args["steps"]:
                        await self.run(step)
                finally:
                    self._transactions.pop()
            return None
        if name == "changePassword":
            await c.change_password(self._str(args, "currentPassword"), self._str(args, "newPassword"))
            return None
        if name == "close":
            await c.close()
            return None
        raise AssertionError(f"client.{name}")

    @staticmethod
    def _txn_options(args: Mapping[str, Any]) -> TransactionOptions:
        m = args.get("options") or {}
        return TransactionOptions(
            isolation=IsolationLevel(m["isolation"]) if "isolation" in m else None,
            read_only=bool(m.get("readOnly")),
            max_retry_time=m["maxRetryTimeMs"] / 1000 if "maxRetryTimeMs" in m else 120.0,
        )

    def _params(self, args: Mapping[str, Any]) -> dict[str, Any]:
        return {k: self.v(x) for k, x in (args.get("params") or {}).items()}

    async def _database_op(self, d: AsyncDatabase, name: str, args: Mapping[str, Any]) -> Any:
        if name == "query":
            cur = await d.query(self._str(args, "rgql"), self._params(args), batch_size=args.get("batchSize"))
            return await cur.to_list()
        if name == "createCollection":
            v = _validator(args["validator"]) if "validator" in args else None
            created = await d.create_collection(
                self._str(args, "name"), if_not_exists=bool(args.get("ifNotExists")), validator=v
            )
            return {"created": created}
        if name == "dropCollection":
            return {"dropped": await d.drop_collection(self._str(args, "name"), if_exists=bool(args.get("ifExists")))}
        if name == "listCollectionNames":
            return await d.list_collection_names()
        raise AssertionError(f"database.{name}")

    async def _transaction_op(self, t: AsyncTransaction, name: str, args: Mapping[str, Any]) -> Any:
        if name == "query":
            return await (await t.query(self._str(args, "rgql"), self._params(args))).to_list()
        if name == "commit":
            await t.commit()
        elif name == "rollback":
            await t.rollback()
        elif name == "close":
            await t.close()
        elif name == "resolve":
            return await t.resolve()
        else:
            raise AssertionError(f"transaction.{name}")
        return None

    async def _collection_op(
        self, c: AsyncCollection[dict[str, Any]], name: str, args: Mapping[str, Any], op: Mapping[str, Any]
    ) -> Any:
        options: Mapping[str, Any] = args.get("options") or {}
        if_rev = self.v(options["ifRev"]) if options.get("ifRev") is not None else None
        f: Callable[[], Any] = lambda: dsl_filter(args.get("filter", {}), self.v)  # noqa: E731
        if name == "insertOne":
            return {"insertedId": (await c.insert_one(self.v(args["document"]))).inserted_id}
        if name == "insertMany":
            return {"insertedIds": (await c.insert_many([self.v(d) for d in args["documents"]])).inserted_ids}
        if name == "findById":
            return await c.find_by_id(self.v(args["id"]))
        if name == "find":
            return await self._find(c, args, op.get("then", "toList"))
        if name == "updateOne":
            return _update_result(await c.update_one(f(), dsl_update(args["update"], self.v), if_rev=if_rev))
        if name == "updateMany":
            if if_rev is not None:
                raise ValueError("if_rev needs a Filter.id filter")
            return _update_result(await c.update_many(f(), dsl_update(args["update"], self.v)))
        if name == "replaceOne":
            r = await c.replace_one(f(), self.v(args["replacement"]), upsert=bool(options.get("upsert")), if_rev=if_rev)
            return _update_result(r)
        if name == "deleteOne":
            return {"deletedCount": (await c.delete_one(f(), if_rev=if_rev)).deleted_count}
        if name == "deleteMany":
            if if_rev is not None:
                raise ValueError("if_rev needs a Filter.id filter")
            return {"deletedCount": (await c.delete_many(f())).deleted_count}
        if name == "bulkWrite":
            return await self._bulk(c, args)
        if name == "createIndex":
            i = await c.create_index(self._str(args, "name"), _keys(args["keys"]), unique=bool(args.get("unique")))
            return {"name": i.name, "state": i.state.value}
        if name == "dropIndex":
            return {"dropped": await c.drop_index(self._str(args, "name"), if_exists=bool(args.get("ifExists")))}
        if name == "listIndexes":
            return [
                {
                    "name": i.name,
                    "keys": [{"path": k.path, "descending": k.descending} for k in i.keys],
                    "unique": i.unique,
                    "state": i.state.value,
                }
                for i in await c.list_indexes()
            ]
        raise AssertionError(f"collection.{name}")

    async def _find(self, c: AsyncCollection[dict[str, Any]], args: Mapping[str, Any], then: str) -> Any:
        f = c.find(dsl_filter(args.get("filter", {}), self.v))
        if args.get("sort") is not None:
            f.sort(dsl_sort(args["sort"]))
        if "limit" in args:
            f.limit(args["limit"])
        if "skip" in args:
            f.skip(args["skip"])
        if args.get("projection") is not None:
            f.project(dsl_projection(args["projection"]))
        if "batchSize" in args:
            f.batch_size(args["batchSize"])
        if then == "first":
            return await f.first()
        if then == "cursor":
            cur = await f.cursor()
            self._opened.append(cur)
            return cur
        return await f.to_list()

    async def _bulk(self, c: AsyncCollection[dict[str, Any]], args: Mapping[str, Any]) -> Any:
        ops: list[BulkOperation] = []
        for o in args["operations"]:
            ((kind, a),) = o.items()
            rev = self.v(a["ifRev"]) if a.get("ifRev") is not None else None
            if kind == "insert":
                b = BulkOperation.insert(self.v(a["document"]))
            elif kind == "upsert":
                b = BulkOperation.upsert(self.v(a["document"]))
            elif kind == "replace":
                b = BulkOperation.replace(self.v(a["id"]), self.v(a["document"]), if_rev=rev)
            elif kind == "update":
                b = BulkOperation.update_by_id(self.v(a["id"]), dsl_update(a["update"], self.v), if_rev=rev)
            elif kind == "delete":
                b = BulkOperation.delete(self.v(a["id"]), if_rev=rev)
            else:
                raise AssertionError(f"bulk {kind}")
            ops.append(b)
        r = await c.bulk_write(ops, ordered=args.get("ordered", True) is not False)
        return {
            "insertedCount": r.inserted_count,
            "matchedCount": r.matched_count,
            "modifiedCount": r.modified_count,
            "deletedCount": r.deleted_count,
            "errors": [{"index": e.index, "code": e.error.code} for e in r.errors],
        }
