# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""TC-DRV-PY-009, 019, 025…027: the driver against a real ``rustegond`` (PD-072): the ADR-034 plain-text
default with the DEC-014 connection string, the blocking facade end to end, mapped dataclasses,
and ``with_transaction`` under concurrent conflicts (RGN-2001 retried, nothing lost)."""

from __future__ import annotations

import asyncio
import dataclasses
import secrets
from collections.abc import Iterator
from decimal import Decimal
from typing import Any
from urllib.parse import quote

import pytest

from rustegon import (
    AsyncRustegonClient,
    AsyncTransaction,
    BulkOperation,
    Filter,
    RustegonClient,
    Sort,
    Transaction,
    Update,
)
from tests import server

pytestmark = [pytest.mark.server]


@pytest.fixture(scope="module")
def plain_node() -> Iterator[server.TestServer]:
    node = server.start(tls=False)
    yield node
    node.stop()


def test_tc_drv_py_009_plain_text_connection_string(plain_node: server.TestServer) -> None:
    """ADR-034 + DEC-014: host, port, user, password, database and nothing else."""
    pwd = quote(plain_node.admin_password, safe="")
    uri = f"rustegon://{server.ADMIN_USER}:{pwd}@{plain_node.host}:{plain_node.port}/plain_db"
    with RustegonClient(uri) as client:
        assert client.settings.tls is False
        client.create_database("plain_db", if_not_exists=True)
        items = client.get_database().get_collection("items")
        assert items.insert_one({"_id": 1, "v": "a"}).inserted_id == 1
        assert _plain(items.find_by_id(1)) == {"_id": 1, "v": "a"}
        client.drop_database("plain_db")


@pytest.fixture
def database() -> Iterator[str]:
    name = f"py_it_{secrets.token_hex(4)}"
    with RustegonClient(server.shared().admin_settings(database=name)) as c:
        c.create_database(name)
        yield name
        c.drop_database(name, if_exists=True)


def _plain(d: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if d is None else {k: v for k, v in d.items() if k not in ("_rev", "_createdAt", "_updatedAt")}


def test_tc_drv_py_019_blocking_api_end_to_end(database: str) -> None:
    with RustegonClient(server.shared().admin_settings(database=database)) as client:
        orders = client.get_database().get_collection("orders")
        orders.insert_many([{"_id": i, "status": "paid" if i % 2 else "new", "total": Decimal(i)} for i in range(1, 8)])
        paid = orders.find(Filter.eq("status", "paid")).sort(Sort.desc("_id")).batch_size(2)
        assert [d["_id"] for d in paid] == [7, 5, 3, 1]  # four rows over two GetMore batches
        assert _plain(orders.find(Filter.gt("total", Decimal(5))).sort(Sort.asc("_id")).first()) == {
            "_id": 6,
            "status": "new",
            "total": Decimal(6),
        }
        assert orders.update_many(Filter.eq("status", "new"), Update().set("status", "open")).matched_count == 3
        r = orders.bulk_write([BulkOperation.delete(1), BulkOperation.insert({"_id": 1}), BulkOperation.delete(99)])
        assert (r.deleted_count, r.inserted_count, r.errors) == (1, 1, [])
        rows = client.get_database().query("FROM orders WHERE status = $s SELECT VALUE _id ORDER BY _id", {"s": "open"})
        assert rows.to_list() == [{"value": 2}, {"value": 4}, {"value": 6}]  # rows are documents

        def move(txn: Transaction) -> int:
            coll = txn.get_collection("orders")
            coll.update_one(Filter.id(2), Update().inc("total", Decimal(10)))
            return 42

        assert client.with_transaction(move) == 42
        assert _plain(orders.find_by_id(2)) == {"_id": 2, "status": "open", "total": Decimal(12)}


@dataclasses.dataclass
class Account:
    id: str | None = None
    owner: str | None = None
    balance: int = 0


async def test_tc_drv_py_025_mapped_dataclasses(database: str) -> None:
    async with AsyncRustegonClient(server.shared().admin_settings(database=database)) as client:
        accounts = client.get_database().get_collection("accounts", Account)
        await accounts.insert_one(Account("a1", "ann", 10))
        assert await accounts.find_by_id("a1") == Account("a1", "ann", 10)
        assert await accounts.find(Filter.eq("owner", "ann")).to_list() == [Account("a1", "ann", 10)]


async def test_tc_drv_py_026_with_transaction_retries_conflicts(database: str) -> None:
    """Concurrent increments of one document conflict (RGN-2001); with_transaction re-runs them."""
    async with AsyncRustegonClient(server.shared().admin_settings(database=database)) as client:
        counters = client.get_database().get_collection("counters")
        await counters.insert_one({"_id": "c", "n": 0})

        async def increment(txn: AsyncTransaction) -> None:
            coll = txn.get_collection("counters")
            doc = await coll.find_by_id("c")
            assert doc is not None
            await coll.replace_one(Filter.id("c"), {"_id": "c", "n": doc["n"] + 1})

        await asyncio.gather(*(client.with_transaction(increment) for _ in range(8)))
        doc = await counters.find_by_id("c")
        assert doc is not None and doc["n"] == 8


async def test_tc_drv_py_027_closed_client_and_cursor(database: str) -> None:
    client = AsyncRustegonClient(server.shared().admin_settings(database=database))
    coll = client.get_database().get_collection("c")
    await coll.insert_many([{"_id": i} for i in range(5)])
    cursor = await coll.find().sort(Sort.asc("_id")).batch_size(2).cursor()
    assert _plain(await cursor.try_next()) == {"_id": 0}
    await cursor.close()
    await cursor.close()  # idempotent
    assert await cursor.try_next() is None
    await client.close()
    with pytest.raises(RuntimeError):
        await client.list_database_names()
