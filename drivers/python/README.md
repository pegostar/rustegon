# Rustegon Python driver

The official Python driver of the Rustegon document database: an asyncio API and a blocking
facade over the same core. Specification: [`docs/specifications/python-driver.md`](../../docs/specifications/python-driver.md).
Requires Python 3.11 or later (tested on CPython 3.14). Not yet published to PyPI.

## Quick start

```python
from rustegon import RustegonClient, Filter, Updates

# DEC-014: host, port, user, password, database. A default single node is plain text (ADR-034).
with RustegonClient("rustegon://app_user:secret@localhost:7700/shop") as client:
    orders = client.get_database().get_collection("orders")
    orders.insert_one({"_id": 1, "status": "paid", "total": 12})
    for order in orders.find(Filter.eq("status", "paid")):
        print(order)
    orders.update_one(Filter.id(1), Updates.set("status", "shipped"))
```

The same with asyncio:

```python
import asyncio
from rustegon import AsyncRustegonClient, ClientSettings, Credential, Filter, Updates


async def main() -> None:
    settings = ClientSettings(
        hosts=[("db1.example.com", 7700)],
        credential=Credential.scram("app_user", "secret"),  # or Credential.api_key / Credential.x509
        tls_ca_file="/etc/rustegon/ca.crt",  # any TLS option turns TLS on
        database="shop",
    )
    async with AsyncRustegonClient(settings) as client:
        orders = client.get_database().get_collection("orders")
        async for order in orders.find(Filter.gte("total", 10)).limit(20):
            print(order)

        async def pay(txn) -> None:  # re-run on conflicts (transactions.md §5)
            await txn.get_collection("orders").update_one(Filter.id(1), Updates.set("status", "paid"))

        await client.with_transaction(pay)


asyncio.run(main())
```

Documents are `dict` (field order = insertion order) or dataclasses
(`get_collection("orders", Order)`, markers in `rustegon.mapping`). Values: `int` int64, `float`,
`Decimal` decimal128, timezone-aware `datetime`, `bytes`, `uuid.UUID`, `ObjectId`, `Vector`, …
(python-driver.md §7). Errors are `rustegon.errors.RustegonException` subclasses with `code`,
`retryable` and `trace_id`; reads and idempotent writes are retried once by default.

## Development

```bash
cd drivers/python
python -m venv .venv && .venv/Scripts/python -m pip install -e . --group dev   # .venv/bin on Linux
.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m ruff format --check .
.venv/Scripts/python -m mypy                                                     # --strict (pyproject)
RUSTEGON_BIN_DIR=<dir with rustegon and rustegond> .venv/Scripts/python -m pytest
python scripts/generate.py            # regenerate src/rustegon/_pb and _error_table.py (PD-171)
```

Without `RUSTEGON_BIN_DIR` (default `<repo>/target/debug`) the server tests are skipped (they
fail under `CI=true`). The conformance runner writes `RUSTEGON_CONFORMANCE_RESULTS` (default
`build/conformance-results.json`), compared with the .NET and Java results by
`scripts/ci-local.sh` (AC-DRV-003). Server binaries must follow ADR-034 (plain text by default, `init --tls`).
