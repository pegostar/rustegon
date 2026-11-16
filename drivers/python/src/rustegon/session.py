# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Client sessions (python-driver.md §6). R1 sessions are a pass-through of the
``rgn-causality-token``: the session remembers the last token the server returned and sends it on
its later calls; there is no server-side session yet (PD-069, DIVERGENCES.md §1)."""

from __future__ import annotations

from types import TracebackType

__all__ = ["ClientSession"]


class ClientSession:
    """A causal-consistency session; use it through ``with_options(session=...)`` handles."""

    def __init__(self, causal_consistency: bool = True) -> None:
        self.causal_consistency = causal_consistency
        self._token: str | None = None
        self._closed = False

    @property
    def causality_token(self) -> str | None:
        """The last causality token seen (``None`` before the first one)."""
        return self._token

    def observe(self, token: str) -> None:
        """Records a token returned by the server."""
        self._token = token

    def ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("the session is closed")

    def close(self) -> None:
        """Ends the session; idempotent."""
        self._closed = True

    def __enter__(self) -> ClientSession:
        return self

    def __exit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    async def __aenter__(self) -> ClientSession:
        return self

    async def __aexit__(self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None) -> None:
        self.close()
