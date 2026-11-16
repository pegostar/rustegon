# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""The exception hierarchy of the driver (python-driver.md §8, errors-map.yaml, PD-075).

Every server error and every failed call raises a ``RustegonException`` (or a subclass) carrying
``code``, ``name``, ``retryable``, ``committed``, ``details``, ``trace_id`` and
``retry_after_ms``. The class is chosen by the error code only (``_error_table.py``, generated
from ``drivers/conformance/generated/errors.json``); the flags come from the server's
``ErrorDetail``. Codes this version does not know map to ``RustegonException`` itself, so newer
servers never break older drivers (protocol.md §9).

Argument errors detected before any I/O raise ``ValueError`` / ``TypeError``; using a closed
client, session, cursor or transaction raises ``RuntimeError`` (the language conventions of
README §5, ``Argument`` and ``InvalidState``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final

from rustegon import _error_table

__all__ = [
    "AuthenticationException",
    "AuthorizationException",
    "CommitOutcomeUnknownException",
    "DocumentValidationException",
    "DuplicateKeyException",
    "PasswordChangeRequiredException",
    "QuerySyntaxException",
    "RDocError",
    "RateLimitedException",
    "RustegonClientException",
    "RustegonException",
    "RustegonServerException",
    "RustegonTimeoutException",
    "TransactionAbortedException",
    "TransactionConflictException",
    "UnavailableException",
]


class RustegonException(Exception):
    """Base class of every Rustegon error (``Base`` in errors-map.yaml)."""

    def __init__(
        self,
        message: str,
        *,
        code: int,
        name: str = "",
        retryable: bool = False,
        committed: bool | None = None,
        details: Mapping[str, str] | None = None,
        trace_id: str = "",
        retry_after_ms: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.name = name
        self.retryable = retryable
        self.committed = committed
        self.details: Mapping[str, str] = dict(details or {})
        self.trace_id = trace_id
        self.retry_after_ms = retry_after_ms

    def __str__(self) -> str:
        return f"RGN-{self.code} {self.name}: {self.args[0] if self.args else ''}"


class RustegonClientException(RustegonException):
    """Client errors (1xxx) not mapped to a more specific class."""


class QuerySyntaxException(RustegonClientException):
    """RGQL syntax, type and unknown-function errors (RGN-1010/1011/1012)."""


class RDocError(RustegonClientException, ValueError):
    """An RDoc or extended-JSON input the codec refuses (RGN-1001/1002/1003/1004/1040).

    Also a ``ValueError``: it is raised by the codec before any I/O.
    """

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message, code=code, name=_error_table.CODES[code][0])


class DuplicateKeyException(RustegonException):
    """A unique key (``_id`` or a unique index) already exists (RGN-1005)."""


class DocumentValidationException(RustegonException):
    """A collection validator refused the document (RGN-1006)."""


class TransactionConflictException(RustegonException):
    """A conflict, deadlock or stale read aborted the transaction; retry it (RGN-2001/2005/2007/2008)."""


class TransactionAbortedException(RustegonException):
    """The transaction was aborted (RGN-2002); ``retryable`` depends on the reason."""


class CommitOutcomeUnknownException(RustegonException):
    """The commit may or may not have been applied (RGN-2006); ``resolve()`` asks the server."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self._resolver: Callable[[], Awaitable[str]] | None = None

    async def resolve(self) -> str:
        """``"committed"``, ``"aborted"`` or ``"unknown"`` (TransactionService.Status)."""
        if self._resolver is None:
            raise RuntimeError("this error is not attached to a transaction")
        return await self._resolver()


class AuthenticationException(RustegonException):
    """Authentication failed or the session expired (RGN-4001/4004/4005/4007)."""


class PasswordChangeRequiredException(AuthenticationException):
    """The account must change its password first (PD-076); see ``allow_password_change_only``."""


class AuthorizationException(RustegonException):
    """The principal lacks a privilege (RGN-4002)."""


class UnavailableException(RustegonException):
    """The node or the cluster cannot serve the request now (RGN-3xxx)."""


class RateLimitedException(RustegonException):
    """Too many requests (RGN-4003); ``retry_after_ms`` says when to come back."""


class RustegonTimeoutException(RustegonException):
    """A deadline passed (RGN-5006, RGN-2003, RGN-1024, RGN-3006).

    Named like the Java class: ``TimeoutError`` is a built-in Python exception.
    """


class RustegonServerException(RustegonException):
    """Server-side failures (5xxx and internal codes)."""


# errors-map.yaml class id -> Python class (the hierarchy is pinned by test_tc_drv_py_006).
CLASSES: Final[dict[str, type[RustegonException]]] = {
    "Base": RustegonException,
    "Client": RustegonClientException,
    "QuerySyntax": QuerySyntaxException,
    "DuplicateKey": DuplicateKeyException,
    "DocumentValidation": DocumentValidationException,
    "TransactionConflict": TransactionConflictException,
    "TransactionAborted": TransactionAbortedException,
    "CommitOutcomeUnknown": CommitOutcomeUnknownException,
    "Authentication": AuthenticationException,
    "PasswordChangeRequired": PasswordChangeRequiredException,
    "Authorization": AuthorizationException,
    "Unavailable": UnavailableException,
    "RateLimited": RateLimitedException,
    "Timeout": RustegonTimeoutException,
    "Server": RustegonServerException,
}


def create(
    message: str,
    code: int,
    *,
    name: str | None = None,
    retryable: bool = False,
    committed: bool | None = None,
    details: Mapping[str, str] | None = None,
    trace_id: str = "",
    retry_after_ms: int | None = None,
) -> RustegonException:
    """The exception of an error code: the class of the table, the base class for unknown codes."""
    entry = _error_table.CODES.get(code)
    cls = CLASSES[entry[1] if entry else _error_table.UNKNOWN]
    if name is None:
        name = entry[0] if entry else ""
    return cls(
        message,
        code=code,
        name=name,
        retryable=retryable,
        committed=committed,
        details=details,
        trace_id=trace_id,
        retry_after_ms=retry_after_ms,
    )


def local(code: int, message: str) -> RustegonException:
    """An error raised by the driver itself: retryable only if the catalog says always ("yes")."""
    entry = _error_table.CODES[code]
    return create(message, code, retryable=entry[3] == "yes")


def transport(status_name: str, message: str) -> RustegonException:
    """A failure without ``ErrorDetail``: the transport fallback of errors-map.yaml."""
    _cls, code, retryable = _error_table.TRANSPORT.get(status_name, _error_table.TRANSPORT["default"])
    return create(message, code, retryable=retryable)
