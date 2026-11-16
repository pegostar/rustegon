# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors

"""Error table generated from drivers/conformance/generated/errors.json - do not edit.

Regenerate with ``python scripts/generate.py`` (PD-075, PD-171).
"""

from typing import Final

# code -> (name, errors-map.yaml class id, gRPC status name, catalog retryable: yes|no|depends)
CODES: Final[dict[int, tuple[str, str, str, str]]] = {
    1001: ("InvalidArgument", "Client", "INVALID_ARGUMENT", "no"),
    1002: ("DocumentTooLarge", "Client", "INVALID_ARGUMENT", "no"),
    1003: ("NestingTooDeep", "Client", "INVALID_ARGUMENT", "no"),
    1004: ("InvalidFieldName", "Client", "INVALID_ARGUMENT", "no"),
    1005: ("DuplicateKey", "DuplicateKey", "ALREADY_EXISTS", "no"),
    1006: ("SchemaValidationFailed", "DocumentValidation", "INVALID_ARGUMENT", "no"),
    1007: ("PartitionTooLarge", "Client", "FAILED_PRECONDITION", "no"),
    1008: ("IndexKeyTooLarge", "Client", "INVALID_ARGUMENT", "no"),
    1009: ("CounterOverflow", "Client", "OUT_OF_RANGE", "no"),
    1010: ("QuerySyntaxError", "QuerySyntax", "INVALID_ARGUMENT", "no"),
    1011: ("QueryTypeError", "QuerySyntax", "INVALID_ARGUMENT", "no"),
    1012: ("UnknownFunction", "QuerySyntax", "INVALID_ARGUMENT", "no"),
    1013: ("QueryTooComplex", "Client", "INVALID_ARGUMENT", "no"),
    1020: ("IndexAlreadyExists", "Client", "ALREADY_EXISTS", "no"),
    1021: ("IndexNotFound", "Client", "NOT_FOUND", "no"),
    1022: ("IndexBuildFailed", "Client", "FAILED_PRECONDITION", "no"),
    1023: ("IndexLimitExceeded", "Client", "RESOURCE_EXHAUSTED", "no"),
    1024: ("IndexStaleTimeout", "Timeout", "DEADLINE_EXCEEDED", "yes"),
    1025: ("MultikeyCompoundArrays", "Client", "INVALID_ARGUMENT", "no"),
    1030: ("NotFound", "Client", "NOT_FOUND", "no"),
    1031: ("AlreadyExists", "Client", "ALREADY_EXISTS", "no"),
    1032: ("ResumeTokenExpired", "Client", "OUT_OF_RANGE", "no"),
    1033: ("SchemaChangeInProgress", "Client", "ABORTED", "yes"),
    1034: ("DescriptorVersionMismatch", "Server", "ABORTED", "yes"),
    1040: ("InvalidVector", "Client", "INVALID_ARGUMENT", "no"),
    1041: ("InvalidGeometry", "Client", "INVALID_ARGUMENT", "no"),
    2001: ("TransactionConflict", "TransactionConflict", "ABORTED", "yes"),
    2002: ("TransactionAborted", "TransactionAborted", "ABORTED", "conditional"),
    2003: ("TransactionTimeout", "Timeout", "DEADLINE_EXCEEDED", "no"),
    2004: ("TransactionTooLarge", "Client", "RESOURCE_EXHAUSTED", "no"),
    2005: ("DeadlockDetected", "TransactionConflict", "ABORTED", "yes"),
    2006: ("CommitOutcomeUnknown", "CommitOutcomeUnknown", "UNKNOWN", "conditional"),
    2007: ("ReadTimestampTooOld", "TransactionConflict", "ABORTED", "yes"),
    2008: ("WriteTooOld", "TransactionConflict", "ABORTED", "yes"),
    2009: ("PreconditionFailed", "Client", "FAILED_PRECONDITION", "no"),
    3001: ("NotLeaseholder", "Unavailable", "UNAVAILABLE", "yes"),
    3002: ("Unavailable", "Unavailable", "UNAVAILABLE", "yes"),
    3003: ("RangeKeyMismatch", "Unavailable", "UNAVAILABLE", "yes"),
    3004: ("NodeDraining", "Unavailable", "UNAVAILABLE", "yes"),
    3005: ("ClockOffsetExceeded", "Unavailable", "UNAVAILABLE", "yes"),
    3006: ("WriteConcernTimeout", "Timeout", "DEADLINE_EXCEEDED", "no"),
    3007: ("StaleReadUnavailable", "Unavailable", "UNAVAILABLE", "yes"),
    4001: ("Unauthenticated", "Authentication", "UNAUTHENTICATED", "no"),
    4002: ("PermissionDenied", "Authorization", "PERMISSION_DENIED", "no"),
    4003: ("RateLimited", "RateLimited", "RESOURCE_EXHAUSTED", "yes"),
    4004: ("TlsRequired", "Authentication", "FAILED_PRECONDITION", "no"),
    4005: ("SessionExpired", "Authentication", "UNAUTHENTICATED", "yes"),
    4006: ("KeyUnavailable", "Server", "FAILED_PRECONDITION", "no"),
    4007: ("AccountLocked", "Authentication", "PERMISSION_DENIED", "no"),
    5001: ("Internal", "Server", "INTERNAL", "no"),
    5002: ("StorageCorruption", "Server", "DATA_LOSS", "no"),
    5003: ("DiskFull", "Server", "RESOURCE_EXHAUSTED", "yes"),
    5004: ("ResourceExhausted", "Server", "RESOURCE_EXHAUSTED", "yes"),
    5005: ("Cancelled", "Server", "CANCELLED", "no"),
    5006: ("DeadlineExceeded", "Timeout", "DEADLINE_EXCEEDED", "no"),
    5007: ("VersionIncompatible", "Client", "FAILED_PRECONDITION", "no"),
}

# gRPC status name -> (class id, synthesized code, retryable) for failures without ErrorDetail
TRANSPORT: Final[dict[str, tuple[str, int, bool]]] = {
    "UNKNOWN": ("Server", 5001, False),
    "DEADLINE_EXCEEDED": ("Timeout", 5006, False),
    "PERMISSION_DENIED": ("Authorization", 4002, False),
    "RESOURCE_EXHAUSTED": ("Server", 5004, True),
    "INTERNAL": ("Server", 5001, False),
    "UNAVAILABLE": ("Unavailable", 3002, True),
    "UNAUTHENTICATED": ("Authentication", 4001, False),
    "default": ("Server", 5001, False),
}

UNKNOWN: Final = "Base"
