# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Client settings, credentials and the ``rustegon://`` connection string (DEC-014,
python-driver.md §3, drivers/conformance/connstring.yaml).

TLS (ADR-034): plain text unless asked for. ``tls`` defaults to off; any TLS option
(``tls_ca_file``, ``tls_server_name``, ``tls_certificate_file``/``tls_key_file``) or the X509
mechanism turns it on when ``tls`` is not given; an explicit ``tls=False`` together with a TLS
option is an error. Secrets (passwords, API keys) are excluded from ``repr`` and never quoted
in an error message.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import unquote_to_bytes

__all__ = ["ClientSettings", "Credential", "ReadConsistency", "WriteConcern"]

DEFAULT_PORT: Final = 7700


class ReadConsistency(enum.Enum):
    """Read consistency level (protocol.md §2); the server default is ``LINEARIZABLE``."""

    LINEARIZABLE = "linearizable"
    BOUNDED_STALENESS = "bounded_staleness"
    FOLLOWER = "follower"


class WriteConcern(enum.Enum):
    """Write concern; the server default is ``MAJORITY``."""

    MAJORITY = "majority"
    ALL = "all"


SCRAM_SHA_256: Final = "SCRAM-SHA-256"
X509: Final = "X509"
APIKEY: Final = "APIKEY"


@dataclass(frozen=True, slots=True)
class Credential:
    """How the client authenticates: ``scram``, ``api_key`` or ``x509`` (protocol.md §8)."""

    mechanism: str
    user: str | None = None
    # The password (SCRAM) or the API key: a secret, excluded from repr.
    secret: str | None = field(default=None, repr=False)
    certificate_file: str | None = None
    key_file: str | None = None

    @staticmethod
    def scram(user: str, password: str) -> Credential:
        """SCRAM-SHA-256 with a user name and a password (preferred over the connection string)."""
        if not user:
            raise ValueError("a SCRAM credential needs a user name")
        if password is None:
            raise ValueError("a SCRAM credential needs a password")
        return Credential(SCRAM_SHA_256, user=user, secret=password)

    @staticmethod
    def api_key(key: str) -> Credential:
        """An API key (``rgn_…``) sent as ``authorization: ApiKey <key>`` on every call."""
        if not key:
            raise ValueError("an API key must not be empty")
        return Credential(APIKEY, secret=key)

    @staticmethod
    def x509(certificate_file: str | None = None, key_file: str | None = None) -> Credential:
        """A TLS client certificate (PEM files; default: the TLS settings' certificate)."""
        if (certificate_file is None) != (key_file is None):
            raise ValueError("give both the certificate and its key, or neither")
        return Credential(X509, certificate_file=certificate_file, key_file=key_file)


def _seconds(value: float | None, what: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{what} must be a positive number of seconds")
    return float(value)


@dataclass(frozen=True, slots=True)
class ClientSettings:
    """Everything a client needs; build it directly or with ``from_connection_string``.

    Durations are seconds (``float``). ``tls=None`` means "derive" (ADR-034); after construction
    ``tls`` is always a ``bool``.
    """

    hosts: Sequence[tuple[str, int]] = ((("localhost", DEFAULT_PORT)),)
    database: str | None = None
    credential: Credential | None = None
    auth_mechanism: str | None = None
    tls: bool | None = None
    tls_ca_file: str | None = None
    tls_server_name: str | None = None
    tls_certificate_file: str | None = None
    tls_key_file: str | None = None
    application_name: str | None = None
    connect_timeout: float = 10.0
    operation_timeout: float = 30.0
    read_consistency: ReadConsistency | None = None
    max_staleness: float | None = None
    write_concern: WriteConcern | None = None
    retry_reads: bool = True
    retry_writes: bool = True
    max_retries: int = 1
    connections_per_endpoint: int = 2
    allow_password_change_only: bool = False
    # A user named by a connection string without a password (DIVERGENCES.md §2): kept so that
    # the client can say which credential is missing; the password is never stored here.
    user: str | None = None

    def __post_init__(self) -> None:
        hosts = tuple((str(h).lower(), int(p)) for h, p in self.hosts)
        if not hosts:
            raise ValueError("at least one host")
        for h, p in hosts:
            if not h or not 1 <= p <= 65535:
                raise ValueError("a host needs a name and a port in 1..65535")
        object.__setattr__(self, "hosts", hosts)
        if self.tls_server_name == "" or self.tls_ca_file == "":
            raise ValueError("TLS options must not be empty")
        if (self.tls_certificate_file is None) != (self.tls_key_file is None):
            raise ValueError("tls_certificate_file and tls_key_file go together")
        mechanism = self.auth_mechanism or (self.credential.mechanism if self.credential else None)
        tls_options = any(x is not None for x in (self.tls_ca_file, self.tls_server_name, self.tls_certificate_file))
        if self.tls is False and tls_options:
            raise ValueError("tls=false contradicts the TLS options (ADR-034)")
        if self.tls is False and mechanism == X509:
            raise ValueError("the X509 mechanism needs TLS")
        if self.tls is None:
            object.__setattr__(self, "tls", tls_options or mechanism == X509)
        object.__setattr__(self, "connect_timeout", _seconds(self.connect_timeout, "connect_timeout"))
        object.__setattr__(self, "operation_timeout", _seconds(self.operation_timeout, "operation_timeout"))
        object.__setattr__(self, "max_staleness", _seconds(self.max_staleness, "max_staleness"))
        if self.read_consistency is ReadConsistency.BOUNDED_STALENESS and self.max_staleness is None:
            raise ValueError("bounded_staleness needs max_staleness")
        if not 0 <= self.max_retries <= 10:
            raise ValueError("max_retries must be in 0..10")
        if not 1 <= self.connections_per_endpoint <= 64:
            raise ValueError("connections_per_endpoint must be in 1..64")

    def replace(self, **changes: Any) -> ClientSettings:
        """A copy with some settings changed (``dataclasses.replace``)."""
        return dataclasses.replace(self, **changes)

    @staticmethod
    def from_connection_string(uri: str, **overrides: Any) -> ClientSettings:
        """Parses ``rustegon://[user[:password]@]host[:port][,…][/database][?options]``.

        Invalid strings raise ``ValueError`` before any I/O; the message never quotes the
        password. ``overrides`` replace settings of the string (e.g. ``credential=``).
        """
        settings = _parse(uri)
        return settings.replace(**overrides) if overrides else settings


# ------------------------------------------------------------------------------ parsing

_HOST: Final = re.compile(r"[A-Za-z0-9._~-]+", re.ASCII)
_IPV6: Final = re.compile(r"[0-9A-Fa-f:.]+", re.ASCII)
_DIGITS: Final = re.compile(r"[0-9]+", re.ASCII)
_PCT: Final = re.compile(r"%(?![0-9A-Fa-f]{2})")
_KEYS: Final = {
    k.lower(): k
    for k in (
        "tls",
        "tlsCaFile",
        "tlsServerName",
        "tlsCertificateFile",
        "tlsKeyFile",
        "authMechanism",
        "apiKey",
        "appName",
        "connectTimeoutMs",
        "operationTimeoutMs",
        "readConsistency",
        "maxStalenessMs",
        "writeConcern",
        "retryReads",
        "retryWrites",
        "maxRetries",
        "connectionsPerEndpoint",
    )
}
_MECHANISMS: Final = {"scram-sha-256": SCRAM_SHA_256, "x509": X509, "apikey": APIKEY, "api-key": APIKEY}


def _decode(text: str, what: str) -> str:
    if _PCT.search(text):
        raise ValueError(f"bad percent-encoding in the {what}")
    try:
        return unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"the {what} is not UTF-8 after percent-decoding") from e


def _bool(key: str, value: str) -> bool:
    v = value.lower()
    if v not in ("true", "false"):
        raise ValueError(f"{key} must be true or false")
    return v == "true"


def _int(key: str, value: str, low: int, high: int) -> int:
    if not _DIGITS.fullmatch(value) or not low <= int(value) <= high:
        raise ValueError(f"{key} must be an integer in {low}..{high}")
    return int(value)


def _parse(uri: str) -> ClientSettings:
    if not isinstance(uri, str):
        raise TypeError("a connection string is a str")
    if uri.startswith("rustegon+srv://"):
        raise ValueError("rustegon+srv:// is not supported yet (M5)")
    if not uri.startswith("rustegon://"):
        raise ValueError("a connection string starts with rustegon://")
    if any(c.isspace() or ord(c) < 0x20 for c in uri):
        raise ValueError("a connection string must not contain whitespace or control characters")
    rest = uri[len("rustegon://") :]
    rest, _, query = rest.partition("?")
    authority, slash, path = rest.partition("/")
    user = password = None
    if "@" in authority:
        userinfo, _, hostlist = authority.rpartition("@")
        if "@" in userinfo:
            raise ValueError("'@' in the user or password must be percent-encoded")
        raw_user, colon, raw_password = userinfo.partition(":")
        user = _decode(raw_user, "user")
        if not user:
            raise ValueError("the user name is empty")
        password = _decode(raw_password, "password") if colon else None
    else:
        hostlist = authority
    hosts: list[tuple[str, int]] = []
    for item in hostlist.split(","):
        hosts.append(_host(item))
    database = None
    if slash and path:
        if "/" in path:
            raise ValueError("the database name must not contain '/'")
        database = _decode(path, "database")
    options: dict[str, str] = {}
    if query:
        for pair in query.split("&"):
            key, eq, value = pair.partition("=")
            if not eq:
                raise ValueError("an option needs a value (key=value)")
            canonical = _KEYS.get(key.lower())
            if canonical is None:
                raise ValueError(f"unknown option {key!r}")
            if canonical in options:
                raise ValueError(f"option {canonical} given twice")
            options[canonical] = _decode(value, f"option {canonical}")
    return _settings(hosts, user, password, database, options)


def _host(item: str) -> tuple[str, int]:
    if not item:
        raise ValueError("empty host in the host list")
    if item.startswith("["):
        end = item.find("]")
        if end < 0 or not _IPV6.fullmatch(item[1:end]):
            raise ValueError("bad IPv6 literal")
        host, after = item[1:end], item[end + 1 :]
        if after and not after.startswith(":"):
            raise ValueError("bad IPv6 host")
        port_text = after[1:] if after else None
    else:
        host, colon, after_colon = item.partition(":")
        port_text = after_colon if colon else None
        if not _HOST.fullmatch(host):
            raise ValueError("bad host name (IPv6 literals need brackets)")
    port = DEFAULT_PORT
    if port_text is not None:
        port = _int("the port", port_text, 1, 65535)
    return host.lower(), port


def _settings(
    hosts: list[tuple[str, int]],
    user: str | None,
    password: str | None,
    database: str | None,
    o: dict[str, str],
) -> ClientSettings:
    kw: dict[str, Any] = {"hosts": hosts, "database": database}
    if "tls" in o:
        kw["tls"] = _bool("tls", o["tls"])
    for key, name in (
        ("tlsCaFile", "tls_ca_file"),
        ("tlsServerName", "tls_server_name"),
        ("tlsCertificateFile", "tls_certificate_file"),
        ("tlsKeyFile", "tls_key_file"),
    ):
        if key in o:
            if not o[key]:
                raise ValueError(f"{key} must not be empty")
            kw[name] = o[key]
    if ("tlsCertificateFile" in o) != ("tlsKeyFile" in o):
        raise ValueError("tlsCertificateFile and tlsKeyFile go together")
    if kw.get("tls") is False and any(k in o for k in ("tlsCaFile", "tlsServerName", "tlsCertificateFile")):
        raise ValueError("tls=false contradicts the TLS options (ADR-034)")
    mechanism = None
    if "authMechanism" in o:
        mechanism = _MECHANISMS.get(o["authMechanism"].lower())
        if mechanism is None:
            raise ValueError("unknown authMechanism")
    api_key = o.get("apiKey")
    if api_key is not None:
        if not api_key:
            raise ValueError("apiKey must not be empty")
        if mechanism not in (None, APIKEY):
            raise ValueError("apiKey needs authMechanism=APIKEY")
        if user is not None:
            raise ValueError("an API key cannot be combined with a user")
        mechanism = APIKEY
    elif mechanism == APIKEY:
        raise ValueError("authMechanism=APIKEY needs apiKey")
    if mechanism == X509 and password is not None:
        raise ValueError("the X509 mechanism takes no password")
    if mechanism is None and user is not None:
        mechanism = SCRAM_SHA_256
    kw["auth_mechanism"] = mechanism
    if mechanism == APIKEY and api_key:
        kw["credential"] = Credential.api_key(api_key)
    elif mechanism == SCRAM_SHA_256 and user is not None and password is not None:
        kw["credential"] = Credential(SCRAM_SHA_256, user=user, secret=password)
    elif mechanism == X509:
        kw["credential"] = Credential(X509, user=user)
    if user is not None and "credential" not in kw:
        kw["user"] = user
    if "appName" in o:
        kw["application_name"] = o["appName"]
    if "connectTimeoutMs" in o:
        kw["connect_timeout"] = _int("connectTimeoutMs", o["connectTimeoutMs"], 1, 2**31) / 1000
    if "operationTimeoutMs" in o:
        kw["operation_timeout"] = _int("operationTimeoutMs", o["operationTimeoutMs"], 1, 2**31) / 1000
    if "readConsistency" in o:
        try:
            kw["read_consistency"] = ReadConsistency(o["readConsistency"].lower())
        except ValueError as e:
            raise ValueError("readConsistency is linearizable, bounded_staleness or follower") from e
    if "maxStalenessMs" in o:
        kw["max_staleness"] = _int("maxStalenessMs", o["maxStalenessMs"], 1, 2**31) / 1000
    if "writeConcern" in o:
        try:
            kw["write_concern"] = WriteConcern(o["writeConcern"].lower())
        except ValueError as e:
            raise ValueError("writeConcern is majority or all") from e
    for key, name in (("retryReads", "retry_reads"), ("retryWrites", "retry_writes")):
        if key in o:
            kw[name] = _bool(key, o[key])
    if "maxRetries" in o:
        kw["max_retries"] = _int("maxRetries", o["maxRetries"], 0, 10)
    if "connectionsPerEndpoint" in o:
        kw["connections_per_endpoint"] = _int("connectionsPerEndpoint", o["connectionsPerEndpoint"], 1, 64)
    return ClientSettings(**kw)
